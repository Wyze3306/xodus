use tao::dpi::{LogicalSize, Size};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder, EventLoopWindowTarget};
use tao::platform::run_return::EventLoopExtRunReturn;
use tao::window::{Window, WindowBuilder};
use wry::http::{HeaderMap, HeaderValue};
use wry::{PageLoadEvent, WebView, WebViewBuilder};
use xodus::models::live::{DAProperty, HostBridgeMessage};

type HandlerResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(u64);

pub enum HandlerControl<T> {
    Continue,
    Complete(T),
}

pub trait SessionHandler {
    type Output: std::fmt::Debug;

    fn bootstrap(&mut self, runtime: &mut RuntimeCommands) -> HandlerResult<()>;

    fn on_token(
        &mut self,
        session_id: SessionId,
        data: DAProperty,
        runtime: &mut RuntimeCommands,
    ) -> HandlerResult<HandlerControl<Self::Output>>;

    fn on_closed(
        &mut self,
        _session_id: SessionId,
        _runtime: &mut RuntimeCommands,
    ) -> HandlerResult<HandlerControl<Self::Output>> {
        Ok(HandlerControl::Continue)
    }
}

pub struct WebviewRequest {
    title: String,
    url: String,
    headers: HeaderMap,
}

pub struct RuntimeCommands {
    next_session_id: u64,
    actions: Vec<RuntimeAction>,
}

enum RuntimeAction {
    OpenSession {
        session_id: SessionId,
        request: WebviewRequest,
    },
    CloseSession(SessionId),
}

enum CustomEvent {
    OpenSession {
        session_id: SessionId,
        request: WebviewRequest,
    },
    HostGetContext(SessionId, String),
    Finish(SessionId),
    IpcCallback(SessionId, DAProperty),
}

struct RuntimeState<T: SessionHandler> {
    handler: T,
    next_session_id: u64,
    window: Option<Window>,
    active_session: Option<SessionId>,
    active_webview: Option<WebView>,
    result: Option<T::Output>,
    error: Option<String>,
}

impl RuntimeCommands {
    fn new(next_session_id: u64) -> Self {
        Self {
            next_session_id,
            actions: Vec::new(),
        }
    }

    pub fn open_session(&mut self, request: WebviewRequest) -> SessionId {
        let session_id = SessionId(self.next_session_id);
        self.next_session_id += 1;
        self.actions.push(RuntimeAction::OpenSession {
            session_id,
            request,
        });
        session_id
    }

    pub fn close_session(&mut self, session_id: SessionId) {
        self.actions.push(RuntimeAction::CloseSession(session_id));
    }
}

impl WebviewRequest {
    fn new(title: impl Into<String>, url: String, headers: HeaderMap) -> Self {
        Self {
            title: title.into(),
            url,
            headers,
        }
    }
}

/// The headers that tell login.live.com it is talking to the token broker.
///
/// They are what selects the CloudExperienceHost flow -- the one that drives
/// the host bridge and ends by posting `ServerData` back through
/// `ppsecure/post.srf`. Every page of a sign-in needs them, not just the
/// first: served without them, the same URL renders the ordinary consumer
/// page instead, which waits on a host that is never told about it.
fn host_headers() -> HeaderMap {
    let uid = uuid::Uuid::new_v4();
    let mut headers = HeaderMap::new();
    headers.insert("cxh-capabilities", HeaderValue::from_static(r#"{"PrivatePropertyBag":1,"PasswordlessConnect":1,"PreferAssociate":1,"ChromelessUI":0}"#));
    headers.insert(
        "cxh-correlationId",
        HeaderValue::from_str(&format!("{uid}")).unwrap(),
    );
    headers.insert("cxh-msaBinaryVersion", HeaderValue::from_static(r#"55"#));
    headers.insert(
        "cxh-identityClientBinaryVersion",
        HeaderValue::from_static(r#"3"#),
    );
    headers.insert(
        "cxh-osVersionInfo",
        HeaderValue::from_static(
            r#"{"platformId":2,"majorVersion":10,"minorVersion":0,"buildNumber":26100}"#,
        ),
    );
    headers.insert(
        "cxh-platform",
        HeaderValue::from_static(r#"CloudExperienceHost.Platform.DESKTOP"#),
    );
    headers.insert("cxh-protocol", HeaderValue::from_static(r#"TokenBroker"#));
    headers.insert("cxh-source", HeaderValue::from_static(r#"TokenBroker"#));
    headers.insert(
        "hostApp",
        HeaderValue::from_static(r#"CloudExperienceHost"#),
    );

    headers
}

pub fn login_request(client_id: String, market: String) -> WebviewRequest {
    let url = format!(
        "https://login.live.com/ppsecure/InlineLogin.srf?id=80604&scid=3&mkt={market}&Platform=Windows10&clientid={client_id}&hosted=1"
    );

    WebviewRequest::new("Xodus login", url, host_headers())
}

/// The second leg of a sign-in: the `inline_auth_url` a faulted token
/// exchange hands back, opened in a session of its own.
///
/// It carries the same headers as the first leg. Opened without them the
/// page has no way to know it is hosted, so login.live.com serves the
/// consumer interrupt -- "Please wait" and a disabled OK button -- which
/// never reaches `ppsecure/post.srf`. That URL is the only one
/// `create_session` fires `Finish` on, so `ServerData` is never read back
/// and the window sits there for as long as anyone leaves it open.
pub fn finalize_request(url: String) -> WebviewRequest {
    WebviewRequest::new("Xodus login", url, host_headers())
}

pub fn run_sessions<T>(handler: T) -> HandlerResult<Option<T::Output>>
where
    T: SessionHandler,
{
    let mut event_loop: EventLoop<CustomEvent> = EventLoopBuilder::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let mut state = RuntimeState {
        handler,
        next_session_id: 1,
        window: None,
        active_session: None,
        active_webview: None,
        result: None,
        error: None,
    };

    let mut commands = RuntimeCommands::new(state.next_session_id);
    state.handler.bootstrap(&mut commands)?;
    state.next_session_id = commands.next_session_id;
    dispatch_actions(&proxy, commands.actions)?;
    event_loop.run_return(|event, target, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::UserEvent(CustomEvent::OpenSession {
                session_id,
                request,
            }) => {
                if let Err(err) = create_session(
                    target,
                    proxy.clone(),
                    &mut state,
                    session_id,
                    request,
                ) {
                    state.error = Some(err.to_string());
                }
            }
            Event::UserEvent(CustomEvent::Finish(session_id)) => {
                if state.active_session == Some(session_id)
                    && let Some(webview) = state.active_webview.as_ref()
                {
                    let _ = webview.evaluate_script("window.ipc.postMessage(JSON.stringify(ServerData))");
                }
            }
            Event::UserEvent(CustomEvent::HostGetContext(session_id, ctx)) => {
                if state.active_session == Some(session_id)
                    && let Some(webview) = state.active_webview.as_ref()
                {
                    let _ = webview.evaluate_script(&format!(r#"window["CloudExperienceHost.Bridge.dispatchMessage"](JSON.stringify({{"type": "callback", "value": {{ "name": "CloudExperienceHost.getContext", "args": ["CloudExperienceHost", "TokenBroker", "TokenBroker", "{{\"PrivatePropertyBag\":1,\"PasswordlessConnect\":1,\"PreferAssociate\":1,\"ChromelessUI\":0}}"], "context": "{ctx}"}}}}))"#));
                }
            }
            Event::UserEvent(CustomEvent::IpcCallback(session_id, data)) => {
                apply_handler_result(
                    &proxy,
                    target,
                    &mut state,
                    move |handler, runtime| handler.on_token(session_id, data, runtime),
                );
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if let Some(session_id) = state.active_session {
                    remove_session(&mut state, session_id);
                    apply_handler_result(&proxy, target, &mut state, move |handler, runtime| {
                        handler.on_closed(session_id, runtime)
                    });
                }
            }
            _ => {}
        }

        if state.error.is_some() || state.result.is_some() {
            *control_flow = ControlFlow::Exit;
        }
    });

    if let Some(error) = state.error {
        return Err(std::io::Error::other(error).into());
    }

    Ok(state.result)
}

fn dispatch_actions(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    actions: Vec<RuntimeAction>,
) -> HandlerResult<()> {
    for action in actions {
        match action {
            RuntimeAction::OpenSession {
                session_id,
                request,
            } => proxy
                .send_event(CustomEvent::OpenSession {
                    session_id,
                    request,
                })
                .map_err(|_| std::io::Error::other("failed to open session"))?,
            RuntimeAction::CloseSession(session_id) => {
                let _ = session_id;
            }
        }
    }

    Ok(())
}

fn apply_handler_result<T, F>(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    target: &EventLoopWindowTarget<CustomEvent>,
    state: &mut RuntimeState<T>,
    callback: F,
) where
    T: SessionHandler,
    F: FnOnce(&mut T, &mut RuntimeCommands) -> HandlerResult<HandlerControl<T::Output>>,
{
    let mut commands = RuntimeCommands::new(state.next_session_id);
    match callback(&mut state.handler, &mut commands) {
        Ok(HandlerControl::Continue) => {}
        Ok(HandlerControl::Complete(result)) => state.result = Some(result),
        Err(err) => state.error = Some(err.to_string()),
    }

    state.next_session_id = commands.next_session_id;
    apply_actions(proxy, target, state, commands.actions);
}

fn apply_actions<T>(
    proxy: &tao::event_loop::EventLoopProxy<CustomEvent>,
    target: &EventLoopWindowTarget<CustomEvent>,
    state: &mut RuntimeState<T>,
    actions: Vec<RuntimeAction>,
) where
    T: SessionHandler,
{
    for action in actions {
        match action {
            RuntimeAction::OpenSession {
                session_id,
                request,
            } => {
                if let Err(err) = create_session(target, proxy.clone(), state, session_id, request)
                {
                    state.error = Some(err.to_string());
                    break;
                }
            }
            RuntimeAction::CloseSession(session_id) => {
                remove_session(state, session_id);
                let _ = proxy;
            }
        }
    }
}

fn create_session<T: SessionHandler>(
    target: &EventLoopWindowTarget<CustomEvent>,
    proxy: tao::event_loop::EventLoopProxy<CustomEvent>,
    state: &mut RuntimeState<T>,
    session_id: SessionId,
    request: WebviewRequest,
) -> HandlerResult<()> {
    if state.window.is_none() {
        let window = WindowBuilder::new()
            .with_resizable(false)
            .with_title(&request.title)
            .with_inner_size(Size::Logical(LogicalSize::new(500.0, 700.0)))
            .build(target)?;
        state.window = Some(window);
    }

    let window = state
        .window
        .as_ref()
        .ok_or_else(|| std::io::Error::other("window was not initialized"))?;
    window.set_title(&request.title);

    let proxy_ipc = proxy.clone();
    let builder = WebViewBuilder::new()
            .with_url(&request.url)
            .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; MSAppHost/3.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.26100")
            .with_headers(request.headers)
            .with_initialization_script("window.external = {notify: window.ipc.postMessage }")
            .with_ipc_handler(move |request| {
                let body = request.body();
                let payload = serde_json::from_str::<DAProperty>(body);
                if let Ok(data) = payload {
                    if proxy_ipc
                        .send_event(CustomEvent::IpcCallback(session_id, data))
                        .is_err()
                    {
                        eprintln!("Failed to dispatch IPC token callback event");
                    }
                } else if let Some(missing) = unusable_token_bag(body) {
                    // Any JSON object parses as a HostBridgeMessage, so this
                    // used to be dropped in silence with the page left on
                    // "Please wait".
                    eprintln!(
                        "Sign-in page returned its tokens without {}; cannot finish the sign-in",
                        missing.join(", ")
                    );
                } else {
                    match serde_json::from_str::<HostBridgeMessage>(body) {
                        Ok(message) => {
                            if let Some(ctx) = message.get_context_invoke()
                                && proxy_ipc
                                    .send_event(CustomEvent::HostGetContext(
                                        session_id,
                                        ctx.to_string(),
                                    ))
                                    .is_err()
                            {
                                eprintln!("Failed to dispatch host context event");
                            }
                            if let Some(name) = message.unanswered_invoke() {
                                eprintln!("Sign-in page is waiting on {name}, which this host does not answer");
                            }
                        }
                        Err(_) => {
                            eprintln!("Ignoring unsupported IPC payload");
                        }
                    }
                }
            })
            .with_on_page_load_handler(move |event, url| {
                if !matches!(event, PageLoadEvent::Finished) {
                    return;
                }
                // Where a sign-in stopped is the first question about one
                // that hangs, and nothing else answers it. The path only: a
                // query string here can carry a flow token.
                eprintln!("Sign-in page loaded: {}", page_without_query(&url));
                if url.starts_with("https://login.live.com/ppsecure/post.srf") {
                    proxy.send_event(CustomEvent::Finish(session_id)).ok();
                }
            });

    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        builder.build_gtk(window.default_vbox().unwrap()).unwrap()
    };
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window).unwrap();

    state.active_session = Some(session_id);
    state.active_webview = Some(webview);
    Ok(())
}

/// The missing fields of a `ServerData` that carries sign-in tokens but not
/// all the ones the exchange needs; None for any other payload.
fn unusable_token_bag(body: &str) -> Option<Vec<&'static str>> {
    let value = serde_json::from_str::<serde_json::Value>(body).ok()?;
    if !DAProperty::is_token_bag(&value) {
        return None;
    }
    let missing = DAProperty::missing(&value);
    // Every field present and still unreadable: a type Microsoft changed.
    Some(if missing.is_empty() { vec!["fields of the expected type"] } else { missing })
}

fn page_without_query(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

fn remove_session<T: SessionHandler>(state: &mut RuntimeState<T>, session_id: SessionId) {
    if state.active_session == Some(session_id) {
        state.active_session = None;
        state.active_webview = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_is_logged_without_its_query() {
        assert_eq!(
            page_without_query("https://login.live.com/ppsecure/post.srf?uaid=x&ft=secret"),
            "https://login.live.com/ppsecure/post.srf"
        );
        assert_eq!(page_without_query("https://login.live.com/a#b"), "https://login.live.com/a");
    }

    #[test]
    fn a_token_bag_short_of_a_field_is_named_and_others_are_not() {
        assert_eq!(
            unusable_token_bag(r#"{"sDAToken":"t","sSigninName":"u","K":"1"}"#),
            Some(vec!["sDAStartTime", "sDAExpires"])
        );
        assert_eq!(unusable_token_bag(r#"{"type":"invoke","value":{}}"#), None);
        assert_eq!(unusable_token_bag("not json"), None);
    }

    /// Every leg of the sign-in has to look like the same host, or the leg
    /// that does not never finishes.
    #[test]
    fn both_legs_of_a_sign_in_are_hosted_the_same_way() {
        let first = login_request("000000004424da1f".to_string(), "en-US".to_string());
        let second = finalize_request("https://login.live.com/ppsecure/inlineconnect.srf".to_string());

        for name in [
            "cxh-capabilities",
            "cxh-msaBinaryVersion",
            "cxh-identityClientBinaryVersion",
            "cxh-osVersionInfo",
            "cxh-platform",
            "cxh-protocol",
            "cxh-source",
            "hostApp",
        ] {
            assert_eq!(
                first.headers.get(name),
                second.headers.get(name),
                "{name} differs between the two legs of the sign-in"
            );
        }
        assert_eq!(
            first.headers.get("hostApp").unwrap().to_str().unwrap(),
            "CloudExperienceHost"
        );
    }

    /// The correlation id identifies one request, so it is the one header
    /// that must *not* be carried over.
    #[test]
    fn each_request_gets_its_own_correlation_id() {
        let first = host_headers();
        let second = host_headers();

        assert_ne!(
            first.get("cxh-correlationId"),
            second.get("cxh-correlationId")
        );
    }
}
