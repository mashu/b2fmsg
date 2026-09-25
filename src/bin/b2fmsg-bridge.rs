//! WebSocket ↔ TCP bridge so the browser client can reach the Winlink CMS
//! (telnet) or Direwolf's AGW port. Browsers cannot open raw TCP sockets.
//!
//!   b2fmsg-bridge [--listen 127.0.0.1:8765] [--cms HOST:PORT] [--agw HOST:PORT]
//!                 [--allow-origin URL ...]
//!
//! Routes are fixed (`/cms`, `/agw`) so a web page cannot point the bridge
//! at arbitrary hosts, and only pages from allowed origins may connect:
//! otherwise any website you visit could key your transmitter.

use std::env;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

const DEFAULT_LISTEN: &str = "127.0.0.1:8765";
const DEFAULT_CMS: &str = "server.winlink.org:8772";
const DEFAULT_AGW: &str = "127.0.0.1:8000";
const DEFAULT_ORIGINS: &[&str] = &[
    "https://mashu.github.io",
    "http://localhost",
    "http://127.0.0.1",
];

struct Settings {
    listen: String,
    cms: String,
    agw: String,
    origins: Vec<String>,
    any_origin: bool,
}

#[derive(Clone, Copy)]
enum Route {
    Cms,
    Agw,
}

impl Route {
    fn name(self) -> &'static str {
        match self {
            Route::Cms => "Winlink CMS",
            Route::Agw => "Direwolf AGW port",
        }
    }
}

#[tokio::main]
async fn main() {
    let settings = Arc::new(parse_args());
    let listen_addr: SocketAddr = settings.listen.parse().unwrap_or_else(|e| {
        eprintln!("b2fmsg-bridge: bad --listen {:?}: {e}", settings.listen);
        process::exit(2);
    });
    let listener = TcpListener::bind(listen_addr).await.unwrap_or_else(|e| {
        eprintln!("b2fmsg-bridge: cannot bind {listen_addr}: {e}");
        process::exit(1);
    });
    eprintln!(
        "b2fmsg-bridge: ws://{listen_addr}/cms → tcp://{}",
        settings.cms
    );
    eprintln!(
        "b2fmsg-bridge: ws://{listen_addr}/agw → tcp://{}",
        settings.agw
    );
    if settings.any_origin {
        eprintln!("b2fmsg-bridge: accepting pages from any origin");
    } else {
        eprintln!(
            "b2fmsg-bridge: accepting pages from {}",
            settings.origins.join(", ")
        );
    }

    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let settings = Arc::clone(&settings);
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, &settings).await {
                eprintln!("b2fmsg-bridge: {peer}: {e}");
            }
        });
    }
}

fn origin_allowed(settings: &Settings, origin: Option<&str>) -> bool {
    if settings.any_origin {
        return true;
    }
    // Non-browser clients send no Origin; they could open TCP themselves.
    let Some(origin) = origin else {
        return true;
    };
    settings.origins.iter().any(|allowed| {
        origin == allowed
            || origin.strip_prefix(allowed.as_str()).is_some_and(|rest| {
                rest.starts_with(':') && rest[1..].chars().all(|c| c.is_ascii_digit())
            })
    })
}

fn reject(status: StatusCode, text: String) -> ErrorResponse {
    let mut response = ErrorResponse::new(Some(text));
    *response.status_mut() = status;
    response
}

async fn handle_client(
    stream: TcpStream,
    settings: &Settings,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut route = None;
    // Handshake callback signature is fixed by tungstenite; ErrorResponse is large.
    #[allow(clippy::result_large_err)]
    let callback = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let origin = req.headers().get("origin").and_then(|v| v.to_str().ok());
        if !origin_allowed(settings, origin) {
            let origin = origin.unwrap_or_default();
            eprintln!(
                "b2fmsg-bridge: refused page from {origin} (add --allow-origin {origin} to permit)"
            );
            return Err(reject(
                StatusCode::FORBIDDEN,
                format!("origin {origin} is not allowed"),
            ));
        }
        route = match req.uri().path().trim_end_matches('/') {
            "/cms" => Some(Route::Cms),
            "/agw" => Some(Route::Agw),
            other => {
                return Err(reject(
                    StatusCode::NOT_FOUND,
                    format!("unknown route {other:?}; use /cms or /agw"),
                ));
            }
        };
        Ok(resp)
    };
    let mut ws = accept_hdr_async(stream, callback).await?;
    let route = route.ok_or("no route")?;
    let target = match route {
        Route::Cms => settings.cms.as_str(),
        Route::Agw => settings.agw.as_str(),
    };

    let tcp = match TcpStream::connect(target).await {
        Ok(tcp) => tcp,
        Err(e) => {
            let hint = match route {
                Route::Agw => " — start Direwolf with its AGW port enabled",
                Route::Cms => " — check your internet connection",
            };
            let reason = format!("{} not reachable at {target} ({e}){hint}", route.name());
            let _ = ws
                .close(Some(CloseFrame {
                    code: CloseCode::Error,
                    reason: reason.clone().into(),
                }))
                .await;
            return Err(reason.into());
        }
    };
    tcp.set_nodelay(true)?;
    let (mut tcp_rd, mut tcp_wr) = tcp.into_split();
    let (ws_tx, mut ws_rx) = ws.split();
    let ws_tx = Arc::new(Mutex::new(ws_tx));

    let to_tcp = {
        let ws_tx = Arc::clone(&ws_tx);
        async move {
            while let Some(msg) = ws_rx.next().await {
                match msg? {
                    Message::Binary(data) => tcp_wr.write_all(&data).await?,
                    Message::Text(text) => tcp_wr.write_all(text.as_bytes()).await?,
                    Message::Ping(p) => ws_tx.lock().await.send(Message::Pong(p)).await?,
                    Message::Close(_) => break,
                    Message::Pong(_) | Message::Frame(_) => {}
                }
            }
            let _ = tcp_wr.shutdown().await;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
    };

    let to_ws = async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = tcp_rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            ws_tx
                .lock()
                .await
                .send(Message::Binary(buf[..n].to_vec().into()))
                .await?;
        }
        let _ = ws_tx.lock().await.close().await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    tokio::select! {
        r = to_tcp => r?,
        r = to_ws => r?,
    }
    Ok(())
}

fn parse_args() -> Settings {
    let mut settings = Settings {
        listen: DEFAULT_LISTEN.into(),
        cms: DEFAULT_CMS.into(),
        agw: DEFAULT_AGW.into(),
        origins: DEFAULT_ORIGINS.iter().map(|s| s.to_string()).collect(),
        any_origin: false,
    };
    let mut extra_origins = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .unwrap_or_else(|| die(&format!("{name} needs a value")))
        };
        match arg.as_str() {
            "--listen" => settings.listen = value("--listen"),
            "--cms" => settings.cms = value("--cms"),
            "--agw" => settings.agw = value("--agw"),
            "--allow-origin" => {
                let origin = value("--allow-origin");
                if origin == "*" {
                    settings.any_origin = true;
                } else {
                    extra_origins.push(origin.trim_end_matches('/').to_owned());
                }
            }
            "-h" | "--help" => {
                println!(
                    "usage: b2fmsg-bridge [--listen {DEFAULT_LISTEN}] [--cms {DEFAULT_CMS}] [--agw {DEFAULT_AGW}]\n\
                     \x20                    [--allow-origin URL ...]\n\n\
                     Lets the b2fmsg web page reach the Winlink CMS (ws://HOST/cms) or\n\
                     Direwolf's AGW port (ws://HOST/agw). Pages are accepted only from\n\
                     {} (any port for localhost);\n\
                     add your own with --allow-origin, or --allow-origin '*' to accept any.",
                    DEFAULT_ORIGINS.join(", ")
                );
                process::exit(0);
            }
            other => die(&format!("unknown argument {other:?}")),
        }
    }
    settings.origins.extend(extra_origins);
    settings
}

fn die(msg: &str) -> ! {
    eprintln!("b2fmsg-bridge: {msg}");
    process::exit(2);
}
