//! WebAssembly bindings: the exchange state machine and message format for
//! the browser UI. Networking (WebSocket to the bridge) and storage
//! (IndexedDB) stay in JavaScript; this module turns bytes into actions.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::base64;
use crate::clock;
use crate::exchange::{Action, Exchange, ExchangeConfig, LinkSpec};
use crate::message::{Attachment, Draft, Message, display_address, generate_mid};
use crate::session::{LogKind, Outbound};
use crate::{CMS_TARGET, CMS_TELNET_PASSWORD};

fn default_paclen() -> usize {
    128
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeOptions {
    /// `"cms"` (telnet through the bridge) or `"agw"` (Direwolf).
    mode: String,
    call: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    locator: String,
    /// RMS gateway callsign for `"agw"`.
    #[serde(default)]
    gateway: String,
    #[serde(default)]
    via: Vec<String>,
    #[serde(default)]
    agw_port: u8,
    #[serde(default = "default_paclen")]
    paclen: usize,
    /// Base64 raw messages waiting to be sent.
    #[serde(default)]
    outbox: Vec<String>,
    /// MIDs already received.
    #[serde(default)]
    known: Vec<String>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum JsAction {
    Send { data: String },
    Log { kind: &'static str, text: String },
    Received { mid: String, raw: String },
    Delivered { mid: String },
    AlreadyDelivered { mid: String },
    Deferred { mid: String },
    Close,
    Done { ok: bool, text: String },
}

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(js_err)
}

fn kind_name(kind: LogKind) -> &'static str {
    match kind {
        LogKind::Info => "info",
        LogKind::Tx => "tx",
        LogKind::Rx => "rx",
        LogKind::Warn => "warn",
        LogKind::Error => "error",
        LogKind::Ok => "ok",
    }
}

fn encode_actions(actions: Vec<Action>) -> Result<JsValue, JsValue> {
    let out: Vec<JsAction> = actions
        .into_iter()
        .map(|action| match action {
            Action::Transmit(bytes) => JsAction::Send {
                data: base64::encode(&bytes),
            },
            Action::Log(kind, text) => JsAction::Log {
                kind: kind_name(kind),
                text,
            },
            Action::Received { message, raw } => JsAction::Received {
                mid: message.mid().to_owned(),
                raw: base64::encode(&raw),
            },
            Action::Delivered(mid) => JsAction::Delivered { mid },
            Action::AlreadyDelivered(mid) => JsAction::AlreadyDelivered { mid },
            Action::Deferred(mid) => JsAction::Deferred { mid },
            Action::Close => JsAction::Close,
            Action::Done { ok, summary } => JsAction::Done { ok, text: summary },
        })
        .collect();
    to_js(&out)
}

/// One mail exchange over a WebSocket to `b2fmsg-bridge`.
#[wasm_bindgen]
pub struct WebExchange {
    ex: Exchange,
}

#[wasm_bindgen]
impl WebExchange {
    #[wasm_bindgen(constructor)]
    pub fn new(options: JsValue) -> Result<WebExchange, JsValue> {
        let o: ExchangeOptions = serde_wasm_bindgen::from_value(options).map_err(js_err)?;
        let call = o.call.trim().to_uppercase();
        if call.is_empty() {
            return Err(js_err("enter your callsign"));
        }
        let (link, target) = match o.mode.as_str() {
            "cms" => (
                LinkSpec::Telnet {
                    login_password: CMS_TELNET_PASSWORD.into(),
                },
                CMS_TARGET.to_owned(),
            ),
            "agw" => {
                let gateway = o.gateway.trim().to_uppercase();
                if gateway.is_empty() {
                    return Err(js_err("enter the RMS gateway callsign"));
                }
                (
                    LinkSpec::Agw {
                        port: o.agw_port,
                        via: o
                            .via
                            .iter()
                            .map(|d| d.trim().to_uppercase())
                            .filter(|d| !d.is_empty())
                            .collect(),
                        paclen: o.paclen,
                    },
                    gateway,
                )
            }
            other => return Err(js_err(format!("mode must be cms or agw, not {other:?}"))),
        };
        let mut outbound = Vec::new();
        for b64 in &o.outbox {
            let raw = base64::decode(b64).map_err(js_err)?;
            let message = Message::parse(&raw).map_err(js_err)?;
            outbound.push(Outbound::new(&message).map_err(js_err)?);
        }
        let idle_timeout_ms = ExchangeConfig::default_timeout(&link);
        let cfg = ExchangeConfig {
            mycall: call,
            target,
            locator: o.locator.trim().to_uppercase(),
            password: o.password.filter(|p| !p.is_empty()),
            link,
            idle_timeout_ms,
        };
        let known: HashSet<String> = o.known.into_iter().collect();
        Ok(WebExchange {
            ex: Exchange::new(cfg, outbound, known),
        })
    }

    /// Call once the WebSocket is open.
    pub fn start(&mut self) -> Result<JsValue, JsValue> {
        encode_actions(self.ex.start(clock::now_ms()))
    }

    /// Feed a WebSocket message (binary payload).
    #[wasm_bindgen(js_name = onBytes)]
    pub fn on_bytes(&mut self, data: &[u8]) -> Result<JsValue, JsValue> {
        encode_actions(self.ex.on_bytes(data, clock::now_ms()))
    }

    /// The WebSocket closed.
    #[wasm_bindgen(js_name = onClosed)]
    pub fn on_closed(&mut self) -> Result<JsValue, JsValue> {
        encode_actions(self.ex.on_closed())
    }

    /// Timers; call about once a second.
    pub fn poll(&mut self) -> Result<JsValue, JsValue> {
        encode_actions(self.ex.poll(clock::now_ms()))
    }

    pub fn abort(&mut self) -> Result<JsValue, JsValue> {
        encode_actions(self.ex.abort("aborted by operator"))
    }

    #[wasm_bindgen(js_name = isDone)]
    pub fn is_done(&self) -> bool {
        self.ex.is_done()
    }
}

#[derive(Deserialize)]
struct FileIn {
    name: String,
    /// Base64.
    data: String,
}

#[derive(Deserialize)]
struct DraftIn {
    from: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    cc: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    files: Vec<FileIn>,
}

#[derive(Serialize)]
struct Composed {
    mid: String,
    raw: String,
    warnings: Vec<String>,
}

/// Builds a message for the outbox: `{from, to, cc, subject, body, files}`
/// → `{mid, raw, warnings}` (raw is base64).
#[wasm_bindgen(js_name = composeMessage)]
pub fn compose_message(draft: JsValue) -> Result<JsValue, JsValue> {
    let d: DraftIn = serde_wasm_bindgen::from_value(draft).map_err(js_err)?;
    let mut files = Vec::new();
    for f in d.files {
        files.push(Attachment {
            name: f.name,
            data: base64::decode(&f.data).map_err(js_err)?,
        });
    }
    let from = d.from.trim().to_uppercase();
    let draft = Draft {
        mid: generate_mid(&from, clock::now_ms(), clock::entropy()),
        from,
        to: vec![d.to],
        cc: vec![d.cc],
        subject: d.subject,
        body: d.body,
        files,
        date: clock::now_secs(),
    };
    let (message, warnings) = Message::compose(draft).map_err(js_err)?;
    to_js(&Composed {
        mid: message.mid().to_owned(),
        raw: base64::encode(&message.to_bytes()),
        warnings,
    })
}

#[derive(Serialize)]
struct FileView {
    name: String,
    size: usize,
    data: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageView {
    mid: String,
    from: String,
    to: Vec<String>,
    cc: Vec<String>,
    subject: String,
    date: String,
    /// Milliseconds since the epoch, for sorting.
    time: Option<f64>,
    body: String,
    files: Vec<FileView>,
    size: usize,
}

/// Parses a stored raw message (base64) for display.
#[wasm_bindgen(js_name = readMessage)]
pub fn read_message(raw_b64: &str) -> Result<JsValue, JsValue> {
    let raw = base64::decode(raw_b64).map_err(js_err)?;
    let m = Message::parse(&raw).map_err(js_err)?;
    let show = |list: Vec<String>| list.iter().map(|a| display_address(a).to_owned()).collect();
    to_js(&MessageView {
        mid: m.mid().to_owned(),
        from: display_address(&m.from()).to_owned(),
        to: show(m.to()),
        cc: show(m.cc()),
        subject: m.subject(),
        date: m.date().to_owned(),
        time: m.unix_date().map(|s| s as f64 * 1000.0),
        body: m.body_text(),
        files: m
            .files
            .iter()
            .map(|f| FileView {
                name: f.name.clone(),
                size: f.data.len(),
                data: base64::encode(&f.data),
            })
            .collect(),
        size: raw.len(),
    })
}
