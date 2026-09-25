//! Winlink-compatible radio email (B2F) for the CMS over telnet, RMS gateways
//! through Direwolf's AGW port, or peer-to-peer telnet.
//!
//! Everything protocol-related is network-free: callers feed received bytes
//! and apply the returned actions, so the same code runs in the CLI and in
//! the browser (WebAssembly).

pub mod agw;
pub mod base64;
pub mod charset;
pub mod clock;
pub mod date;
pub mod exchange;
pub mod lzhuf;
pub mod md5;
pub mod message;
pub mod secure;
pub mod session;
pub mod telnet;

#[cfg(not(target_arch = "wasm32"))]
pub mod mailbox;
#[cfg(not(target_arch = "wasm32"))]
pub mod ui;

#[cfg(target_arch = "wasm32")]
mod wasm;

pub use exchange::{Action, Exchange, ExchangeConfig, LinkSpec};
pub use message::{Attachment, Draft, Message};
pub use session::{LogKind, Outbound};

/// Winlink CMS telnet gateway (callsign login, fixed password `CMSTelnet`).
pub const CMS_ADDRESS: &str = "server.winlink.org:8772";
pub const CMS_TARGET: &str = "WL2K";
pub const CMS_TELNET_PASSWORD: &str = "CMSTelnet";
/// Conventional port for peer-to-peer telnet sessions (Pat uses the same).
pub const P2P_PORT: u16 = 8774;
