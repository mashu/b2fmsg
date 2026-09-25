//! One message exchange: a link layer (telnet login, AGW connected mode, or a
//! raw stream) carrying a B2F [`Session`]. Network-free like the session:
//! feed transport bytes, apply the returned [`Action`]s.

use std::collections::HashSet;

use crate::agw;
use crate::message::Message;
use crate::session::{Event, LogKind, Outbound, Session, SessionConfig};
use crate::telnet;

/// How often to ask Direwolf whether our frames are all acknowledged.
const DRAIN_POLL_MS: u64 = 1_000;
const DRAIN_LIMIT_MS: u64 = 180_000;
const DISCONNECT_LIMIT_MS: u64 = 30_000;

#[derive(Clone, Debug)]
pub enum LinkSpec {
    /// TCP with the Winlink telnet login (CMS, or calling a peer).
    Telnet { login_password: String },
    /// We answer a peer-to-peer telnet call: prompt, then act as master.
    TelnetAnswer,
    /// AX.25 connected mode through an AGW server such as Direwolf.
    Agw {
        port: u8,
        via: Vec<String>,
        paclen: usize,
    },
    /// The stream is B2F from the first byte.
    Raw,
}

#[derive(Clone, Debug)]
pub struct ExchangeConfig {
    pub mycall: String,
    /// `WL2K` for the CMS, the gateway or peer call otherwise. Learned from
    /// the login when answering.
    pub target: String,
    pub locator: String,
    pub password: Option<String>,
    pub link: LinkSpec,
    /// Give up after this long without hearing the remote.
    pub idle_timeout_ms: u64,
}

impl ExchangeConfig {
    /// Sensible idle timeout: radio links are slow and retry a lot.
    pub fn default_timeout(link: &LinkSpec) -> u64 {
        match link {
            LinkSpec::Agw { .. } => 600_000,
            _ => 120_000,
        }
    }
}

#[derive(Debug)]
pub enum Action {
    /// Bytes for the transport (TCP or WebSocket).
    Transmit(Vec<u8>),
    Log(LogKind, String),
    Received {
        message: Message,
        raw: Vec<u8>,
    },
    Delivered(String),
    AlreadyDelivered(String),
    Deferred(String),
    /// Close the transport now.
    Close,
    /// The exchange is over; emitted exactly once.
    Done {
        ok: bool,
        summary: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgwPhase {
    Calling,
    Connected,
    Draining,
    Disconnecting,
}

struct AgwLink {
    port: u8,
    via: Vec<String>,
    paclen: usize,
    decoder: agw::Decoder,
    phase: AgwPhase,
    phase_since: u64,
    last_query: u64,
}

enum Link {
    Telnet(telnet::Login),
    Answer(telnet::Accept),
    Agw(AgwLink),
    Raw,
}

pub struct Exchange {
    cfg: ExchangeConfig,
    link: Link,
    session: Option<Session>,
    pending: Option<(Vec<Outbound>, HashSet<String>)>,
    last_rx: u64,
    now: u64,
    finished_ok: bool,
    done: bool,
    delivered: usize,
    received: usize,
    logged_in: bool,
}

impl Exchange {
    /// `known` are MIDs already received (refused as duplicates).
    pub fn new(cfg: ExchangeConfig, outbound: Vec<Outbound>, known: HashSet<String>) -> Exchange {
        let link = match &cfg.link {
            LinkSpec::Telnet { login_password } => {
                Link::Telnet(telnet::Login::new(&cfg.mycall, login_password))
            }
            LinkSpec::TelnetAnswer => Link::Answer(telnet::Accept::default()),
            LinkSpec::Agw { port, via, paclen } => Link::Agw(AgwLink {
                port: *port,
                via: via.clone(),
                paclen: (*paclen).clamp(16, 256),
                decoder: agw::Decoder::default(),
                phase: AgwPhase::Calling,
                phase_since: 0,
                last_query: 0,
            }),
            LinkSpec::Raw => Link::Raw,
        };
        let mut ex = Exchange {
            link,
            session: None,
            pending: Some((outbound, known)),
            last_rx: 0,
            now: 0,
            finished_ok: false,
            done: false,
            delivered: 0,
            received: 0,
            logged_in: false,
            cfg,
        };
        if !matches!(ex.link, Link::Answer(_)) {
            let target = ex.cfg.target.clone();
            ex.create_session(&target, false);
        }
        ex
    }

    fn create_session(&mut self, target: &str, master: bool) {
        let (outbound, known) = self.pending.take().unwrap_or_default();
        let cfg = SessionConfig {
            mycall: self.cfg.mycall.clone(),
            targetcall: target.to_owned(),
            locator: self.cfg.locator.clone(),
            password: self.cfg.password.clone(),
            master,
        };
        self.session = Some(Session::new(cfg, outbound, known));
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn start(&mut self, now_ms: u64) -> Vec<Action> {
        self.now = now_ms;
        self.last_rx = now_ms;
        let mut out = Vec::new();
        let (mycall, target) = (self.cfg.mycall.clone(), self.cfg.target.clone());
        match &mut self.link {
            Link::Telnet(_) => {
                out.push(Action::Log(
                    LogKind::Info,
                    format!("logging in as {mycall}"),
                ));
            }
            Link::Answer(accept) => {
                for step in accept.start() {
                    if let telnet::Step::Send(bytes) = step {
                        out.push(Action::Transmit(bytes));
                    }
                }
            }
            Link::Agw(agw_link) => {
                let via = if agw_link.via.is_empty() {
                    String::new()
                } else {
                    format!(" via {}", agw_link.via.join(","))
                };
                out.push(Action::Log(LogKind::Info, format!("calling {target}{via}")));
                agw_link.phase_since = now_ms;
                let mut bytes = agw::register(agw_link.port, &mycall);
                bytes.extend(agw::connect(agw_link.port, &mycall, &target, &agw_link.via));
                out.push(Action::Transmit(bytes));
            }
            Link::Raw => {
                let events = self
                    .session
                    .as_mut()
                    .map(Session::start)
                    .unwrap_or_default();
                self.apply(events, &mut out);
            }
        }
        out
    }

    pub fn on_bytes(&mut self, data: &[u8], now_ms: u64) -> Vec<Action> {
        self.now = now_ms;
        self.last_rx = now_ms;
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        enum Input {
            Login(Vec<telnet::Step>, Option<String>),
            Frames(Result<Vec<agw::Frame>, String>),
            Raw,
        }
        let input = match &mut self.link {
            Link::Telnet(login) => Input::Login(login.feed(data), None),
            Link::Answer(accept) => {
                let steps = accept.feed(data);
                Input::Login(steps, Some(accept.remote_call().to_owned()))
            }
            Link::Agw(agw_link) => Input::Frames(agw_link.decoder.push(data)),
            Link::Raw => Input::Raw,
        };
        match input {
            Input::Login(steps, remote) => {
                for step in steps {
                    match step {
                        telnet::Step::Send(bytes) => out.push(Action::Transmit(bytes)),
                        telnet::Step::Banner(line) => out.push(Action::Log(LogKind::Rx, line)),
                        telnet::Step::Failed(reason) => {
                            self.finish(false, reason, &mut out);
                            break;
                        }
                        telnet::Step::Done(rest) => {
                            if !self.logged_in {
                                self.logged_in = true;
                                match &remote {
                                    Some(call) => {
                                        out.push(Action::Log(
                                            LogKind::Info,
                                            format!("{call} logged in"),
                                        ));
                                        self.cfg.target = call.clone();
                                        self.create_session(call, true);
                                        let events = self
                                            .session
                                            .as_mut()
                                            .map(Session::start)
                                            .unwrap_or_default();
                                        self.apply(events, &mut out);
                                    }
                                    None => {
                                        out.push(Action::Log(LogKind::Info, "logged in".into()))
                                    }
                                }
                            }
                            self.feed_session(&rest, &mut out);
                        }
                    }
                }
            }
            Input::Frames(Ok(frames)) => {
                for frame in frames {
                    self.on_agw_frame(frame, &mut out);
                    if self.done {
                        break;
                    }
                }
            }
            Input::Frames(Err(e)) => self.finish(false, e, &mut out),
            Input::Raw => self.feed_session(data, &mut out),
        }
        out
    }

    /// The transport closed underneath us.
    pub fn on_closed(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        if self.finished_ok {
            self.finish(true, String::new(), &mut out);
            return out;
        }
        let events = match self.session.as_mut() {
            Some(s) => s.remote_closed(),
            None => Vec::new(),
        };
        self.apply(events, &mut out);
        if !self.done {
            self.finish(
                false,
                "the link closed before the exchange started".into(),
                &mut out,
            );
        }
        out
    }

    /// Timers: idle timeout and the AGW disconnect handshake.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Action> {
        self.now = now_ms;
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        if let Some((phase, since, last_query, port)) = self.agw_state() {
            let (my, target) = (self.cfg.mycall.clone(), self.cfg.target.clone());
            match phase {
                AgwPhase::Draining => {
                    if now_ms.saturating_sub(since) > DRAIN_LIMIT_MS {
                        out.push(Action::Log(
                            LogKind::Warn,
                            "frames still unacknowledged; disconnecting anyway".into(),
                        ));
                        self.set_agw_phase(AgwPhase::Disconnecting);
                        out.push(Action::Transmit(agw::disconnect(port, &my, &target)));
                    } else if now_ms.saturating_sub(last_query) >= DRAIN_POLL_MS {
                        if let Link::Agw(agw_link) = &mut self.link {
                            agw_link.last_query = now_ms;
                        }
                        out.push(Action::Transmit(agw::outstanding_query(port, &my, &target)));
                    }
                    return out;
                }
                AgwPhase::Disconnecting => {
                    if now_ms.saturating_sub(since) > DISCONNECT_LIMIT_MS {
                        self.finish(true, String::new(), &mut out);
                    }
                    return out;
                }
                _ => {}
            }
        }
        let idle = now_ms.saturating_sub(self.last_rx);
        if idle > self.cfg.idle_timeout_ms {
            let reason = format!("no response for {} s", idle / 1000);
            self.abort_with(&reason, &mut out);
        }
        out
    }

    /// User abort.
    pub fn abort(&mut self, reason: &str) -> Vec<Action> {
        let mut out = Vec::new();
        self.abort_with(reason, &mut out);
        out
    }

    fn abort_with(&mut self, reason: &str, out: &mut Vec<Action>) {
        if self.done {
            return;
        }
        let events = match self.session.as_mut() {
            Some(s) if !s.is_finished() => s.abort(reason),
            _ => Vec::new(),
        };
        self.apply(events, out);
        if !self.done {
            self.finish(false, reason.to_owned(), out);
        }
    }

    fn feed_session(&mut self, data: &[u8], out: &mut Vec<Action>) {
        if data.is_empty() {
            return;
        }
        let events = match self.session.as_mut() {
            Some(s) => s.feed(data),
            None => return,
        };
        self.apply(events, out);
    }

    fn agw_state(&self) -> Option<(AgwPhase, u64, u64, u8)> {
        match &self.link {
            Link::Agw(l) => Some((l.phase, l.phase_since, l.last_query, l.port)),
            _ => None,
        }
    }

    fn set_agw_phase(&mut self, phase: AgwPhase) {
        let now = self.now;
        if let Link::Agw(l) = &mut self.link {
            l.phase = phase;
            l.phase_since = now;
            l.last_query = now;
        }
    }

    fn on_agw_frame(&mut self, frame: agw::Frame, out: &mut Vec<Action>) {
        let Some((phase, _, _, port)) = self.agw_state() else {
            return;
        };
        if frame.port != port && frame.kind != b'X' {
            return;
        }
        let text = String::from_utf8_lossy(&frame.data)
            .trim_matches(|c: char| c.is_whitespace() || c == '\0')
            .to_owned();
        let (my, target) = (self.cfg.mycall.clone(), self.cfg.target.clone());
        match frame.kind {
            b'X' => {
                if frame.data.first() == Some(&1) {
                    out.push(Action::Log(
                        LogKind::Info,
                        format!("{my} registered with the AGW server"),
                    ));
                } else {
                    out.push(Action::Log(
                        LogKind::Warn,
                        format!("{my} is already registered by another program; continuing"),
                    ));
                }
            }
            b'C' if phase == AgwPhase::Calling => {
                self.set_agw_phase(AgwPhase::Connected);
                out.push(Action::Log(
                    LogKind::Ok,
                    if text.is_empty() {
                        format!("connected to {target}")
                    } else {
                        text
                    },
                ));
                let events = self
                    .session
                    .as_mut()
                    .map(Session::start)
                    .unwrap_or_default();
                self.apply(events, out);
            }
            b'D' if phase != AgwPhase::Calling => self.feed_session(&frame.data, out),
            b'd' => {
                if !text.is_empty() {
                    out.push(Action::Log(LogKind::Rx, text.clone()));
                }
                if phase == AgwPhase::Calling {
                    let why = if text.is_empty() {
                        "no answer".to_owned()
                    } else {
                        text
                    };
                    self.finish(false, format!("could not connect to {target} ({why})"), out);
                } else if self.finished_ok {
                    self.finish(true, String::new(), out);
                } else {
                    let events = self
                        .session
                        .as_mut()
                        .map(Session::remote_closed)
                        .unwrap_or_default();
                    self.apply(events, out);
                    if !self.done {
                        self.finish(false, "disconnected".into(), out);
                    }
                }
            }
            b'Y' if phase == AgwPhase::Draining => {
                let n = frame
                    .data
                    .get(..4)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                    .unwrap_or(0);
                if n == 0 {
                    self.set_agw_phase(AgwPhase::Disconnecting);
                    out.push(Action::Transmit(agw::disconnect(port, &my, &target)));
                }
            }
            _ => {}
        }
    }

    fn transmit(&self, bytes: Vec<u8>, out: &mut Vec<Action>) {
        match &self.link {
            Link::Agw(agw_link) => {
                if agw_link.phase == AgwPhase::Calling {
                    return;
                }
                out.push(Action::Transmit(agw::data(
                    agw_link.port,
                    &self.cfg.mycall,
                    &self.cfg.target,
                    &bytes,
                    agw_link.paclen,
                )));
            }
            _ => out.push(Action::Transmit(bytes)),
        }
    }

    fn apply(&mut self, events: Vec<Event>, out: &mut Vec<Action>) {
        for event in events {
            match event {
                Event::Transmit(bytes) => self.transmit(bytes, out),
                Event::Log(kind, text) => out.push(Action::Log(kind, text)),
                Event::Received { message, raw } => {
                    self.received += 1;
                    out.push(Action::Received { message, raw });
                }
                Event::Delivered(mid) => {
                    self.delivered += 1;
                    out.push(Action::Delivered(mid));
                }
                Event::AlreadyDelivered(mid) => out.push(Action::AlreadyDelivered(mid)),
                Event::Deferred(mid) => out.push(Action::Deferred(mid)),
                Event::Finished => {
                    self.finished_ok = true;
                    match self.agw_state() {
                        Some((_, _, _, port)) => {
                            // Let Direwolf deliver everything before hanging up.
                            self.set_agw_phase(AgwPhase::Draining);
                            out.push(Action::Transmit(agw::outstanding_query(
                                port,
                                &self.cfg.mycall,
                                &self.cfg.target,
                            )));
                        }
                        None => self.finish(true, String::new(), out),
                    }
                }
                Event::Failed(reason) => {
                    if let Link::Agw(agw_link) = &self.link {
                        if agw_link.phase != AgwPhase::Calling {
                            out.push(Action::Transmit(agw::disconnect(
                                agw_link.port,
                                &self.cfg.mycall,
                                &self.cfg.target,
                            )));
                        }
                    } else if !reason.starts_with("remote reported")
                        && !reason.starts_with("the link closed")
                    {
                        // Tell the other side why we are hanging up, as Pat does.
                        out.push(Action::Transmit(format!("*** {reason}\r").into_bytes()));
                    }
                    self.finish(false, reason, out);
                }
            }
            if self.done {
                break;
            }
        }
    }

    fn finish(&mut self, ok: bool, reason: String, out: &mut Vec<Action>) {
        if self.done {
            return;
        }
        self.done = true;
        let counts = format!("{} sent, {} received", self.delivered, self.received);
        let summary = if ok {
            format!("exchange complete: {counts}")
        } else {
            format!("exchange failed: {reason} ({counts})")
        };
        out.push(Action::Close);
        out.push(Action::Done { ok, summary });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Draft;

    fn outbound(mid: &str, to: &str) -> Outbound {
        let (msg, _) = Message::compose(Draft {
            from: "SA0KAM".into(),
            to: vec![to.into()],
            subject: "test".into(),
            body: "hello over the air".into(),
            date: 1_790_246_700,
            mid: mid.into(),
            ..Draft::default()
        })
        .unwrap();
        Outbound::new(&msg).unwrap()
    }

    fn cfg(link: LinkSpec, call: &str, target: &str) -> ExchangeConfig {
        ExchangeConfig {
            mycall: call.into(),
            target: target.into(),
            locator: "JO89".into(),
            password: Some("pw".into()),
            idle_timeout_ms: ExchangeConfig::default_timeout(&link),
            link,
        }
    }

    fn transmitted(actions: &[Action]) -> Vec<u8> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Transmit(b) => Some(b.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn done(actions: &[Action]) -> Option<bool> {
        actions.iter().find_map(|a| match a {
            Action::Done { ok, .. } => Some(*ok),
            _ => None,
        })
    }

    /// Caller (telnet login) against answerer (prompts), end to end.
    #[test]
    fn telnet_peer_to_peer() {
        let mut caller = Exchange::new(
            cfg(
                LinkSpec::Telnet {
                    login_password: String::new(),
                },
                "SA0KAM",
                "SO5KM",
            ),
            vec![outbound("CALLERMID001", "SO5KM")],
            HashSet::new(),
        );
        let mut answer = Exchange::new(
            cfg(LinkSpec::TelnetAnswer, "SO5KM", ""),
            vec![outbound("ANSWERMID001", "SA0KAM")],
            HashSet::new(),
        );
        let mut to_caller = transmitted(&answer.start(0));
        let mut to_answer = transmitted(&caller.start(0));
        let (mut caller_done, mut answer_done) = (None, None);
        let (mut got_caller, mut got_answer) = (0, 0);
        for t in 1..200 {
            let a = caller.on_bytes(&std::mem::take(&mut to_caller), t);
            got_caller += a
                .iter()
                .filter(|x| matches!(x, Action::Received { .. }))
                .count();
            caller_done = caller_done.or(done(&a));
            to_answer.extend(transmitted(&a));
            let b = answer.on_bytes(&std::mem::take(&mut to_answer), t);
            got_answer += b
                .iter()
                .filter(|x| matches!(x, Action::Received { .. }))
                .count();
            answer_done = answer_done.or(done(&b));
            to_caller.extend(transmitted(&b));
            if caller.is_done() && answer.is_done() {
                break;
            }
        }
        assert_eq!(caller_done, Some(true));
        assert_eq!(answer_done, Some(true));
        assert_eq!((got_caller, got_answer), (1, 1));
    }

    /// Fake Direwolf: answers the connect, relays data to a master session.
    #[test]
    fn agw_connected_mode() {
        let link = LinkSpec::Agw {
            port: 0,
            via: vec![],
            paclen: 64,
        };
        let mut ex = Exchange::new(
            cfg(link, "SA0KAM", "SK0GW-10"),
            vec![outbound("AGWMID000001", "a@b.se")],
            HashSet::new(),
        );
        let mut gw = Session::new(
            SessionConfig {
                mycall: "SK0GW-10".into(),
                targetcall: "SA0KAM".into(),
                locator: String::new(),
                password: None,
                master: true,
            },
            Vec::new(),
            HashSet::new(),
        );
        let mut dec = agw::Decoder::default();
        let frames = dec.push(&transmitted(&ex.start(0))).unwrap();
        assert_eq!(
            frames.iter().map(|f| f.kind).collect::<Vec<_>>(),
            [b'X', b'C']
        );

        let reply = |kind: u8, data: &[u8]| {
            agw::Frame::new(kind, 0, "SK0GW-10", "SA0KAM", data.to_vec()).encode()
        };
        let mut inbound = reply(b'C', b"*** CONNECTED With Station SK0GW-10\r");
        for e in gw.start() {
            if let Event::Transmit(b) = e {
                inbound.extend(reply(b'D', &b));
            }
        }
        let mut result = None;
        let mut disconnected = false;
        for t in 1..500u64 {
            let actions = ex.on_bytes(&std::mem::take(&mut inbound), t * 100);
            let mut actions = actions;
            actions.extend(ex.poll(t * 100));
            result = result.or(done(&actions));
            for frame in dec.push(&transmitted(&actions)).unwrap() {
                match frame.kind {
                    b'D' => {
                        assert!(frame.data.len() <= 64);
                        for e in gw.feed(&frame.data) {
                            if let Event::Transmit(b) = e {
                                inbound.extend(reply(b'D', &b));
                            }
                        }
                    }
                    b'Y' => inbound.extend(reply(b'Y', &0u32.to_le_bytes())),
                    b'd' => {
                        disconnected = true;
                        inbound.extend(reply(b'd', b"*** DISCONNECTED From Station SK0GW-10\r"));
                    }
                    _ => {}
                }
            }
            if result.is_some() {
                break;
            }
        }
        assert!(disconnected, "client should hang up after draining");
        assert_eq!(result, Some(true));
    }

    #[test]
    fn agw_connect_failure() {
        let link = LinkSpec::Agw {
            port: 0,
            via: vec!["SK0DIG".into()],
            paclen: 128,
        };
        let mut ex = Exchange::new(cfg(link, "SA0KAM", "SK0GW-10"), vec![], HashSet::new());
        ex.start(0);
        let d = agw::Frame::new(
            b'd',
            0,
            "SK0GW-10",
            "SA0KAM",
            b"*** DISCONNECTED RETRYOUT With SK0GW-10\r".to_vec(),
        )
        .encode();
        let actions = ex.on_bytes(&d, 1);
        assert_eq!(done(&actions), Some(false));
        assert!(actions.iter().any(
            |a| matches!(a, Action::Done { summary, .. } if summary.contains("could not connect"))
        ));
    }

    #[test]
    fn idle_timeout_and_close() {
        let mut ex = Exchange::new(cfg(LinkSpec::Raw, "SA0KAM", "WL2K"), vec![], HashSet::new());
        ex.start(0);
        assert!(ex.poll(60_000).is_empty());
        let actions = ex.poll(200_000);
        assert_eq!(done(&actions), Some(false));
        assert!(ex.poll(300_000).is_empty());
        assert!(ex.on_closed().is_empty());

        let mut ex = Exchange::new(cfg(LinkSpec::Raw, "SA0KAM", "WL2K"), vec![], HashSet::new());
        ex.start(0);
        assert_eq!(done(&ex.on_closed()), Some(false));
    }
}
