//! The B2 forwarding protocol (B2F) as a network-free state machine.
//!
//! Feed received bytes with [`Session::feed`] and apply the returned
//! [`Event`]s. The flow for the client (the station that connected):
//!
//! ```text
//!  remote: [WL2K-5.0-B2FWIHJM$]   ;PQ: 12345678   CMS via X >
//!  us:     ;FW: CALL   [b2fmsg-0.1.0-B2FHM$]   ;PR: 87654321   ; WL2K DE CALL (JO89)
//!  us:     FC EM <mid> <size> <csize> 0 … F> <checksum>     (or FF: nothing to send)
//!  remote: FS +-=                                           (accept / have it / later)
//!  us:     <SOH title offset> <STX data>… <EOT checksum>    (per accepted message)
//!  remote: FC … F> …  /  FF  /  FQ                          (turn passes back and forth)
//! ```
//!
//! The session ends when one side sends `FQ` after the other side had
//! nothing left to send.

use std::collections::{HashSet, VecDeque};

use crate::charset;
use crate::lzhuf;
use crate::message::{Message, normalize_address};
use crate::secure;

/// Proposals per block (protocol limit).
pub const MAX_BLOCK: usize = 5;
/// Data bytes per STX block; fits AX.25 links with PACLEN 128.
pub const MAX_CHUNK: usize = 125;
/// Refuse protocol text lines longer than this (DoS / garbage).
const MAX_LINE: usize = 4 * 1024;
const TITLE_MAX: usize = 80;
const SOH: u8 = 0x01;
const STX: u8 = 0x02;
const EOT: u8 = 0x04;

const APP_NAME: &str = "b2fmsg";
/// B2 compressed forwarding, FBB basic, hierarchical addresses, MIDs, BIDs.
const SID_CODES: &str = "B2FHM$";

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub mycall: String,
    /// Whom the handshake greets (`WL2K` for the CMS, the RMS or peer call).
    pub targetcall: String,
    pub locator: String,
    /// Winlink account password, for the `;PQ` challenge.
    pub password: Option<String>,
    /// True for the answering station, which speaks first.
    pub master: bool,
}

/// A message prepared for sending: compressed once, offered by MID.
#[derive(Clone, Debug)]
pub struct Outbound {
    pub mid: String,
    pub title: String,
    pub size: usize,
    pub compressed: Vec<u8>,
    pub recipients: Vec<String>,
    precedence: u8,
}

impl Outbound {
    pub fn new(message: &Message) -> Result<Outbound, String> {
        message.validate()?;
        let raw = message.to_bytes();
        let subject = message.subject();
        Ok(Outbound {
            mid: message.mid().to_owned(),
            title: proposal_title(&subject),
            size: raw.len(),
            compressed: lzhuf::encode_b2(&raw),
            recipients: message.recipients(),
            precedence: precedence(&subject),
        })
    }
}

/// Transfer label: the subject, RFC 2047 encoded like Pat does, at most
/// 80 bytes on the wire.
fn proposal_title(subject: &str) -> String {
    let subject = subject.trim();
    if subject.is_empty() {
        return "No title".into();
    }
    let mut chars: Vec<char> = subject.chars().collect();
    loop {
        let text: String = chars.iter().collect();
        let encoded = charset::encode_header(&text);
        if encoded.len() <= TITLE_MAX || chars.len() <= 1 {
            return encoded.chars().take(TITLE_MAX).collect();
        }
        chars.pop();
    }
}

/// Winlink precedence markers in the subject; lower is more urgent.
fn precedence(subject: &str) -> u8 {
    if subject.contains("//WL2K Z/") {
        0
    } else if subject.contains("//WL2K O/") {
        1
    } else if subject.contains("//WL2K P/") {
        2
    } else {
        3
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogKind {
    Info,
    /// Protocol line we sent.
    Tx,
    /// Protocol line we received.
    Rx,
    Warn,
    Error,
    Ok,
}

#[derive(Debug)]
pub enum Event {
    /// Bytes for the remote station.
    Transmit(Vec<u8>),
    Log(LogKind, String),
    Received {
        message: Message,
        raw: Vec<u8>,
    },
    /// The remote accepted and received this message.
    Delivered(String),
    /// The remote already had this message; treat it as sent.
    AlreadyDelivered(String),
    /// The remote asked for this message later; keep it queued.
    Deferred(String),
    /// Protocol complete: close the link.
    Finished,
    Failed(String),
}

#[derive(Debug)]
struct InProposal {
    code: u8,
    mid: String,
    /// Declared uncompressed size from the FC line.
    raw_size: usize,
    csize: usize,
}

#[derive(Debug)]
enum RxStage {
    Soh,
    HeaderLen,
    Header { len: usize, bytes: Vec<u8> },
    Block,
    BlockLen,
    BlockData { remaining: usize },
    Checksum,
}

#[derive(Debug)]
struct Receiver {
    queue: VecDeque<InProposal>,
    stage: RxStage,
    data: Vec<u8>,
    sum: u32,
}

#[derive(Debug)]
enum State {
    /// Client: collecting the remote handshake up to its `>` prompt.
    Handshake,
    /// Master: collecting the remote handshake up to its first `F` command.
    MasterHandshake,
    TheirTurn,
    AwaitAnswer(Vec<usize>),
    AwaitTurnover(Vec<String>),
    Receiving(Receiver),
    Done,
    Failed,
}

pub struct Session {
    cfg: SessionConfig,
    state: State,
    rx: Vec<u8>,
    outbound: Vec<Outbound>,
    offered: HashSet<usize>,
    known: HashSet<String>,
    remote_sid: Option<String>,
    remote_fw: Vec<String>,
    challenge: Option<String>,
    remote_no_msgs: bool,
    proposals: Vec<InProposal>,
    proposal_sum: u32,
    handshake_sent: bool,
    explained_held: bool,
}

impl Session {
    /// `known` holds MIDs already received, which are refused as duplicates.
    pub fn new(cfg: SessionConfig, outbound: Vec<Outbound>, known: HashSet<String>) -> Session {
        let state = if cfg.master {
            State::MasterHandshake
        } else {
            State::Handshake
        };
        Session {
            cfg,
            state,
            rx: Vec::new(),
            outbound,
            offered: HashSet::new(),
            known,
            remote_sid: None,
            remote_fw: Vec::new(),
            challenge: None,
            remote_no_msgs: false,
            proposals: Vec::new(),
            proposal_sum: 0,
            handshake_sent: false,
            explained_held: false,
        }
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.state, State::Done | State::Failed)
    }

    pub fn remote_sid(&self) -> Option<&str> {
        self.remote_sid.as_deref()
    }

    /// Master speaks first; the client waits for the remote handshake.
    pub fn start(&mut self) -> Vec<Event> {
        let mut ev = Vec::new();
        if self.cfg.master && !self.handshake_sent {
            self.send_handshake(&mut ev);
        }
        ev
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<Event> {
        let mut ev = Vec::new();
        self.rx.extend_from_slice(data);
        loop {
            match self.state {
                State::Done | State::Failed => {
                    self.rx.clear();
                    break;
                }
                State::Receiving(_) => {
                    if !self.step_binary(&mut ev) {
                        break;
                    }
                }
                _ => match self.take_line() {
                    Ok(Some(line)) => self.on_line(&line, &mut ev),
                    Ok(None) => break,
                    Err(e) => {
                        self.fail(&mut ev, e);
                        break;
                    }
                },
            }
        }
        ev
    }

    /// The link dropped. Fine once the protocol is complete.
    pub fn remote_closed(&mut self) -> Vec<Event> {
        match self.state {
            State::Done | State::Failed => Vec::new(),
            _ => {
                self.state = State::Failed;
                vec![Event::Failed(
                    "the link closed before the exchange finished".into(),
                )]
            }
        }
    }

    /// Stops the session (user abort, timeout, link error).
    pub fn abort(&mut self, reason: &str) -> Vec<Event> {
        if self.is_finished() {
            return Vec::new();
        }
        self.state = State::Failed;
        vec![Event::Failed(reason.to_owned())]
    }

    fn fail(&mut self, ev: &mut Vec<Event>, reason: String) {
        self.state = State::Failed;
        ev.push(Event::Failed(reason));
    }

    /// `Ok(None)` = need more bytes; `Err` = line/buffer past [`MAX_LINE`].
    fn take_line(&mut self) -> Result<Option<String>, String> {
        loop {
            let end = match self.rx.iter().position(|&b| b == b'\r' || b == b'\n') {
                Some(end) => end,
                None if self.rx.len() > MAX_LINE => {
                    return Err(format!(
                        "protocol line longer than {MAX_LINE} bytes without a line ending"
                    ));
                }
                None => return Ok(None),
            };
            if end > MAX_LINE {
                return Err(format!("protocol line longer than {MAX_LINE} bytes"));
            }
            let line: Vec<u8> = self.rx.drain(..=end).collect();
            let text: String = line[..line.len() - 1]
                .iter()
                .map(|&b| b as char)
                .collect::<String>()
                .trim()
                .to_owned();
            if !text.is_empty() {
                return Ok(Some(text));
            }
        }
    }

    fn transmit_line(&self, ev: &mut Vec<Event>, line: &str) {
        ev.push(Event::Log(LogKind::Tx, line.to_owned()));
        ev.push(Event::Transmit(format!("{line}\r").into_bytes()));
    }

    fn on_line(&mut self, line: &str, ev: &mut Vec<Event>) {
        match std::mem::replace(&mut self.state, State::Failed) {
            State::Handshake => {
                self.state = State::Handshake;
                self.client_handshake_line(line, ev);
            }
            State::MasterHandshake => {
                self.state = State::MasterHandshake;
                self.master_handshake_line(line, ev);
            }
            State::TheirTurn => {
                self.state = State::TheirTurn;
                self.their_turn_line(line, ev);
            }
            State::AwaitAnswer(batch) => self.answer_line(line, batch, ev),
            State::AwaitTurnover(mids) => {
                ev.push(Event::Log(LogKind::Rx, line.to_owned()));
                // `;` lines are comments (same as AwaitAnswer); only F… means turnover.
                if line.starts_with(';') {
                    self.state = State::AwaitTurnover(mids);
                } else if line.starts_with('F') {
                    for mid in mids {
                        ev.push(Event::Delivered(mid));
                    }
                    self.state = State::TheirTurn;
                    self.their_turn_line_logged(line, ev);
                } else if let Some(err) = remote_error(line) {
                    self.fail(ev, format!("remote reported an error: {err}"));
                } else {
                    self.fail(ev, format!("unexpected reply after transfer: {line:?}"));
                }
            }
            other => self.state = other,
        }
    }

    fn note_sid(&mut self, line: &str, ev: &mut Vec<Event>) -> bool {
        if !(line.starts_with('[') && line.ends_with(']')) {
            return false;
        }
        let codes = line[1..line.len() - 1]
            .rsplit('-')
            .next()
            .unwrap_or("")
            .to_uppercase();
        if !codes.contains("B2") {
            self.fail(
                ev,
                format!("remote does not speak B2F (SID {line}); only B2 is supported"),
            );
            return true;
        }
        self.remote_sid = Some(line.to_owned());
        true
    }

    fn note_fw(&mut self, line: &str) {
        if let Some(rest) = line.strip_prefix(";FW:") {
            self.remote_fw = rest
                .split_whitespace()
                .filter_map(|item| item.split('|').next())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_uppercase())
                .collect();
        }
    }

    fn client_handshake_line(&mut self, line: &str, ev: &mut Vec<Event>) {
        ev.push(Event::Log(LogKind::Rx, line.to_owned()));
        if self.note_sid(line, ev) {
            return;
        }
        if let Some(challenge) = line.strip_prefix(";PQ:") {
            self.challenge = Some(challenge.trim().to_owned());
        } else if line.starts_with(";FW:") {
            self.note_fw(line);
        } else if line.ends_with('>') {
            if self.remote_sid.is_none() {
                return self.fail(ev, "remote sent its prompt without a SID".into());
            }
            if self.send_handshake(ev) {
                self.our_turn(ev);
            }
        }
    }

    fn master_handshake_line(&mut self, line: &str, ev: &mut Vec<Event>) {
        if line.starts_with('F') {
            if self.remote_sid.is_none() {
                ev.push(Event::Log(LogKind::Rx, line.to_owned()));
                return self.fail(ev, "remote started without sending a SID".into());
            }
            self.state = State::TheirTurn;
            return self.their_turn_line(line, ev);
        }
        ev.push(Event::Log(LogKind::Rx, line.to_owned()));
        if self.note_sid(line, ev) {
            return;
        }
        if line.starts_with(";FW:") {
            self.note_fw(line);
        }
    }

    /// Our `;FW`, SID, optional `;PR`, and greeting. False on failure.
    fn send_handshake(&mut self, ev: &mut Vec<Event>) -> bool {
        let mut lines = vec![
            format!(";FW: {}", self.cfg.mycall),
            format!("[{APP_NAME}-{}-{SID_CODES}]", env!("CARGO_PKG_VERSION")),
        ];
        if let Some(challenge) = &self.challenge {
            let Some(password) = self.cfg.password.as_deref().filter(|p| !p.is_empty()) else {
                self.fail(
                    ev,
                    "the gateway asked for a secure login but no Winlink password is set".into(),
                );
                return false;
            };
            lines.push(format!(
                ";PR: {}",
                secure::login_response(challenge, password)
            ));
            ev.push(Event::Log(
                LogKind::Info,
                "answering secure login challenge".into(),
            ));
        }
        let greeting = format!(
            "; {} DE {} ({})",
            self.cfg.targetcall, self.cfg.mycall, self.cfg.locator
        );
        lines.push(if self.cfg.master {
            format!("{greeting}>")
        } else {
            greeting
        });
        for line in &lines {
            self.transmit_line(ev, line);
        }
        self.handshake_sent = true;
        true
    }

    /// Messages the remote may carry: all of them for a gateway; only those
    /// addressed to the peer's forwarding calls in peer-to-peer sessions.
    fn deliverable(&self, out: &Outbound) -> bool {
        if self.remote_fw.is_empty() {
            return true;
        }
        out.recipients.iter().all(|r| {
            let r = normalize_address(r).unwrap_or_else(|_| r.to_uppercase());
            self.remote_fw.contains(&r)
        })
    }

    fn our_turn(&mut self, ev: &mut Vec<Event>) {
        if !self.explained_held && !self.remote_fw.is_empty() {
            self.explained_held = true;
            for o in self.outbound.iter().filter(|o| !self.deliverable(o)) {
                ev.push(Event::Log(
                    LogKind::Info,
                    format!(
                        "{} stays in the outbox: this peer only takes mail addressed to {}",
                        o.mid,
                        self.remote_fw.join(", ")
                    ),
                ));
            }
        }
        let mut batch: Vec<usize> = (0..self.outbound.len())
            .filter(|i| !self.offered.contains(i) && self.deliverable(&self.outbound[*i]))
            .collect();
        batch.sort_by(|&a, &b| {
            let (x, y) = (&self.outbound[a], &self.outbound[b]);
            (x.precedence, x.compressed.len(), &x.mid).cmp(&(
                y.precedence,
                y.compressed.len(),
                &y.mid,
            ))
        });
        batch.truncate(MAX_BLOCK);

        if batch.is_empty() {
            if self.remote_no_msgs {
                self.transmit_line(ev, "FQ");
                self.state = State::Done;
                ev.push(Event::Finished);
            } else {
                self.transmit_line(ev, "FF");
                self.state = State::TheirTurn;
            }
            return;
        }

        let mut sum: u32 = 0;
        for &i in &batch {
            let o = &self.outbound[i];
            let line = format!("FC EM {} {} {} 0", o.mid, o.size, o.compressed.len());
            sum += line.bytes().map(u32::from).sum::<u32>() + u32::from(b'\r');
            self.transmit_line(ev, &line);
            self.offered.insert(i);
        }
        self.transmit_line(ev, &format!("F> {:02X}", (sum as u8).wrapping_neg()));
        self.state = State::AwaitAnswer(batch);
    }

    fn answer_line(&mut self, line: &str, batch: Vec<usize>, ev: &mut Vec<Event>) {
        ev.push(Event::Log(LogKind::Rx, line.to_owned()));
        if line.starts_with(';') {
            self.state = State::AwaitAnswer(batch);
            return;
        }
        if let Some(err) = remote_error(line) {
            return self.fail(ev, format!("remote reported an error: {err}"));
        }
        let Some(answers) = line.strip_prefix("FS ") else {
            return self.fail(ev, format!("expected a proposal answer (FS), got {line:?}"));
        };
        let parsed = match parse_answers(answers.trim()) {
            Ok(p) if p.len() == batch.len() => p,
            Ok(p) => {
                return self.fail(
                    ev,
                    format!("got {} answers for {} proposals", p.len(), batch.len()),
                );
            }
            Err(e) => return self.fail(ev, e),
        };

        let mut accepted = Vec::new();
        for (&i, answer) in batch.iter().zip(parsed) {
            let o = &self.outbound[i];
            match answer {
                Answer::Accept(offset) => {
                    let offset = if offset < o.compressed.len() {
                        offset
                    } else {
                        0
                    };
                    ev.push(Event::Log(
                        LogKind::Info,
                        format!(
                            "sending {} ({} bytes compressed{})",
                            o.mid,
                            o.compressed.len() - offset,
                            if offset > 0 {
                                format!(", resuming at {offset}")
                            } else {
                                String::new()
                            }
                        ),
                    ));
                    ev.push(Event::Transmit(encode_transfer(o, offset)));
                    accepted.push(o.mid.clone());
                }
                Answer::Reject => ev.push(Event::AlreadyDelivered(o.mid.clone())),
                Answer::Defer => ev.push(Event::Deferred(o.mid.clone())),
            }
        }
        self.state = State::AwaitTurnover(accepted);
    }

    fn their_turn_line(&mut self, line: &str, ev: &mut Vec<Event>) {
        ev.push(Event::Log(LogKind::Rx, line.to_owned()));
        self.their_turn_line_logged(line, ev);
    }

    fn their_turn_line_logged(&mut self, line: &str, ev: &mut Vec<Event>) {
        if let Some(pm) = line.strip_prefix(";PM:") {
            let parts: Vec<&str> = pm.trim().splitn(5, ' ').collect();
            if parts.len() >= 3 {
                ev.push(Event::Log(
                    LogKind::Info,
                    format!(
                        "pending for {}: {} ({} bytes)",
                        parts[0], parts[1], parts[2]
                    ),
                ));
            }
            return;
        }
        if line.starts_with(';') {
            return;
        }
        if let Some(err) = remote_error(line) {
            return self.fail(ev, format!("remote reported an error: {err}"));
        }
        if line.len() < 2 || !line.starts_with('F') {
            return self.fail(ev, format!("unexpected protocol line {line:?}"));
        }
        match &line[..2] {
            "FA" | "FB" | "FC" | "FD" => {
                self.proposal_sum += line.bytes().map(u32::from).sum::<u32>() + u32::from(b'\r');
                match parse_proposal(line) {
                    Ok(p) => self.proposals.push(p),
                    Err(e) => self.fail(ev, e),
                }
            }
            "FF" => {
                self.proposals.clear();
                self.proposal_sum = 0;
                self.remote_no_msgs = true;
                self.our_turn(ev);
            }
            "FQ" => {
                if !self.proposals.is_empty() {
                    ev.push(Event::Log(
                        LogKind::Warn,
                        "remote quit with unanswered proposals".into(),
                    ));
                }
                self.proposals.clear();
                self.proposal_sum = 0;
                self.state = State::Done;
                ev.push(Event::Finished);
            }
            "F>" => {
                let expect = (self.proposal_sum as u8).wrapping_neg();
                let theirs = u8::from_str_radix(line[2..].trim(), 16).ok();
                self.proposal_sum = 0;
                if !line[2..].trim().is_empty() && theirs != Some(expect) {
                    return self.fail(
                        ev,
                        format!(
                            "proposal checksum mismatch (ours {expect:02X}, theirs {})",
                            line[2..].trim()
                        ),
                    );
                }
                if self.proposals.is_empty() {
                    self.remote_no_msgs = true;
                    return self.our_turn(ev);
                }
                self.answer_proposals(ev);
            }
            _ => self.fail(ev, format!("unknown protocol command {line:?}")),
        }
    }

    fn answer_proposals(&mut self, ev: &mut Vec<Event>) {
        let proposals = std::mem::take(&mut self.proposals);
        let mut seen = HashSet::new();
        let mut answers = String::new();
        let mut queue = VecDeque::new();
        for p in proposals {
            let oversized =
                p.csize > lzhuf::MAX_UNCOMPRESSED || p.raw_size > lzhuf::MAX_UNCOMPRESSED;
            let answer = if !seen.insert(p.mid.clone()) || p.code != b'C' {
                '='
            } else if oversized {
                ev.push(Event::Log(
                    LogKind::Warn,
                    format!(
                        "deferring {}: declared size {}/{} exceeds limit {}",
                        p.mid,
                        p.raw_size,
                        p.csize,
                        lzhuf::MAX_UNCOMPRESSED
                    ),
                ));
                '='
            } else if self.known.contains(&p.mid) {
                '-'
            } else {
                '+'
            };
            answers.push(answer);
            if answer == '+' {
                queue.push_back(p);
            }
        }
        self.remote_no_msgs = false;
        self.transmit_line(ev, &format!("FS {answers}"));
        if queue.is_empty() {
            self.our_turn(ev);
        } else {
            self.state = State::Receiving(Receiver {
                queue,
                stage: RxStage::Soh,
                data: Vec::new(),
                sum: 0,
            });
        }
    }

    /// Consumes binary transfer bytes; false when more input is needed.
    fn step_binary(&mut self, ev: &mut Vec<Event>) -> bool {
        let State::Receiving(rx) = &mut self.state else {
            return false;
        };
        if self.rx.is_empty() {
            return false;
        }
        match &mut rx.stage {
            RxStage::Soh => {
                let byte = self.rx[0];
                match byte {
                    b'\r' | b'\n' => {
                        self.rx.remove(0);
                    }
                    SOH => {
                        self.rx.remove(0);
                        rx.stage = RxStage::HeaderLen;
                    }
                    b'*' => {
                        let Some(end) = self.rx.iter().position(|&b| b == b'\r' || b == b'\n')
                        else {
                            return false;
                        };
                        let line = String::from_utf8_lossy(&self.rx[..end]).trim().to_owned();
                        let err = remote_error(&line).unwrap_or(line);
                        self.fail(ev, format!("remote reported an error: {err}"));
                    }
                    other => {
                        self.fail(
                            ev,
                            format!("expected a message transfer, got byte {other:#04x}"),
                        );
                    }
                }
            }
            RxStage::HeaderLen => {
                let len = usize::from(self.rx.remove(0));
                rx.stage = RxStage::Header {
                    len,
                    bytes: Vec::with_capacity(len),
                };
            }
            RxStage::Header { len, bytes } => {
                let take = (*len - bytes.len()).min(self.rx.len());
                bytes.extend(self.rx.drain(..take));
                if bytes.len() == *len {
                    let mut parts = bytes.split(|&b| b == 0);
                    let title =
                        String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
                    let offset =
                        String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
                    let mid = rx.queue.front().map(|p| p.mid.clone()).unwrap_or_default();
                    if offset.trim() != "0" {
                        let msg = format!("unexpected transfer offset {offset:?} for {mid}");
                        self.fail(ev, msg);
                        return true;
                    }
                    ev.push(Event::Log(
                        LogKind::Info,
                        format!(
                            "receiving {mid} \"{}\"",
                            charset::decode_header(title.trim())
                        ),
                    ));
                    rx.data.clear();
                    rx.sum = 0;
                    rx.stage = RxStage::Block;
                }
            }
            RxStage::Block => match self.rx.remove(0) {
                STX => rx.stage = RxStage::BlockLen,
                EOT => rx.stage = RxStage::Checksum,
                other => {
                    self.fail(
                        ev,
                        format!("corrupt transfer: unexpected byte {other:#04x}"),
                    );
                }
            },
            RxStage::BlockLen => {
                let len = match self.rx.remove(0) {
                    0 => 256,
                    n => usize::from(n),
                };
                rx.stage = RxStage::BlockData { remaining: len };
            }
            RxStage::BlockData { remaining } => {
                let take = (*remaining).min(self.rx.len());
                for &b in &self.rx[..take] {
                    rx.sum += u32::from(b);
                }
                rx.data.extend(self.rx.drain(..take));
                *remaining -= take;
                if *remaining == 0 {
                    rx.stage = RxStage::Block;
                }
            }
            RxStage::Checksum => {
                let check = self.rx.remove(0);
                let Some(proposal) = rx.queue.pop_front() else {
                    self.fail(
                        ev,
                        "received transfer data with no matching proposal".into(),
                    );
                    return true;
                };
                let data = std::mem::take(&mut rx.data);
                let ok_sum = (rx.sum + u32::from(check)) % 256 == 0;
                let more = !rx.queue.is_empty();
                rx.stage = RxStage::Soh;
                if !ok_sum {
                    self.fail(ev, format!("{}: transfer checksum error", proposal.mid));
                    return true;
                }
                if data.len() != proposal.csize {
                    self.fail(
                        ev,
                        format!(
                            "{}: got {} bytes, proposal said {}",
                            proposal.mid,
                            data.len(),
                            proposal.csize
                        ),
                    );
                    return true;
                }
                let raw = match lzhuf::decode_b2(&data) {
                    Ok(raw) => raw,
                    Err(e) => {
                        self.fail(ev, format!("{}: {e}", proposal.mid));
                        return true;
                    }
                };
                match Message::parse(&raw) {
                    Ok(message) => {
                        if message.mid() != proposal.mid {
                            ev.push(Event::Log(
                                LogKind::Warn,
                                format!(
                                    "proposal {} carried message {}",
                                    proposal.mid,
                                    message.mid()
                                ),
                            ));
                        }
                        self.known.insert(proposal.mid.clone());
                        self.known.insert(message.mid().to_owned());
                        ev.push(Event::Received { message, raw });
                    }
                    Err(e) => {
                        self.fail(ev, format!("{}: unreadable message: {e}", proposal.mid));
                        return true;
                    }
                }
                if !more {
                    self.our_turn(ev);
                }
            }
        }
        true
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Accept(usize),
    Reject,
    Defer,
}

fn parse_answers(s: &str) -> Result<Vec<Answer>, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        i += 1;
        out.push(match c {
            b'+' | b'Y' | b'y' => Answer::Accept(0),
            b'-' | b'N' | b'n' | b'R' | b'r' => Answer::Reject,
            b'=' | b'L' | b'l' | b'H' | b'h' => Answer::Defer,
            b'!' | b'A' | b'a' => {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let offset = s[start..i]
                    .parse()
                    .map_err(|_| format!("proposal answer {s:?} lacks an offset"))?;
                Answer::Accept(offset)
            }
            b' ' => continue,
            other => {
                return Err(format!(
                    "invalid proposal answer {:?} in {s:?}",
                    other as char
                ));
            }
        });
    }
    Ok(out)
}

fn parse_proposal(line: &str) -> Result<InProposal, String> {
    let code = line.as_bytes()[1];
    let parts: Vec<&str> = line[2..].split_whitespace().collect();
    if code == b'C' || code == b'D' {
        if parts.len() < 4 {
            return Err(format!("malformed proposal {line:?}"));
        }
        if parts[0] != "EM" && parts[0] != "CM" {
            return Err(format!("unsupported message type in {line:?}"));
        }
        let raw_size = parts[2]
            .parse()
            .map_err(|_| format!("malformed size in {line:?}"))?;
        let csize = parts[3]
            .parse()
            .map_err(|_| format!("malformed size in {line:?}"))?;
        Ok(InProposal {
            code,
            mid: parts[1].to_owned(),
            raw_size,
            csize,
        })
    } else {
        // FA/FB (old FBB formats): deferred, but keep the MID for the log.
        Ok(InProposal {
            code,
            mid: parts.get(3).copied().unwrap_or("?").to_owned(),
            raw_size: 0,
            csize: 0,
        })
    }
}

/// `*** text` lines carry errors from Winlink servers.
fn remote_error(line: &str) -> Option<String> {
    if !line.starts_with('*') {
        return None;
    }
    let text = line.trim_start_matches('*').trim();
    Some(if text.is_empty() {
        line.to_owned()
    } else {
        text.to_owned()
    })
}

/// SOH header, STX blocks, EOT checksum for one message.
fn encode_transfer(o: &Outbound, offset: usize) -> Vec<u8> {
    let offset_text = offset.to_string();
    let title = &o.title.as_bytes()[..o.title.len().min(TITLE_MAX)];
    let data = &o.compressed[offset..];
    let mut out = Vec::with_capacity(data.len() + data.len() / MAX_CHUNK * 2 + 100);
    out.push(SOH);
    out.push((title.len() + offset_text.len() + 2) as u8);
    out.extend_from_slice(title);
    out.push(0);
    out.extend_from_slice(offset_text.as_bytes());
    out.push(0);
    let mut sum: u32 = 0;
    for chunk in data.chunks(MAX_CHUNK) {
        out.push(STX);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
        sum += chunk.iter().map(|&b| u32::from(b)).sum::<u32>();
    }
    out.push(EOT);
    out.push((sum as u8).wrapping_neg());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Draft;

    fn cfg(call: &str, target: &str, master: bool) -> SessionConfig {
        SessionConfig {
            mycall: call.into(),
            targetcall: target.into(),
            locator: "JO89".into(),
            password: Some("secret".into()),
            master,
        }
    }

    fn message(from: &str, to: &str, subject: &str, body: &str, mid: &str) -> Message {
        Message::compose(Draft {
            from: from.into(),
            to: vec![to.into()],
            subject: subject.into(),
            body: body.into(),
            date: 1_790_246_700,
            mid: mid.into(),
            ..Draft::default()
        })
        .unwrap()
        .0
    }

    fn transmitted(ev: &[Event]) -> Vec<u8> {
        ev.iter()
            .filter_map(|e| match e {
                Event::Transmit(b) => Some(b.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    #[derive(Default)]
    struct Tally {
        received: Vec<Message>,
        delivered: Vec<String>,
        rejected: Vec<String>,
        deferred: Vec<String>,
        finished: bool,
        failed: Option<String>,
    }

    fn tally(t: &mut Tally, ev: Vec<Event>) -> Vec<u8> {
        let bytes = transmitted(&ev);
        for e in ev {
            match e {
                Event::Received { message, .. } => t.received.push(message),
                Event::Delivered(m) => t.delivered.push(m),
                Event::AlreadyDelivered(m) => t.rejected.push(m),
                Event::Deferred(m) => t.deferred.push(m),
                Event::Finished => t.finished = true,
                Event::Failed(r) => t.failed = Some(r),
                _ => {}
            }
        }
        bytes
    }

    /// Runs two sessions against each other, delivering bytes in small
    /// fragments to exercise partial reads.
    fn run_pair(mut client: Session, mut master: Session, frag: usize) -> (Tally, Tally) {
        let (mut tc, mut tm) = (Tally::default(), Tally::default());
        let mut to_client = tally(&mut tm, master.start());
        let mut to_master = tally(&mut tc, client.start());
        for _ in 0..10_000 {
            if to_client.is_empty() && to_master.is_empty() {
                break;
            }
            if !to_client.is_empty() {
                let n = frag.min(to_client.len());
                let chunk: Vec<u8> = to_client.drain(..n).collect();
                to_master.extend(tally(&mut tc, client.feed(&chunk)));
            }
            if !to_master.is_empty() {
                let n = frag.min(to_master.len());
                let chunk: Vec<u8> = to_master.drain(..n).collect();
                to_client.extend(tally(&mut tm, master.feed(&chunk)));
            }
        }
        (tc, tm)
    }

    #[test]
    fn peer_to_peer_both_directions() {
        let big_body = "73 de SA0KAM\n".repeat(400);
        let out_c = vec![
            Outbound::new(&message("SA0KAM", "SO5KM", "one", "hello", "MIDCLIENT001")).unwrap(),
            Outbound::new(&message(
                "SA0KAM",
                "SO5KM",
                "two",
                &big_body,
                "MIDCLIENT002",
            ))
            .unwrap(),
        ];
        let out_m =
            vec![Outbound::new(&message("SO5KM", "SA0KAM", "back", "hi", "MIDMASTER001")).unwrap()];
        for frag in [1, 7, 4096] {
            let client = Session::new(cfg("SA0KAM", "SO5KM", false), out_c.clone(), HashSet::new());
            let master = Session::new(cfg("SO5KM", "SA0KAM", true), out_m.clone(), HashSet::new());
            let (tc, tm) = run_pair(client, master, frag);
            assert!(tc.failed.is_none(), "client: {:?}", tc.failed);
            assert!(tm.failed.is_none(), "master: {:?}", tm.failed);
            assert!(tc.finished && tm.finished);
            let mut delivered = tc.delivered.clone();
            delivered.sort();
            assert_eq!(delivered, ["MIDCLIENT001", "MIDCLIENT002"]);
            assert_eq!(tm.received.len(), 2);
            assert_eq!(
                tm.received
                    .iter()
                    .find(|m| m.mid() == "MIDCLIENT002")
                    .unwrap()
                    .body_text()
                    .len(),
                big_body.len() + 400
            );
            assert_eq!(tc.received.len(), 1);
            assert_eq!(tc.received[0].subject(), "back");
            assert_eq!(tm.delivered, ["MIDMASTER001"]);
        }
    }

    #[test]
    fn duplicates_are_rejected_and_extra_blocks_flow() {
        let outs: Vec<Outbound> = (0..7)
            .map(|i| {
                Outbound::new(&message(
                    "SA0KAM",
                    "SO5KM",
                    &format!("m{i}"),
                    "x",
                    &format!("MID{i:09}"),
                ))
                .unwrap()
            })
            .collect();
        let known: HashSet<String> = ["MID000000003".to_string()].into();
        let client = Session::new(cfg("SA0KAM", "SO5KM", false), outs, HashSet::new());
        let master = Session::new(cfg("SO5KM", "SA0KAM", true), Vec::new(), known);
        let (tc, tm) = run_pair(client, master, 13);
        assert!(
            tc.failed.is_none() && tm.failed.is_none(),
            "{:?} {:?}",
            tc.failed,
            tm.failed
        );
        assert_eq!(tc.delivered.len(), 6);
        assert_eq!(tc.rejected, ["MID000000003"]);
        assert_eq!(tm.received.len(), 6);
    }

    #[test]
    fn p2p_only_offers_messages_for_the_peer() {
        let outs = vec![
            Outbound::new(&message("SA0KAM", "SO5KM", "for peer", "x", "FORPEER00001")).unwrap(),
            Outbound::new(&message(
                "SA0KAM",
                "a@b.se",
                "internet",
                "x",
                "INTERNET0001",
            ))
            .unwrap(),
        ];
        let client = Session::new(cfg("SA0KAM", "SO5KM", false), outs, HashSet::new());
        let master = Session::new(cfg("SO5KM", "SA0KAM", true), Vec::new(), HashSet::new());
        let mut client = client;
        let mut master = master;
        let mut to_client = transmitted(&master.start());
        let mut logs = Vec::new();
        while !to_client.is_empty() {
            let ev = client.feed(&std::mem::take(&mut to_client));
            for e in &ev {
                if let Event::Log(LogKind::Info, t) = e {
                    logs.push(t.clone());
                }
            }
            let reply = transmitted(&ev);
            to_client = transmitted(&master.feed(&reply));
            if client.is_finished() {
                break;
            }
        }
        assert!(
            logs.iter()
                .any(|l| l.contains("INTERNET0001 stays in the outbox")),
            "{logs:?}"
        );
        let client = Session::new(
            cfg("SA0KAM", "SO5KM", false),
            vec![
                Outbound::new(&message("SA0KAM", "SO5KM", "for peer", "x", "FORPEER00001"))
                    .unwrap(),
                Outbound::new(&message(
                    "SA0KAM",
                    "a@b.se",
                    "internet",
                    "x",
                    "INTERNET0001",
                ))
                .unwrap(),
            ],
            HashSet::new(),
        );
        let master = Session::new(cfg("SO5KM", "SA0KAM", true), Vec::new(), HashSet::new());
        let (tc, tm) = run_pair(client, master, 64);
        assert_eq!(tc.delivered, ["FORPEER00001"]);
        assert_eq!(tm.received.len(), 1);
    }

    /// The CMS exchange from Pat's TestSessionCMSv4, byte for byte.
    #[test]
    fn cms_transcript() {
        let mut c = Session::new(cfg("LA5NTA", "LA1B-10", false), Vec::new(), HashSet::new());
        let mut t = Tally::default();
        let sent = tally(&mut t, c.feed(b"[WL2K-4.0-B2FWIHJM$]\rTest CMS >\r"));
        let sent = String::from_utf8(sent).unwrap();
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(
            sent,
            format!(";FW: LA5NTA\r[b2fmsg-{version}-B2FHM$]\r; LA1B-10 DE LA5NTA (JO89)\rFF\r")
        );
        let known = &mut c.known;
        known.insert("TJKYEIMMHSRB".into());
        let sent = tally(
            &mut t,
            c.feed(b";PM: LA5NTA TJKYEIMMHSRB 123 someone@example.com\r;WARNING: Foo\rFC EM TJKYEIMMHSRB 527 123 0\rF> 3b\r"),
        );
        assert_eq!(sent, b"FS -\rFF\r");
        tally(&mut t, c.feed(b";WARNING: Foo bar baz\rFQ\r"));
        assert!(t.finished && t.failed.is_none(), "{:?}", t.failed);
    }

    #[test]
    fn secure_login_and_missing_password() {
        let mut c = Session::new(cfg("LA5NTA", "WL2K", false), Vec::new(), HashSet::new());
        let sent = transmitted(&c.feed(b"[WL2K-5.0-B2FWIHJM$]\r;PQ: 23753528\rCMS >\r"));
        let expect = format!(";PR: {}\r", secure::login_response("23753528", "secret"));
        assert!(String::from_utf8(sent).unwrap().contains(&expect));

        let mut no_pw = cfg("LA5NTA", "WL2K", false);
        no_pw.password = None;
        let mut c = Session::new(no_pw, Vec::new(), HashSet::new());
        let ev = c.feed(b"[WL2K-5.0-B2FWIHJM$]\r;PQ: 1\rCMS >\r");
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Failed(r) if r.contains("password")))
        );
    }

    #[test]
    fn remote_errors_and_bad_checksums_fail() {
        let mut c = Session::new(cfg("A1A", "WL2K", false), Vec::new(), HashSet::new());
        c.feed(b"[WL2K-5.0-B2FWIHJM$]\r>\r");
        let ev = c.feed(b"*** Secure login failed - account password does not match.\r");
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Failed(r) if r.contains("Secure login failed")))
        );

        let mut c = Session::new(cfg("A1A", "WL2K", false), Vec::new(), HashSet::new());
        c.feed(b"[WL2K-5.0-B2FWIHJM$]\r>\r");
        let ev = c.feed(b"FC EM TJKYEIMMHSRB 527 123 0\rF> 00\r");
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Failed(r) if r.contains("checksum")))
        );

        let mut c = Session::new(cfg("A1A", "WL2K", false), Vec::new(), HashSet::new());
        let ev = c.feed(b"[FBB-7.0-FHM$]\r");
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Failed(r) if r.contains("B2F")))
        );
        assert!(c.remote_closed().is_empty());
    }

    #[test]
    fn answer_parsing() {
        assert_eq!(
            parse_answers("+-=Y!123N").unwrap(),
            vec![
                Answer::Accept(0),
                Answer::Reject,
                Answer::Defer,
                Answer::Accept(0),
                Answer::Accept(123),
                Answer::Reject
            ]
        );
        assert!(parse_answers("?").is_err());
        assert!(parse_answers("!").is_err());
    }

    #[test]
    fn transfer_framing() {
        let o = Outbound::new(&message(
            "A1A",
            "B1B",
            "t",
            &"y".repeat(3000),
            "FRAMING00001",
        ))
        .unwrap();
        let bytes = encode_transfer(&o, 0);
        assert_eq!(bytes[0], SOH);
        let header_len = usize::from(bytes[1]);
        assert_eq!(&bytes[2..2 + header_len], b"t\x000\x00");
        assert_eq!(bytes[bytes.len() - 2], EOT);
        let sum: u32 = o.compressed.iter().map(|&b| u32::from(b)).sum::<u32>()
            + u32::from(bytes[bytes.len() - 1]);
        assert_eq!(sum % 256, 0);
    }

    #[test]
    fn comment_after_transfer_is_not_delivery() {
        let outbound =
            vec![Outbound::new(&message("A1A", "B1B", "hi", "body", "COMMENT00001")).unwrap()];
        let mut c = Session::new(cfg("A1A", "B1B", false), outbound, HashSet::new());
        c.feed(b"[WL2K-5.0-B2FWIHJM$]\r>\r");
        let ev = c.feed(b"FS +\r");
        assert!(
            !ev.iter().any(|e| matches!(e, Event::Delivered(_))),
            "still transferring"
        );
        // A `;` warning must not count as turnover / delivery confirmation.
        let ev = c.feed(b";WARNING: ignore me\r");
        assert!(
            !ev.iter().any(|e| matches!(e, Event::Delivered(_))),
            "; comment must not mark Delivered"
        );
        assert!(!c.is_finished());
        // Real turnover finally confirms delivery.
        let ev = c.feed(b"FF\r");
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Delivered(m) if m == "COMMENT00001"))
        );
    }

    #[test]
    fn oversized_proposal_is_deferred() {
        let mut c = Session::new(cfg("A1A", "WL2K", false), Vec::new(), HashSet::new());
        c.feed(b"[WL2K-5.0-B2FWIHJM$]\r>\r");
        let fc = "FC EM HUGE00000001 100 999999999 0";
        let sum: u32 = fc.bytes().map(u32::from).sum::<u32>() + u32::from(b'\r');
        let chk = (sum as u8).wrapping_neg();
        let ev = c.feed(format!("{fc}\rF> {chk:02X}\r").as_bytes());
        let sent = String::from_utf8(transmitted(&ev)).unwrap();
        assert!(
            sent.contains("FS ="),
            "oversized proposal should be deferred, got {sent:?}"
        );
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Log(LogKind::Warn, t) if t.contains("exceeds limit"))),
        );
        assert!(!matches!(c.state, State::Receiving(_)));
    }

    #[test]
    fn rejects_overlong_protocol_line() {
        let mut c = Session::new(cfg("A1A", "WL2K", false), Vec::new(), HashSet::new());
        let junk = vec![b'X'; MAX_LINE + 1];
        let ev = c.feed(&junk);
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Failed(r) if r.contains("longer than")))
        );
    }
}
