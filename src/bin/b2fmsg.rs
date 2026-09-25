//! b2fmsg — Winlink-compatible radio email client (native CLI).

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use b2fmsg::clock;
use b2fmsg::exchange::{Action, Exchange, ExchangeConfig, LinkSpec};
use b2fmsg::mailbox::{Folder, Mailbox};
use b2fmsg::message::{self, Attachment, Draft, Message, generate_mid, parse_addresses};
use b2fmsg::session::Outbound;
use b2fmsg::ui::{Ui, human_size};
use b2fmsg::{CMS_ADDRESS, CMS_TARGET, CMS_TELNET_PASSWORD, P2P_PORT};

const DEFAULT_AGW: &str = "127.0.0.1:8000";
const TICK: Duration = Duration::from_millis(500);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const LARGE_ATTACHMENT: usize = 50_000;

const USAGE: &str = "\
usage: b2fmsg --call MYCALL [options]

  --call MYCALL        your callsign (the Winlink account), e.g. SA0KAM
  --locator GRID       Maidenhead locator sent in the handshake, e.g. JO89
  --mailbox DIR        mailbox root (default: see below); Pat's mailbox works too
  --password-file F    file holding your Winlink password (else $B2FMSG_PASSWORD,
                       else you are asked when connecting)

links:
  --cms HOST:PORT      Winlink CMS telnet server        (default server.winlink.org:8772)
  --agw HOST:PORT      Direwolf AGW port for ax25       (default 127.0.0.1:8000)
  --agw-port N         radio port on the AGW server     (default 0)
  --paclen N           bytes per AX.25 frame            (default 128)
  --timeout SECS       give up after this long without hearing the remote
                       (default 120 over TCP, 600 over radio)

  --once \"CONNECT\"     run one exchange and exit, e.g. --once cms or
                       --once \"ax25 SK0XYZ-10\"; exit status 1 on failure
  --quiet              hide the protocol transcript (toggle with trace)
  --no-color           plain output (also when NO_COLOR is set or output is piped)";

const COMMANDS: &str = "\
commands:
  compose                  write a message: To, Cc, Subject, body ending with a
                           line holding only \".\", then attachments (~q cancels)
  msg TO text              quick message; the text is also the subject
                           e.g.  msg friend@example.com Arrived at the cabin, all well
  inbox | outbox | sent    list a folder; the numbers are used below
  read N                   show message N from the last list
  save N [DIR]             write message N's attachments (default: current directory)
  delete N                 delete message N from the last list
  connect                  exchange mail with the Winlink CMS over the internet
  connect ax25 GW [via D]  through an RMS gateway via Direwolf, e.g.
                           connect ax25 SK0XYZ-10   connect ax25 SK0XYZ-10 via SK0DIG
  connect p2p HOST:PORT CALL   peer-to-peer over TCP (another b2fmsg or Pat)
  listen [HOST:PORT]       accept peer-to-peer TCP calls (default 0.0.0.0:8774)
  stop                     stop listening
  abort                    stop the running exchange
  trace                    toggle the protocol transcript
  quit

markers:  → queued   ✓ delivered   ← received   ✗ failed   › ‹ protocol (trace)";

struct Config {
    call: String,
    locator: String,
    mailbox: PathBuf,
    cms: String,
    agw: String,
    agw_port: u8,
    paclen: usize,
    timeout: Option<u64>,
    password: Option<String>,
    once: Option<String>,
    quiet: bool,
    no_color: bool,
}

fn parse_args() -> Result<Config, String> {
    let mut call = None;
    let mut cfg = Config {
        call: String::new(),
        locator: String::new(),
        mailbox: Mailbox::default_base(),
        cms: CMS_ADDRESS.into(),
        agw: DEFAULT_AGW.into(),
        agw_port: 0,
        paclen: 128,
        timeout: None,
        password: env::var("B2FMSG_PASSWORD").ok().filter(|p| !p.is_empty()),
        once: None,
        quiet: false,
        no_color: false,
    };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--call" => call = Some(value("--call")?),
            "--locator" => cfg.locator = value("--locator")?.to_uppercase(),
            "--mailbox" => cfg.mailbox = PathBuf::from(value("--mailbox")?),
            "--password-file" => {
                let path = value("--password-file")?;
                let text = fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
                cfg.password = Some(text.trim_end_matches(['\r', '\n']).to_owned());
            }
            "--cms" => cfg.cms = value("--cms")?,
            "--agw" => cfg.agw = value("--agw")?,
            "--agw-port" => {
                cfg.agw_port = value("--agw-port")?
                    .parse()
                    .map_err(|_| "--agw-port must be 0-255")?
            }
            "--paclen" => {
                cfg.paclen = value("--paclen")?
                    .parse()
                    .ok()
                    .filter(|n| (16..=256).contains(n))
                    .ok_or("--paclen must be 16-256")?
            }
            "--timeout" => {
                cfg.timeout = Some(
                    value("--timeout")?
                        .parse()
                        .ok()
                        .filter(|&n: &u64| n >= 10)
                        .ok_or("--timeout must be at least 10 seconds")?,
                )
            }
            "--once" => cfg.once = Some(value("--once")?),
            "--quiet" => cfg.quiet = true,
            "--no-color" => cfg.no_color = true,
            "-h" | "--help" => {
                println!(
                    "{USAGE}\n\n  mailbox default: {}\n\n{COMMANDS}",
                    Mailbox::default_base().display()
                );
                process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let call = call.ok_or("--call is required")?.trim().to_uppercase();
    if call.is_empty() || !call.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!("{call:?} is not a callsign"));
    }
    cfg.call = call;
    Ok(cfg)
}

enum Event {
    Line(String),
    InputClosed,
    Net { id: u64, data: Vec<u8> },
    NetClosed { id: u64, reason: Option<String> },
    Accepted { stream: TcpStream, peer: SocketAddr },
    ListenFailed(String),
}

#[derive(Clone, Debug)]
enum Target {
    Cms,
    Ax25 { gateway: String, via: Vec<String> },
    P2p { addr: String, call: String },
}

impl Target {
    fn parse(words: &[&str]) -> Result<Target, String> {
        match words {
            [] | ["cms"] | ["telnet"] => Ok(Target::Cms),
            ["ax25", gw] => Ok(Target::Ax25 {
                gateway: gw.to_uppercase(),
                via: Vec::new(),
            }),
            ["ax25", gw, "via", digis] => Ok(Target::Ax25 {
                gateway: gw.to_uppercase(),
                via: digis
                    .split(',')
                    .filter(|d| !d.is_empty())
                    .map(str::to_uppercase)
                    .collect(),
            }),
            ["p2p", addr, call] => Ok(Target::P2p {
                addr: with_port(addr, P2P_PORT),
                call: call.to_uppercase(),
            }),
            _ => Err(
                "usage: connect | connect ax25 GATEWAY [via DIGI,DIGI] | connect p2p HOST:PORT CALL"
                    .into(),
            ),
        }
    }

    fn needs_password(&self) -> bool {
        !matches!(self, Target::P2p { .. })
    }
}

fn with_port(addr: &str, port: u16) -> String {
    if addr.contains(':') {
        addr.to_owned()
    } else {
        format!("{addr}:{port}")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    To,
    Cc,
    Subject,
    Body,
    Attach,
}

struct Compose {
    stage: Stage,
    to: Vec<String>,
    cc: Vec<String>,
    subject: String,
    body: Vec<String>,
    files: Vec<Attachment>,
}

struct Running {
    ex: Exchange,
    stream: TcpStream,
    id: u64,
}

enum Mode {
    Idle,
    Compose(Compose),
    Password(Target),
    Exchange(Box<Running>),
}

struct App {
    cfg: Config,
    ui: Ui,
    mailbox: Mailbox,
    events: Sender<Event>,
    mode: Mode,
    listing: Option<(Folder, Vec<String>)>,
    listener: Option<(String, Arc<AtomicBool>)>,
    next_id: u64,
    input_open: bool,
    exit_code: Option<i32>,
}

impl App {
    fn handle_line(&mut self, line: String) {
        match std::mem::replace(&mut self.mode, Mode::Idle) {
            Mode::Compose(c) => self.compose_line(c, &line),
            Mode::Password(target) => {
                set_echo(true);
                println!();
                let pw = line.trim_end_matches(['\r', '\n']).to_owned();
                self.cfg.password = if pw.is_empty() { None } else { Some(pw) };
                self.start(target);
            }
            Mode::Exchange(running) => {
                self.mode = Mode::Exchange(running);
                match line.trim() {
                    "abort" => self.with_exchange(|ex| ex.abort("aborted by operator")),
                    "trace" => self.toggle_trace(),
                    "quit" | "exit" => {
                        self.with_exchange(|ex| ex.abort("aborted by operator"));
                        self.exit_code.get_or_insert(0);
                    }
                    "help" => self.ui.plain(COMMANDS),
                    "" => {}
                    _ => self
                        .ui
                        .warn("an exchange is running; wait for it or type abort"),
                }
            }
            Mode::Idle => self.command(line.trim()),
        }
    }

    fn command(&mut self, line: &str) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some((&cmd, rest)) = words.split_first() else {
            return;
        };
        match cmd {
            "help" | "?" => self.ui.plain(COMMANDS),
            "compose" => {
                self.ui
                    .prompt("To (callsigns or e-mail addresses, comma separated):");
                self.mode = Mode::Compose(Compose {
                    stage: Stage::To,
                    to: Vec::new(),
                    cc: Vec::new(),
                    subject: String::new(),
                    body: Vec::new(),
                    files: Vec::new(),
                });
            }
            "msg" => {
                let text = line
                    .splitn(3, char::is_whitespace)
                    .nth(2)
                    .unwrap_or("")
                    .trim();
                match rest.first() {
                    Some(to) if !text.is_empty() => {
                        let subject: String = text.chars().take(60).collect();
                        self.queue(
                            vec![to.to_string()],
                            Vec::new(),
                            subject,
                            text.to_owned(),
                            Vec::new(),
                        );
                    }
                    _ => self.ui.error("usage: msg TO text"),
                }
            }
            "inbox" | "in" => self.list(Folder::Inbox),
            "outbox" | "out" => self.list(Folder::Outbox),
            "sent" => self.list(Folder::Sent),
            "archive" => self.list(Folder::Archive),
            "read" | "show" => {
                if let Some((_, _, message)) = self.pick(rest.first().copied()) {
                    self.ui.show_message(&message);
                }
            }
            "save" => {
                if let Some((_, _, message)) = self.pick(rest.first().copied()) {
                    let dir = rest
                        .get(1)
                        .map_or_else(|| PathBuf::from("."), PathBuf::from);
                    self.save_attachments(&message, &dir);
                }
            }
            "delete" | "rm" => {
                if let Some((folder, mid, _)) = self.pick(rest.first().copied()) {
                    match self.mailbox.delete(folder, &mid) {
                        Ok(()) => {
                            self.ui
                                .info(&format!("deleted {mid} from {}", folder.label()));
                            self.listing = None;
                        }
                        Err(e) => self.ui.error(&format!("cannot delete {mid}: {e}")),
                    }
                }
            }
            "connect" | "c" => match Target::parse(rest) {
                Ok(target) => self.connect(target),
                Err(e) => self.ui.error(&e),
            },
            "listen" => self.listen(rest.first().copied()),
            "stop" => self.stop_listening(),
            "trace" => self.toggle_trace(),
            "abort" => self.ui.info("nothing to abort"),
            "quit" | "exit" | "q" => {
                self.exit_code.get_or_insert(0);
            }
            other => self
                .ui
                .error(&format!("unknown command {other:?}; type help")),
        }
    }

    fn toggle_trace(&mut self) {
        let on = !self.ui.trace();
        self.ui.set_trace(on);
        self.ui.info(if on {
            "protocol transcript on"
        } else {
            "protocol transcript off"
        });
    }

    fn compose_line(&mut self, mut c: Compose, line: &str) {
        let text = line.trim_end_matches(['\r', '\n']);
        if text.trim() == "~q" {
            self.ui.info("message discarded");
            return;
        }
        match c.stage {
            Stage::To => {
                if text.trim().is_empty() {
                    self.ui.info("message discarded");
                    return;
                }
                match parse_addresses(&[text.to_owned()]) {
                    Ok(to) => {
                        c.to = to;
                        c.stage = Stage::Cc;
                        self.ui.prompt("Cc (optional):");
                    }
                    Err(e) => {
                        self.ui.error(&e);
                        self.ui.prompt("To:");
                    }
                }
            }
            Stage::Cc => match parse_addresses(&[text.to_owned()]) {
                Ok(cc) => {
                    c.cc = cc;
                    c.stage = Stage::Subject;
                    self.ui.prompt("Subject:");
                }
                Err(e) => {
                    self.ui.error(&e);
                    self.ui.prompt("Cc (optional):");
                }
            },
            Stage::Subject => {
                if text.trim().is_empty() {
                    self.ui.prompt("Subject (required):");
                } else {
                    c.subject = text.trim().to_owned();
                    c.stage = Stage::Body;
                    self.ui.info("body: end with a line holding only \".\"");
                }
            }
            Stage::Body => {
                if text == "." {
                    c.stage = Stage::Attach;
                    self.ui
                        .prompt("Attach a file (path, empty line to finish):");
                } else {
                    c.body.push(text.to_owned());
                }
            }
            Stage::Attach => {
                let path = text.trim();
                if path.is_empty() {
                    let body = c.body.join("\n");
                    self.queue(c.to, c.cc, c.subject, body, c.files);
                    return;
                }
                match fs::read(path) {
                    Ok(data) => {
                        if data.len() > LARGE_ATTACHMENT {
                            self.ui.warn(&format!(
                                "{path} is {}; large attachments take a long time over radio",
                                human_size(data.len())
                            ));
                        }
                        let name = Path::new(path).file_name().map_or_else(
                            || "attachment".into(),
                            |n| n.to_string_lossy().into_owned(),
                        );
                        c.files.push(Attachment { name, data });
                    }
                    Err(e) => self.ui.error(&format!("{path}: {e}")),
                }
                self.ui.prompt("Attach another (empty line to finish):");
            }
        }
        self.mode = Mode::Compose(c);
    }

    fn queue(
        &mut self,
        to: Vec<String>,
        cc: Vec<String>,
        subject: String,
        body: String,
        files: Vec<Attachment>,
    ) {
        let draft = Draft {
            from: self.cfg.call.clone(),
            to,
            cc,
            subject,
            body,
            files,
            date: clock::now_secs(),
            mid: generate_mid(&self.cfg.call, clock::now_ms(), clock::entropy()),
        };
        match Message::compose(draft) {
            Ok((message, warnings)) => {
                for w in warnings {
                    self.ui.warn(&w);
                }
                match self
                    .mailbox
                    .store(Folder::Outbox, message.mid(), &message.to_bytes())
                {
                    Ok(_) => self.ui.queued(message.mid(), &message),
                    Err(e) => self.ui.error(&format!("cannot write to the outbox: {e}")),
                }
            }
            Err(e) => self.ui.error(&e),
        }
    }

    fn list(&mut self, folder: Folder) {
        match self.mailbox.list(folder) {
            Ok((entries, problems)) => {
                for p in problems {
                    self.ui.warn(&format!("skipped unreadable {p}"));
                }
                self.ui.listing(folder, &entries);
                self.listing = Some((folder, entries.into_iter().map(|e| e.mid).collect()));
            }
            Err(e) => self
                .ui
                .error(&format!("cannot read {}: {e}", folder.label())),
        }
    }

    fn pick(&self, arg: Option<&str>) -> Option<(Folder, String, Message)> {
        let Some((folder, mids)) = &self.listing else {
            self.ui.error("list a folder first (inbox, outbox, sent)");
            return None;
        };
        let n: usize = match arg.and_then(|a| a.parse().ok()) {
            Some(n) if (1..=mids.len()).contains(&n) => n,
            _ => {
                self.ui
                    .error(&format!("give a number from 1 to {}", mids.len()));
                return None;
            }
        };
        let mid = &mids[n - 1];
        let path = self
            .mailbox
            .root()
            .join(folder.dir())
            .join(format!("{mid}.b2f"));
        match fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|raw| Message::parse(&raw))
        {
            Ok(message) => Some((*folder, mid.clone(), message)),
            Err(e) => {
                self.ui.error(&format!("{mid}: {e}"));
                None
            }
        }
    }

    fn save_attachments(&self, message: &Message, dir: &Path) {
        if message.files.is_empty() {
            self.ui.info("this message has no attachments");
            return;
        }
        if let Err(e) = fs::create_dir_all(dir) {
            return self.ui.error(&format!("{}: {e}", dir.display()));
        }
        for file in &message.files {
            let path = unique_path(dir, &message::sanitize_filename(&file.name));
            match fs::write(&path, &file.data) {
                Ok(()) => self.ui.ok(&format!("saved {}", path.display())),
                Err(e) => self.ui.error(&format!("{}: {e}", path.display())),
            }
        }
    }

    fn connect(&mut self, target: Target) {
        let interactive = self.cfg.once.is_none() && io::stdin().is_terminal();
        if self.cfg.password.is_none() && target.needs_password() && interactive {
            self.ui.prompt(&format!(
                "Winlink password for {} (not shown; empty to try without):",
                self.cfg.call
            ));
            set_echo(false);
            self.mode = Mode::Password(target);
            return;
        }
        self.start(target);
    }

    fn start(&mut self, target: Target) {
        let (addr, link, remote) = match &target {
            Target::Cms => (
                self.cfg.cms.clone(),
                LinkSpec::Telnet {
                    login_password: CMS_TELNET_PASSWORD.into(),
                },
                CMS_TARGET.to_owned(),
            ),
            Target::Ax25 { gateway, via } => (
                self.cfg.agw.clone(),
                LinkSpec::Agw {
                    port: self.cfg.agw_port,
                    via: via.clone(),
                    paclen: self.cfg.paclen,
                },
                gateway.clone(),
            ),
            Target::P2p { addr, call } => (
                addr.clone(),
                LinkSpec::Telnet {
                    login_password: String::new(),
                },
                call.clone(),
            ),
        };
        self.ui.info(&format!("connecting to {addr}"));
        let stream = match open_tcp(&addr) {
            Ok(s) => s,
            Err(e) => {
                let hint = if matches!(target, Target::Ax25 { .. }) {
                    " — is Direwolf running with its AGW port enabled?"
                } else {
                    ""
                };
                self.ui.error(&format!("cannot reach {addr}: {e}{hint}"));
                return self.finish_once(false);
            }
        };
        self.run_exchange(stream, link, remote);
    }

    fn outbound(&self) -> Vec<Outbound> {
        let mut out = Vec::new();
        match self.mailbox.list(Folder::Outbox) {
            Ok((entries, problems)) => {
                for p in problems {
                    self.ui.warn(&format!("skipped unreadable {p}"));
                }
                for e in entries {
                    match Outbound::new(&e.message) {
                        Ok(o) => out.push(o),
                        Err(err) => self.ui.warn(&format!("not sending {}: {err}", e.mid)),
                    }
                }
            }
            Err(e) => self.ui.error(&format!("cannot read the outbox: {e}")),
        }
        out
    }

    fn run_exchange(&mut self, stream: TcpStream, link: LinkSpec, remote: String) {
        let outbound = self.outbound();
        if !outbound.is_empty() {
            self.ui
                .info(&format!("{} message(s) in the outbox", outbound.len()));
        }
        let known: HashSet<String> = self.mailbox.known_mids();
        let timeout = self
            .cfg
            .timeout
            .map_or_else(|| ExchangeConfig::default_timeout(&link), |s| s * 1000);
        let cfg = ExchangeConfig {
            mycall: self.cfg.call.clone(),
            target: remote,
            locator: self.cfg.locator.clone(),
            password: self.cfg.password.clone(),
            link,
            idle_timeout_ms: timeout,
        };
        let id = self.next_id;
        self.next_id += 1;
        let reader = match stream.try_clone() {
            Ok(r) => r,
            Err(e) => {
                self.ui.error(&format!("socket error: {e}"));
                return self.finish_once(false);
            }
        };
        spawn_reader(reader, id, self.events.clone());
        let mut ex = Exchange::new(cfg, outbound, known);
        let actions = ex.start(clock::now_ms());
        self.mode = Mode::Exchange(Box::new(Running { ex, stream, id }));
        self.apply(actions);
    }

    fn with_exchange(&mut self, f: impl FnOnce(&mut Exchange) -> Vec<Action>) {
        if let Mode::Exchange(running) = &mut self.mode {
            let actions = f(&mut running.ex);
            self.apply(actions);
        }
    }

    fn apply(&mut self, actions: Vec<Action>) {
        for action in actions {
            let Mode::Exchange(running) = &mut self.mode else {
                return;
            };
            match action {
                Action::Transmit(bytes) => {
                    if let Err(e) = running.stream.write_all(&bytes) {
                        let more = running.ex.abort(&format!("write failed: {e}"));
                        self.apply(more);
                        return;
                    }
                }
                Action::Log(kind, text) => self.ui.log(kind, &text),
                Action::Received { message, raw } => {
                    let mid = message.mid().to_owned();
                    match self.mailbox.store(Folder::Inbox, &mid, &raw) {
                        Ok(_) => self.ui.received(&message),
                        Err(e) => self
                            .ui
                            .error(&format!("received {mid} but cannot save it: {e}")),
                    }
                }
                Action::Delivered(mid) => {
                    self.move_to_sent(&mid);
                    self.ui.delivered(&mid);
                }
                Action::AlreadyDelivered(mid) => {
                    self.move_to_sent(&mid);
                    self.ui.already(&mid);
                }
                Action::Deferred(mid) => self.ui.deferred(&mid),
                Action::Close => {
                    let _ = running.stream.shutdown(Shutdown::Both);
                }
                Action::Done { ok, summary } => {
                    self.ui.done(ok, &summary);
                    self.mode = Mode::Idle;
                    self.listing = None;
                    self.finish_once(ok);
                }
            }
        }
    }

    fn move_to_sent(&self, mid: &str) {
        if self.mailbox.contains(Folder::Outbox, mid) {
            if let Err(e) = self.mailbox.move_message(mid, Folder::Outbox, Folder::Sent) {
                self.ui.error(&format!(
                    "{mid} was delivered but could not be moved to sent: {e}"
                ));
            }
        }
    }

    fn finish_once(&mut self, ok: bool) {
        if self.cfg.once.is_some() {
            self.exit_code = Some(if ok { 0 } else { 1 });
        }
    }

    fn listen(&mut self, addr: Option<&str>) {
        if let Some((addr, _)) = &self.listener {
            return self.ui.info(&format!("already listening on {addr}"));
        }
        let addr = with_port(addr.unwrap_or("0.0.0.0"), P2P_PORT);
        let stop = Arc::new(AtomicBool::new(false));
        match spawn_listener(&addr, self.events.clone(), Arc::clone(&stop)) {
            Ok(()) => {
                self.ui.ok(&format!(
                    "listening for peer-to-peer calls on {addr}; stop ends it"
                ));
                self.listener = Some((addr, stop));
            }
            Err(e) => self.ui.error(&format!("cannot listen on {addr}: {e}")),
        }
    }

    fn stop_listening(&mut self) {
        match self.listener.take() {
            Some((addr, stop)) => {
                stop.store(true, Ordering::Relaxed);
                self.ui.info(&format!("stopped listening on {addr}"));
            }
            None => self.ui.info("not listening"),
        }
    }

    fn accepted(&mut self, mut stream: TcpStream, peer: SocketAddr) {
        if !matches!(self.mode, Mode::Idle) {
            self.ui.warn(&format!("refused a call from {peer}: busy"));
            let _ = stream.write_all(b"*** busy, try again later\r");
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        self.ui.info(&format!("incoming call from {peer}"));
        self.run_exchange(stream, LinkSpec::TelnetAnswer, String::new());
    }

    fn net(&mut self, id: u64, data: Option<Vec<u8>>, reason: Option<String>) {
        let Mode::Exchange(running) = &mut self.mode else {
            return;
        };
        if running.id != id {
            return;
        }
        let actions = match data {
            Some(bytes) => running.ex.on_bytes(&bytes, clock::now_ms()),
            None => {
                let actions = running.ex.on_closed();
                if let Some(r) = reason {
                    self.ui.warn(&format!("link error: {r}"));
                }
                actions
            }
        };
        self.apply(actions);
    }

    fn tick(&mut self) {
        self.with_exchange(|ex| ex.poll(clock::now_ms()));
    }

    fn busy(&self) -> bool {
        !matches!(self.mode, Mode::Idle)
    }
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_owned(), format!(".{e}")),
        _ => (name.to_owned(), String::new()),
    };
    (1..)
        .map(|i| dir.join(format!("{stem} ({i}){ext}")))
        .find(|p| !p.exists())
        .expect("some free name")
}

fn open_tcp(addr: &str) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address found");
    for sa in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn spawn_reader(mut stream: TcpStream, id: u64, events: Sender<Event>) {
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    let _ = events.send(Event::NetClosed { id, reason: None });
                    return;
                }
                Ok(n) => {
                    let data = buf[..n].to_vec();
                    if events.send(Event::Net { id, data }).is_err() {
                        return;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    let reason = match e.kind() {
                        io::ErrorKind::NotConnected | io::ErrorKind::ConnectionAborted => None,
                        _ => Some(e.to_string()),
                    };
                    let _ = events.send(Event::NetClosed { id, reason });
                    return;
                }
            }
        }
    });
}

fn spawn_listener(addr: &str, events: Sender<Event>, stop: Arc<AtomicBool>) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    thread::spawn(move || {
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            match listener.accept() {
                Ok((stream, peer)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_nodelay(true);
                    if events.send(Event::Accepted { stream, peer }).is_err() {
                        return;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200))
                }
                Err(e) => {
                    let _ = events.send(Event::ListenFailed(e.to_string()));
                    return;
                }
            }
        }
    });
    Ok(())
}

fn spawn_stdin_reader(events: Sender<Event>) {
    thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if events.send(Event::Line(line)).is_err() {
                return;
            }
        }
        let _ = events.send(Event::InputClosed);
    });
}

/// Hides typed characters while the password is entered (Unix terminals).
fn set_echo(on: bool) {
    #[cfg(unix)]
    if io::stdin().is_terminal() {
        let _ = process::Command::new("stty")
            .arg(if on { "echo" } else { "-echo" })
            .stdin(process::Stdio::inherit())
            .status();
    }
    #[cfg(not(unix))]
    let _ = on;
}

fn run(cfg: Config) -> Result<i32, String> {
    let mailbox = Mailbox::open(&cfg.mailbox, &cfg.call)
        .map_err(|e| format!("cannot open mailbox {}: {e}", cfg.mailbox.display()))?;
    let ui = Ui::new(cfg.no_color, !cfg.quiet);
    let (events_tx, events) = mpsc::channel();
    let once = cfg.once.clone();
    if once.is_none() {
        spawn_stdin_reader(events_tx.clone());
    }
    let mut app = App {
        cfg,
        ui,
        mailbox,
        events: events_tx,
        mode: Mode::Idle,
        listing: None,
        listener: None,
        next_id: 1,
        input_open: true,
        exit_code: None,
    };
    app.ui.info(&format!(
        "{} — mailbox {} — type help",
        app.cfg.call,
        app.mailbox.root().display()
    ));

    if let Some(spec) = once {
        let words: Vec<&str> = spec.split_whitespace().collect();
        app.connect(Target::parse(&words)?);
    }

    loop {
        if let Some(code) = app.exit_code {
            if !matches!(app.mode, Mode::Exchange(_)) {
                set_echo(true);
                return Ok(code);
            }
        }
        if !app.input_open && !app.busy() && app.listener.is_none() {
            return Ok(0);
        }
        match events.recv_timeout(TICK) {
            Ok(Event::Line(line)) => app.handle_line(line),
            Ok(Event::InputClosed) => {
                app.input_open = false;
                if matches!(app.mode, Mode::Compose(_) | Mode::Password(_)) {
                    set_echo(true);
                    app.mode = Mode::Idle;
                }
            }
            Ok(Event::Net { id, data }) => app.net(id, Some(data), None),
            Ok(Event::NetClosed { id, reason }) => app.net(id, None, reason),
            Ok(Event::Accepted { stream, peer }) => app.accepted(stream, peer),
            Ok(Event::ListenFailed(e)) => {
                app.listener = None;
                app.ui.error(&format!("listener stopped: {e}"));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(0),
        }
        app.tick();
    }
}

fn main() {
    let cfg = match parse_args() {
        Ok(cfg) => cfg,
        Err(msg) => {
            eprintln!("b2fmsg: {msg}\n\n{USAGE}");
            process::exit(2);
        }
    };
    match run(cfg) {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("b2fmsg: {e}");
            process::exit(1);
        }
    }
}
