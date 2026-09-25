//! Terminal output for the CLI, in the same style as aprsmsg: a UTC stamp,
//! a marker, then the station and text.

use std::env;
use std::io::{self, IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::mailbox::{Entry, Folder};
use crate::message::{Message, display_address};
use crate::session::LogKind;

const WHO_WIDTH: usize = 22;
const SUBJECT_WIDTH: usize = 38;

#[derive(Clone, Copy)]
enum Style {
    Dim,
    Bold,
    Cyan,
    Green,
    Yellow,
    Red,
    Blue,
}

impl Style {
    fn sgr(self) -> &'static str {
        match self {
            Style::Dim => "2",
            Style::Bold => "1",
            Style::Cyan => "1;36",
            Style::Green => "1;32",
            Style::Yellow => "1;33",
            Style::Red => "1;31",
            Style::Blue => "1;34",
        }
    }
}

pub struct Ui {
    color: bool,
    trace: bool,
}

impl Ui {
    pub fn new(no_color: bool, trace: bool) -> Ui {
        let color = !no_color && env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal();
        Ui { color, trace }
    }

    pub fn trace(&self) -> bool {
        self.trace
    }

    pub fn set_trace(&mut self, on: bool) {
        self.trace = on;
    }

    fn paint(&self, style: Style, text: &str) -> String {
        if self.color && !text.is_empty() {
            format!("\x1b[{}m{text}\x1b[0m", style.sgr())
        } else {
            text.to_owned()
        }
    }

    fn line(&self, marker: &str, style: Style, text: &str) {
        println!(
            "{} {} {text}",
            self.paint(Style::Dim, &stamp()),
            self.paint(style, marker)
        );
    }

    pub fn info(&self, text: &str) {
        println!(
            "{} {}",
            self.paint(Style::Dim, &stamp()),
            self.paint(Style::Dim, text)
        );
    }

    pub fn warn(&self, text: &str) {
        self.line("!", Style::Yellow, text);
    }

    pub fn error(&self, text: &str) {
        self.line("✗", Style::Red, &self.paint(Style::Red, text));
    }

    pub fn ok(&self, text: &str) {
        self.line("✓", Style::Green, text);
    }

    /// A prompt that the next input line answers.
    pub fn prompt(&self, text: &str) {
        print!("{} ", self.paint(Style::Cyan, text));
        let _ = io::stdout().flush();
    }

    pub fn plain(&self, text: &str) {
        println!("{text}");
    }

    pub fn log(&self, kind: LogKind, text: &str) {
        match kind {
            LogKind::Tx if self.trace => self.line("›", Style::Dim, &self.paint(Style::Dim, text)),
            LogKind::Rx if self.trace => self.line("‹", Style::Dim, &self.paint(Style::Dim, text)),
            LogKind::Tx | LogKind::Rx => {}
            LogKind::Info => self.info(text),
            LogKind::Warn => self.warn(text),
            LogKind::Error => self.error(text),
            LogKind::Ok => self.ok(text),
        }
    }

    pub fn queued(&self, mid: &str, message: &Message) {
        let who = message
            .recipients()
            .iter()
            .map(|a| display_address(a).to_owned())
            .collect::<Vec<_>>()
            .join(", ");
        self.line(
            "→",
            Style::Cyan,
            &format!(
                "{} {}  {}",
                self.paint(Style::Bold, &who),
                message.subject(),
                self.paint(Style::Dim, &format!("{mid} queued — connect to send"))
            ),
        );
    }

    pub fn delivered(&self, mid: &str) {
        self.line("✓", Style::Green, &format!("{mid} delivered"));
    }

    pub fn already(&self, mid: &str) {
        self.line(
            "✓",
            Style::Green,
            &format!("{mid} was already delivered; moved to sent"),
        );
    }

    pub fn deferred(&self, mid: &str) {
        self.line(
            "…",
            Style::Yellow,
            &format!("{mid} deferred by the remote; stays in the outbox"),
        );
    }

    pub fn received(&self, message: &Message) {
        let files = match message.files.len() {
            0 => String::new(),
            1 => "  +1 attachment".into(),
            n => format!("  +{n} attachments"),
        };
        self.line(
            "←",
            Style::Yellow,
            &format!(
                "{} {}{}",
                self.paint(Style::Bold, display_address(&message.from())),
                message.subject(),
                self.paint(Style::Dim, &format!("  {}{files}", message.mid()))
            ),
        );
    }

    pub fn done(&self, ok: bool, summary: &str) {
        if ok {
            self.ok(summary);
        } else {
            self.error(summary);
        }
    }

    pub fn listing(&self, folder: Folder, entries: &[Entry]) {
        if entries.is_empty() {
            self.info(&format!("{} is empty", folder.label()));
            return;
        }
        println!(
            "{}",
            self.paint(
                Style::Bold,
                &format!("{} ({})", folder.label(), entries.len())
            )
        );
        for (i, e) in entries.iter().enumerate() {
            let m = &e.message;
            let who = if folder == Folder::Inbox {
                display_address(&m.from()).to_owned()
            } else {
                m.recipients()
                    .iter()
                    .map(|a| display_address(a).to_owned())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let files = if m.files.is_empty() {
                String::new()
            } else {
                format!(" +{}", m.files.len())
            };
            println!(
                "{:>3}  {}  {}  {}  {}",
                i + 1,
                self.paint(Style::Dim, m.date()),
                self.paint(Style::Bold, &fit(&who, WHO_WIDTH)),
                fit(&m.subject(), SUBJECT_WIDTH),
                self.paint(Style::Dim, &format!("{}{files}", human_size(e.bytes)))
            );
        }
    }

    pub fn show_message(&self, message: &Message) {
        let row = |label: &str, value: &str| {
            println!("{} {value}", self.paint(Style::Dim, &format!("{label:>8}")));
        };
        println!();
        row("From", display_address(&message.from()));
        let to: Vec<String> = message
            .to()
            .iter()
            .map(|a| display_address(a).to_owned())
            .collect();
        row("To", &to.join(", "));
        let cc: Vec<String> = message
            .cc()
            .iter()
            .map(|a| display_address(a).to_owned())
            .collect();
        if !cc.is_empty() {
            row("Cc", &cc.join(", "));
        }
        row("Date", &format!("{} UTC", message.date()));
        row("Subject", &self.paint(Style::Bold, &message.subject()));
        row("MID", message.mid());
        println!();
        for line in message.body_text().lines() {
            println!("  {line}");
        }
        if !message.files.is_empty() {
            println!();
            for f in &message.files {
                println!(
                    "  {} {}  {}",
                    self.paint(Style::Blue, "📎"),
                    f.name,
                    self.paint(Style::Dim, &human_size(f.data.len()))
                );
            }
            println!(
                "  {}",
                self.paint(Style::Dim, "save N [DIR] writes the attachments")
            );
        }
        println!();
    }
}

fn fit(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        format!("{text}{}", " ".repeat(width - count))
    } else {
        let cut: String = text.chars().take(width - 1).collect();
        format!("{cut}…")
    }
}

pub fn human_size(bytes: usize) -> String {
    if bytes < 1000 {
        format!("{bytes} B")
    } else if bytes < 1_000_000 {
        format!("{:.1} kB", bytes as f64 / 1000.0)
    } else {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    }
}

fn stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        % 86_400;
    format!("{:02}:{:02}:{:02}Z", secs / 3600, secs / 60 % 60, secs % 60)
}
