//! On-disk mailbox: `<root>/<CALL>/{in,out,sent,archive}/<MID>.b2f`, one
//! raw Winlink message per file. This is Pat's layout, so `--mailbox` can
//! point at Pat's mailbox directory and both programs see the same messages.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::message::Message;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Folder {
    Inbox,
    Outbox,
    Sent,
    Archive,
}

impl Folder {
    pub const ALL: [Folder; 4] = [Folder::Inbox, Folder::Outbox, Folder::Sent, Folder::Archive];

    pub fn dir(self) -> &'static str {
        match self {
            Folder::Inbox => "in",
            Folder::Outbox => "out",
            Folder::Sent => "sent",
            Folder::Archive => "archive",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Folder::Inbox => "inbox",
            Folder::Outbox => "outbox",
            Folder::Sent => "sent",
            Folder::Archive => "archive",
        }
    }
}

pub struct Entry {
    pub mid: String,
    pub message: Message,
    pub bytes: usize,
}

pub struct Mailbox {
    root: PathBuf,
}

impl Mailbox {
    /// Opens (creating if needed) the mailbox for `call` under `base`.
    pub fn open(base: &Path, call: &str) -> io::Result<Mailbox> {
        let root = base.join(call.to_uppercase());
        for folder in Folder::ALL {
            fs::create_dir_all(root.join(folder.dir()))?;
        }
        Ok(Mailbox { root })
    }

    /// `$XDG_DATA_HOME/b2fmsg/mailbox`, `~/.local/share/...`, or the
    /// platform equivalent.
    pub fn default_base() -> PathBuf {
        let data = if cfg!(windows) {
            env::var_os("APPDATA").map(PathBuf::from)
        } else if cfg!(target_os = "macos") {
            env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"))
        } else {
            env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        };
        data.unwrap_or_else(|| PathBuf::from("."))
            .join("b2fmsg")
            .join("mailbox")
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, folder: Folder, mid: &str) -> PathBuf {
        self.root.join(folder.dir()).join(format!("{mid}.b2f"))
    }

    /// Messages in a folder, oldest first. Unreadable files are skipped and
    /// reported in the second value.
    pub fn list(&self, folder: Folder) -> io::Result<(Vec<Entry>, Vec<String>)> {
        let mut entries = Vec::new();
        let mut problems = Vec::new();
        for item in fs::read_dir(self.root.join(folder.dir()))? {
            let path = item?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("b2f") {
                continue;
            }
            let raw = match fs::read(&path) {
                Ok(raw) => raw,
                Err(e) => {
                    problems.push(format!("{}: {e}", path.display()));
                    continue;
                }
            };
            match Message::parse(&raw) {
                Ok(message) => entries.push(Entry {
                    mid: message.mid().to_owned(),
                    bytes: raw.len(),
                    message,
                }),
                Err(e) => problems.push(format!("{}: {e}", path.display())),
            }
        }
        entries
            .sort_by(|a, b| (a.message.unix_date(), &a.mid).cmp(&(b.message.unix_date(), &b.mid)));
        Ok((entries, problems))
    }

    /// Writes a raw message atomically (temporary file, then rename).
    pub fn store(&self, folder: Folder, mid: &str, raw: &[u8]) -> io::Result<PathBuf> {
        if mid.is_empty() || mid.contains(['/', '\\', '.']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad MID {mid:?}"),
            ));
        }
        let path = self.path(folder, mid);
        let tmp = path.with_extension("b2f.tmp");
        fs::write(&tmp, raw)?;
        fs::rename(&tmp, &path)?;
        Ok(path)
    }

    pub fn move_message(&self, mid: &str, from: Folder, to: Folder) -> io::Result<()> {
        fs::rename(self.path(from, mid), self.path(to, mid))
    }

    pub fn delete(&self, folder: Folder, mid: &str) -> io::Result<()> {
        fs::remove_file(self.path(folder, mid))
    }

    pub fn contains(&self, folder: Folder, mid: &str) -> bool {
        self.path(folder, mid).exists()
    }

    /// MIDs we already hold (so the remote's copies are refused).
    pub fn known_mids(&self) -> HashSet<String> {
        let mut known = HashSet::new();
        for folder in [Folder::Inbox, Folder::Archive] {
            if let Ok(items) = fs::read_dir(self.root.join(folder.dir())) {
                for item in items.flatten() {
                    let path = item.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("b2f") {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            known.insert(stem.to_owned());
                        }
                    }
                }
            }
        }
        known
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Draft;

    #[test]
    fn store_list_move() {
        let base = env::temp_dir().join(format!("b2fmsg-test-{}", std::process::id()));
        let mb = Mailbox::open(&base, "sa0kam").unwrap();
        assert!(mb.root().ends_with("SA0KAM"));
        let (msg, _) = Message::compose(Draft {
            from: "SA0KAM".into(),
            to: vec!["SO5KM".into()],
            subject: "hi".into(),
            body: "body".into(),
            date: 1_790_246_700,
            mid: "STOREMID0001".into(),
            ..Draft::default()
        })
        .unwrap();
        mb.store(Folder::Outbox, msg.mid(), &msg.to_bytes())
            .unwrap();
        fs::write(base.join("SA0KAM/out/broken.b2f"), b"garbage").unwrap();
        let (entries, problems) = mb.list(Folder::Outbox).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(problems.len(), 1);
        mb.move_message("STOREMID0001", Folder::Outbox, Folder::Inbox)
            .unwrap();
        assert!(mb.known_mids().contains("STOREMID0001"));
        assert!(mb.store(Folder::Inbox, "../evil", b"x").is_err());
        fs::remove_dir_all(&base).unwrap();
    }
}
