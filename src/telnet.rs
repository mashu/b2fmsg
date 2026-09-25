//! The Winlink "telnet" login used by the CMS and by peer-to-peer TCP
//! sessions: the answering side prompts `Callsign :` and `Password :`,
//! then the B2F session starts on the same stream.

/// Refuse login lines longer than this (DoS / garbage).
const MAX_LINE: usize = 4 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Send(Vec<u8>),
    /// A line that was not a prompt (banner text).
    Banner(String),
    /// Login finished; these bytes already belong to the B2F session.
    Done(Vec<u8>),
    /// The peer sent an absurdly long line before login finished.
    Failed(String),
}

/// Client side: answers the prompts.
pub struct Login {
    call: String,
    password: String,
    buf: Vec<u8>,
    done: bool,
}

impl Login {
    pub fn new(call: &str, password: &str) -> Login {
        Login {
            call: call.to_owned(),
            password: password.to_owned(),
            buf: Vec::new(),
            done: false,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<Step> {
        let mut steps = Vec::new();
        if self.done {
            steps.push(Step::Done(data.to_vec()));
            return steps;
        }
        self.buf.extend_from_slice(data);
        loop {
            let (line, consumed) = match self.buf.iter().position(|&b| b == b'\r' || b == b'\n') {
                Some(end) if end > MAX_LINE => {
                    self.buf.clear();
                    steps.push(Step::Failed(format!(
                        "login line longer than {MAX_LINE} bytes"
                    )));
                    return steps;
                }
                Some(end) => (text(&self.buf[..end]), end + 1),
                // Prompts may arrive without a line ending.
                None if is_prompt(&text(&self.buf)) => (text(&self.buf), self.buf.len()),
                None if self.buf.len() > MAX_LINE => {
                    self.buf.clear();
                    steps.push(Step::Failed(format!(
                        "login line longer than {MAX_LINE} bytes without a line ending"
                    )));
                    return steps;
                }
                None => break,
            };
            self.buf.drain(..consumed);
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("callsign") {
                steps.push(Step::Send(format!("{}\r", self.call).into_bytes()));
            } else if lower.starts_with("password") {
                steps.push(Step::Send(format!("{}\r", self.password).into_bytes()));
                self.done = true;
                steps.push(Step::Done(std::mem::take(&mut self.buf)));
                break;
            } else if !line.is_empty() {
                steps.push(Step::Banner(line));
            }
        }
        steps
    }
}

/// Answering side (peer-to-peer listener): prompts and learns the caller.
#[derive(Default)]
pub struct Accept {
    stage: u8,
    buf: Vec<u8>,
    remote: String,
}

impl Accept {
    pub fn start(&mut self) -> Vec<Step> {
        vec![Step::Send(b"Callsign :\r".to_vec())]
    }

    pub fn remote_call(&self) -> &str {
        &self.remote
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<Step> {
        let mut steps = Vec::new();
        if self.stage >= 2 {
            steps.push(Step::Done(data.to_vec()));
            return steps;
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() > MAX_LINE && !self.buf.iter().any(|&b| b == b'\r' || b == b'\n') {
            self.buf.clear();
            steps.push(Step::Failed(format!(
                "login line longer than {MAX_LINE} bytes without a line ending"
            )));
            return steps;
        }
        while let Some(end) = self.buf.iter().position(|&b| b == b'\r' || b == b'\n') {
            if end > MAX_LINE {
                self.buf.clear();
                steps.push(Step::Failed(format!(
                    "login line longer than {MAX_LINE} bytes"
                )));
                return steps;
            }
            let line = text(&self.buf[..end]);
            // CRLF is one line ending, so an empty password stays empty.
            let crlf = self.buf[end] == b'\r' && self.buf.get(end + 1) == Some(&b'\n');
            self.buf.drain(..end + 1 + usize::from(crlf));
            if self.stage == 0 && line.is_empty() {
                continue;
            }
            if self.stage == 0 {
                self.remote = line.split_whitespace().next().unwrap_or("").to_uppercase();
                self.stage = 1;
                steps.push(Step::Send(b"Password :\r".to_vec()));
            } else {
                self.stage = 2;
                steps.push(Step::Done(std::mem::take(&mut self.buf)));
                break;
            }
        }
        steps
    }
}

fn text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| b as char)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn is_prompt(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    (lower.starts_with("callsign") || lower.starts_with("password")) && lower.ends_with(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cms_login() {
        let mut l = Login::new("SA0KAM", "CMSTelnet");
        assert_eq!(
            l.feed(b"Welcome\r\nCallsign :\r\n"),
            vec![
                Step::Banner("Welcome".into()),
                Step::Send(b"SA0KAM\r".to_vec())
            ]
        );
        assert_eq!(
            l.feed(b"Password :\r[WL2K-5.0-B2FWIHJM$]\r"),
            vec![
                Step::Send(b"CMSTelnet\r".to_vec()),
                Step::Done(b"[WL2K-5.0-B2FWIHJM$]\r".to_vec())
            ]
        );
        assert!(l.is_done());
        assert_eq!(l.feed(b"x"), vec![Step::Done(b"x".to_vec())]);
    }

    #[test]
    fn prompt_without_newline() {
        let mut l = Login::new("A1A", "");
        assert_eq!(l.feed(b"Callsign :"), vec![Step::Send(b"A1A\r".to_vec())]);
    }

    #[test]
    fn accept_side() {
        let mut a = Accept::default();
        assert_eq!(a.start(), vec![Step::Send(b"Callsign :\r".to_vec())]);
        assert_eq!(
            a.feed(b"so5km\r"),
            vec![Step::Send(b"Password :\r".to_vec())]
        );
        assert_eq!(a.remote_call(), "SO5KM");
        assert_eq!(
            a.feed(b"\r;FW: SO5KM\r"),
            vec![Step::Done(b";FW: SO5KM\r".to_vec())]
        );
    }

    #[test]
    fn rejects_overlong_login_line() {
        let mut l = Login::new("A1A", "");
        let junk = vec![b'X'; MAX_LINE + 1];
        let steps = l.feed(&junk);
        assert!(matches!(steps.as_slice(), [Step::Failed(_)]));
    }
}
