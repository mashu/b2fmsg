//! The Winlink message structure (winlink.org/B2F): an ASCII header block,
//! a body of exactly `Body:` bytes, then `File:` attachments in header order.
//! Each section is terminated by CRLF.

use crate::charset;
use crate::date;
use crate::md5;

pub const MAX_MID_LEN: usize = 12;
pub const MAX_SUBJECT_LEN: usize = 128;
pub const MAX_FILENAME_LEN: usize = 255;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    fields: Vec<(String, String)>,
}

impl Header {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.remove(key);
        self.add(key, value);
    }

    pub fn add(&mut self, key: &str, value: impl Into<String>) {
        self.fields.push((canonical_key(key), value.into()));
    }

    pub fn remove(&mut self, key: &str) {
        self.fields.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// `content-type` → `Content-Type`, like MIME header canonicalisation.
fn canonical_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut upper = true;
    for c in key.trim().chars() {
        out.push(if upper {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        });
        upper = c == '-';
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub body: Vec<u8>,
    pub files: Vec<Attachment>,
}

/// Everything needed to write a new message.
#[derive(Clone, Debug, Default)]
pub struct Draft {
    /// Sender callsign (the Winlink account).
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub body: String,
    pub files: Vec<Attachment>,
    /// Unix seconds.
    pub date: i64,
    pub mid: String,
}

impl Message {
    /// Builds a message; returns it with human-readable warnings.
    pub fn compose(draft: Draft) -> Result<(Message, Vec<String>), String> {
        let mut warnings = Vec::new();
        let from = draft.from.trim().to_uppercase();
        if from.is_empty() {
            return Err("sender callsign is empty".into());
        }
        let to = parse_addresses(&draft.to)?;
        let cc = parse_addresses(&draft.cc)?;
        if to.is_empty() && cc.is_empty() {
            return Err("add at least one recipient".into());
        }
        let subject = draft.subject.trim();
        if subject.is_empty() {
            return Err("the subject is empty".into());
        }

        let body_text = normalize_body(&draft.body);
        let (body, body_charset) = charset::encode_text(&body_text);
        let (_, subject_charset) = charset::encode_text(subject);
        if body_charset == charset::UTF8 || subject_charset == charset::UTF8 {
            warnings.push(
                "text has characters outside Latin-1; it is sent as UTF-8, which some Winlink programs show garbled".into(),
            );
        }

        let mut header = Header::default();
        header.set("Mid", draft.mid.clone());
        header.set("Date", date::format(draft.date));
        header.set("Type", "Private");
        header.set("From", from.clone());
        header.set("Mbo", from);
        for addr in &to {
            header.add("To", addr.clone());
        }
        for addr in &cc {
            header.add("Cc", addr.clone());
        }
        header.set("Subject", charset::encode_header(subject));
        header.set(
            "Content-Type",
            format!("text/plain; charset={body_charset}"),
        );
        header.set("Content-Transfer-Encoding", "8bit");
        header.set("Body", body.len().to_string());
        for file in &draft.files {
            let name = sanitize_filename(&file.name);
            header.add(
                "File",
                format!("{} {}", file.data.len(), charset::encode_header(&name)),
            );
        }
        let files = draft
            .files
            .into_iter()
            .map(|f| Attachment {
                name: sanitize_filename(&f.name),
                data: f.data,
            })
            .collect();
        let message = Message {
            header,
            body,
            files,
        };
        message.validate()?;
        Ok((message, warnings))
    }

    /// The constraints the CMS enforces (some are undocumented; Pat checks
    /// the same set).
    pub fn validate(&self) -> Result<(), String> {
        let mid = self.mid();
        if mid.is_empty() {
            return Err("message has no MID".into());
        }
        if mid.len() > MAX_MID_LEN {
            return Err(format!("MID {mid} is longer than {MAX_MID_LEN} characters"));
        }
        if self.to().is_empty() && self.cc().is_empty() {
            return Err(format!("{mid}: no recipient"));
        }
        if self.header.get("From").is_none_or(|f| f.trim().is_empty()) {
            return Err(format!("{mid}: empty From"));
        }
        if self.body.is_empty() {
            return Err(format!("{mid}: empty body"));
        }
        let subject = self.header.get("Subject").unwrap_or("");
        if subject.is_empty() {
            return Err(format!("{mid}: empty subject"));
        }
        if subject.len() > MAX_SUBJECT_LEN {
            return Err(format!(
                "{mid}: subject is {} bytes on the wire (limit {MAX_SUBJECT_LEN}); shorten it",
                subject.len()
            ));
        }
        for file in &self.files {
            if file.name.len() > MAX_FILENAME_LEN {
                return Err(format!("{mid}: attachment name too long: {}", file.name));
            }
        }
        Ok(())
    }

    pub fn mid(&self) -> &str {
        self.header.get("Mid").unwrap_or("").trim()
    }

    pub fn subject(&self) -> String {
        charset::decode_header(self.header.get("Subject").unwrap_or(""))
    }

    pub fn from(&self) -> String {
        self.header.get("From").unwrap_or("").trim().to_owned()
    }

    pub fn to(&self) -> Vec<String> {
        self.header
            .get_all("To")
            .map(|s| s.trim().to_owned())
            .collect()
    }

    pub fn cc(&self) -> Vec<String> {
        self.header
            .get_all("Cc")
            .map(|s| s.trim().to_owned())
            .collect()
    }

    /// All recipients (To then Cc).
    pub fn recipients(&self) -> Vec<String> {
        let mut all = self.to();
        all.extend(self.cc());
        all
    }

    pub fn date(&self) -> &str {
        self.header.get("Date").unwrap_or("").trim()
    }

    pub fn unix_date(&self) -> Option<i64> {
        date::parse(self.date())
    }

    pub fn charset(&self) -> String {
        self.header
            .get("Content-Type")
            .and_then(|ct| {
                ct.split(';')
                    .filter_map(|p| p.trim().split_once('='))
                    .find(|(k, _)| k.trim().eq_ignore_ascii_case("charset"))
                    .map(|(_, v)| v.trim().trim_matches('"').to_owned())
            })
            .unwrap_or_else(|| charset::LATIN1.to_owned())
    }

    pub fn body_text(&self) -> String {
        charset::decode_text(&self.body, &self.charset())
    }

    /// Serialises to the Winlink message format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 512);
        out.extend_from_slice(format!("Mid: {}\r\n", self.mid()).as_bytes());
        let mut rest: Vec<&(String, String)> = self
            .header
            .fields
            .iter()
            .filter(|(k, _)| !k.eq_ignore_ascii_case("Mid"))
            .collect();
        // Stable order keeps the output reproducible; File: order is kept.
        rest.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, value) in rest {
            out.extend_from_slice(format!("{key}: {}\r\n", value.trim()).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out.extend_from_slice(b"\r\n");
        for file in &self.files {
            out.extend_from_slice(&file.data);
            out.extend_from_slice(b"\r\n");
        }
        out
    }

    pub fn parse(data: &[u8]) -> Result<Message, String> {
        let start = data
            .iter()
            .position(|b| !b" \t\r\n".contains(b))
            .ok_or("empty message")?;
        let data = &data[start..];

        let mut header = Header::default();
        let mut pos = 0;
        loop {
            let end = data[pos..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|i| pos + i)
                .ok_or("message header is not terminated")?;
            let mut line = &data[pos..end];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len() - 1];
            }
            pos = end + 1;
            if line.is_empty() {
                break;
            }
            let text = String::from_utf8_lossy(line);
            if text.starts_with([' ', '\t']) {
                if let Some(last) = header.fields.last_mut() {
                    last.1.push(' ');
                    last.1.push_str(text.trim());
                }
                continue;
            }
            let (key, value) = text
                .split_once(':')
                .ok_or_else(|| format!("malformed header line {text:?}"))?;
            header.add(key, value.trim());
        }

        let body_len: usize = header
            .get("Body")
            .unwrap_or("0")
            .trim()
            .parse()
            .map_err(|_| "Body: is not a number")?;
        let body = take_section(data, &mut pos, body_len, "body")?;

        let mut files = Vec::new();
        for value in header.get_all("File") {
            let (size, name) = value
                .trim()
                .split_once(' ')
                .ok_or_else(|| format!("malformed File header {value:?}"))?;
            let size: usize = size
                .parse()
                .map_err(|_| format!("malformed File size {size:?}"))?;
            let data = take_section(data, &mut pos, size, "attachment")?;
            files.push(Attachment {
                name: sanitize_filename(&charset::decode_header(name.trim())),
                data,
            });
        }

        let message = Message {
            header,
            body,
            files,
        };
        if message.mid().is_empty() {
            return Err("message has no Mid header".into());
        }
        Ok(message)
    }
}

/// Reads `len` bytes, then skips the CRLF that ends the section (if any).
fn take_section(data: &[u8], pos: &mut usize, len: usize, what: &str) -> Result<Vec<u8>, String> {
    let end = pos
        .checked_add(len)
        .filter(|&e| e <= data.len())
        .ok_or_else(|| format!("message is truncated inside the {what}"))?;
    let section = data[*pos..end].to_vec();
    *pos = end;
    if data[*pos..].starts_with(b"\r\n") {
        *pos += 2;
    } else if data[*pos..].starts_with(b"\n") {
        *pos += 1;
    }
    Ok(section)
}

/// CRLF line endings, lines of at most 998 bytes, final CRLF.
fn normalize_body(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    let text = text.replace("\r\n", "\n");
    let trimmed = text.trim_end_matches('\n');
    if trimmed.is_empty() {
        return "\r\n".into();
    }
    for line in trimmed.split('\n') {
        let line = line.trim_end_matches('\r');
        let mut rest = line;
        loop {
            let mut cut = rest.len().min(998);
            while !rest.is_char_boundary(cut) {
                cut -= 1;
            }
            out.push_str(&rest[..cut]);
            out.push_str("\r\n");
            rest = &rest[cut..];
            if rest.is_empty() {
                break;
            }
        }
    }
    out
}

/// Keeps only the last path component and drops control characters.
pub fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let clean: String = base.chars().filter(|c| !c.is_control()).collect();
    let clean = clean.trim().trim_start_matches('.').to_owned();
    if clean.is_empty() {
        "attachment".into()
    } else {
        clean
    }
}

/// Winlink address form: callsigns upper-case, e-mail as `SMTP:user@host`,
/// `CALL@winlink.org` as plain `CALL`.
pub fn normalize_address(addr: &str) -> Result<String, String> {
    let addr = addr.trim().trim_matches(|c| c == '<' || c == '>');
    if addr.is_empty() {
        return Err("empty address".into());
    }
    if addr.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("address {addr:?} contains spaces"));
    }
    if let Some((proto, rest)) = addr.split_once(':') {
        if proto.eq_ignore_ascii_case("smtp") && rest.contains('@') {
            return Ok(format!("SMTP:{rest}"));
        }
        return Err(format!("unsupported address {addr:?}"));
    }
    if let Some((local, domain)) = addr.split_once('@') {
        if local.is_empty() || domain.is_empty() || domain.contains('@') {
            return Err(format!("malformed e-mail address {addr:?}"));
        }
        if domain.eq_ignore_ascii_case("winlink.org") {
            return Ok(local.to_uppercase());
        }
        return Ok(format!("SMTP:{addr}"));
    }
    if !addr
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '/')
    {
        return Err(format!(
            "{addr:?} is neither a callsign nor an e-mail address"
        ));
    }
    Ok(addr.to_uppercase())
}

/// Splits comma/semicolon separated address lists and normalises them.
pub fn parse_addresses(items: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for item in items {
        for part in item.split([',', ';']) {
            if part.trim().is_empty() {
                continue;
            }
            let addr = normalize_address(part)?;
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    Ok(out)
}

/// A 12-character message ID (base32 of an MD5 over call, time and noise).
pub fn generate_mid(call: &str, now_ms: u64, entropy: u64) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let sum = md5::digest(format!("{now_ms}-{call}-{entropy}").as_bytes());
    let mut bits = u64::from_be_bytes(sum[..8].try_into().expect("8 bytes"));
    let mut mid = String::with_capacity(MAX_MID_LEN);
    for _ in 0..MAX_MID_LEN {
        mid.push(ALPHABET[(bits >> 59) as usize] as char);
        bits <<= 5;
    }
    mid
}

/// Human-friendly form of a Winlink address (drops the `SMTP:` prefix).
pub fn display_address(addr: &str) -> &str {
    addr.strip_prefix("SMTP:")
        .or_else(|| addr.strip_prefix("smtp:"))
        .unwrap_or(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> Draft {
        Draft {
            from: "sa0kam".into(),
            to: vec!["sm0abc, friend@example.com".into()],
            cc: vec!["N0CALL@winlink.org".into()],
            subject: "Hej från stationen".into(),
            body: "Line one\nLine two\n".into(),
            files: vec![Attachment {
                name: "../../etc/log.txt".into(),
                data: b"QSO 14.070".to_vec(),
            }],
            date: 1_790_246_700,
            mid: "ABCDEFGHIJKL".into(),
        }
    }

    #[test]
    fn compose_and_parse_roundtrip() {
        let (msg, warnings) = Message::compose(draft()).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(msg.to(), ["SM0ABC", "SMTP:friend@example.com"]);
        assert_eq!(msg.cc(), ["N0CALL"]);
        assert_eq!(msg.files[0].name, "log.txt");
        let bytes = msg.to_bytes();
        assert!(bytes.starts_with(b"Mid: ABCDEFGHIJKL\r\n"));
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!(back.subject(), "Hej från stationen");
        assert_eq!(back.body_text(), "Line one\r\nLine two\r\n");
        assert_eq!(back.date(), "2026/09/24 10:45");
        assert_eq!(back.files[0].data, b"QSO 14.070");
    }

    #[test]
    fn utf8_warns() {
        let mut d = draft();
        d.body = "Pozdrawiam, Łódź".into();
        let (msg, warnings) = Message::compose(d).unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(msg.charset(), "UTF-8");
        assert_eq!(
            Message::parse(&msg.to_bytes()).unwrap().body_text(),
            "Pozdrawiam, Łódź\r\n"
        );
    }

    #[test]
    fn parses_pat_style_without_trailing_crlf() {
        let raw = b"\r\nMid: XYZ123\r\nBody: 4\r\nFrom: N0CALL\r\nTo: SA0KAM\r\nSubject: hi\r\nDate: 2026/01/02 03:04\r\n\r\nhi\r\n";
        let msg = Message::parse(raw).unwrap();
        assert_eq!(msg.mid(), "XYZ123");
        assert_eq!(msg.body, b"hi\r\n");
    }

    #[test]
    fn rejects_truncation() {
        let raw = b"Mid: X\r\nBody: 40\r\n\r\nshort";
        assert!(Message::parse(raw).unwrap_err().contains("truncated"));
    }

    #[test]
    fn addresses() {
        assert_eq!(normalize_address("sa0kam").unwrap(), "SA0KAM");
        assert_eq!(normalize_address("a@b.se").unwrap(), "SMTP:a@b.se");
        assert_eq!(normalize_address("smtp:a@b.se").unwrap(), "SMTP:a@b.se");
        assert_eq!(normalize_address("so5km@WINLINK.org").unwrap(), "SO5KM");
        assert!(normalize_address("not an address").is_err());
        assert!(normalize_address("x@").is_err());
        assert_eq!(display_address("SMTP:a@b.se"), "a@b.se");
    }

    #[test]
    fn mids_are_valid() {
        let a = generate_mid("SA0KAM", 1, 2);
        let b = generate_mid("SA0KAM", 1, 3);
        assert_eq!(a.len(), 12);
        assert_ne!(a, b);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
        );
    }

    #[test]
    fn validation_errors() {
        let mut d = draft();
        d.to.clear();
        d.cc.clear();
        assert!(Message::compose(d).is_err());
        let mut d = draft();
        d.subject = "x".repeat(200);
        assert!(Message::compose(d).unwrap_err().contains("subject"));
        let mut d = draft();
        d.body = String::new();
        assert_eq!(Message::compose(d).unwrap().0.body, b"\r\n");
    }
}
