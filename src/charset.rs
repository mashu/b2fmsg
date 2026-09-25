//! Text encodings used on the wire.
//!
//! Winlink programs send ISO-8859-1 bodies and RFC 2047 encoded headers.
//! Text that does not fit in Latin-1 (Polish letters, for example) is sent
//! as UTF-8 with the charset declared, which Pat and modern mail clients
//! decode; older Winlink programs may show it garbled.

use crate::base64;

pub const LATIN1: &str = "ISO-8859-1";
pub const UTF8: &str = "UTF-8";

/// Encodes text as ISO-8859-1 when possible, otherwise UTF-8.
pub fn encode_text(text: &str) -> (Vec<u8>, &'static str) {
    if text.chars().all(|c| (c as u32) < 0x100) {
        (text.chars().map(|c| c as u8).collect(), LATIN1)
    } else {
        (text.as_bytes().to_vec(), UTF8)
    }
}

/// Decodes bytes in the given charset (unknown charsets fall back to UTF-8
/// when valid, else Latin-1).
pub fn decode_text(bytes: &[u8], charset: &str) -> String {
    let cs = charset.trim().to_ascii_lowercase();
    if cs == "utf-8" || cs == "utf8" {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let latin = matches!(
        cs.as_str(),
        "iso-8859-1"
            | "iso8859-1"
            | "latin1"
            | "latin-1"
            | "us-ascii"
            | "ascii"
            | "windows-1252"
            | "cp1252"
    );
    if !latin {
        if let Ok(s) = std::str::from_utf8(bytes) {
            return s.to_owned();
        }
    }
    bytes.iter().map(|&b| b as char).collect()
}

/// Header value safe for the wire: ASCII as-is, anything else as one or more
/// RFC 2047 Q-encoded words.
pub fn encode_header(value: &str) -> String {
    if value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return value.to_owned();
    }
    let (bytes, charset) = encode_text(value);
    let prefix = format!("=?{charset}?Q?");
    let max_payload = 75 - prefix.len() - 2;
    let mut words = Vec::new();
    let mut word = String::new();
    // Split only between characters so multibyte UTF-8 stays in one word.
    let mut units: Vec<&[u8]> = Vec::new();
    if charset == UTF8 {
        let mut i = 0;
        for c in value.chars() {
            let n = c.len_utf8();
            units.push(&bytes[i..i + n]);
            i += n;
        }
    } else {
        units.extend(bytes.chunks(1));
    }
    for unit in units {
        let mut piece = String::new();
        for &b in unit {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'!' | b'*' | b'+' | b'-' | b'/' => {
                    piece.push(b as char)
                }
                b' ' => piece.push('_'),
                _ => piece.push_str(&format!("={b:02X}")),
            }
        }
        if word.len() + piece.len() > max_payload {
            words.push(format!("{prefix}{word}?="));
            word.clear();
        }
        word.push_str(&piece);
    }
    if !word.is_empty() {
        words.push(format!("{prefix}{word}?="));
    }
    words.join(" ")
}

/// Decodes RFC 2047 encoded words (Q or B) anywhere in a header value.
/// Whitespace between two adjacent encoded words is dropped.
pub fn decode_header(value: &str) -> String {
    let mut out = String::new();
    let mut rest = value;
    let mut last_was_word = false;
    while let Some(start) = rest.find("=?") {
        let (before, after) = rest.split_at(start);
        match decode_word(after) {
            Some((text, used)) => {
                if !(last_was_word && before.trim().is_empty()) {
                    out.push_str(before);
                }
                out.push_str(&text);
                rest = &after[used..];
                last_was_word = true;
            }
            None => {
                out.push_str(before);
                out.push_str("=?");
                rest = &after[2..];
                last_was_word = false;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Parses one `=?charset?enc?text?=` at the start of `s`.
fn decode_word(s: &str) -> Option<(String, usize)> {
    let body = s.strip_prefix("=?")?;
    let q1 = body.find('?')?;
    let charset = &body[..q1];
    let rest = &body[q1 + 1..];
    let q2 = rest.find('?')?;
    let encoding = &rest[..q2];
    let text_and_more = &rest[q2 + 1..];
    let end = text_and_more.find("?=")?;
    let text = &text_and_more[..end];
    let bytes = match encoding {
        "Q" | "q" => {
            let mut out = Vec::new();
            let raw = text.as_bytes();
            let mut i = 0;
            while i < raw.len() {
                match raw[i] {
                    b'_' => out.push(b' '),
                    b'=' if i + 2 < raw.len() => {
                        let hex = std::str::from_utf8(&raw[i + 1..i + 3]).ok()?;
                        out.push(u8::from_str_radix(hex, 16).ok()?);
                        i += 2;
                    }
                    b => out.push(b),
                }
                i += 1;
            }
            out
        }
        "B" | "b" => base64::decode(text).ok()?,
        _ => return None,
    };
    let charset = charset.split('*').next().unwrap_or(charset);
    let used = 2 + q1 + 1 + q2 + 1 + end + 2;
    Some((decode_text(&bytes, charset), used))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin1_or_utf8() {
        assert_eq!(encode_text("Hej då").1, LATIN1);
        assert_eq!(encode_text("Cześć").1, UTF8);
        let (bytes, cs) = encode_text("Hej då");
        assert_eq!(decode_text(&bytes, cs), "Hej då");
    }

    #[test]
    fn header_roundtrip() {
        for s in [
            "plain ascii subject",
            "Grüße aus Stockholm",
            "Zażółć gęślą jaźń",
            "a_b=c?d",
            &"ł".repeat(60),
        ] {
            let enc = encode_header(s);
            assert!(enc.is_ascii(), "{enc}");
            assert_eq!(decode_header(&enc), s, "{enc}");
        }
        assert_eq!(encode_header("plain"), "plain");
    }

    #[test]
    fn decodes_foreign_words() {
        assert_eq!(decode_header("=?utf-8?B?SGVqIGTDpQ==?="), "Hej då");
        assert_eq!(
            decode_header("Re: =?ISO-8859-1?Q?caf=E9?= ok"),
            "Re: café ok"
        );
        assert_eq!(decode_header("=?x?Q?broken"), "=?x?Q?broken");
    }
}
