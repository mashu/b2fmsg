//! Standard base64 (RFC 4648) for the browser bridge and RFC 2047 words.

const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Decodes base64, ignoring whitespace; padding is optional.
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in text.as_bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return Err(format!("invalid base64 character {:?}", c as char)),
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            assert_eq!(decode(&encode(s.as_bytes())).unwrap(), s.as_bytes());
        }
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(decode("Zm8").unwrap(), b"fo");
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode("Zm9v*").is_err());
    }
}
