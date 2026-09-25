//! AGWPE TCP protocol, as served by Direwolf (default port 8000).
//!
//! Every frame is a 36-byte header plus data. Direwolf runs the AX.25
//! connected-mode state machine (SABM, I-frames, retries); we only ask it to
//! connect, pass data, and disconnect.

pub const HEADER_LEN: usize = 36;
/// No-layer-3 protocol identifier used for connected-mode data.
pub const PID_NO_L3: u8 = 0xF0;
const MAX_DATA: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub port: u8,
    pub kind: u8,
    pub pid: u8,
    pub call_from: String,
    pub call_to: String,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn new(kind: u8, port: u8, call_from: &str, call_to: &str, data: Vec<u8>) -> Frame {
        Frame {
            port,
            kind,
            pid: if kind == b'D' || kind == b'C' || kind == b'v' {
                PID_NO_L3
            } else {
                0
            },
            call_from: call_from.to_owned(),
            call_to: call_to.to_owned(),
            data,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; HEADER_LEN];
        out[0] = self.port;
        out[4] = self.kind;
        out[6] = self.pid;
        put_call(&mut out[8..18], &self.call_from);
        put_call(&mut out[18..28], &self.call_to);
        out[28..32].copy_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

fn put_call(dst: &mut [u8], call: &str) {
    let bytes = call.as_bytes();
    let n = bytes.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&bytes[..n]);
}

fn get_call(src: &[u8]) -> String {
    let end = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    String::from_utf8_lossy(&src[..end]).trim().to_owned()
}

/// Splits a TCP byte stream into frames.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Frame>, String> {
        self.buf.extend_from_slice(data);
        let mut frames = Vec::new();
        while self.buf.len() >= HEADER_LEN {
            let len = u32::from_le_bytes([self.buf[28], self.buf[29], self.buf[30], self.buf[31]])
                as usize;
            if len > MAX_DATA {
                self.buf.clear();
                return Err(format!(
                    "AGW frame claims {len} bytes of data; is this really an AGW port?"
                ));
            }
            if self.buf.len() < HEADER_LEN + len {
                break;
            }
            let frame = Frame {
                port: self.buf[0],
                kind: self.buf[4],
                pid: self.buf[6],
                call_from: get_call(&self.buf[8..18]),
                call_to: get_call(&self.buf[18..28]),
                data: self.buf[HEADER_LEN..HEADER_LEN + len].to_vec(),
            };
            self.buf.drain(..HEADER_LEN + len);
            frames.push(frame);
        }
        Ok(frames)
    }
}

/// Registers our callsign (lets Direwolf route incoming frames to us).
pub fn register(port: u8, call: &str) -> Vec<u8> {
    Frame::new(b'X', port, call, "", Vec::new()).encode()
}

/// Opens a connection, optionally through digipeaters.
pub fn connect(port: u8, mycall: &str, target: &str, via: &[String]) -> Vec<u8> {
    if via.is_empty() {
        return Frame::new(b'C', port, mycall, target, Vec::new()).encode();
    }
    let mut data = vec![via.len().min(7) as u8];
    for digi in via.iter().take(7) {
        let mut field = [0u8; 10];
        put_call(&mut field, digi);
        data.extend_from_slice(&field);
    }
    Frame::new(b'v', port, mycall, target, data).encode()
}

/// Connected-mode data, split so each frame fits in one I-frame.
pub fn data(port: u8, mycall: &str, target: &str, bytes: &[u8], paclen: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(paclen.max(1)) {
        out.extend(Frame::new(b'D', port, mycall, target, chunk.to_vec()).encode());
    }
    out
}

pub fn disconnect(port: u8, mycall: &str, target: &str) -> Vec<u8> {
    Frame::new(b'd', port, mycall, target, Vec::new()).encode()
}

/// Asks how many frames are still waiting to be sent or acknowledged.
pub fn outstanding_query(port: u8, mycall: &str, target: &str) -> Vec<u8> {
    Frame::new(b'Y', port, mycall, target, Vec::new()).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_frames() {
        let mut bytes = connect(0, "SA0KAM", "SK0XYZ-10", &[]);
        bytes.extend(data(1, "SA0KAM", "SK0XYZ-10", &[7u8; 300], 128));
        let mut dec = Decoder::default();
        // Arrives in awkward pieces.
        let mut frames = Vec::new();
        for piece in bytes.chunks(17) {
            frames.extend(dec.push(piece).unwrap());
        }
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0].kind, b'C');
        assert_eq!(frames[0].call_from, "SA0KAM");
        assert_eq!(frames[0].call_to, "SK0XYZ-10");
        assert_eq!(frames[0].pid, PID_NO_L3);
        assert_eq!(frames[1].port, 1);
        assert_eq!(frames[1].data.len(), 128);
        assert_eq!(frames[3].data.len(), 44);
    }

    #[test]
    fn header_layout() {
        let f = disconnect(2, "N0CALL", "N1CALL-5");
        assert_eq!(f.len(), HEADER_LEN);
        assert_eq!(f[0], 2);
        assert_eq!(f[4], b'd');
        assert_eq!(&f[8..14], b"N0CALL");
        assert_eq!(f[14], 0);
        assert_eq!(&f[18..26], b"N1CALL-5");
    }

    #[test]
    fn via_digipeaters() {
        let f = connect(
            0,
            "SA0KAM",
            "SK0XYZ-10",
            &["SK0DIG".into(), "WIDE2-1".into()],
        );
        let frame = Decoder::default().push(&f).unwrap().remove(0);
        assert_eq!(frame.kind, b'v');
        assert_eq!(frame.data[0], 2);
        assert_eq!(&frame.data[1..7], b"SK0DIG");
        assert_eq!(&frame.data[11..18], b"WIDE2-1");
    }

    #[test]
    fn rejects_non_agw_streams() {
        let mut junk = vec![0u8; HEADER_LEN];
        junk[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Decoder::default().push(&junk).is_err());
    }
}
