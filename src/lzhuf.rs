//! LZHUF compression in the FBB "B2" container used by Winlink.
//!
//! The stream is classic LZHUF (LZSS back-references coded with an adaptive
//! Huffman tree) with the FBB parameters: 2 KiB window, 60-byte lookahead.
//! The B2 container prepends a CRC-16/XMODEM (little-endian) computed over
//! everything that follows it, then the uncompressed length (u32 LE).
//!
//! Written from the algorithm description; the encoder uses hash chains with
//! one-step lazy matching instead of the original binary search tree, which
//! changes the choice of matches but not the bit format.

const N: usize = 2048;
const F: usize = 60;
const THRESHOLD: usize = 2;
const N_CHAR: usize = 256 - THRESHOLD + F;
const T: usize = N_CHAR * 2 - 1;
const R: usize = T - 1;
const MAX_FREQ: u32 = 0x8000;

/// Farthest back-reference we emit; stays inside the reference encoder's window.
const MAX_DISTANCE: usize = N - F;
const HASH_BITS: u32 = 15;
const CHAIN_DEPTH: usize = 192;
/// Refuse absurd length headers instead of allocating them.
pub const MAX_UNCOMPRESSED: usize = 64 * 1024 * 1024;

/// Code lengths for the upper 6 bits of a match position.
const P_LEN: [u8; 64] = p_len_table();
/// Left-aligned 8-bit codes for the upper 6 bits of a match position.
const P_CODE: [u8; 64] = p_code_table();
/// Decoding tables indexed by the next 8 bits of the stream.
const D_CODE: [u8; 256] = d_tables().0;
const D_LEN: [u8; 256] = d_tables().1;

const fn p_len_table() -> [u8; 64] {
    // (code length, how many positions use it): a canonical prefix code.
    const COUNTS: [(u8, usize); 6] = [(3, 1), (4, 3), (5, 8), (6, 12), (7, 24), (8, 16)];
    let mut table = [0u8; 64];
    let mut i = 0;
    let mut c = 0;
    while c < COUNTS.len() {
        let (len, count) = COUNTS[c];
        let mut k = 0;
        while k < count {
            table[i] = len;
            i += 1;
            k += 1;
        }
        c += 1;
    }
    table
}

const fn p_code_table() -> [u8; 64] {
    let lens = p_len_table();
    let mut table = [0u8; 64];
    let mut code: u32 = 0;
    let mut i = 0;
    while i < 64 {
        table[i] = code as u8;
        code += 1 << (8 - lens[i]);
        i += 1;
    }
    table
}

const fn d_tables() -> ([u8; 256], [u8; 256]) {
    let lens = p_len_table();
    let codes = p_code_table();
    let mut d_code = [0u8; 256];
    let mut d_len = [0u8; 256];
    let mut i = 0;
    while i < 64 {
        let span = 1usize << (8 - lens[i]);
        let mut k = 0;
        while k < span {
            d_code[codes[i] as usize + k] = i as u8;
            d_len[codes[i] as usize + k] = lens[i];
            k += 1;
        }
        i += 1;
    }
    (d_code, d_len)
}

const CRC_TABLE: [u16; 256] = crc_table();

const fn crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// CRC-16/XMODEM (poly 0x1021, init 0), as used by FBB B2 and Winlink.
pub fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(0u16, |crc, &b| {
        (crc << 8) ^ CRC_TABLE[usize::from((crc >> 8) as u8 ^ b)]
    })
}

/// Compresses `data` into the B2 container sent in B2F `FC` proposals.
pub fn encode_b2(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(data.len() / 2 + 8);
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&compress(data));
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&crc16(&body).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Verifies and decompresses a B2 container.
pub fn decode_b2(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 6 {
        return Err(format!(
            "compressed message too short ({} bytes)",
            data.len()
        ));
    }
    let stored = u16::from_le_bytes([data[0], data[1]]);
    let actual = crc16(&data[2..]);
    if stored != actual {
        return Err(format!(
            "compressed message CRC mismatch (header {stored:04X}, data {actual:04X})"
        ));
    }
    let size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
    if size > MAX_UNCOMPRESSED {
        return Err(format!(
            "message claims {size} bytes uncompressed; refusing"
        ));
    }
    decompress(&data[6..], size)
}

/// Adaptive Huffman tree shared (bit-for-bit) by encoder and decoder.
struct Tree {
    freq: [u32; T + 1],
    /// Parent of each node; entries `T..T+N_CHAR` locate the leaves.
    prnt: [usize; T + N_CHAR],
    /// Left child of each node, or `T + symbol` for leaves.
    son: [usize; T],
}

impl Tree {
    fn new() -> Box<Tree> {
        let mut t = Box::new(Tree {
            freq: [0; T + 1],
            prnt: [0; T + N_CHAR],
            son: [0; T],
        });
        for i in 0..N_CHAR {
            t.freq[i] = 1;
            t.son[i] = i + T;
            t.prnt[i + T] = i;
        }
        let (mut i, mut j) = (0, N_CHAR);
        while j <= R {
            t.freq[j] = t.freq[i] + t.freq[i + 1];
            t.son[j] = i;
            t.prnt[i] = j;
            t.prnt[i + 1] = j;
            i += 2;
            j += 1;
        }
        t.freq[T] = 0xffff;
        t.prnt[R] = 0;
        t
    }

    /// Halves all frequencies and rebuilds the tree.
    fn reconstruct(&mut self) {
        let mut j = 0;
        for i in 0..T {
            if self.son[i] >= T {
                self.freq[j] = self.freq[i].div_ceil(2);
                self.son[j] = self.son[i];
                j += 1;
            }
        }
        let (mut i, mut j) = (0, N_CHAR);
        while j < T {
            let f = self.freq[i] + self.freq[i + 1];
            self.freq[j] = f;
            let mut k = j;
            while f < self.freq[k - 1] {
                k -= 1;
            }
            self.freq.copy_within(k..j, k + 1);
            self.freq[k] = f;
            self.son.copy_within(k..j, k + 1);
            self.son[k] = i;
            i += 2;
            j += 1;
        }
        for i in 0..T {
            let k = self.son[i];
            self.prnt[k] = i;
            if k < T {
                self.prnt[k + 1] = i;
            }
        }
    }

    /// Counts one occurrence of `symbol`, swapping nodes to keep order.
    fn update(&mut self, symbol: usize) {
        if self.freq[R] == MAX_FREQ {
            self.reconstruct();
        }
        let mut c = self.prnt[symbol + T];
        loop {
            self.freq[c] += 1;
            let k = self.freq[c];
            let mut l = c + 1;
            if k > self.freq[l] {
                while k > self.freq[l + 1] {
                    l += 1;
                }
                self.freq[c] = self.freq[l];
                self.freq[l] = k;

                let i = self.son[c];
                self.prnt[i] = l;
                if i < T {
                    self.prnt[i + 1] = l;
                }
                let j = self.son[l];
                self.son[l] = i;
                self.prnt[j] = c;
                if j < T {
                    self.prnt[j + 1] = c;
                }
                self.son[c] = j;
                c = l;
            }
            c = self.prnt[c];
            if c == 0 {
                break;
            }
        }
    }
}

#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    bits: u32,
}

impl BitWriter {
    /// Appends the low `count` bits of `value`, most significant first.
    fn put(&mut self, count: u32, value: u64) {
        self.acc = (self.acc << count) | (value & ((1u64 << count) - 1));
        self.bits += count;
        while self.bits >= 8 {
            self.bits -= 8;
            self.out.push((self.acc >> self.bits) as u8);
        }
        self.acc &= (1u64 << self.bits) - 1;
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits > 0 {
            self.out.push((self.acc << (8 - self.bits)) as u8);
        }
        self.out
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u32,
    bits: u32,
    overrun: bool,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            acc: 0,
            bits: 0,
            overrun: false,
        }
    }

    fn get(&mut self, count: u32) -> u32 {
        while self.bits < count {
            let byte = match self.data.get(self.pos) {
                Some(&b) => b,
                None => {
                    self.overrun = true;
                    0
                }
            };
            self.pos += 1;
            self.acc = (self.acc << 8) | u32::from(byte);
            self.bits += 8;
        }
        self.bits -= count;
        let value = (self.acc >> self.bits) & ((1 << count) - 1);
        self.acc &= (1 << self.bits) - 1;
        value
    }
}

fn encode_symbol(tree: &mut Tree, bits: &mut BitWriter, symbol: usize) {
    // Walk leaf → root; odd node positions are the right-hand child.
    let mut code: u64 = 0;
    let mut len = 0u32;
    let mut k = tree.prnt[symbol + T];
    loop {
        code |= ((k & 1) as u64) << len;
        len += 1;
        k = tree.prnt[k];
        if k == R {
            break;
        }
    }
    bits.put(len, code);
    tree.update(symbol);
}

fn encode_position(bits: &mut BitWriter, position: usize) {
    let upper = position >> 6;
    let len = u32::from(P_LEN[upper]);
    bits.put(len, u64::from(P_CODE[upper]) >> (8 - len));
    bits.put(6, (position & 0x3f) as u64);
}

fn decode_symbol(tree: &mut Tree, bits: &mut BitReader) -> usize {
    let mut c = tree.son[R];
    while c < T {
        c = tree.son[c + bits.get(1) as usize];
    }
    let symbol = c - T;
    tree.update(symbol);
    symbol
}

fn decode_position(bits: &mut BitReader) -> usize {
    let mut i = bits.get(8) as usize;
    let upper = usize::from(D_CODE[i]) << 6;
    for _ in 2..D_LEN[i] {
        i = (i << 1) | bits.get(1) as usize;
    }
    upper | (i & 0x3f)
}

/// Hash chains over 3-byte prefixes for finding back-references.
struct Matcher<'a> {
    data: &'a [u8],
    head: Vec<i32>,
    prev: Vec<i32>,
    inserted: usize,
}

impl<'a> Matcher<'a> {
    fn new(data: &'a [u8]) -> Self {
        Matcher {
            data,
            head: vec![-1; 1 << HASH_BITS],
            prev: vec![-1; data.len()],
            inserted: 0,
        }
    }

    fn hash(&self, pos: usize) -> usize {
        let d = self.data;
        ((usize::from(d[pos]) << 10) ^ (usize::from(d[pos + 1]) << 5) ^ usize::from(d[pos + 2]))
            & ((1 << HASH_BITS) - 1)
    }

    /// Adds every position before `upto` to the chains.
    fn insert_until(&mut self, upto: usize) {
        while self.inserted < upto {
            let pos = self.inserted;
            if pos + 2 < self.data.len() {
                let h = self.hash(pos);
                self.prev[pos] = self.head[h];
                self.head[h] = pos as i32;
            }
            self.inserted += 1;
        }
    }

    /// Longest earlier match for `pos` as (length, distance).
    fn find(&mut self, pos: usize) -> (usize, usize) {
        self.insert_until(pos);
        let data = self.data;
        let max_len = F.min(data.len() - pos);
        if max_len <= THRESHOLD {
            return (0, 0);
        }
        let (mut best_len, mut best_dist) = (0, 0);
        let mut candidate = self.head[self.hash(pos)];
        let mut depth = 0;
        while candidate >= 0 && depth < CHAIN_DEPTH {
            let cand = candidate as usize;
            let dist = pos - cand;
            if dist > MAX_DISTANCE {
                break;
            }
            if data[cand + best_len] == data[pos + best_len] {
                let len = data[cand..]
                    .iter()
                    .zip(&data[pos..pos + max_len])
                    .take_while(|(a, b)| a == b)
                    .count();
                if len > best_len {
                    best_len = len;
                    best_dist = dist;
                    if len == max_len {
                        break;
                    }
                }
            }
            candidate = self.prev[cand];
            depth += 1;
        }
        (best_len, best_dist)
    }
}

/// Raw LZHUF stream (no container).
pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut tree = Tree::new();
    let mut bits = BitWriter::default();
    let mut matcher = Matcher::new(data);
    let mut pos = 0;
    while pos < data.len() {
        let (len, dist) = matcher.find(pos);
        if len > THRESHOLD {
            // Lazy matching: a literal now can buy a longer match next.
            if len < F && pos + 1 < data.len() {
                let (next_len, _) = matcher.find(pos + 1);
                if next_len > len {
                    encode_symbol(&mut tree, &mut bits, usize::from(data[pos]));
                    pos += 1;
                    continue;
                }
            }
            encode_symbol(&mut tree, &mut bits, 255 - THRESHOLD + len);
            encode_position(&mut bits, dist - 1);
            pos += len;
        } else {
            encode_symbol(&mut tree, &mut bits, usize::from(data[pos]));
            pos += 1;
        }
    }
    bits.finish()
}

/// Decodes `size` bytes from a raw LZHUF stream.
pub fn decompress(stream: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let mut tree = Tree::new();
    let mut bits = BitReader::new(stream);
    let mut ring = [0u8; N];
    ring[..N - F].fill(b' ');
    let mut r = N - F;
    let mut out = Vec::with_capacity(size);

    while out.len() < size {
        let symbol = decode_symbol(&mut tree, &mut bits);
        if symbol < 256 {
            let byte = symbol as u8;
            out.push(byte);
            ring[r] = byte;
            r = (r + 1) & (N - 1);
        } else {
            let start = r.wrapping_sub(decode_position(&mut bits) + 1) & (N - 1);
            let len = symbol - 255 + THRESHOLD;
            if out.len() + len > size {
                return Err("compressed data runs past the declared length".into());
            }
            for k in 0..len {
                let byte = ring[(start + k) & (N - 1)];
                out.push(byte);
                ring[r] = byte;
                r = (r + 1) & (N - 1);
            }
        }
        if bits.overrun {
            return Err("compressed data ends early".into());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8]) {
        let packed = encode_b2(data);
        assert_eq!(decode_b2(&packed).unwrap(), data);
    }

    #[test]
    fn position_tables_match_lzhuf() {
        // Spot checks against the published LZHUF tables.
        assert_eq!(
            &P_CODE[..8],
            &[0x00, 0x20, 0x30, 0x40, 0x50, 0x58, 0x60, 0x68]
        );
        assert_eq!(
            &P_CODE[56..],
            &[0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF]
        );
        assert_eq!(P_LEN[0], 3);
        assert_eq!(P_LEN[63], 8);
        assert_eq!(D_CODE[0x30], 2);
        assert_eq!(D_LEN[0x30], 4);
        assert_eq!(D_CODE[0xC0], 0x18);
        assert_eq!(D_CODE[0xFF], 0x3F);
    }

    #[test]
    fn crc_xmodem_check_value() {
        assert_eq!(crc16(b"123456789"), 0x31C3);
    }

    #[test]
    fn empty_is_six_bytes() {
        let packed = encode_b2(b"");
        assert_eq!(packed.len(), 6);
        assert_eq!(decode_b2(&packed).unwrap(), b"");
    }

    #[test]
    fn roundtrips() {
        roundtrip(b"a");
        roundtrip(b"abc");
        roundtrip(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        roundtrip(b"Hello, Winlink! Hello, Winlink! Hello, Winlink!\r\n");
        let text: Vec<u8> = (0..20_000)
            .map(|i| b"the quick brown fox jumps over the lazy dog "[i % 44])
            .collect();
        roundtrip(&text);
        let mut noise = Vec::with_capacity(70_000);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..70_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            noise.push((x >> 24) as u8);
        }
        roundtrip(&noise);
        // Long runs force frequent tree reconstruction.
        roundtrip(&vec![0u8; 200_000]);
    }

    #[test]
    fn compresses_text() {
        let text = b"CQ CQ CQ de SA0KAM SA0KAM SA0KAM pse k. ".repeat(50);
        let packed = encode_b2(&text);
        assert!(
            packed.len() * 4 < text.len(),
            "{} vs {}",
            packed.len(),
            text.len()
        );
    }

    #[test]
    fn detects_corruption() {
        let mut packed = encode_b2(b"Some message body that is long enough to matter.");
        let last = packed.len() - 1;
        packed[last] ^= 0x55;
        assert!(decode_b2(&packed).unwrap_err().contains("CRC"));
        assert!(decode_b2(&[1, 2, 3]).is_err());
    }

    #[test]
    fn detects_truncation() {
        let text = b"truncate me please, truncate me please, 0123456789".repeat(20);
        let raw = compress(&text);
        assert!(decompress(&raw[..raw.len() / 2], text.len()).is_err());
    }
}
