//! Hash with domain separation (same as src/crypto/hash.js):
//! H64(domain, parts…) = BLAKE2b-512("KRV" ‖ len(domain) ‖ domain ‖ Σ u32le(len(part)) ‖ part)
//! H = the first 32 bytes.
//! Encoding of the parts in JavaScript: Buffer → bytes; string → UTF-8; number → u64 LE;
//! bigint → 32 bytes big-endian; point → 33 compressed bytes.

use blake2::{Blake2b512, Digest};
use sha3::digest::{ExtendableOutput, Update, XofReader};

#[derive(Clone)]
pub struct H(Blake2b512);

impl H {
    pub fn new(domain: &str) -> Self {
        let mut h = Blake2b512::new();
        Digest::update(&mut h, b"KRV");
        Digest::update(&mut h, [domain.len() as u8]);
        Digest::update(&mut h, domain.as_bytes());
        H(h)
    }
    /// Part as bytes.
    pub fn b(mut self, p: &[u8]) -> Self {
        Digest::update(&mut self.0, (p.len() as u32).to_le_bytes());
        Digest::update(&mut self.0, p);
        self
    }
    /// Text part (UTF-8).
    pub fn s(self, s: &str) -> Self { self.b(s.as_bytes()) }
    /// JavaScript "number" part (u64 little-endian).
    pub fn n(self, v: u64) -> Self { self.b(&v.to_le_bytes()) }
    pub fn d64(self) -> [u8; 64] { self.0.finalize().into() }
    pub fn d32(self) -> [u8; 32] { self.d64()[..32].try_into().unwrap() }
}

pub fn blake2b512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Blake2b512::new();
    for p in parts { Digest::update(&mut h, p); }
    h.finalize().into()
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Sha256;
    let mut h = Sha256::new();
    Digest::update(&mut h, b);
    h.finalize().into()
}

pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = sha3::Shake256::default();
    h.update(data);
    let mut r = h.finalize_xof();
    let mut out = vec![0u8; out_len];
    r.read(&mut out);
    out
}
