//! KrevoHash and compact targets (mirrors src/consensus/pow.js).
//!   h1 = BLAKE2b("KRV/KrevoHash/1" ‖ prePow ‖ timestamp ‖ nonce)
//!   p_i = (Σ_j M[i][j]·v_j) >> 10 with the 64×64 matrix generated from prePow
//!   h2 = BLAKE2b("KRV/KrevoHash/2" ‖ h1 XOR p)   — valid if h2 (LE) ≤ target

use crate::block::Header;
use crate::hash::blake2b512;
use num_bigint::BigUint;
use num_traits::{One, Zero};

pub fn compact_to_target(bits: u32) -> Result<BigUint, String> {
    if bits & 0x0080_0000 != 0 { return Err("negative target".into()); }
    let exp = bits >> 24;
    let mant = BigUint::from(bits & 0x007f_ffff);
    Ok(if exp <= 3 { mant >> (8 * (3 - exp)) } else { mant << (8 * (exp - 3)) })
}

pub fn target_to_compact(t: &BigUint) -> u32 {
    if t.is_zero() { return 0; }
    let mut size = t.to_bytes_be().len() as u32;
    let mut mant: u32 = if size <= 3 {
        let v: BigUint = t << (8 * (3 - size));
        v.iter_u32_digits().next().unwrap_or(0)
    } else {
        let v: BigUint = t >> (8 * (size - 3));
        v.iter_u32_digits().next().unwrap_or(0)
    };
    if mant & 0x0080_0000 != 0 { mant >>= 8; size += 1; }
    (size << 24) | mant
}

pub fn calc_work(bits: u32) -> BigUint {
    let t = compact_to_target(bits).unwrap_or_else(|_| BigUint::zero());
    (BigUint::one() << 256usize) / (t + 1u32)
}

struct Xoshiro([u64; 4]);
impl Xoshiro {
    fn next(&mut self) -> u64 {
        let s = &mut self.0;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
        s[2] ^= t; s[3] = s[3].rotate_left(45);
        result
    }
}

fn rank_mod_prime(mat: &[u8; 4096]) -> usize {
    const P: i64 = 65521;
    let mut a = [[0i64; 64]; 64];
    for i in 0..64 { for j in 0..64 { a[i][j] = mat[i * 64 + j] as i64; } }
    let mut rank = 0usize;
    for col in 0..64 {
        if rank >= 64 { break; }
        let mut piv = None;
        for r in rank..64 { if a[r][col] % P != 0 { piv = Some(r); break; } }
        let Some(piv) = piv else { continue };
        a.swap(rank, piv);
        let (mut inv, mut b, mut e) = (1i64, a[rank][col] % P, P - 2);
        while e > 0 { if e & 1 == 1 { inv = inv * b % P; } b = b * b % P; e >>= 1; }
        for r in 0..64 {
            if r == rank || a[r][col] == 0 { continue; }
            let f = a[r][col] * inv % P;
            for c in col..64 { a[r][c] = ((a[r][c] - f * a[rank][c]) % P + P) % P; }
        }
        rank += 1;
    }
    rank
}

pub fn generate_matrix(pre_pow: &[u8; 32]) -> Box<[u8; 4096]> {
    let mut s = [0u64; 4];
    for i in 0..4 { s[i] = u64::from_le_bytes(pre_pow[8 * i..8 * i + 8].try_into().unwrap()); }
    let mut rng = Xoshiro(s);
    loop {
        let mut m = Box::new([0u8; 4096]);
        for i in (0..4096).step_by(16) {
            let mut v = rng.next();
            for j in 0..16 { m[i + j] = (v & 15) as u8; v >>= 4; }
        }
        if rank_mod_prime(&m) == 64 { return m; }
    }
}

pub struct PowState { pre_pow: [u8; 32], matrix: Box<[u8; 4096]> }

impl PowState {
    pub fn new(pre_pow: [u8; 32]) -> Self { PowState { matrix: generate_matrix(&pre_pow), pre_pow } }
    pub fn hash(&self, timestamp: u64, nonce: u64) -> [u8; 32] {
        let h1 = blake2b512(&[b"KRV/KrevoHash/1", &self.pre_pow, &timestamp.to_le_bytes(), &nonce.to_le_bytes()]);
        let mut v = [0u32; 64];
        for i in 0..32 { v[2 * i] = (h1[i] >> 4) as u32; v[2 * i + 1] = (h1[i] & 15) as u32; }
        let m = &self.matrix;
        let mut mix = [0u8; 32];
        for i in 0..32 {
            let (r0, r1) = (128 * i, 128 * i + 64);
            let (mut s0, mut s1) = (0u32, 0u32);
            for j in 0..64 { s0 += m[r0 + j] as u32 * v[j]; s1 += m[r1 + j] as u32 * v[j]; }
            mix[i] = h1[i] ^ (((((s0 >> 10) & 15) << 4) | ((s1 >> 10) & 15)) as u8);
        }
        blake2b512(&[b"KRV/KrevoHash/2", &mix])[..32].try_into().unwrap()
    }
}

pub fn target_to_le(t: &BigUint) -> [u8; 32] {
    let mut b = [0u8; 32];
    let le = t.to_bytes_le();
    let n = le.len().min(32);
    b[..n].copy_from_slice(&le[..n]);
    b
}

pub fn hash_meets_target(hash: &[u8; 32], target_le: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if hash[i] < target_le[i] { return true; }
        if hash[i] > target_le[i] { return false; }
    }
    true
}

pub fn check_pow(h: &Header) -> bool {
    let Ok(t) = compact_to_target(h.bits) else { return false };
    let st = PowState::new(h.pre_pow_hash());
    hash_meets_target(&st.hash(h.timestamp, h.nonce), &target_to_le(&t))
}
