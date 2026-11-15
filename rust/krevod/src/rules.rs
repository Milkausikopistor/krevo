//! Auxiliary consensus rules: emission, mass, spending policies (multisig,
//! inheritance, hash locks), quantum-safe address, names and address data.
//! Mirrors emission.js, mass.js, policy.js, pqlock.js, names.js and address.js.

use crate::bytes::Reader;
use crate::crypto::{mldsa_verify, schnorr_verify, MLDSA_PUB_SIZE, MLDSA_SIG_SIZE};
use crate::curve::P1;
use crate::hash::{sha256, H};
use crate::params::{Params, MAX_SUPPLY};
use crate::tx::Transaction;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
use std::sync::OnceLock;

// ======================================================================== emission
fn iroot(x: &BigUint, k: u32) -> BigUint {
    if *x < BigUint::from(2u32) { return x.clone(); }
    let kb = BigUint::from(k);
    let bits = x.bits();
    let mut r = BigUint::one() << (bits as usize).div_ceil(k as usize);
    loop {
        let s = ((&kb - 1u32) * &r + x / r.pow(k - 1)) / &kb;
        if s >= r { break; }
        r = s;
    }
    while r.pow(k) > *x { r -= 1u32; }
    while (&r + 1u32).pow(k) <= *x { r += 1u32; }
    r
}

fn factor_table(steps: u64) -> &'static Vec<u128> {
    static T: OnceLock<Vec<u128>> = OnceLock::new();
    assert_eq!(steps, 48, "emission table only for 48 steps");
    T.get_or_init(|| (0..steps).map(|j| {
        let x = BigUint::one() << ((64 * steps - j) as usize);
        iroot(&x, steps as u32).to_u128().unwrap()
    }).collect())
}

pub fn blocks_per_month(p: &Params) -> u64 { p.bps * p.seconds_per_month }

pub fn subsidy_for_month(month: u64, p: &Params) -> u64 {
    let steps = p.reductions_per_halving;
    let halvings = month / steps;
    if halvings >= 64 { return 0; }
    let r0 = (p.reward_per_second0 / p.bps) as u128;
    let f = factor_table(steps)[(month % steps) as usize];
    let shift = 64 + halvings as u32;
    let prod = BigUint::from(r0) * BigUint::from(f);
    (prod >> shift as usize).to_u64().unwrap()
}

pub fn capped_subsidy(daa: u64, minted: u64, p: &Params) -> u64 {
    let s = subsidy_for_month(daa / blocks_per_month(p), p);
    let room = MAX_SUPPLY.saturating_sub(minted);
    s.min(room)
}

// ======================================================================== policies
pub const LOCK_MULTISIG: u8 = 0x03;
pub const LOCK_PQ: u8 = 0x04;
pub const LOCK_NAME: u8 = 0x05;
pub const LOCK_NAME_COMMIT: u8 = 0x06;
pub const COMMIT_WITNESS: u8 = 0xc1;
pub const PQ_WITNESS_VERSION: u8 = 0xf1;
pub const PQ_WITNESS_SIZE: usize = 1 + 33 + MLDSA_PUB_SIZE + 64 + MLDSA_SIG_SIZE;
const MAX_POLICY_KEYS: u8 = 15;
const MAX_PATHS: u8 = 4;
const MAX_DELAY: u64 = 1 << 40;

pub struct PolicyPath { pub m: u8, pub n: u8, pub keys: Vec<P1>, pub delay: u64, pub hash: Option<[u8; 32]> }
pub struct Policy { pub version: u8, pub paths: Vec<PolicyPath>, pub len: usize }

fn read_keys(buf: &[u8], o: usize, n: usize) -> Option<Vec<P1>> {
    if buf.len() < o + 33 * n { return None; }
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let k = &buf[o + 33 * i..o + 33 * (i + 1)];
        if i > 0 && buf[o + 33 * (i - 1)..o + 33 * i] >= *k { return None; }
        keys.push(P1::from_bytes(k)?);
    }
    Some(keys)
}

pub fn parse_policy(buf: &[u8]) -> Option<Policy> {
    let ver = *buf.first()?;
    let mut paths = vec![];
    let o;
    if ver == 0x01 {
        let (m, n) = (*buf.get(1)?, *buf.get(2)?);
        if m < 1 || m > n || n > MAX_POLICY_KEYS { return None; }
        paths.push(PolicyPath { m, n, keys: read_keys(buf, 3, n as usize)?, delay: 0, hash: None });
        o = 3 + 33 * n as usize;
    } else if ver == 0x02 || ver == 0x03 {
        let c = *buf.get(1)?;
        if c == 0 || c > MAX_PATHS { return None; }
        let mut p = 2usize;
        for _ in 0..c {
            if buf.len() < p + 10 { return None; }
            let (m, n) = (buf[p], buf[p + 1]);
            let delay = u64::from_le_bytes(buf[p + 2..p + 10].try_into().unwrap());
            if m < 1 || m > n || n > MAX_POLICY_KEYS || delay > MAX_DELAY { return None; }
            p += 10;
            let mut hash = None;
            if ver == 0x03 {
                let flag = *buf.get(p)?;
                p += 1;
                if flag > 1 { return None; }
                if flag == 1 {
                    if buf.len() < p + 32 { return None; }
                    hash = Some(buf[p..p + 32].try_into().unwrap());
                    p += 32;
                }
            }
            paths.push(PolicyPath { m, n, keys: read_keys(buf, p, n as usize)?, delay, hash });
            p += 33 * n as usize;
        }
        if ver == 0x03 && !paths.iter().any(|x| x.hash.is_some()) { return None; }
        o = p;
    } else { return None; }
    Some(Policy { version: ver, paths, len: o })
}

pub fn policy_hash(bytes: &[u8]) -> [u8; 32] { H::new("lock/multisig").b(bytes).d32() }

pub struct WitnessPath { pub pol: Policy, pub path: usize, pub secret: Option<[u8; 32]>, pub o: usize }

pub fn parse_witness_path(w: &[u8]) -> Option<WitnessPath> {
    let pol = parse_policy(w)?;
    let mut o = pol.len;
    let path = if pol.version == 0x02 || pol.version == 0x03 { let p = *w.get(o)? as usize; o += 1; p } else { 0 };
    let p = pol.paths.get(path)?;
    let mut secret = None;
    if p.hash.is_some() {
        if w.len() < o + 32 { return None; }
        secret = Some(w[o..o + 32].try_into().unwrap());
        o += 32;
    }
    Some(WitnessPath { pol, path, secret, o })
}

pub fn witness_delay(w: &[u8]) -> Option<u64> { parse_witness_path(w).map(|x| x.pol.paths[x.path].delay) }

pub fn verify_multisig_witness(lock: &[u8], w: &[u8], msg: &[u8]) -> bool {
    if lock.len() != 33 || lock[0] != LOCK_MULTISIG { return false; }
    let Some(wp) = parse_witness_path(w) else { return false };
    if policy_hash(&w[..wp.pol.len]) != lock[1..] { return false; }
    let p = &wp.pol.paths[wp.path];
    if let Some(h) = p.hash { if sha256(&wp.secret.unwrap()) != h { return false; } }
    let mut o = wp.o;
    if w.get(o) != Some(&p.m) { return false; }
    o += 1;
    if w.len() != o + p.m as usize * 65 { return false; }
    let mut last: i32 = -1;
    for _ in 0..p.m {
        let idx = w[o] as i32;
        if idx <= last || idx >= p.n as i32 { return false; }
        last = idx;
        if !schnorr_verify(&p.keys[idx as usize], msg, &w[o + 1..o + 65], "sig") { return false; }
        o += 65;
    }
    true
}

pub fn is_pq_witness(w: &[u8]) -> bool { w.len() == PQ_WITNESS_SIZE && w[0] == PQ_WITNESS_VERSION }

pub fn verify_pq_witness(lock: &[u8], w: &[u8], msg: &[u8]) -> bool {
    if lock.len() != 33 || lock[0] != LOCK_PQ || !is_pq_witness(w) { return false; }
    let s_pub = &w[1..34];
    let q_pub = &w[34..34 + MLDSA_PUB_SIZE];
    let s_sig = &w[34 + MLDSA_PUB_SIZE..34 + MLDSA_PUB_SIZE + 64];
    let q_sig = &w[34 + MLDSA_PUB_SIZE + 64..];
    if H::new("lock/pq").b(s_pub).b(q_pub).d32() != lock[1..] { return false; }
    let Some(p) = P1::from_bytes(s_pub) else { return false };
    schnorr_verify(&p, msg, s_sig, "sig") && mldsa_verify(q_pub, msg, q_sig)
}

// ======================================================================== names
pub fn is_valid_name(n: &[u8]) -> bool {
    if n.len() < 3 || n.len() > 32 { return false; }
    let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !ok(n[0]) || !ok(n[n.len() - 1]) { return false; }
    if !n.iter().all(|&c| ok(c) || c == b'-') { return false; }
    !n.windows(2).any(|w| w == b"--")
}

pub fn name_fee(p: &Params, name: &str) -> u64 {
    let f = &p.name_fees;
    match name.len() { 0..=3 => f[0], 4 => f[1], 5 => f[2], _ => f[3] }
}

pub struct NameRecord { pub name: String, pub expiry: u64, pub owner: Vec<u8>, pub target: Vec<u8> }

pub fn parse_name_record(lock: &[u8]) -> Option<NameRecord> {
    if lock.first() != Some(&LOCK_NAME) { return None; }
    let mut r = Reader::new(lock);
    r.u8().ok()?;
    let n = r.u8().ok()? as usize;
    let name = r.bytes(n).ok()?;
    if !is_valid_name(name) { return None; }
    let expiry = r.u64().ok()?;
    let ol = r.u8().ok()? as usize;
    let owner = r.bytes(ol).ok()?.to_vec();
    let target = r.bytes(r.remaining()).ok()?.to_vec();
    if owner.is_empty() || target.is_empty() { return None; }
    Some(NameRecord { name: String::from_utf8(name.to_vec()).ok()?, expiry, owner, target })
}

pub fn name_of_lock(lock: &[u8]) -> Option<String> {
    if lock.first() != Some(&LOCK_NAME) || lock.len() < 2 || lock.len() < 2 + lock[1] as usize { return None; }
    Some(lock[2..2 + lock[1] as usize].iter().map(|&c| (c & 0x7f) as char).collect())
}

pub fn name_commit_hash(name: &str, salt: &[u8], owner: &[u8]) -> [u8; 32] {
    H::new("name/commit").s(name).b(salt).b(owner).d32()
}

pub struct CommitWitness { pub name: String, pub salt: Vec<u8>, pub owner: Vec<u8>, pub inner: Vec<u8> }

pub fn parse_commit_witness(w: &[u8]) -> Option<CommitWitness> {
    if w.first() != Some(&COMMIT_WITNESS) { return None; }
    let mut r = Reader::new(w);
    r.u8().ok()?;
    let n = r.u8().ok()? as usize;
    let name = r.bytes(n).ok()?;
    if !is_valid_name(name) { return None; }
    let salt = r.bytes(32).ok()?.to_vec();
    let ol = r.u8().ok()? as usize;
    let owner = r.bytes(ol).ok()?.to_vec();
    let inner = r.bytes(r.remaining()).ok()?.to_vec();
    Some(CommitWitness { name: String::from_utf8(name.to_vec()).ok()?, salt, owner, inner })
}

// ======================================================================== mass
fn sig_count(w: &[u8]) -> u64 {
    if w.len() == 64 { return 1; }
    if is_pq_witness(w) { return 2; }
    if w.first() == Some(&COMMIT_WITNESS) {
        if let Some(c) = parse_commit_witness(w) { return sig_count(&c.inner); }
    }
    match parse_witness_path(w) {
        Some(p) => p.pol.paths[p.path].m as u64,
        None => ((w.len() / 65) as u64).max(1),
    }
}

pub fn compute_mass(tx: &Transaction, p: &Params) -> u64 {
    let mut m = tx.size() as u64 * p.mass_per_byte;
    for i in &tx.t_in { m += sig_count(&i.sig) * p.mass_per_sig; }
    for s in &tx.s_in { m += if s.ring.is_empty() { p.mass_per_fcmp_input } else { s.ring.len() as u64 * p.mass_per_ring_member }; }
    m + tx.s_out.len() as u64 * p.mass_per_shielded_output
}

pub fn storage_mass(tx: &Transaction, input_amounts: &[u64], p: &Params) -> u64 {
    const MAX_SAFE: u64 = (1 << 53) - 1;
    let c = p.storage_mass_c as u128;
    let mut harmonic: u128 = 0;
    for o in &tx.t_out {
        if o.amount == 0 { return MAX_SAFE; }
        harmonic += c / o.amount as u128;
    }
    let sum_in: u128 = input_amounts.iter().map(|&a| a as u128).sum();
    let mut arith: u128 = 0;
    if sum_in > 0 {
        let n = input_amounts.len() as u128;
        arith = (c * n * n) / sum_in;
    }
    let mut m = harmonic.saturating_sub(arith);
    m += tx.s_out.len() as u128 * p.shielded_storage_mass as u128;
    if m > MAX_SAFE as u128 { MAX_SAFE } else { m as u64 }
}

// ======================================================================== addresses
pub enum Addr {
    T { data: Vec<u8>, pubkey: P1 },
    S { data: Vec<u8>, a: P1, b: P1 },
    M { data: Vec<u8> },
    Q { data: Vec<u8> },
    N { data: Vec<u8>, record: NameRecord },
    C { data: Vec<u8> },
}
impl Addr {
    pub fn kind(&self) -> char {
        match self { Addr::T { .. } => 't', Addr::S { .. } => 's', Addr::M { .. } => 'm', Addr::Q { .. } => 'q', Addr::N { .. } => 'n', Addr::C { .. } => 'c' }
    }
    pub fn data(&self) -> &[u8] {
        match self { Addr::T { data, .. } | Addr::S { data, .. } | Addr::M { data } | Addr::Q { data } | Addr::N { data, .. } | Addr::C { data } => data }
    }
}

pub fn parse_address_data(d: &[u8]) -> Option<Addr> {
    let data = d.to_vec();
    match (d.first()?, d.len()) {
        (0x00, 34) => Some(Addr::T { pubkey: P1::from_bytes(&d[1..])?, data }),
        (0x01, 67) => Some(Addr::S { a: P1::from_bytes(&d[1..34])?, b: P1::from_bytes(&d[34..])?, data }),
        (0x03, 33) => Some(Addr::M { data }),
        (0x04, 33) => Some(Addr::Q { data }),
        (&LOCK_NAME, _) => Some(Addr::N { record: parse_name_record(d)?, data }),
        (&LOCK_NAME_COMMIT, 33) => Some(Addr::C { data }),
        _ => None,
    }
}

// --------------------------------------------------------------- bech32m
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc830a3;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() { if (b >> i) & 1 == 1 { chk ^= g; } }
    }
    chk
}
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut bits) = (0u32, 0u32);
    let maxv = (1u32 << to) - 1;
    let mut out = vec![];
    for &v in data {
        if (v as u32) >> from != 0 { return None; }
        acc = (acc << from) | v as u32;
        bits += from;
        while bits >= to { bits -= to; out.push(((acc >> bits) & maxv) as u8); }
    }
    if pad { if bits > 0 { out.push(((acc << (to - bits)) & maxv) as u8); } }
    else if bits >= from || ((acc << (to - bits)) & maxv) != 0 { return None; }
    Some(out)
}
pub fn bech32m_encode(hrp: &str, bytes: &[u8]) -> String {
    let data = convert_bits(bytes, 8, 5, true).unwrap();
    let mut values = hrp_expand(hrp);
    values.extend(&data);
    values.extend([0u8; 6]);
    let m = polymod(&values) ^ BECH32M_CONST;
    let mut s = format!("{hrp}1");
    for d in &data { s.push(CHARSET[*d as usize] as char); }
    for i in 0..6 { s.push(CHARSET[((m >> (5 * (5 - i))) & 31) as usize] as char); }
    s
}
pub fn bech32m_decode(s: &str) -> Option<(String, Vec<u8>)> {
    if s != s.to_lowercase() && s != s.to_uppercase() { return None; }
    let s = s.to_lowercase();
    let pos = s.rfind('1')?;
    if pos < 1 || pos + 7 > s.len() { return None; }
    let hrp = &s[..pos];
    let mut data = vec![];
    for c in s[pos + 1..].bytes() { data.push(CHARSET.iter().position(|&x| x == c)? as u8); }
    let mut v = hrp_expand(hrp);
    v.extend(&data);
    if polymod(&v) != BECH32M_CONST { return None; }
    Some((hrp.to_string(), convert_bits(&data[..data.len() - 6], 5, 8, false)?))
}

pub fn encode_address(p: &Params, data: &[u8]) -> Option<String> {
    let hrp = match data.first()? { 0x00 | 0x03 => p.hrp.t, 0x01 => p.hrp.s, 0x04 => p.hrp.q, 0x05 | 0x06 => return None, _ => p.hrp.v };
    Some(bech32m_encode(hrp, data))
}
pub fn decode_address(p: &Params, s: &str) -> Result<Addr, String> {
    let (hrp, bytes) = bech32m_decode(s.trim()).ok_or("invalid address")?;
    let a = parse_address_data(&bytes).ok_or("invalid address data")?;
    let expected = match a.kind() { 't' | 'm' => p.hrp.t, 's' => p.hrp.s, 'q' => p.hrp.q, _ => "" };
    if hrp != expected { return Err(format!("address of another network or type (prefix {hrp}, expected {expected})")); }
    Ok(a)
}
/// Text to display a lock: the address, or what it is.
pub fn describe_lock(p: &Params, lock: &[u8]) -> String {
    match lock.first() {
        Some(&LOCK_NAME) => match parse_name_record(lock) { Some(r) => format!("@{} (name record)", r.name), None => "invalid name record".into() },
        Some(&LOCK_NAME_COMMIT) => "name commitment (hidden until the reveal)".into(),
        _ => encode_address(p, lock).unwrap_or_default(),
    }
}
