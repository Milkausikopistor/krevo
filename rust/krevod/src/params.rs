//! Parâmetros de consenso (idênticos a src/params.js). Mudar qualquer valor cria uma rede
//! incompatível.

pub const COIN: u64 = 100_000_000;
pub const MAX_SUPPLY: u64 = 1_000_000_000 * COIN;

#[derive(Clone, Debug)]
pub struct Hrp { pub t: &'static str, pub s: &'static str, pub v: &'static str, pub q: &'static str }

#[derive(Clone, Debug)]
pub struct Params {
    pub name: &'static str,
    pub bps: u64,
    pub target_time_ms: u64,
    pub max_parents: usize,
    pub mergeset_size_limit: usize,
    pub max_future_ms: u64,
    pub coinbase_maturity: u64,
    pub ring_size: usize,
    pub ring_maturity: u64,
    pub ring_inputs: bool,
    pub fcmp_branch: usize,
    pub fcmp_maturity: u64,
    pub max_block_mass: u64,
    pub max_tx_mass: u64,
    pub mass_per_byte: u64,
    pub mass_per_sig: u64,
    pub mass_per_ring_member: u64,
    pub mass_per_fcmp_input: u64,
    pub mass_per_shielded_output: u64,
    pub storage_mass_c: u64,
    pub shielded_storage_mass: u64,
    pub min_relay_fee_rate: u64,
    pub fee_pool_share_num: u64,
    pub fee_pool_share_den: u64,
    pub fee_pool_decay: u64,
    pub reward_per_second0: u64,
    pub seconds_per_month: u64,
    pub reductions_per_halving: u64,
    pub max_coinbase_payload: usize,
    pub max_tx_payload: usize,
    pub name_period: u64,
    pub name_grace: u64,
    pub name_commit_min: u64,
    pub name_commit_max: u64,
    pub name_min_deposit: u64,
    pub name_fees: [u64; 4],
    pub light_proof_depth: u64,
    pub ghostdag_k: usize,
    pub merge_depth: u64,
    pub daa_window_size: usize,
    pub daa_min_window: usize,
    pub past_median_time_window: usize,
    pub p2p_magic: u32,
    pub default_p2p_port: u16,
    pub default_rpc_port: u16,
    pub hrp: Hrp,
    pub genesis_timestamp: u64,
    pub genesis_bits: u32,
    pub genesis_message: &'static str,
}

/// k do GHOSTDAG: o menor k com P[Poisson(2Dλ) > k] < δ (mesma conta do JavaScript).
pub fn compute_ghostdag_k(bps: f64, delay_seconds: f64, delta: f64) -> usize {
    let mean = 2.0 * delay_seconds * bps;
    let mut term = (-mean).exp();
    let mut cdf = term;
    let mut k = 0usize;
    while 1.0 - cdf >= delta {
        k += 1;
        term *= mean / k as f64;
        cdf += term;
    }
    k
}

fn common(name: &'static str) -> Params {
    Params {
        name,
        bps: 10,
        target_time_ms: 100,
        max_parents: 16,
        mergeset_size_limit: 512,
        max_future_ms: 120_000,
        coinbase_maturity: 1000,
        ring_size: 16,
        ring_maturity: 300,
        ring_inputs: false,
        fcmp_branch: 256,
        fcmp_maturity: 1000,
        max_block_mass: 500_000,
        max_tx_mass: 250_000,
        mass_per_byte: 1,
        mass_per_sig: 1_000,
        mass_per_ring_member: 1_500,
        mass_per_fcmp_input: 20_000,
        mass_per_shielded_output: 3_000,
        storage_mass_c: 1_000_000_000,
        shielded_storage_mass: 2_000,
        min_relay_fee_rate: 1,
        fee_pool_share_num: 1,
        fee_pool_share_den: 2,
        fee_pool_decay: 864_000,
        reward_per_second0: 545_000_000,
        seconds_per_month: 2_629_800,
        reductions_per_halving: 48,
        max_coinbase_payload: 200,
        max_tx_payload: 256,
        name_period: 315_576_000,
        name_grace: 25_920_000,
        name_commit_min: 300,
        name_commit_max: 864_000,
        name_min_deposit: 1_000_000,
        name_fees: [10_000_000_000, 2_000_000_000, 500_000_000, 100_000_000],
        light_proof_depth: 100,
        ghostdag_k: compute_ghostdag_k(10.0, 5.0, 0.01),
        merge_depth: 3_600,
        daa_window_size: 2_640,
        daa_min_window: 60,
        past_median_time_window: 263,
        p2p_magic: 0,
        default_p2p_port: 0,
        default_rpc_port: 0,
        hrp: Hrp { t: "krv", s: "krs", v: "krw", q: "krq" },
        genesis_timestamp: 0,
        genesis_bits: 0,
        genesis_message: "",
    }
}

pub fn get_params(name: &str) -> Option<Params> {
    let mut p = match name {
        "mainnet" => {
            let mut p = common("mainnet");
            p.p2p_magic = 0x4b525631; p.default_p2p_port = 16110; p.default_rpc_port = 16111;
            p.genesis_timestamp = 1798761600000; p.genesis_bits = 0x1f00ffff;
            p.genesis_message = "Krevo mainnet — PREENCHER NO LANÇAMENTO";
            p
        }
        "testnet" => {
            let mut p = common("testnet");
            p.p2p_magic = 0x4b525654; p.default_p2p_port = 16210; p.default_rpc_port = 16211;
            p.hrp = Hrp { t: "krvtest", s: "krstest", v: "krwtest", q: "krqtest" };
            p.genesis_timestamp = 1794355200000; p.genesis_bits = 0x1f0fffff; p.genesis_message = "Krevo testnet";
            p
        }
        "devnet" | "simnet" => {
            let mut p = common("devnet");
            p.merge_depth = 1_200; p.daa_window_size = 300; p.daa_min_window = 30; p.past_median_time_window = 41;
            p.coinbase_maturity = 100; p.ring_maturity = 20; p.fcmp_maturity = 100;
            p.name_commit_min = 50; p.light_proof_depth = 30;
            p.p2p_magic = 0x4b525644; p.default_p2p_port = 16310; p.default_rpc_port = 16311;
            p.hrp = Hrp { t: "krvdev", s: "krsdev", v: "krwdev", q: "krqdev" };
            p.genesis_timestamp = 1794355200000; p.genesis_bits = 0x1f0fffff; p.genesis_message = "Krevo devnet";
            p
        }
        _ => return None,
    };
    if name == "simnet" {
        p.name = "simnet";
        p.daa_min_window = 1_000_000_000;
        p.coinbase_maturity = 10; p.ring_maturity = 2; p.ring_size = 4; p.ring_inputs = true;
        p.fcmp_branch = 4; p.fcmp_maturity = 10;
        p.name_period = 400; p.name_grace = 100; p.name_commit_min = 3; p.name_commit_max = 200;
        p.light_proof_depth = 3;
        p.p2p_magic = 0x4b525653; p.default_p2p_port = 16410; p.default_rpc_port = 16411;
        p.hrp = Hrp { t: "krvsim", s: "krssim", v: "krwsim", q: "krqsim" };
        p.genesis_bits = 0x207fffff; p.genesis_message = "Krevo simnet";
    }
    Some(p)
}

/// Formatação igual à do JavaScript ("1.234,5 KRV").
pub fn format_krv(grains: u64) -> String {
    let whole = grains / COIN;
    let frac = format!("{:08}", grains % COIN);
    let frac = frac.trim_end_matches('0');
    let mut w = whole.to_string();
    let mut out = String::new();
    while w.len() > 3 { out = format!(".{}{}", &w[w.len() - 3..], out); w.truncate(w.len() - 3); }
    out = format!("{w}{out}");
    if frac.is_empty() { format!("{out} KRV") } else { format!("{out},{frac} KRV") }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn k_is_124() { assert_eq!(compute_ghostdag_k(10.0, 5.0, 0.01), 124); }
}
