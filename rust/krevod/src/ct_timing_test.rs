//! Medição estatística de tempo constante (método "dudect", Reparaz–Balasch–Verbauwhede 2017).
//!
//! Para cada operação com segredo, duas classes de entradas são intercaladas ao acaso:
//!   classe 0 — um segredo FIXO e "especial" (ex.: k = 1, valor 0: poucos bits ligados);
//!   classe 1 — um segredo ALEATÓRIO novo a cada medida.
//! Se o tempo dependesse do segredo, as duas distribuições de tempo seriam diferentes; o teste t
//! de Welch mede isso (também depois de cortar a cauda em vários percentis, como o dudect).
//! |t| > 4,5 = vazamento detectado. Um CONTROLE com a multiplicação de tempo variável (a de
//! verificação) precisa acusar vazamento — prova de que o teste enxerga quando há.
//!
//!   cargo test ct_timing -- --ignored --nocapture        (≈1–2 min)

use crate::crypto::*;
use crate::curve::P1;
use crate::wallet_ops::*;
use std::hint::black_box;
use std::time::Instant;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
}

#[derive(Default, Clone, Copy)]
struct Welch { n: [f64; 2], mean: [f64; 2], m2: [f64; 2] }
impl Welch {
    fn push(&mut self, c: usize, x: f64) {
        self.n[c] += 1.0;
        let d = x - self.mean[c];
        self.mean[c] += d / self.n[c];
        self.m2[c] += d * (x - self.mean[c]);
    }
    fn t(&self) -> f64 {
        if self.n[0] < 2.0 || self.n[1] < 2.0 { return 0.0; }
        let v0 = self.m2[0] / (self.n[0] - 1.0);
        let v1 = self.m2[1] / (self.n[1] - 1.0);
        (self.mean[0] - self.mean[1]) / (v0 / self.n[0] + v1 / self.n[1]).sqrt()
    }
}

/// Mede `n` execuções; `prep(classe)` prepara a entrada (fora do cronômetro), `run` executa.
/// Devolve o maior |t| entre: sem corte e cortes nos percentis 50/75/90/95/99.
fn dudect<T>(n: usize, seed: u64, mut prep: impl FnMut(usize, &mut Rng) -> T, mut run: impl FnMut(&T)) -> f64 {
    let mut rng = Rng(seed | 1);
    for _ in 0..n / 20 { let x = prep((rng.next() & 1) as usize, &mut rng); run(&x); } // aquecimento
    let mut samples: Vec<(usize, f64)> = Vec::with_capacity(n);
    for _ in 0..n {
        let c = (rng.next() & 1) as usize;
        let x = prep(c, &mut rng);
        let t0 = Instant::now();
        run(black_box(&x));
        samples.push((c, t0.elapsed().as_nanos() as f64));
    }
    let mut sorted: Vec<f64> = samples.iter().map(|s| s.1).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut all = Welch::default();
    for &(c, x) in &samples { all.push(c, x); }
    if std::env::var("KREVO_CT_VERBOSE").is_ok() { println!("   médias: classe 0 = {:.0} ns, classe 1 = {:.0} ns", all.mean[0], all.mean[1]); }
    let mut best: f64 = 0.0;
    for pct in [100.0, 99.0, 95.0, 90.0, 75.0, 50.0] {
        let cut = sorted[((sorted.len() - 1) as f64 * pct / 100.0) as usize];
        let mut w = Welch::default();
        for &(c, x) in &samples { if x <= cut { w.push(c, x); } }
        best = best.max(w.t().abs());
    }
    best
}

fn sc(rng: &mut Rng) -> Sc { let mut b = [0u8; 64]; for x in b.chunks_mut(8) { x.copy_from_slice(&rng.next().to_le_bytes()); } Sc::from_be_bytes_wide(&b) }

#[test]
#[ignore]
fn ct_timing() {
    let one = Sc::from_u64(1);
    let base = mul_g(&Sc::from_u64(0x1234_5678));
    let mut report = vec![];
    let mut check = |name: &str, t: f64, must_leak: bool| {
        report.push(format!("{name:<44} |t| = {t:7.2}  {}", if must_leak { if t > 4.5 { "vazamento detectado (esperado: controle)" } else { "CONTROLE NÃO DETECTOU" } } else if t > 4.5 { "VAZAMENTO" } else { "ok" }));
        (t > 4.5) == must_leak
    };
    let mut ok = true;
    let n = 20_000;
    ok &= check("k·G tempo constante (k = 1 × aleatório)", dudect(n, 1, |c, r| { let x = sc(r); if c == 0 { one } else { x } }, |k| { black_box(mul_g_ct(k)); }), false);
    ok &= check("k·P tempo constante (k = 1 × aleatório)", dudect(n, 2, |c, r| { let x = sc(r); if c == 0 { one } else { x } }, |k| { black_box(mul_ct(&base, k)); }), false);
    ok &= check("k·H tempo constante (k = 1 × aleatório)", dudect(n, 3, |c, r| { let x = sc(r); if c == 0 { one } else { x } }, |k| { black_box(mul_h_ct(k)); }), false);
    let fixed = Sc::from_u64(0xdead_beef_cafe);
    ok &= check("Schnorr (chave fixa × aleatória)", dudect(n / 2, 4, |c, r| { let x = sc(r); if c == 0 { fixed } else { x } }, |x| { black_box(schnorr_sign(x, b"m", "sig").unwrap()); }), false);
    ok &= check("prova de intervalo (valor 0 × aleatório)", dudect(600, 5, |c, r| if c == 0 { 0u64 } else { r.next() }, |v| { black_box(range_prove(&[*v], &[one]).unwrap()); }), false);
    let p1: P1 = base;
    let fk = sc(&mut Rng(77));
    ok &= check("k·G (k fixo aleatório × aleatório)", dudect(n, 7, |c, r| { let x = sc(r); if c == 0 { fk } else { x } }, |k| { black_box(mul_g_ct(k)); }), false);
    ok &= check("CONTROLE: k·P de tempo variável (verificação)", dudect(n, 6, |c, r| { let x = sc(r); if c == 0 { one } else { x } }, |k| { black_box(p1.mul(k)); }), true);
    println!("\n{}", report.join("\n"));
    assert!(ok, "resultado inesperado na medição de tempo constante");
}
