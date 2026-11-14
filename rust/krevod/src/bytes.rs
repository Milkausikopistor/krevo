//! Serialização binária canônica (igual a src/util/bytes.js): little-endian e varints estilo
//! Bitcoin; o leitor é estrito (varint não canônico, limite ou fim inesperado → erro).

pub type Res<T> = Result<T, String>;

#[derive(Default, Clone)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Self { Writer(Vec::new()) }
    pub fn u8(&mut self, v: u8) -> &mut Self { self.0.push(v); self }
    pub fn u16(&mut self, v: u16) -> &mut Self { self.0.extend_from_slice(&v.to_le_bytes()); self }
    pub fn u32(&mut self, v: u32) -> &mut Self { self.0.extend_from_slice(&v.to_le_bytes()); self }
    pub fn u64(&mut self, v: u64) -> &mut Self { self.0.extend_from_slice(&v.to_le_bytes()); self }
    pub fn varint(&mut self, n: u64) -> &mut Self {
        if n < 0xfd { self.u8(n as u8) } else if n <= 0xffff { self.u8(0xfd).u16(n as u16) } else if n <= 0xffff_ffff { self.u8(0xfe).u32(n as u32) } else { self.u8(0xff).u64(n) }
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self { self.0.extend_from_slice(b); self }
    pub fn varbytes(&mut self, b: &[u8]) -> &mut Self { self.varint(b.len() as u64); self.bytes(b) }
    pub fn done(self) -> Vec<u8> { self.0 }
}

pub struct Reader<'a> { pub buf: &'a [u8], pub pos: usize }

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self { Reader { buf, pos: 0 } }
    fn need(&self, n: usize) -> Res<()> {
        if self.pos + n > self.buf.len() { Err("fim inesperado dos dados".into()) } else { Ok(()) }
    }
    pub fn u8(&mut self) -> Res<u8> { self.need(1)?; self.pos += 1; Ok(self.buf[self.pos - 1]) }
    pub fn u16(&mut self) -> Res<u16> { let b = self.bytes(2)?; Ok(u16::from_le_bytes(b.try_into().unwrap())) }
    pub fn u32(&mut self) -> Res<u32> { let b = self.bytes(4)?; Ok(u32::from_le_bytes(b.try_into().unwrap())) }
    pub fn u64(&mut self) -> Res<u64> { let b = self.bytes(8)?; Ok(u64::from_le_bytes(b.try_into().unwrap())) }
    pub fn varint(&mut self, max: u64) -> Res<u64> {
        let f = self.u8()?;
        let v = match f {
            0xfd => { let v = self.u16()? as u64; if v < 0xfd { return Err("varint não canônico".into()); } v }
            0xfe => { let v = self.u32()? as u64; if v <= 0xffff { return Err("varint não canônico".into()); } v }
            0xff => { let v = self.u64()?; if v <= 0xffff_ffff { return Err("varint não canônico".into()); } v }
            x => x as u64,
        };
        if v > max { return Err(format!("varint acima do limite ({v} > {max})")); }
        Ok(v)
    }
    pub fn bytes(&mut self, n: usize) -> Res<&'a [u8]> {
        self.need(n)?;
        let b = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(b)
    }
    pub fn arr<const L: usize>(&mut self) -> Res<[u8; L]> { Ok(self.bytes(L)?.try_into().unwrap()) }
    pub fn varbytes(&mut self, max: u64) -> Res<&'a [u8]> { let n = self.varint(max)? as usize; self.bytes(n) }
    pub fn end(&self) -> Res<()> {
        if self.pos != self.buf.len() { Err("bytes sobrando após o fim da estrutura".into()) } else { Ok(()) }
    }
    pub fn remaining(&self) -> usize { self.buf.len() - self.pos }
}

pub fn to_hex(b: &[u8]) -> String { crate::field::hex(b) }

pub fn from_hex(s: &str) -> Res<Vec<u8>> {
    if s.len() % 2 != 0 { return Err("hex inválido".into()); }
    let v: Result<Vec<u8>, _> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16)).collect();
    v.map_err(|_| "hex inválido".to_string())
}

pub fn from_hex32(s: &str) -> Res<[u8; 32]> {
    let v = from_hex(s)?;
    v.try_into().map_err(|_| "hash inválido".to_string())
}
