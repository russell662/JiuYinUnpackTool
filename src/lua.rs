//! Lua 5.1 字节码（`.lua` 条目 zlib 解压后）的逐字段 XOR 去混淆。
//!
//! dump 前 12 字节头部为明文（签名 `\x1bLuaQ` + 各字段宽度，其中
//! offset 8 = sizeof(size_t)，游戏端为 4、更新器端为 8）；其后内容按
//! ldump.c 的 Dump 粒度逐字段 XOR：**每个字段各自从密钥下标 0 开始**，
//! 指令/行号数组整块算一个字段，字符串的 size_t 前缀与内容是两个独立
//! 字段。该字段切分已在真实资源包上验证（undump 消耗 == 文件长度、
//! opcode/行号/常量全部合法、chunkname 可读）。
//!
//! 解密输出 = 原 12 字节明文头 + 还原后的标准 Lua 5.1 字节码。

use anyhow::{bail, Result};

pub const LUA_SIG: &[u8; 4] = b"\x1bLua";
pub const LUA_VERSION_51: u8 = 0x51;
const MAX_PROTO_DEPTH: usize = 250;

/// 判断数据是否为（被 XOR 混淆的）Lua 5.1 dump。
pub fn is_lua_dump(data: &[u8]) -> bool {
    data.len() > 12
        && &data[0..4] == LUA_SIG
        && data[4] == LUA_VERSION_51
        && data[5] == 0 // format
        && data[6] == 1 // 小端
}

/// 按逐字段规则去 XOR。成功时返回标准 Lua 5.1 字节码；
/// 结构校验失败（密钥错误/数据损坏）时返回 Err，由调用方回退写原始数据。
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if !is_lua_dump(data) {
        bail!("不是 Lua 5.1 dump 头");
    }
    if key.is_empty() {
        bail!("密钥为空");
    }
    let s_int = data[7] as usize;
    let s_size_t = data[8] as usize;
    let s_instr = data[9] as usize;
    let s_number = data[10] as usize;
    if s_int != 4 || !(s_size_t == 4 || s_size_t == 8) || s_instr != 4 || s_number != 8 {
        bail!(
            "非常规字段宽度 int={s_int} size_t={s_size_t} instr={s_instr} number={s_number}"
        );
    }

    // 就地解密：先复制原文，随后每消费一个字段就地对该区间 XOR。
    let mut out = data.to_vec();
    let mut c = Cursor {
        out: &mut out,
        p: 12,
        key,
        s_size_t,
    };
    c.load_function(0)?;
    if c.p != data.len() {
        bail!("undump 未恰好消费整个文件：{}/{} 字节", c.p, data.len());
    }
    Ok(out)
}

struct Cursor<'a> {
    out: &'a mut [u8],
    p: usize,
    key: &'a [u8],
    s_size_t: usize,
}

impl<'a> Cursor<'a> {
    fn remaining(&self) -> usize {
        self.out.len() - self.p
    }

    /// 消费 n 字节并从密钥下标 0 起对它们 XOR（字段级重置的落点）。
    fn field(&mut self, n: usize) -> Result<()> {
        if n > self.remaining() {
            bail!("字段越界：需要 {n} 字节，仅剩 {}", self.remaining());
        }
        for i in 0..n {
            self.out[self.p + i] ^= self.key[i % self.key.len()];
        }
        self.p += n;
        Ok(())
    }

    fn u8_field(&mut self) -> Result<u8> {
        self.field(1)?;
        Ok(self.out[self.p - 1])
    }

    /// 解密一个 int 字段（本格式恒 4 字节）并按小端解析。
    fn u32_field(&mut self) -> Result<u32> {
        self.field(4)?;
        let b: [u8; 4] = self.out[self.p - 4..self.p].try_into().unwrap();
        Ok(u32::from_le_bytes(b))
    }

    fn usize_field(&mut self, n: usize) -> Result<usize> {
        self.field(n)?;
        let b = &self.out[self.p - n..self.p];
        let mut v: u64 = 0;
        for (i, &x) in b.iter().enumerate() {
            v |= (x as u64) << (8 * i);
        }
        Ok(v as usize)
    }

    /// 字符串 = size_t 前缀字段 + 内容字段（含结尾 NUL）；前缀 0 表示 NULL。
    fn load_string(&mut self) -> Result<()> {
        let n = self.usize_field(self.s_size_t)?;
        if n == 0 {
            return Ok(());
        }
        if n > self.remaining() {
            bail!("字符串长度 {n} 越界（剩余 {}）", self.remaining());
        }
        self.field(n)
    }

    /// 对应 lundump.c 的 LoadFunction，字段顺序即 ldump.c 的 Dump 顺序。
    fn load_function(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_PROTO_DEPTH {
            bail!("Proto 嵌套过深（>{MAX_PROTO_DEPTH}），数据或密钥错误");
        }
        self.load_string()?; // source（主函数为 chunkname）
        self.field(4)?; // linedefined
        self.field(4)?; // lastlinedefined
        self.field(1)?; // nups
        self.field(1)?; // numparams
        self.field(1)?; // is_vararg
        self.field(1)?; // maxstacksize

        let sizecode = self.u32_field()? as usize;
        if sizecode as u64 * 4 > self.remaining() as u64 {
            bail!("sizecode={sizecode} 越界（剩余 {}）", self.remaining());
        }
        self.field(sizecode * 4)?; // 指令数组：整块一个字段

        let sizek = self.u32_field()? as usize;
        if sizek > self.remaining() {
            bail!("sizek={sizek} 越界（剩余 {}）", self.remaining());
        }
        for _ in 0..sizek {
            match self.u8_field()? {
                0 => {} // NIL
                1 => self.field(1)?,     // BOOLEAN
                3 => self.field(8)?,     // NUMBER（lua_Number，8B 一个字段）
                4 => self.load_string()?, // STRING
                tag => bail!("非法常量 tag {tag}"),
            }
        }

        let sizep = self.u32_field()? as usize;
        if sizep > self.remaining() / 24 {
            bail!("sizep={sizep} 越界（剩余 {}）", self.remaining());
        }
        for _ in 0..sizep {
            self.load_function(depth + 1)?;
        }

        let sizelineinfo = self.u32_field()? as usize;
        if sizelineinfo as u64 * 4 > self.remaining() as u64 {
            bail!("sizelineinfo={sizelineinfo} 越界（剩余 {}）", self.remaining());
        }
        self.field(sizelineinfo * 4)?; // 行号数组：整块一个字段

        let sizelocvars = self.u32_field()? as usize;
        if sizelocvars > self.remaining() / 10 {
            bail!("sizelocvars={sizelocvars} 越界（剩余 {}）", self.remaining());
        }
        for _ in 0..sizelocvars {
            self.load_string()?; // varname
            self.field(4)?; // startpc
            self.field(4)?; // endpc
        }

        let nupvalues = self.u32_field()? as usize;
        if nupvalues > self.remaining() / 5 {
            bail!("nupvalues={nupvalues} 越界（剩余 {}）", self.remaining());
        }
        for _ in 0..nupvalues {
            self.load_string()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与生产解密逻辑相互独立的测试端"加密器"：按同一字段规范构造
    /// 明文 dump 与其加密形态，用于端到端验证字段边界一致性。
    struct Enc {
        plain: Vec<u8>,
        enc: Vec<u8>,
        key: Vec<u8>,
        s_size_t: usize,
    }

    impl Enc {
        fn f(&mut self, bytes: &[u8]) {
            self.plain.extend_from_slice(bytes);
            for (i, &b) in bytes.iter().enumerate() {
                self.enc.push(b ^ self.key[i % self.key.len()]);
            }
        }
        fn u32(&mut self, v: u32) {
            self.f(&v.to_le_bytes());
        }
        fn u8b(&mut self, v: u8) {
            self.f(&[v]);
        }
        fn string(&mut self, s: Option<&str>) {
            match s {
                None => self.f(&vec![0; self.s_size_t]),
                Some(s) => {
                    let mut n = vec![0u8; self.s_size_t];
                    let len_bytes = ((s.len() + 1) as u64).to_le_bytes();
                    n.copy_from_slice(&len_bytes[..self.s_size_t]);
                    self.f(&n);
                    let mut b = s.as_bytes().to_vec();
                    b.push(0);
                    self.f(&b);
                }
            }
        }
        fn function(&mut self, source: Option<&str>, nested: usize) {
            self.string(source);
            self.u32(0); // linedefined
            self.u32(10); // lastlinedefined
            self.u8b(1); // nups
            self.u8b(0); // numparams
            self.u8b(2); // is_vararg
            self.u8b(4); // maxstacksize
            self.u32(3); // sizecode
            self.f(&[0x21, 0, 0, 0, 0x22, 0, 0, 0, 0x23, 0, 0, 0]); // 3 条指令整块
            self.u32(4); // sizek
            self.u8b(0); // NIL
            self.u8b(1); // BOOLEAN
            self.u8b(1); // bool 值
            self.u8b(3); // NUMBER
            self.f(&1.5f64.to_le_bytes());
            self.u8b(4); // STRING
            self.string(Some("hello"));
            let sizep = if nested > 0 { 1 } else { 0 };
            self.u32(sizep);
            if nested > 0 {
                self.function(None, nested - 1);
            }
            self.u32(3); // sizelineinfo
            self.f(&[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
            self.u32(1); // sizelocvars
            self.string(Some("x"));
            self.u32(0);
            self.u32(5);
            self.u32(1); // nupvalues
            self.string(Some("_ENV"));
        }
        fn build(s_size_t: usize, key: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let mut e = Enc {
                plain: Vec::new(),
                enc: Vec::new(),
                key: key.to_vec(),
                s_size_t,
            };
            // 12 字节明文头（两种端各自的 size_t 宽度）。
            let head = [
                0x1B, b'L', b'u', b'a', 0x51, 0, 1, 4, s_size_t as u8, 4, 8, 0,
            ];
            e.plain.extend_from_slice(&head);
            e.enc.extend_from_slice(&head);
            e.function(Some("@test\\src\\a.lua"), 1);
            (e.plain, e.enc)
        }
    }

    #[test]
    fn roundtrip_size_t_4_and_8() {
        let key = b"K3Y-SAMPLE-KEY-0123456789";
        for s in [4usize, 8] {
            let (plain, enc) = Enc::build(s, key);
            assert!(is_lua_dump(&enc));
            let dec = decrypt(&enc, key).expect("size_t=4 解密失败");
            assert_eq!(dec, plain, "size_t={s} 往返不一致");
        }
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (_, enc) = Enc::build(4, b"correct-key-abcdefghijklmnop");
        let r = decrypt(&enc, b"wrong-key-00000000000000000000");
        assert!(r.is_err(), "错误密钥应当被结构校验拒绝");
    }

    #[test]
    fn truncated_data_is_rejected() {
        let key = b"K3Y-SAMPLE-KEY-0123456789";
        let (_, enc) = Enc::build(4, key);
        assert!(decrypt(&enc[..enc.len() - 3], key).is_err());
    }
}
