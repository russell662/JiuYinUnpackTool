//! Lua 5.1 字节码逐字段 XOR 解密集成测试。
//!
//! `Enc` 是与生产解密逻辑相互独立的测试端"加密器"：按同一字段规范构造
//! 明文 dump 与其加密形态，端到端验证字段边界一致性。

use jiuyin_unpack::lua::{decrypt, is_lua_dump};

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
