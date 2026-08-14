//! PCK0 容器解析集成测试。

use jiuyin_unpack::pck::{self, ENTRY_FIXED_SIZE, HEADER_SIZE, MAGIC, SUPPORTED_VERSION};
use std::path::Path;

fn build_pkg(entries: &[(u64, u32, u32, &str, Option<&str>)]) -> Vec<u8> {
    let mut index = Vec::new();
    for &(off, raw, comp, name, pkg) in entries {
        let name_b = name.as_bytes();
        let mut rec_len = (ENTRY_FIXED_SIZE + name_b.len() + 1) as u16;
        let extra = match pkg {
            Some(p) => {
                rec_len += (p.len() + 1) as u16;
                (name_b.len() + 1) as u16
            }
            None => 0,
        };
        index.extend_from_slice(&rec_len.to_le_bytes());
        index.extend_from_slice(&off.to_le_bytes());
        index.extend_from_slice(&raw.to_le_bytes());
        index.extend_from_slice(&comp.to_le_bytes());
        index.extend_from_slice(&[0xEA, 0x07, 6, 3, 10, 1, 21]); // 时间戳
        index.extend_from_slice(&extra.to_le_bytes());
        index.extend_from_slice(name_b);
        index.push(0);
        if let Some(p) = pkg {
            index.extend_from_slice(p.as_bytes());
            index.push(0);
        }
    }
    let index_end = (HEADER_SIZE + index.len()) as u32;
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&SUPPORTED_VERSION.to_le_bytes());
    buf.extend_from_slice(&[0u8; 4]); // 偏移 6..0x0A 保留区（两段保留字均为 0）
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    buf.extend_from_slice(&index_end.to_le_bytes());
    buf.push(0);
    debug_assert_eq!(buf.len(), HEADER_SIZE);
    buf.extend_from_slice(&index);
    buf.extend_from_slice(&[0x78, 0x9C]); // 假数据区
    // 补齐到覆盖最大条目的 offset+comp_size（真实文件数据区连续铺满到 EOF）。
    let max_end = entries
        .iter()
        .map(|&(off, _, comp, _, _)| off + comp as u64)
        .max()
        .unwrap_or(0) as usize;
    buf.resize(buf.len().max(max_end), 0);
    buf
}

#[test]
fn parse_plain_entries() {
    let buf = build_pkg(&[
        (0x1AB, 29, 37, "version.ini", None),
        (
            0x1D0,
            320757,
            36173,
            "res\\share\\rule\\card.ini",
            Some("res\\share.package"),
        ),
    ]);
    let pkg = pck::parse(&buf[..], buf.len() as u64).unwrap();
    assert_eq!(pkg.entries.len(), 2);
    assert_eq!(pkg.entries[0].name, "version.ini");
    assert!(pkg.entries[0].package_name.is_none());
    assert_eq!(pkg.entries[1].name, "res\\share\\rule\\card.ini");
    assert_eq!(
        pkg.entries[1].package_name.as_deref(),
        Some("res\\share.package")
    );
    assert_eq!(pkg.entries[1].raw_size, 320757);
    assert_eq!(pkg.entries[1].comp_size, 36173);
    assert_eq!(pkg.entries[1].timestamp_string(), "2026-06-03 10:01:21");
}

#[test]
fn reject_bad_magic() {
    let mut buf = build_pkg(&[(0, 1, 1, "a", None)]);
    buf[0] = b'X';
    assert!(pck::parse(&buf[..], buf.len() as u64).is_err());
}

#[test]
fn reject_encrypted_index_flag() {
    // 头部 0x06 标志非 0（新补丁的索引加密格式）应被明确拒绝。
    let mut buf = build_pkg(&[(0, 1, 1, "a", None)]);
    buf[6] = 4;
    let err = pck::parse(&buf[..], buf.len() as u64).unwrap_err().to_string();
    assert!(err.contains("索引加密"), "实际错误：{err}");
}

#[test]
fn safe_path_blocks_traversal() {
    let base = Path::new("out");
    let p = pck::safe_output_path(base, "..\\..\\evil.txt");
    assert_eq!(p, Path::new("out").join("evil.txt"));
    let p = pck::safe_output_path(base, "C:\\abs\\x.png");
    assert_eq!(p, Path::new("out").join("abs").join("x.png"));
    let p = pck::safe_output_path(base, "res\\eff\\a.c");
    assert_eq!(p, Path::new("out").join("res").join("eff").join("a.c"));
}
