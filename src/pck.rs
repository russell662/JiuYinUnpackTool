//! PCK0 v15 容器格式解析（.package 与 .patch 通用）。
//!
//! 头部 19 字节，条目区从 0x13 连续排列，数据块为逐条目独立的标准 zlib 流：
//!
//! ```text
//! 头部:  "PCK0" | u16 版本=15 | u16 保留 | u32 保留 | u32 条目数
//!        | u32 索引结束偏移(=数据区起点) | u8 0
//! 条目:  u16 记录总长 | u64 数据偏移 | u32 原始大小 | u32 压缩大小
//!        | 7B 时间戳 | u16 扩展 | NUL 结尾 GBK 文件名 [ | NUL 结尾目标包名 ]
//! ```
//!
//! 扩展字段在普通 .package 中恒为 0；在 .patch 中为 0（散文件）或
//! `strlen(文件名)+1`（其后跟随目标包名字符串）。

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub const MAGIC: &[u8; 4] = b"PCK0";
pub const HEADER_SIZE: usize = 0x13;
pub const ENTRY_FIXED_SIZE: usize = 27;
pub const SUPPORTED_VERSION: u16 = 15;

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u16,
    pub entry_count: u32,
    /// 索引区结束偏移，同时是数据区起点。
    pub index_end: u64,
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// 条目数据在包文件中的绝对偏移。
    pub data_offset: u64,
    /// zlib 解压后的原始大小。
    pub raw_size: u32,
    /// zlib 压缩后的存储大小。
    pub comp_size: u32,
    /// 7 字节时间戳：u16 LE 年 + 月/日/时/分/秒（各 1 字节，顺序未完全确证，仅用于展示）。
    pub timestamp: [u8; 7],
    /// GBK 解码后的条目内相对路径（反斜杠分隔）。
    pub name: String,
    /// 仅 .patch：该条目归属的目标包名（如 `res\share.package`）。
    pub package_name: Option<String>,
}

impl Entry {
    /// 时间戳格式化为 `YYYY-MM-DD HH:MM:SS`（仅供 --list 展示）。
    pub fn timestamp_string(&self) -> String {
        let year = u16::from_le_bytes([self.timestamp[0], self.timestamp[1]]);
        let [_, _, mon, day, hour, min, sec] = self.timestamp;
        format!("{year:04}-{mon:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
    }
}

#[derive(Debug)]
pub struct Package {
    pub header: Header,
    pub entries: Vec<Entry>,
}

/// 从 reader（已打开的 .package/.patch 文件）解析头部与全部条目。
pub fn parse<R: Read>(mut reader: R, file_len: u64) -> Result<Package> {
    let mut head = [0u8; HEADER_SIZE];
    reader
        .read_exact(&mut head)
        .context("读取 PCK0 头部失败（文件过小？）")?;
    if &head[0..4] != MAGIC {
        bail!(
            "不是 PCK0 包（魔数 {:02X?}，期望 {:02X?}）",
            &head[0..4],
            MAGIC
        );
    }
    let header = Header {
        version: u16::from_le_bytes([head[4], head[5]]),
        entry_count: u32::from_le_bytes([head[0x0A], head[0x0B], head[0x0C], head[0x0D]]),
        index_end: u32::from_le_bytes([head[0x0E], head[0x0F], head[0x10], head[0x11]]) as u64,
    };
    if header.version != SUPPORTED_VERSION {
        bail!("不支持的 PCK0 版本 {}（仅支持 15）", header.version);
    }
    if header.index_end < HEADER_SIZE as u64 || header.index_end > file_len {
        bail!(
            "头部索引结束偏移非法：{}（文件长度 {}）",
            header.index_end,
            file_len
        );
    }

    let index_len = header.index_end as usize - HEADER_SIZE;
    let mut index = vec![0u8; index_len];
    reader
        .read_exact(&mut index)
        .context("读取索引区失败")?;

    let mut entries = Vec::with_capacity(header.entry_count as usize);
    let mut pos = 0usize;
    while pos + ENTRY_FIXED_SIZE <= index_len {
        let rest = &index[pos..];
        let record_len = u16::from_le_bytes([rest[0], rest[1]]) as usize;
        if record_len < ENTRY_FIXED_SIZE + 1 || pos + record_len > index_len {
            bail!(
                "条目 #{} 记录长度非法：{}（索引区剩余 {}）",
                entries.len(),
                record_len,
                index_len - pos
            );
        }
        let rec = &rest[..record_len];
        entries.push(parse_entry(rec)?);
        pos += record_len;
    }
    if pos != index_len {
        bail!(
            "索引区解析后剩余 {} 字节未消费（索引区 {} 字节）",
            index_len - pos,
            index_len
        );
    }
    if entries.len() as u32 != header.entry_count {
        bail!(
            "条目数不符：头部声明 {}，实际解析 {}",
            header.entry_count,
            entries.len()
        );
    }
    for (i, e) in entries.iter().enumerate() {
        if e.data_offset + e.comp_size as u64 > file_len {
            bail!(
                "条目 #{} ({}) 数据范围越界：offset={} size={} > 文件长度 {}",
                i,
                e.name,
                e.data_offset,
                e.comp_size,
                file_len
            );
        }
    }
    Ok(Package {
        header,
        entries,
    })
}

/// 解析单条记录（rec 长度即记录总长，含全部字段与 NUL）。
fn parse_entry(rec: &[u8]) -> Result<Entry> {
    let data_offset = u64::from_le_bytes(rec[2..10].try_into().unwrap());
    let raw_size = u32::from_le_bytes(rec[10..14].try_into().unwrap());
    let comp_size = u32::from_le_bytes(rec[14..18].try_into().unwrap());
    let timestamp = rec[18..25].try_into().unwrap();
    let extra = u16::from_le_bytes([rec[25], rec[26]]);

    let name_bytes = &rec[ENTRY_FIXED_SIZE..];
    let name_field_len = if extra != 0 {
        extra as usize
    } else {
        memchr(name_bytes, 0).context("条目文件名缺少 NUL 结尾")? + 1
    };
    if name_field_len > name_bytes.len() {
        bail!("扩展字段 {} 超出记录范围", extra);
    }
    let name = decode_gbk(&name_bytes[..name_field_len - 1]);

    // extra != 0 时其后还有 NUL 结尾的目标包名（.patch 格式）。
    let package_name = if extra != 0 {
        let pkg_bytes = &name_bytes[name_field_len..];
        let pkg_len = memchr(pkg_bytes, 0).context("目标包名缺少 NUL 结尾")? + 1;
        Some(decode_gbk(&pkg_bytes[..pkg_len - 1]))
    } else {
        None
    };
    Ok(Entry {
        data_offset,
        raw_size,
        comp_size,
        timestamp,
        name,
        package_name,
    })
}

fn memchr(buf: &[u8], b: u8) -> Option<usize> {
    buf.iter().position(|&x| x == b)
}

/// 条目名是 GBK（或 ASCII）明文，转为 UTF-8；无效序列以替换字符呈现。
pub fn decode_gbk(bytes: &[u8]) -> String {
    let (cow, _, had_errors) = encoding_rs::GBK.decode(bytes);
    if had_errors {
        eprintln!("警告：文件名含非法 GBK 序列：{:02X?}", bytes);
    }
    cow.into_owned()
}

/// 将条目内的反斜杠相对路径映射为输出目录下的安全路径。
///
/// 清洗规则：反斜杠转为分隔符；丢弃 `..`、`.`、空组件与盘符前缀，
/// 防止条目名逃逸输出目录（如 `..\..\x` 或 `C:\x`）。
pub fn safe_output_path(base: &Path, entry_name: &str) -> PathBuf {
    let mut out = base.to_path_buf();
    let normalized = entry_name.replace('\\', "/");
    for comp in Path::new(&normalized).components() {
        match comp {
            Component::Normal(c) => {
                let s = c.to_string_lossy();
                // 过滤 Windows 盘符（如 "C:"）与保留设备名。
                if s.len() == 2 && s.as_bytes()[1] == b':' {
                    continue;
                }
                out.push(c);
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
            (0x1D0, 320757, 36173, "res\\share\\rule\\card.ini", Some("res\\share.package")),
        ]);
        let pkg = parse(&buf[..], buf.len() as u64).unwrap();
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
        assert!(parse(&buf[..], buf.len() as u64).is_err());
    }

    #[test]
    fn safe_path_blocks_traversal() {
        let base = Path::new("out");
        let p = safe_output_path(base, "..\\..\\evil.txt");
        assert_eq!(p, Path::new("out").join("evil.txt"));
        let p = safe_output_path(base, "C:\\abs\\x.png");
        assert_eq!(p, Path::new("out").join("abs").join("x.png"));
        let p = safe_output_path(base, "res\\eff\\a.c");
        assert_eq!(p, Path::new("out").join("res").join("eff").join("a.c"));
    }
}
