//! 从启动器/客户端二进制中静态提取 Lua 字节码 XOR 密钥（无需运行程序）。
//!
//! 密钥为 523 字节可打印 ASCII 的 C 字符串（NUL 结尾），已确认存在于：
//!   - `updater_\fxupdate.exe`  偏移 0x4EE40（.rdata 明文区）
//!   - `bin64\fxgame.exe`       偏移 0x64530
//! 两处一致。提取策略：
//!   1. 主策略：搜索 16 字节签名锚点，向后延伸至首个非可打印字节（NUL）；
//!   2. 兜底：若签名未命中（游戏更新轮换密钥），取文件中最长的可打印 ASCII
//!      字符串（≥300 字节）作为启发式候选，最终由 Lua undump 校验把关。

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// 密钥开头的 16 字节签名锚点（完整密钥从启动器文件中读出）。
const KEY_SIGNATURE: &[u8] = b"abcd464fghfgfjhf";
/// 实测密钥长度（fxupdate.exe 与 fxgame.exe 中一致）。
pub const EXPECTED_KEY_LEN: usize = 523;
const MIN_KEY_LEN: usize = 128;
const FALLBACK_MIN_LEN: usize = 300;

/// 从 exe 文件提取密钥，返回 (密钥, 提取方式说明)。
pub fn extract_key(path: &Path) -> Result<(Vec<u8>, &'static str)> {
    let data = std::fs::read(path)
        .with_context(|| format!("读取启动器文件失败：{}", path.display()))?;

    if let Some(pos) = find_sub(&data, KEY_SIGNATURE) {
        let end = data[pos..]
            .iter()
            .position(|&b| !is_printable(b))
            .map(|i| pos + i)
            .unwrap_or(data.len());
        let key = &data[pos..end];
        if key.len() < MIN_KEY_LEN {
            bail!(
                "签名命中但密钥长度异常（{} 字节），文件：{}",
                key.len(),
                path.display()
            );
        }
        let note = if key.len() == EXPECTED_KEY_LEN {
            "签名锚点"
        } else {
            "签名锚点（长度与实测 523 不同，可能已轮换，将由 undump 校验）"
        };
        return Ok((key.to_vec(), note));
    }

    // 兜底：最长可打印 ASCII 串。
    let (start, len) = longest_printable_run(&data);
    if len >= FALLBACK_MIN_LEN {
        return Ok((
            data[start..start + len].to_vec(),
            "启发式（签名未命中，取最长可打印串）",
        ));
    }
    bail!(
        "在 {} 中未找到候选密钥（签名未命中，最长可打印串仅 {} 字节）",
        path.display(),
        len
    );
}

fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn longest_printable_run(data: &[u8]) -> (usize, usize) {
    let mut best = (0usize, 0usize);
    let mut run_start = 0usize;
    let mut in_run = false;
    for (i, &b) in data.iter().enumerate() {
        if is_printable(b) {
            if !in_run {
                in_run = true;
                run_start = i;
            }
        } else if in_run {
            in_run = false;
            let len = i - run_start;
            if len > best.1 {
                best = (run_start, len);
            }
        }
    }
    if in_run && data.len() - run_start > best.1 {
        best = (run_start, data.len() - run_start);
    }
    best
}

/// 在 anchor 目录及其上级（最多 3 级）自动探测启动器/客户端 exe。
/// anchor 为游戏安装目录（批量模式）或包文件所在目录（单包模式）。
pub fn find_launcher(anchor: &Path) -> Option<PathBuf> {
    let mut base = anchor;
    for _ in 0..3 {
        for rel in [
            "updater_/fxupdate.exe",
            "updater/fxupdate.exe",
            "bin64/fxgame.exe",
            "fxupdate.exe",
            "fxgame.exe",
        ] {
            let cand = base.join(rel);
            if cand.is_file() {
                return Some(cand);
            }
        }
        base = base.parent()?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_hit_extends_to_nul() {
        let mut exe = vec![0u8; 64];
        exe.extend_from_slice(b"\x00\x00abcd464fghfgfjhfREST_OF_KEY\x00NEXT_STR");
        let pos = find_sub(&exe, KEY_SIGNATURE).unwrap();
        assert_eq!(pos, 66);
        let end = exe[pos..]
            .iter()
            .position(|&b| !is_printable(b))
            .map(|i| pos + i)
            .unwrap();
        assert_eq!(&exe[pos..end], b"abcd464fghfgfjhfREST_OF_KEY");
    }

    #[test]
    fn longest_run_fallback() {
        let data = b"short\x00aaaa\x00this_is_a_very_long_printable_run_for_fallback\x00zz";
        let (start, len) = longest_printable_run(data);
        assert_eq!(&data[start..start + len], b"this_is_a_very_long_printable_run_for_fallback");
    }
}
