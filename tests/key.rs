//! 启动器密钥提取集成测试。

use jiuyin_unpack::key::{
    extract_key, find_sub, is_printable, longest_printable_run, KEY_SIGNATURE,
};
use std::path::PathBuf;

fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "jyu_{tag}_{}.tmp",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

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
    assert_eq!(
        &data[start..start + len],
        b"this_is_a_very_long_printable_run_for_fallback"
    );
}

#[test]
fn extract_key_from_fake_exe() {
    // 构造含签名锚点的伪 exe（密钥体 ≥128 字节过长度校验），走公开 API 提取。
    let sig = std::str::from_utf8(KEY_SIGNATURE).unwrap();
    let body = format!("{sig}{}", "X".repeat(200));
    let mut exe = vec![0u8; 64];
    exe.extend_from_slice(body.as_bytes());
    exe.push(0);
    exe.extend_from_slice(b"other strings follow");
    let path = temp_path("key");
    std::fs::write(&path, &exe).unwrap();

    let (key, note) = extract_key(&path).unwrap();
    assert_eq!(key, body.as_bytes());
    assert!(note.contains("签名"));
    std::fs::remove_file(&path).ok();
}
