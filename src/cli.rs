//! CLI 参数定义、模式校验与批量扫描（供 main 与集成测试共用）。

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "jiuyin-unpack",
    version,
    about = "九阴真经 .package/.patch 资源包解包工具（PCK0 + zlib + Lua 字节码去混淆）"
)]
pub struct Args {
    /// .package 或 .patch 文件路径
    pub package: Option<PathBuf>,

    /// 递归解包该目录下所有 .package 文件
    #[arg(long, value_name = "DIR")]
    pub all_packages: Option<PathBuf>,

    /// 递归解包该目录下所有 .patch 文件
    #[arg(long, value_name = "DIR")]
    pub all_patches: Option<PathBuf>,

    /// 输出目录（单包默认：./<包名>_unpacked；批量默认：./<目录名>_packages|patches_unpacked）
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// 用于提取 Lua 解密密钥的启动器/客户端 exe（默认按安装目录自动探测）
    #[arg(short, long, value_name = "EXE")]
    pub launcher: Option<PathBuf>,

    /// 仅列出包内条目，不解包
    #[arg(long)]
    pub list: bool,

    /// 跳过 Lua 字节码解密，写出 zlib 解压后的原始数据
    #[arg(long)]
    pub no_lua_decrypt: bool,

    /// 并行线程数（默认：CPU 核数）
    #[arg(short, long, value_name = "N")]
    pub jobs: Option<usize>,
}

/// 校验三种模式（单包 / 全部 package / 全部 patch）的组合合法性。
pub fn validate_modes(args: &Args) -> Result<()> {
    let has_batch = args.all_packages.is_some() || args.all_patches.is_some();
    if args.package.is_none() && !has_batch {
        bail!("必须指定 <PACKAGE>、--all-packages <目录> 或 --all-patches <目录> 之一（-h 查看帮助）");
    }
    if args.package.is_some() && has_batch {
        bail!("<PACKAGE> 不能与 --all-packages/--all-patches 同时使用");
    }
    Ok(())
}

/// 递归扫描 root 下指定扩展名的包文件（大小写不敏感），按路径排序。
/// 不跟随符号链接，避免循环遍历。
pub fn scan_packages(root: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    fn walk(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            // file_type 基于目录项本身，符号链接不会被当作目录深入。
            if entry.file_type()?.is_dir() {
                walk(&path, ext, out)?;
            } else if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case(ext))
            {
                out.push(path);
            }
        }
        Ok(())
    }
    walk(root, ext, &mut found)
        .with_context(|| format!("扫描目录 {} 失败", root.display()))?;
    found.sort();
    Ok(found)
}
