//! jiuyin-unpack：九阴真经 .package/.patch 命令行解包工具。

mod key;
mod lua;
mod pck;

use anyhow::{bail, Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// 单条目压缩块读取上限（防御异常索引；实测条目远小于此值）。
const MAX_ENTRY_COMP: u64 = 512 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "jiuyin-unpack",
    version,
    about = "九阴真经 .package/.patch 资源包解包工具（PCK0 + zlib + Lua 字节码去混淆）"
)]
struct Args {
    /// .package 或 .patch 文件路径
    package: PathBuf,

    /// 输出目录（默认：./<包名去后缀>）
    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,

    /// 用于提取 Lua 解密密钥的启动器/客户端 exe（默认自动探测）
    #[arg(short, long, value_name = "EXE")]
    launcher: Option<PathBuf>,

    /// 仅列出包内条目，不解包
    #[arg(long)]
    list: bool,

    /// 跳过 Lua 字节码解密，写出 zlib 解压后的原始数据
    #[arg(long)]
    no_lua_decrypt: bool,

    /// 并行线程数（默认：CPU 核数）
    #[arg(short, long, value_name = "N")]
    jobs: Option<usize>,
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(&args) {
        eprintln!("错误：{e:#}");
        std::process::exit(1);
    }
}

fn run(args: &Args) -> Result<()> {
    if let Some(j) = args.jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(j)
            .build_global()
            .context("初始化线程池失败")?;
    }

    let file_len = std::fs::metadata(&args.package)
        .with_context(|| format!("打开 {} 失败", args.package.display()))?
        .len();
    let mut reader = File::open(&args.package)
        .with_context(|| format!("打开 {} 失败", args.package.display()))?;
    let pkg = pck::parse(&mut reader, file_len)
        .with_context(|| format!("解析 {} 失败", args.package.display()))?;
    println!(
        "包：{}（{} 字节）  版本 {}  条目 {}  数据区 @ {}",
        args.package.display(),
        file_len,
        pkg.header.version,
        pkg.entries.len(),
        pkg.header.index_end
    );

    if args.list {
        list_entries(&pkg);
        return Ok(());
    }

    let output = args
        .output
        .clone()
        .unwrap_or_else(|| default_output(&args.package));
    ensure_output_safe(&output, &args.package)?;

    // Lua 解密密钥：从启动器二进制静态提取（无需启动游戏）。
    let lua_key = if args.no_lua_decrypt {
        None
    } else {
        match resolve_key(&args.launcher, &args.package) {
            Ok(Some((k, src))) => {
                println!("Lua 密钥：{src}（{} 字节）", k.len());
                Some(k)
            }
            Ok(None) => {
                println!("已指定 --no-lua-decrypt，跳过 Lua 字节码解密");
                None
            }
            Err(e) => {
                eprintln!("警告：{e:#}");
                eprintln!("未获得密钥，Lua 条目将保持原始数据继续解包");
                None
            }
        }
    };

    extract_all(&args.package, &pkg, &output, lua_key.as_deref())
}

fn default_output(package: &Path) -> PathBuf {
    let stem = package
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unpacked".to_string());
    PathBuf::from(format!("{stem}_unpacked"))
}

/// 拒绝把输出放进包文件所在目录树内（避免写入游戏安装目录）。
fn ensure_output_safe(output: &Path, package: &Path) -> Result<()> {
    let out_abs = std::path::absolute(output)
        .with_context(|| format!("输出路径非法：{}", output.display()))?;
    let pkg_dir = package
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let pkg_dir_abs = std::path::absolute(pkg_dir)
        .with_context(|| format!("包路径非法：{}", package.display()))?;
    let norm = |p: &Path| p.to_string_lossy().to_lowercase().replace('/', "\\");
    if norm(&out_abs).starts_with(&norm(&pkg_dir_abs)) {
        bail!(
            "输出目录 {} 位于包文件所在目录 {} 内（游戏目录只读，请用 -o 指定其他位置）",
            out_abs.display(),
            pkg_dir_abs.display()
        );
    }
    Ok(())
}

fn resolve_key(
    launcher: &Option<PathBuf>,
    package: &Path,
) -> Result<Option<(Vec<u8>, String)>> {
    let path = match launcher {
        Some(p) => p.clone(),
        None => key::find_launcher(package).ok_or_else(|| {
            anyhow::anyhow!(
                "未自动探测到启动器（尝试过 ../updater_/fxupdate.exe 等），请用 -l 指定 fxupdate.exe 或 fxgame.exe"
            )
        })?,
    };
    let (k, note) = key::extract_key(&path)?;
    let src = format!("{}（{}）", path.display(), note);
    Ok(Some((k, src)))
}

fn list_entries(pkg: &pck::Package) {
    for (i, e) in pkg.entries.iter().enumerate() {
        let pkg_name = e.package_name.as_deref().unwrap_or("-");
        println!(
            "{i:>6}  {:>12} -> {:>12}  {}  {:<24} {}",
            e.comp_size,
            e.raw_size,
            e.timestamp_string(),
            pkg_name,
            e.name
        );
    }
}

fn extract_all(
    package_path: &Path,
    pkg: &pck::Package,
    output: &Path,
    lua_key: Option<&[u8]>,
) -> Result<()> {
    let shared = Mutex::new(
        File::open(package_path)
            .with_context(|| format!("打开 {} 失败", package_path.display()))?,
    );
    let pb = ProgressBar::new(pkg.entries.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:38.cyan/blue}] {pos}/{len} ({percent}%) {bytes_per_sec} {msg}",
        )
        .unwrap()
        .progress_chars("##-"),
    );

    let results: Vec<(String, Result<Outcome>)> = pkg
        .entries
        .par_iter()
        .map(|e| {
            let r = extract_entry(&shared, e, output, lua_key);
            if let Ok(o) = &r {
                pb.set_message(format!("{} ({})", truncate(&e.name, 40), o.label()));
            }
            pb.inc(1);
            (e.name.clone(), r)
        })
        .collect();

    pb.finish_and_clear();

    let mut ok = 0usize;
    let mut lua_ok = 0usize;
    let mut lua_fallback = 0usize;
    let mut errors = Vec::new();
    let mut total_bytes = 0u64;
    for (name, r) in results {
        match r {
            Ok(Outcome::Plain(n)) => {
                ok += 1;
                total_bytes += n;
            }
            Ok(Outcome::Lua(n)) => {
                ok += 1;
                total_bytes += n;
                lua_ok += 1;
            }
            Ok(Outcome::LuaFallbackRaw) => {
                ok += 1;
                lua_fallback += 1;
            }
            Err(e) => errors.push((name, e)),
        }
    }

    println!("输出目录：{}", output.display());
    println!(
        "完成：{}/{} 成功（解压 {total_bytes} 字节），其中 Lua 解密 {lua_ok} 个",
        ok,
        pkg.entries.len()
    );
    if lua_fallback > 0 {
        println!(
            "警告：{lua_fallback} 个 Lua 条目解密失败，已按原始数据写出（可能是密钥不匹配）"
        );
    }
    if !errors.is_empty() {
        eprintln!("失败 {} 个：", errors.len());
        for (name, e) in errors.iter().take(20) {
            eprintln!("  {name}: {e:#}");
        }
        if errors.len() > 20 {
            eprintln!("  …… 其余 {} 个略", errors.len() - 20);
        }
        bail!("有 {} 个条目解包失败", errors.len());
    }
    Ok(())
}

enum Outcome {
    /// 写出字节数（普通条目）。
    Plain(u64),
    /// 写出字节数（Lua 条目且解密成功）。
    Lua(u64),
    /// Lua 条目但解密失败，回退写原始数据。
    LuaFallbackRaw,
}

impl Outcome {
    fn label(&self) -> &'static str {
        match self {
            Outcome::Plain(_) => "ok",
            Outcome::Lua(_) => "lua解密",
            Outcome::LuaFallbackRaw => "lua原始",
        }
    }
}

fn extract_entry(
    shared: &Mutex<File>,
    e: &pck::Entry,
    output: &Path,
    lua_key: Option<&[u8]>,
) -> Result<Outcome> {
    if e.comp_size as u64 > MAX_ENTRY_COMP {
        bail!("压缩块过大：{} 字节", e.comp_size);
    }
    // .patch 条目按目标包名分目录（如 out/res/share.package/...），散文件直接落地。
    let mut dest = match &e.package_name {
        Some(pkg) => pck::safe_output_path(output, pkg),
        None => output.to_path_buf(),
    };
    dest = pck::safe_output_path(&dest, &e.name);

    let mut data = if e.comp_size == 0 {
        Vec::new()
    } else {
        let mut buf = vec![0u8; e.comp_size as usize];
        {
            let mut f = shared.lock().unwrap();
            f.seek(SeekFrom::Start(e.data_offset))
                .with_context(|| format!("seek {} 失败", e.name))?;
            f.read_exact(&mut buf)
                .with_context(|| format!("读取 {} 数据失败", e.name))?;
        }
        let mut out = Vec::with_capacity(e.raw_size as usize);
        flate2::read::ZlibDecoder::new(&buf[..])
            .read_to_end(&mut out)
            .with_context(|| format!("zlib 解压 {} 失败", e.name))?;
        if out.len() as u64 != e.raw_size as u64 {
            bail!(
                "{} 解压大小不符：实际 {}，索引声明 {}",
                e.name,
                out.len(),
                e.raw_size
            );
        }
        out
    };

    let outcome = match lua_key {
        Some(k) if lua::is_lua_dump(&data) => match lua::decrypt(&data, k) {
            Ok(dec) => {
                let n = dec.len() as u64;
                data = dec;
                Outcome::Lua(n)
            }
            Err(err) => {
                eprintln!("警告：{} Lua 解密失败（{err:#}），写出原始数据", e.name);
                Outcome::LuaFallbackRaw
            }
        },
        _ => Outcome::Plain(data.len() as u64),
    };

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建目录 {} 失败", parent.display()))?;
    }
    std::fs::write(&dest, &data).with_context(|| format!("写出 {} 失败", dest.display()))?;
    Ok(outcome)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}…")
    }
}
