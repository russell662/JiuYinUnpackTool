//! jiuyin-unpack 可执行入口：CLI 编排、进度条、并行解包与汇总。
//! 格式解析与算法实现见 `src/lib.rs`（crate `jiuyin_unpack`），测试见 `tests/`。

use anyhow::{bail, Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use jiuyin_unpack::cli::{scan_packages, validate_modes, Args};
use jiuyin_unpack::{key, lua, pck};
use rayon::prelude::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// 单条目压缩块读取上限（防御异常索引；实测条目远小于此值）。
const MAX_ENTRY_COMP: u64 = 512 * 1024 * 1024;

fn main() {
    let args = Args::parse();
    if let Err(e) = run(&args) {
        eprintln!("错误：{e:#}");
        std::process::exit(1);
    }
}

fn run(args: &Args) -> Result<()> {
    validate_modes(args)?;
    if let Some(j) = args.jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(j)
            .build_global()
            .context("初始化线程池失败")?;
    }

    if let Some(package) = &args.package {
        return run_single(args, package);
    }

    // 批量模式：--all-packages 与 --all-patches 可同时指定（各自扫描）。
    let mut failures = 0usize;
    if let Some(root) = &args.all_packages {
        failures += run_batch(args, root, "package")?;
    }
    if let Some(root) = &args.all_patches {
        failures += run_batch(args, root, "patch")?;
    }
    if failures > 0 {
        bail!("批量解包共 {failures} 个条目/包失败");
    }
    Ok(())
}

// ---------- 单包模式 ----------

fn run_single(args: &Args, package: &Path) -> Result<()> {
    let pkg = open_package(package)?;
    println!(
        "包：{}（{} 字节）  版本 {}  条目 {}  数据区 @ {}",
        package.display(),
        pkg_file_len(package)?,
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
        .unwrap_or_else(|| default_single_output(package));
    ensure_output_safe(&output, package)?;

    let lua_key = resolve_key(&args.launcher, package.parent(), args.no_lua_decrypt);

    let pb = new_progress_bar(pkg.entries.len() as u64);
    let summary = extract_all(&pb, "", package, &pkg, &output, lua_key.as_deref())?;
    pb.finish_and_clear();
    print_summary(&output, &summary);
    if !summary.errors.is_empty() {
        print_errors(&summary);
        bail!("有 {} 个条目解包失败", summary.errors.len());
    }
    Ok(())
}

// ---------- 批量模式 ----------

fn run_batch(args: &Args, root: &Path, kind: &str) -> Result<usize> {
    let files = scan_packages(root, kind)?;
    if files.is_empty() {
        bail!("在 {} 下未找到任何 .{kind} 文件", root.display());
    }
    println!(
        "批量模式（.{kind}）：{} 个包，根目录 {}",
        files.len(),
        root.display()
    );

    // 全部先解析（仅读头部与索引），既提前暴露损坏/不支持格式，也便于统一进度条。
    let mut parsed: Vec<(PathBuf, pck::Package)> = Vec::new();
    let mut skipped = 0usize;
    for f in &files {
        match open_package(f) {
            Ok(pkg) => parsed.push((f.clone(), pkg)),
            Err(e) => {
                skipped += 1;
                eprintln!("跳过 {}：{e:#}", f.display());
            }
        }
    }
    if parsed.is_empty() {
        bail!("根目录下没有可解析的 .{kind} 文件（{skipped} 个被跳过）");
    }
    if args.list {
        for (i, (path, pkg)) in parsed.iter().enumerate() {
            println!(
                "\n[{}/{}] {}（{} 字节）  条目 {}",
                i + 1,
                parsed.len(),
                path.display(),
                pkg_file_len(path)?,
                pkg.entries.len()
            );
            list_entries(pkg);
        }
        return Ok(0);
    }

    let output = args
        .output
        .clone()
        .unwrap_or_else(|| default_batch_output(root, kind));
    ensure_output_safe(&output, root)?;

    let lua_key = resolve_key(&args.launcher, Some(root), args.no_lua_decrypt);

    let total_entries: u64 = parsed.iter().map(|(_, p)| p.entries.len() as u64).sum();
    let pb = new_progress_bar(total_entries);
    let mut total_failures = 0usize;
    let mut total_bytes = 0u64;
    let mut total_lua = 0usize;
    for (i, (path, pkg)) in parsed.iter().enumerate() {
        // 按包在安装目录下的相对路径分目录，避免 updater/ 与 updater_/ 等同名包互相覆盖。
        let rel = path.strip_prefix(root).unwrap_or(path.as_path());
        let dest = pck::safe_output_path(&output, &rel.to_string_lossy());
        let prefix = format!("[{}/{}] ", i + 1, parsed.len());
        let summary = match extract_all(&pb, &prefix, path, pkg, &dest, lua_key.as_deref()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{prefix}{} — 打开失败：{e:#}", rel.display());
                total_failures += pkg.entries.len();
                continue;
            }
        };
        println!(
            "{prefix}{} — {}/{} 成功（{} 字节），Lua 解密 {}",
            rel.display(),
            summary.ok,
            summary.total,
            summary.bytes,
            summary.lua_ok
        );
        if !summary.errors.is_empty() {
            print_errors(&summary);
        }
        total_failures += summary.errors.len();
        total_bytes += summary.bytes;
        total_lua += summary.lua_ok;
    }
    pb.finish_and_clear();
    println!(
        "\n批量完成：{} 个包（另跳过 {skipped} 个），输出目录 {}，解压 {} 字节，Lua 解密 {} 个，失败 {} 个条目",
        parsed.len(),
        output.display(),
        total_bytes,
        total_lua,
        total_failures
    );
    Ok(total_failures + skipped)
}

// ---------- 公共流程 ----------

fn open_package(package: &Path) -> Result<pck::Package> {
    let file_len = pkg_file_len(package)?;
    let mut reader =
        File::open(package).with_context(|| format!("打开 {} 失败", package.display()))?;
    pck::parse(&mut reader, file_len)
        .with_context(|| format!("解析 {} 失败", package.display()))
}

fn pkg_file_len(package: &Path) -> Result<u64> {
    std::fs::metadata(package)
        .with_context(|| format!("打开 {} 失败", package.display()))
        .map(|m| m.len())
}

fn default_single_output(package: &Path) -> PathBuf {
    let stem = package
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unpacked".to_string());
    PathBuf::from(format!("{stem}_unpacked"))
}

fn default_batch_output(root: &Path, kind: &str) -> PathBuf {
    let name = root
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "install".to_string());
    PathBuf::from(format!("{name}_{kind}s_unpacked"))
}

/// 拒绝把输出放进包文件所在目录树内（避免写入游戏安装目录）。
/// guard_base 为单包模式的包目录，或批量模式的扫描根目录。
fn ensure_output_safe(output: &Path, guard_base_file_or_dir: &Path) -> Result<()> {
    let out_abs = std::path::absolute(output)
        .with_context(|| format!("输出路径非法：{}", output.display()))?;
    let base = if guard_base_file_or_dir.is_dir() {
        guard_base_file_or_dir.to_path_buf()
    } else {
        guard_base_file_or_dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf()
    };
    let base_abs = std::path::absolute(&base)
        .with_context(|| format!("路径非法：{}", base.display()))?;
    let norm = |p: &Path| p.to_string_lossy().to_lowercase().replace('/', "\\");
    if norm(&out_abs).starts_with(&norm(&base_abs)) {
        bail!(
            "输出目录 {} 位于 {} 内（游戏目录只读，请用 -o 指定其他位置）",
            out_abs.display(),
            base_abs.display()
        );
    }
    Ok(())
}

fn resolve_key(
    launcher: &Option<PathBuf>,
    anchor_dir: Option<&Path>,
    no_lua_decrypt: bool,
) -> Option<Vec<u8>> {
    if no_lua_decrypt {
        println!("已指定 --no-lua-decrypt，跳过 Lua 字节码解密");
        return None;
    }
    let anchor = anchor_dir.unwrap_or(Path::new("."));
    let path = match launcher {
        Some(p) => p.clone(),
        None => match key::find_launcher(anchor) {
            Some(p) => p,
            None => {
                eprintln!(
                    "警告：未自动探测到启动器（尝试过 ../updater_/fxupdate.exe 等），请用 -l 指定 fxupdate.exe 或 fxgame.exe"
                );
                eprintln!("未获得密钥，Lua 条目将保持原始数据继续解包");
                return None;
            }
        },
    };
    match key::extract_key(&path) {
        Ok((k, note)) => {
            println!("Lua 密钥：{note}（{}，{} 字节）", path.display(), k.len());
            Some(k)
        }
        Err(e) => {
            eprintln!("警告：{e:#}");
            eprintln!("未获得密钥，Lua 条目将保持原始数据继续解包");
            None
        }
    }
}

fn new_progress_bar(len: u64) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:38.cyan/blue}] {pos}/{len} ({percent}%) {bytes_per_sec} {msg}",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    pb
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

/// 单个包（或批量中的单个包）的解包统计。
struct PackageSummary {
    total: usize,
    ok: usize,
    lua_ok: usize,
    lua_fallback: usize,
    bytes: u64,
    errors: Vec<(String, String)>,
}

fn extract_all(
    pb: &ProgressBar,
    msg_prefix: &str,
    package_path: &Path,
    pkg: &pck::Package,
    output: &Path,
    lua_key: Option<&[u8]>,
) -> Result<PackageSummary> {
    let shared = Mutex::new(
        File::open(package_path).with_context(|| format!("打开 {} 失败", package_path.display()))?,
    );
    let results: Vec<(String, Result<Outcome>)> = pkg
        .entries
        .par_iter()
        .map(|e| {
            let r = extract_entry(&shared, e, output, lua_key);
            if let Ok(o) = &r {
                pb.set_message(format!(
                    "{msg_prefix}{} ({})",
                    truncate(&e.name, 40),
                    o.label()
                ));
            }
            pb.inc(1);
            (e.name.clone(), r)
        })
        .collect();

    let mut s = PackageSummary {
        total: pkg.entries.len(),
        ok: 0,
        lua_ok: 0,
        lua_fallback: 0,
        bytes: 0,
        errors: Vec::new(),
    };
    for (name, r) in results {
        match r {
            Ok(Outcome::Plain(n)) => {
                s.ok += 1;
                s.bytes += n;
            }
            Ok(Outcome::Lua(n)) => {
                s.ok += 1;
                s.bytes += n;
                s.lua_ok += 1;
            }
            Ok(Outcome::LuaFallbackRaw) => {
                s.ok += 1;
                s.lua_fallback += 1;
            }
            Err(e) => s.errors.push((name, format!("{e:#}"))),
        }
    }
    Ok(s)
}

fn print_summary(output: &Path, s: &PackageSummary) {
    println!("输出目录：{}", output.display());
    println!(
        "完成：{}/{} 成功（解压 {} 字节），其中 Lua 解密 {} 个",
        s.ok, s.total, s.bytes, s.lua_ok
    );
    if s.lua_fallback > 0 {
        println!(
            "警告：{} 个 Lua 条目解密失败，已按原始数据写出（可能是密钥不匹配）",
            s.lua_fallback
        );
    }
}

fn print_errors(s: &PackageSummary) {
    eprintln!("失败 {} 个：", s.errors.len());
    for (name, e) in s.errors.iter().take(20) {
        eprintln!("  {name}: {e}");
    }
    if s.errors.len() > 20 {
        eprintln!("  …… 其余 {} 个略", s.errors.len() - 20);
    }
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
