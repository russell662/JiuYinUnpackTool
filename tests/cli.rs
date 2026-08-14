//! CLI 参数校验与批量目录扫描集成测试。

use jiuyin_unpack::cli::{scan_packages, validate_modes, Args};
use std::path::PathBuf;

#[test]
fn scan_finds_nested_packages_case_insensitive() {
    let root = std::env::temp_dir().join(format!(
        "jyu_scan_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mk = |rel: &str| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"").unwrap();
    };
    mk("res/eff.package");
    mk("res/map_mdl.package");
    mk("res/sub/UPPER.PACKAGE");
    mk("updater_/updater_lua.package");
    mk("patch/a.patch");
    mk("patch/b.PATCH");
    mk("res/not_a_package.txt");
    mk("res/package_readme.md");

    let pkgs = scan_packages(&root, "package").unwrap();
    let names: Vec<_> = pkgs
        .iter()
        .map(|p| {
            p.strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    assert_eq!(
        names,
        vec![
            "res/eff.package",
            "res/map_mdl.package",
            "res/sub/UPPER.PACKAGE",
            "updater_/updater_lua.package",
        ]
    );
    let patches = scan_packages(&root, "patch").unwrap();
    assert_eq!(patches.len(), 2);

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn mode_validation() {
    let mut args = Args {
        package: None,
        all_packages: None,
        all_patches: None,
        output: None,
        launcher: None,
        list: false,
        no_lua_decrypt: false,
        jobs: None,
    };
    assert!(validate_modes(&args).is_err());
    args.package = Some(PathBuf::from("a.package"));
    assert!(validate_modes(&args).is_ok());
    args.all_packages = Some(PathBuf::from("dir"));
    assert!(validate_modes(&args).is_err());
    args.package = None;
    assert!(validate_modes(&args).is_ok());
    args.all_patches = Some(PathBuf::from("dir"));
    assert!(validate_modes(&args).is_ok());
    args.output = Some(PathBuf::from("out"));
    assert!(validate_modes(&args).is_ok()); // 双批量共用 -o 无冲突（输出按相对路径区分）
}
