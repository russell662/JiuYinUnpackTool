# jiuyin-unpack

九阴真经（9yinjh）`.package` / `.patch` 资源包命令行解包工具，纯 Rust 实现。

- **PCK0 v15 容器**：明文索引 + 逐条目标准 zlib，直接解包
- **Lua 字节码去混淆**：`.lua` 条目内的 Lua 5.1 dump 被逐字段 XOR，本工具按
  ldump.c 的字段粒度精确还原为标准 Lua 5.1 字节码
- **密钥静态提取**：直接从启动器/客户端 exe 的明文区读取 XOR 密钥，**无需启动游戏**
- 进度条、多线程并行解包、防路径穿越、拒绝向包所在目录（游戏目录）输出

## 用法

```text
jiuyin-unpack <PACKAGE> [OPTIONS]
jiuyin-unpack --all-packages <游戏安装目录> [OPTIONS]
jiuyin-unpack --all-patches <游戏安装目录> [OPTIONS]

参数：
  <PACKAGE>              .package 或 .patch 文件路径（三选一）

选项：
  --all-packages <DIR>   递归解包该目录下所有 .package 文件
  --all-patches <DIR>    递归解包该目录下所有 .patch 文件（两者可同时指定）
  -o, --output <DIR>     输出目录（单包默认：./<包名>_unpacked；
                         批量默认：./<目录名>_packages|patches_unpacked）
  -l, --launcher <EXE>   用于提取解密密钥的启动器/客户端 exe
                         （默认自动探测：../updater_/fxupdate.exe →
                          ../updater/fxupdate.exe → ../bin64/fxgame.exe）
      --list             仅列出条目（路径、压缩/原始大小、时间戳、目标包名）
      --no-lua-decrypt   跳过 Lua 字节码解密，写出原始数据
  -j, --jobs <N>         并行线程数（默认：CPU 核数）
```

示例：

```bash
# 列出包内条目（只读）
jiuyin-unpack --list "D:\游戏蜗牛\9yinjh\res\eff.package"

# 解包到指定目录（密钥自动从启动器提取）
jiuyin-unpack "D:\游戏蜗牛\9yinjh\res\lua.package" -o D:\out\lua

# 批量：解包安装目录下全部 .package（递归，统一进度条，按相对路径分目录）
jiuyin-unpack --all-packages "D:\游戏蜗牛\9yinjh" -o D:\out\all

# 批量：解包全部 .patch（可同时指定 --all-packages 一起跑）
jiuyin-unpack --all-patches "D:\游戏蜗牛\9yinjh\patch" -o D:\out\patches

# 指定另一个密钥来源
jiuyin-unpack "D:\游戏蜗牛\9yinjh\updater_\updater_lua.package" -l "D:\游戏蜗牛\9yinjh\bin64\fxgame.exe" -o D:\out\ulua
```

`.patch` 条目携带目标包名（如 `res\share.package`），输出组织为
`<out>/<目标包名>/<条目路径>`；散文件（如 `version.ini`）直接落在 `<out>` 下。
批量模式按包文件在扫描根目录下的**相对路径**分目录（如
`out/res/lua.package/...`、`out/patch/xxx.patch/...`），因此
`updater\` 与 `updater_\` 下的同名包不会互相覆盖；个别包解析失败会跳过并在
汇总中计数，不影响其余包。

## 格式分析

### PCK0 容器（.package 与 .patch 通用）

```text
头部 19 字节（条目区从 0x13 开始）:
  0x00  char[4]  魔数 "PCK0"
  0x04  u16      版本 = 15
  0x06  u16      标志：0 = 明文索引；4 = 索引区整体加密（新补丁格式）
  0x08  u16      保留 = 0
  0x0A  u32      条目数
  0x0E  u32      索引结束偏移（= 数据区起点）
  0x12  u8       0

条目（变长，连续排列，靠 u16 记录总长推进）:
  +0   u16   记录总长 = 27 + len(文件名)+1 (+ len(包名)+1，仅 .patch)
  +2   u64   数据绝对偏移
  +10  u32   原始大小（解压后）
  +14  u32   压缩大小
  +18  7B    时间戳（u16 LE 年 + 月/日/时/分/秒）
  +25  u16   扩展：普通包恒 0；.patch 为 0（散文件）或 len(文件名)+1（后跟目标包名）
  +27  NUL 串  文件名（GBK，反斜杠路径）
  可选 NUL 串  目标包名（仅 .patch，扩展≠0 时）

数据区：逐条目独立的标准 zlib 流（78 9C），无容器层加密。
```

### 关于索引加密的新补丁格式（暂不支持）

2026-05 前后的补丁（实测 1.0.2.596-597 起）头部标志为 4，索引区（0x13 至
索引结束偏移）整体被加密，数据块仍为明文 zlib（首块 `version.ini` 可直接
解压验证）。已排除的加密方式：523 字节密钥的连续/旋转 XOR、按记录重置 XOR、
exe 内全部可打印串作 XOR/RC4 密钥。破解需要逆向加壳的更新器
（`fxupdate.exe`），故当前版本遇到此类包会给出明确报错并跳过
（实测 17 个补丁中 12 个可正常解包，5 个为新格式）。

### Lua 5.1 字节码 XOR 层（唯一加密）

`.lua` 条目 zlib 解压后为 Lua 5.1 dump：前 12 字节头明文
（`\x1bLuaQ` + 各字段宽度，offset 8 = sizeof(size_t)：游戏端 4、更新器端 8），
其后内容**逐字段 XOR**：

- 每个独立 dump 字段（对应 ldump.c 的一次 Dump 调用）各自从密钥下标 0 开始；
- 指令数组 / 行号数组整块算一个字段，不在元素间重置；
- 字符串的 size_t 前缀与内容是两个独立字段；
- 常量的 tag 与数据、4 个栈信息 byte 均各自为独立字段。

### 密钥来源（无需启动游戏）

523 字节可打印 ASCII 的 C 字符串（NUL 结尾），静态存在于：

| 文件 | 偏移 |
|---|---|
| `updater_\fxupdate.exe`（及 `updater\` 同名文件） | 0x4EE40（.rdata） |
| `bin64\fxgame.exe` | 0x64530 |

两处逐字节一致。工具以 16 字节签名锚点定位后向后取整串；签名未命中时
退化为取文件中最长可打印串（应对密钥轮换），并由 undump 结构校验把关。

## 实测记录（2026-08，1.0.2.584 客户端）

| 包 | 条目 | 结果 |
|---|---|---|
| `res/eff.package` | 79 | 全部成功，`.c` 为明文 HLSL 着色器 |
| `res/lua.package` | 2251 | 全部成功，2250 个 Lua 解密（chunkname `@G:\Version_wx_JinJi\...` 可读） |
| `res/ini.package` | 18459 | 全部成功（84MB，约 1.6s） |
| `updater_/updater_lua.package` | 11 | 全部成功，11 个 Lua 解密（size_t=8） |
| `updater_/updater_res.package` | 572 | 全部成功，PNG 完好 |
| `patch/jyzj-1.0.2.585-1.0.2.586.patch` | 6 | 全部成功，按目标包名分目录 |
| 批量 `--all-packages`（整个安装目录） | 58 包 | 全部解析并可解包（res + updater + updater_） |
| 批量 `--all-patches`（patch 目录） | 17 包 | 12 个成功，5 个为索引加密新格式被跳过 |

`-l bin64\fxgame.exe` 与默认 `fxupdate.exe` 提取的密钥解密结果逐字节一致；
游戏目录全程零写入（工具亦内置输出目录防护，拒绝向包所在目录树输出）。

## 构建

```bash
cargo build --release   # 产物 target/release/jiuyin-unpack.exe
cargo test              # 单元测试（PCK 解析 / Lua 往返解密 / 密钥定位 / 路径清洗）
```

## 项目结构

```text
src/
  main.rs   CLI（clap）、进度条（indicatif）、并行解包（rayon）与汇总
  pck.rs    PCK0 头/条目解析、GBK 文件名解码、安全输出路径
  key.rs    启动器密钥提取（签名锚点 + 最长可打印串兜底）与自动探测
  lua.rs    Lua 5.1 undump 结构遍历与逐字段去 XOR（含结构校验）
```

仅供学习研究游戏资源格式之用。
