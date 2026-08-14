# jiuyin-unpack

九阴真经（9yinjh）`.package` / `.patch` 资源包命令行解包工具，Rust 实现。

## 用法

```text
jiuyin-unpack <PACKAGE> [OPTIONS]

参数：
  <PACKAGE>              .package 或 .patch 文件路径

选项：
  -o, --output <DIR>     输出目录（默认：./<包名去后缀>）
  -l, --launcher <EXE>   用于提取解密密钥的启动器/客户端 exe
                         （默认自动探测：../updater_/fxupdate.exe、
                          ../updater/fxupdate.exe、../bin64/fxgame.exe）
      --list             仅列出条目，不解包
      --no-lua-decrypt   跳过 Lua 字节码解密，写出原始数据
  -j, --jobs <N>         并行线程数（默认：CPU 核数）
  -h, --help             帮助
```

## 格式说明

详见 README「格式分析」一节：PCK0 v15 容器（明文索引 + 逐条目 zlib）、
`.lua` 条目内的 Lua 5.1 字节码逐字段 XOR 混淆层、以及从启动器二进制
（`fxupdate.exe` / `fxgame.exe`）静态提取 523 字节 XOR 密钥的方法。
