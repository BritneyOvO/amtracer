# DebugPlz

Android ARM64 进程追踪工具，基于 Rust / Aya。

- **uprobe**：多探针、寄存器与内存表达式、原生调用栈。
- **itrace**：指定范围逐指令追踪，输出反汇编与寄存器增量。
- **syscall / Binder**：复用 ktools 驱动，支持系统调用栈与 Binder 回复关联。
- **混合会话**：JSON 配置，统一 JSONL 输出，按时长或事件数停止。

需要 root 及相应内核权限。uprobe 需要 eBPF / perf 支持；itrace 需要配套 UXN-uprobe 内核；syscall / Binder 需要 ktools trace 驱动。当前支持独立 ARM64 ELF，不支持 APK 内直接映射的库或匿名 JIT。

## 构建与部署

主机：Linux x86_64、Rust stable / nightly（含 rust-src）、Android NDK、`bpf-linker`。首次环境配置见 [使用指南](docs/usage.md#构建)。

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk
cargo xtask build

adb shell mkdir -p /data/local/tmp/debugplz
adb push artifacts/debugplz artifacts/debugplz-*.o /data/local/tmp/debugplz/
adb shell chmod 700 /data/local/tmp/debugplz/debugplz
```

## 使用

在设备 root shell 中执行，替换 PID、库名和地址：

```sh
cd /data/local/tmp/debugplz
./debugplz doctor

# 多探针、寄存器、内存与调用栈
./debugplz uprobe -p 1234 \
  --probe 'libfoo.so+target_func' --probe 'libfoo.so+0x1234' \
  --print 'r13' --print '*r13' --print '*(r13 + 1W):u16' \
  --stack --count 10 --json

# 逐指令追踪
./debugplz itrace -p 1234 --range 'libfoo.so+0x1200:0x40' \
  --regs --count 1000 --json

# 系统调用 / Binder
./debugplz syscall -p 1234 --syscalls openat,read,write --stack --duration 5 --json
./debugplz binder -p 1234 --with-replies --duration 5 --json

# 混合会话（先修改配置中的 PID 与探针）
./debugplz run --config ./session.json
```

`--probe` 支持 `库名+ELF地址`、`库名+符号[+偏移]`、绝对虚拟地址，可重复指定。表达式中的 `B/W/D/Q` 表示偏移单位 1/2/4/8 字节，默认解引用为 u64。

`--duration` 限制秒数，`--count` 限制输出事件数，默认均不限；Ctrl-C 结束并清理。事件写 stdout，诊断与统计写 stderr。完整参数见 `debugplz <命令> --help`。

## 文档

- [使用指南](docs/usage.md)：定位语法、表达式、参数采集、输出与限制。
- [混合会话配置](docs/session-example.json) · [指令追踪设计](docs/instruction-trace.md)
- [构建检查与实机测试](docs/testing.md) · [性能报告](docs/itrace-efficiency-2026-11-25.md)
- [整体设计](docs/design.md) · [实施记录](docs/implementation.md) · [Roadmap](docs/roadmap.md)
