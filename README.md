# amtracer

Android ARM64 追踪工具。Aya 用于 uprobe，syscall 与 Binder 使用现有 ktools 驱动。
设计见 [docs/design.md](docs/design.md)，提交与验收计划见 [docs/roadmap.md](docs/roadmap.md)。

## 构建

需要 Rust stable（已验证 1.99.1）、nightly + rust-src、Android NDK、bpf-linker 0.13.0。
用户态与 eBPF 依赖固定在 Cargo.lock。bpf-linker 建议使用上游 release，避免依赖本机 LLVM 版本。

```sh
rustup target add aarch64-linux-android
rustup component add rust-src --toolchain nightly
export ANDROID_NDK_HOME=/path/to/android-ndk
cargo xtask build
```

产物为 `artifacts/amtracer` 与 `artifacts/amtracer-ebpf.o`，部署在同一目录即可。
只有 uprobe 子命令加载 eBPF 对象。`--object` 可指定其他路径。
当前 Android 构建以 API 30 为基线，原生目标只支持 AArch64。

## 当前可用入口

```sh
./amtracer doctor
./amtracer resolve -p 1234 --probe 'libfoo.so+target'
./amtracer uprobe -p 1234 --probe 'libfoo.so+target' --regs --duration 5 --json
./amtracer uprobe -p 1234 --probe 'libfoo.so+target' --print '*r13' --print '*(r13+1Q):u16'
./amtracer uprobe -p 1234 --probe 'libfoo.so+target' --print 'cstr(x0,128)' --print 'bytes(x1,64)'
./amtracer syscall -p 1234 --syscalls openat,read,write --duration 5 --json
./amtracer binder -p 1234 --duration 5 --json
```

`--count` 限制事件数，`--duration` 单位为秒，0 表示不限。Ctrl-C 关闭本次会话。
Binder 的 PID 过滤是事件发生进程，不保证另一端回复也被捕获。
本阶段文本暂为格式化 JSON，`--json` 为逐行 JSON。
`--print` 可以重复使用，支持寄存器、加减常量、最多四层解引用、类型后缀与 bytes/cstr。
每个表达式暂支持一条寄存器/指针链，不支持 `x0+x1`；每探针最多 16 项、额外内存总量 4 KiB。
B/W/D/Q 是 1/2/4/8 字节偏移，默认解引用宽度为 u64。读取故障、截断和溢出分别显示状态。
uprobe 和 syscall 的 `--stack` 使用 framehop 解栈并输出模块、符号、偏移和停止原因。
只读取命中时的栈快照。syscall 驱动的 nofault 栈采集失败会显示 `capture_fault`，可缩小
`--stack-bytes`；uprobe 的跨页读取保留有效前缀。
APK 内库定位尚未接入，遇到 APK 文件会报告解析错误。

## UAPI 和检查

```sh
cargo xtask sync-uapi /path/to/kernel/common
cargo xtask gen-uapi
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

UAPI 更新是显式操作。普通构建使用已提交的绑定，不要求 bindgen 或内核源码。
`uapi/SOURCE.md` 记录原始头的来源和 SHA-256，绑定包含 ARM64 布局断言。

真机 smoke 脚本只操作它创建的受控 fixture，必须指定设备，不抢占已有 trace 会话。
fixture 构建示例（从项目目录）：

```sh
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
  -O1 -fno-omit-frame-pointer -fno-optimize-sibling-calls -Wl,--export-dynamic -pthread \
  tests/fixtures/native.c tests/fixtures/native.S -o target/amtracer-fixture
python3 tests/device_smoke.py --serial 282eb4e4
```

2026-11-24 已在 fuxi 验证符号/绝对地址 uprobe、x13、syscall getpid ENTER/EXIT、Binder
会话开关、16 项表达式和 uprobe/syscall 原生回溯；有/无帧指针 fixture 均通过。
另有 `tests/binder_smoke.py --serial 282eb4e4`，验证受控进程无效句柄事务的结果、
同步/oneway 标记、发送者、数据截断与 Android 13 interface token。先构建对应 fixture：

```sh
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
  -O2 -Wall -Wextra tests/fixtures/binder.c -o target/amtracer-binder-fixture
python3 tests/binder_smoke.py --serial 282eb4e4
```

Binder 成功事务及请求/回复关联、PAC 完整矩阵、APK、混合会话和性能基准仍未完成。
完整进度与限制见 [docs/implementation.md](docs/implementation.md)。
