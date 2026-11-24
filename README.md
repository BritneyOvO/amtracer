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
./amtracer syscall -p 1234 --syscalls openat,write \
  --capture openat:1:string:128 --capture write:1:bytes:32 --duration 5 --json
./amtracer binder -p 1234 --duration 5 --json
```

`--count` 限制事件数，`--duration` 单位为秒，0 表示不限。Ctrl-C 关闭本次会话。
Binder 的 PID 过滤是事件发生进程，不保证另一端回复也被捕获。
`--capture SYSCALL:ARG:KIND[:BYTES]` 可重复指定 syscall 用户参数，参数编号从 0 开始，
类型为 `string`、`bytes` 或 `sockaddr`，默认上限分别为 256、256、128 字节；例如
`openat:1:string:128`。`--capture SYSCALL:stack:BYTES` 为单个 syscall 采集栈窗口。
采集规则覆盖驱动对同一 syscall 参数的内置采集，并会自动将对应 syscall 加入过滤列表。
自定义参数规则在 ENTER 时读取，因此 `--capture read:1:bytes:64` 是调用前快照；驱动已有的
`read` 输出采集仍会在 EXIT 事件中单独提供返回数据。`write` 输入 buffer 则适合用自定义
规则在入口采集。
本阶段文本暂为格式化 JSON，`--json` 为逐行 JSON。
`--print` 可以重复使用，支持寄存器、加减常量、最多四层解引用、类型后缀与 bytes/cstr。
每个表达式暂支持一条寄存器/指针链，不支持 `x0+x1`；每探针最多 16 项、额外内存总量 4 KiB。
B/W/D/Q 是 1/2/4/8 字节偏移，默认解引用宽度为 u64。读取故障、截断和溢出分别显示状态。
uprobe 和 syscall 的 `--stack` 使用 framehop 解栈并输出模块、符号、偏移和停止原因。
只读取命中时的栈快照。syscall 驱动的 nofault 栈采集失败会显示 `capture_fault`，可缩小
`--stack-bytes`；uprobe 的跨页读取保留有效前缀。
不支持直接从 APK 映射的库；仅支持可访问的独立 ELF 文件。
会话定期检查目标的启动时间与可执行文件身份，发现进程退出、PID 复用或可执行文件
身份变化时退出。探针对应的可执行映射变化时会停止 uprobe；开启栈回溯时，可执行映射
变化会重建解栈缓存。检查间隔为 250 ms，无法检测两次检查之间完成的瞬时变化，也不能
保证队列中旧事件使用采集时的映射；同一可执行文件的 exec 尚未完整检测。

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
python3 tests/process_smoke.py --serial 282eb4e4
```

动态映射测试还需构建受控的两个 so 和加载程序：

```sh
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
"$CC" -O1 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls -shared -fPIC tests/fixtures/mapping_lib.c -o target/libmap_a.so
"$CC" -O1 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls -shared -fPIC tests/fixtures/mapping_lib.c -o target/libmap_b.so
"$CC" -O1 -g -fno-omit-frame-pointer -Wall -Wextra tests/fixtures/mapping_runner.c -ldl -pthread -o target/mapping-runner
python3 tests/mapping_smoke.py --serial 282eb4e4
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

Binder 成功事务及请求/回复关联、PAC 完整矩阵、混合会话和性能基准仍未完成。
完整进度与限制见 [docs/implementation.md](docs/implementation.md)。
