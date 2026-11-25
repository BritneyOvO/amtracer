# 构建检查与设备验证

所有命令从仓库根目录执行。功能状态以 [实施记录](implementation.md) 和 [roadmap](roadmap.md) 为准；本页提供复现步骤，不表示完整验收已经完成。

## 主机检查

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo xtask build
```

`cargo test` 默认覆盖用户态、ABI 和 xtask，不运行 Android fixture。eBPF release 构建由 `cargo xtask build` 执行。

## 设备和工具准备

设备测试需要 Python 3、ADB、NDK，以及已运行配套内核、具有相应权限的 ADB shell。**脚本直接执行 `adb shell`，不会自动调用 `su`。** 手工运行工具可使用 `su`，但运行这些脚本前需自行准备有权限的 ADB 环境。

每个脚本都要求显式指定设备，只操作它创建的受控目标；已有 syscall / Binder trace 被占用时应报错，不抢占其他会话。无需刷机或联系系统 Binder 服务。

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk
AMTRACER_CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
SERIAL=your-device-serial

adb -s "$SERIAL" get-state
mkdir -p target
```

已有记录的验证设备为 fuxi，序列号 `282eb4e4`。测试前先完成 `cargo xtask build`，确保 `artifacts/amtracer` 与 `artifacts/amtracer-ebpf.o` 来自同一次构建。

## uprobe、表达式、syscall 与原生栈

```sh
"$AMTRACER_CC" -O1 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls \
  -Wl,--export-dynamic -pthread \
  tests/fixtures/native.c tests/fixtures/native.S -o target/amtracer-fixture

python3 tests/device_smoke.py --serial "$SERIAL"
python3 tests/process_smoke.py --serial "$SERIAL"
python3 tests/session_smoke.py --serial "$SERIAL"
```

| 脚本 | 覆盖范围 |
| --- | --- |
| `device_smoke.py` | 地址解析、符号 / ELF 地址 / 绝对 VA、多探针、线程、16 项表达式、字符串与跨页读取、uprobe / syscall 栈、syscall 参数、Binder 会话开关 |
| `process_smoke.py` | 三类会话在目标退出后结束，syscall / Binder 可以再次打开 |
| `session_smoke.py` | uprobe + syscall 同时采集、syscall + 空闲 Binder 的全局 count、无效 uprobe 启动后的会话回收 |

`device_smoke.py` 和 `session_smoke.py` 会上传工具和 fixture。`process_smoke.py` 复用 `/data/local/tmp/amtracer-smoke/` 中的文件，因此应在 `device_smoke.py` 后执行。

无帧指针的 fixture 可单独编译并另存报告：

```sh
"$AMTRACER_CC" -O1 -g -fomit-frame-pointer -fno-optimize-sibling-calls \
  -Wl,--export-dynamic -pthread \
  tests/fixtures/native.c tests/fixtures/native.S -o target/amtracer-fixture-no-fp

python3 tests/device_smoke.py --serial "$SERIAL" \
  --fixture target/amtracer-fixture-no-fp --report device-smoke-no-fp.json
```

这会将远端 `fixture` 替换为无帧指针版本；需要恢复时，重新执行默认的 `device_smoke.py`。

## 动态映射

```sh
"$AMTRACER_CC" -O1 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls \
  -shared -fPIC tests/fixtures/mapping_lib.c -o target/libmap_a.so
"$AMTRACER_CC" -O1 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls \
  -shared -fPIC tests/fixtures/mapping_lib.c -o target/libmap_b.so
"$AMTRACER_CC" -O1 -g -fno-omit-frame-pointer -Wall -Wextra \
  tests/fixtures/mapping_runner.c -ldl -pthread -o target/mapping-runner

python3 tests/mapping_smoke.py --serial "$SERIAL"
```

脚本使用独立目录 `/data/local/tmp/amtracer-mapping/`，验证 dlopen 后 syscall 栈识别新库，以及 dlclose 后对应 uprobe 会话停止。

## Binder 失败事务与成功配对

先验证无效句柄的同步 / oneway 失败请求、发送者、截断和 interface token。该脚本只上传自己的 Binder fixture，因此先显式部署工具：

```sh
"$AMTRACER_CC" -O2 -Wall -Wextra \
  tests/fixtures/binder.c -o target/amtracer-binder-fixture

adb -s "$SERIAL" shell mkdir -p /data/local/tmp/amtracer-smoke
adb -s "$SERIAL" push artifacts/amtracer /data/local/tmp/amtracer-smoke/amtracer
adb -s "$SERIAL" shell chmod 700 /data/local/tmp/amtracer-smoke/amtracer
python3 tests/binder_smoke.py --serial "$SERIAL"
```

再验证私有 client / service 的同步成功、回复 ID 配对和 oneway：

```sh
"$AMTRACER_CC" -O2 -Wall -Wextra \
  tests/fixtures/binder_pair.c -o target/amtracer-binder-pair
python3 tests/binder_pair_smoke.py --serial "$SERIAL"
```

成功配对测试要求可访问 `/dev/binderfs/binder-control`，允许创建私有 binderfs 设备并注册 context manager。fixture 使用唯一的临时设备，不连接系统服务，结束后清理设备节点。

`binder_pair_smoke.py` 会自行上传工具，并在结束时删除共享测试目录中的 `amtracer`、`amtracer-ebpf.o` 和 `binder-pair`。依赖这些文件的其他脚本应先执行，或在之后重新部署。

## recomp 指令 trace

2026-11-25 已在指定 fuxi 上通过受控 smoke，完整路径用例共核对 601 条事件且无丢失。
复现时先执行 `cargo xtask build`，再构建专用 fixture；其汇编
按 4 KiB 页隔离，含分支/循环、间接调用、跨页调用、80 NOP、可恢复访存异常和拒绝样例：

```sh
"$AMTRACER_CC" -O2 -g -Wall -Wextra -Werror \
  -Wl,--export-dynamic -Wl,-z,max-page-size=4096 -pthread \
  tests/fixtures/instruction.c tests/fixtures/instruction.S \
  -o target/amtracer-instruction-fixture

python3 tests/instruction_smoke.py --serial "$SERIAL"
python3 tests/instruction_delta.py --serial "$SERIAL"
```

脚本使用唯一的 `/data/local/tmp/amtracer-itrace-*` 目录，上传工具、`amtracer-itrace.o`
和 fixture；等待 `itrace: ready` 后再驱动目标。核对每 TID 的实际 PC 序列、序号、
原始 LR、寄存器返回值和丢失统计，覆盖重复范围、已有/新线程、跨 CPU、超过 64 点、
跨页、信号异常、排他/SVC 拒绝、原生后端回退、count、目标退出与再次安装。
它不使用系统进程；清理仅向仍指向自己目录下程序的 PID 发信号。
输出为 `artifacts/instruction-smoke.json`，原始 JSONL/stderr 留在同名子目录。

`instruction_delta.py` 校验 ABI v2 增量的完整重建、空变更和周期快照，并仅暂停自己的
消费进程，让 BPF 在 32 MiB 缓冲区写满后持续失败。恢复消费并再次驱动目标，核对缺口
之后的完整快照、后续寄存器值、载荷字节统计及 sticky incomplete。它产生数十万条
记录，需要为本地 JSONL 留出空间。每次测试的原始文件目录取 `--report` 去掉扩展名，
使用不同报告名即可保留旧结果。

性能脚本每组使用新目标 mm，先预热，再比较基线、PC/寄存器 summary-only、PC JSONL。
默认重复三次，包含不节流吞吐以及目标 1k/10k/50k 指令事件率：

```sh
python3 tests/instruction_bench.py --serial "$SERIAL"
# 可选：增加寄存器 JSONL 输出成本
python3 tests/instruction_bench.py --serial "$SERIAL" \
  --modes baseline,pc,regs,pc-json,regs-json \
  --seconds 2 --repeats 3 --report artifacts/instruction-bench-full.json
```

保存实际吞吐、目标 elapsed/CPU、最多 1024 个均匀采样调用的 p50/p95/p99、工具 CPU
ticks/峰值 RSS、安装时间、输出量、丢失和原始命令。节流率是目标值，不代表设备达到
该吞吐；原始 CPU ticks 保留 CLK_TCK 查询结果，不假定 100 Hz。trace 丢失率非零时
必须连同吞吐一起比较。脚本不运行普通 stackplz 对照，不能据此声称完成整个项目的
性能 roadmap。2026-11-25 已完成本脚本的 60 组设备对照，详细数据与限制见
[fuxi 报告](instruction-device-2026-11-25.md)。下面仿真中的时间不能用作设备性能数字。

没有设备时，可独立检查 fixture。主机需安装 `unicorn` Python 包、QEMU user 和
AArch64 GNU 工具链及运行库；NDK fixture 仍按前面的命令构建：

```sh
aarch64-linux-gnu-gcc -O2 -g -Wall -Wextra -Werror \
  -Wl,--export-dynamic -Wl,-z,max-page-size=4096 -pthread \
  tests/fixtures/instruction.c tests/fixtures/instruction.S \
  -o target/amtracer-instruction-fixture-linux
python3 tests/instruction_host.py
```

Unicorn 核对 Android ELF 中的 4 组真实指令路径；QEMU 执行 Linux fixture 的 7 组命令，
核对线程、信号恢复、迁移、节流和结果。输出 `artifacts/instruction-host.json` 的
`kernel_uprobe_verified` 固定为 false：这项检查不运行目标内核或 BPF verifier。

## 报告与覆盖边界

测试生成的 JSON 报告位于本地 `artifacts/`，部分生命周期 / 映射测试只输出验证结果。该目录被 Git 忽略；[validation-2026-11-24.json](validation-2026-11-24.json) 是已有一次验证的工具链、产物与报告哈希清单，不会随测试自动更新。

2026-11-24 已验证主机 27 项测试、Android / eBPF 构建及上述设备 smoke 的相应场景。应同时检查 stdout 事件和 stderr 统计：`kernel_lost=0` 不等于队列排空，停止时的 `queued` 记录可能尚未输出。

尚待补充的主要项目：Binder 回复逆序、失败回复设备场景，三路同时产生事件，慢输出 / EBUSY / 丢失压力，完整生命周期与 PAC / TBI 矩阵，以及可复现性能基准。不能从单次请求 / 回复的时间差推导性能开销。
