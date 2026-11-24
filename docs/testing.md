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

## 报告与覆盖边界

测试生成的 JSON 报告位于本地 `artifacts/`，部分生命周期 / 映射测试只输出验证结果。该目录被 Git 忽略；[validation-2026-11-24.json](validation-2026-11-24.json) 是已有一次验证的工具链、产物与报告哈希清单，不会随测试自动更新。

2026-11-24 已验证主机 27 项测试、Android / eBPF 构建及上述设备 smoke 的相应场景。应同时检查 stdout 事件和 stderr 统计：`kernel_lost=0` 不等于队列排空，停止时的 `queued` 记录可能尚未输出。

尚待补充的主要项目：Binder 回复逆序、失败回复设备场景，三路同时产生事件，慢输出 / EBUSY / 丢失压力，完整生命周期与 PAC / TBI 矩阵，以及可复现性能基准。不能从单次请求 / 回复的时间差推导性能开销。
