# amtracer

面向 Android ARM64 的进程追踪工具，使用 Rust 编写。通过 **Aya / eBPF uprobe** 观察用户态指令命中，通过已有的 **ktools syscall_trace / binder_trace** 驱动采集系统调用和 Binder 事务。

可以在一个进程中同时挂载多个 uprobe，读取寄存器、求值内存表达式、回溯原生调用栈；也可以用一份 JSON 配置组合三种来源，统一输出 JSONL。

项目仍在开发中。已验证平台为 **fuxi（小米 13）、Android 13、ARM64 Linux 5.15.167、SELinux Enforcing**。功能与验证范围见下文，详细进度见 [实施记录](docs/implementation.md) 和 [roadmap](docs/roadmap.md)。

- [功能与运行条件](#功能与运行条件)
- [构建](#构建)
- [部署与快速开始](#部署与快速开始)
- [uprobe：定位、多探针与表达式](#uprobe定位多探针与表达式)
- [逐指令 trace](#逐指令-trace)
- [syscall：过滤、参数与调用栈](#syscall过滤参数与调用栈)
- [Binder：事务与回复关联](#binder事务与回复关联)
- [混合会话](#混合会话)
- [输出与会话结束](#输出与会话结束)
- [当前限制](#当前限制)
- [开发与验证](#开发与验证)

## 功能与运行条件

| 功能 | 当前实现 | 设备要求 |
| --- | --- | --- |
| 用户态 uprobe | 库名 + ELF 地址、库名 + 符号、符号内偏移、绝对虚拟地址；同一进程最多 64 个探针 | uprobe/perf、eBPF、RingBuf、attach cookie 支持及相应权限 |
| 指令 trace | 范围内每条原始指令执行前的 PC、反汇编、线程内序号、可选通用寄存器；最多 1024 个唯一点位 | 配套 UXN-uprobe 内核、UXN 查询 ABI v4、4 KiB 页、raw sched_process_exit |
| 寄存器与内存 | x0–x30、sp、pc、pstate；有界指针链、整数、字符串和字节读取 | 随 uprobe 在命中时采集 |
| 原生调用栈 | uprobe / syscall 栈快照，framehop CFI / FP 解栈，模块与符号输出 | 可访问目标的映射和原始 ELF；syscall 栈另需对应驱动 |
| 系统调用 | 名称 / 编号过滤、ENTER / EXIT 配对、返回值、errno、耗时、参数采集 | ktools 控制 ABI v1 与 syscall_trace v2 |
| Binder | 同步 / oneway、事务结果、最多 256 字节数据、interface token、可选回复关联 | ktools 控制 ABI v1 与 binder_trace v3 |
| 混合会话 | JSON 配置、来源组合、全局 duration / count、JSONL 汇总、退出传播 | 按启用的来源满足上述要求 |

**syscall 和 Binder 依赖配套内核驱动。** 本仓库包含用户态工具、eBPF 程序及固定的 UAPI 快照，不包含驱动安装包。普通 Android 内核不会因为安装 amtracer 就获得这两个接口。对应内核配置为 `CONFIG_KTOOLS`、`CONFIG_KTOOLS_SYSCALL_TRACE` 和 `CONFIG_KTOOLS_BINDER_TRACE`。

设备端通常需要 root。两种 trace 驱动检查 `CAP_SYS_ADMIN`；读取目标 `/proc`、加载 BPF 和附加 perf 事件还受内核与 SELinux 权限约束。纯 uprobe 不调用 ktools 控制接口，纯 syscall / Binder 不加载 eBPF 对象。

工具通过现有 `PR_KTOOLS` 获取 trace FD，不创建 `/dev` 控制节点。使用已集成 UXN-uprobe 的内核时，注册、激活与清理由内核 uprobe 路径处理，amtracer 无需手动执行 UXN `prctl`。

## 构建

当前构建脚本面向 **Linux x86_64 主机**，生成 `aarch64-linux-android` 用户态程序和 `bpfel-unknown-none` eBPF 对象。Android 链接器固定使用 NDK 的 API 30 包装器。

已验证的工具链：

| 组件 | 版本 |
| --- | --- |
| Rust stable | 1.99.1 |
| Rust nightly | 1.102.0-nightly（2026-11-17）及 rust-src |
| Android NDK | r23b，23.1.7779620 |
| bpf-linker | 0.13.0 |

Rust 依赖由 `Cargo.lock` 固定；尚未声明最低 Rust 版本，也未固定 nightly 日期。

```sh
git clone https://github.com/BritneyOvO/amtracer.git
cd amtracer

rustup toolchain install stable
rustup toolchain install nightly --component rust-src
rustup target add aarch64-linux-android

export ANDROID_NDK_HOME=/path/to/android-ndk
```

将 `bpf-linker` 0.13.0 放入 `PATH`。Linux x86_64 可使用上游预编译包，避免自行匹配源码构建所需的 LLVM：

```sh
curl -fL -o /tmp/bpf-linker-0.13.0.tar.zst \
  https://github.com/aya-rs/bpf-linker/releases/download/v0.13.0/bpf-linker-x86_64-unknown-linux-musl.tar.zst
mkdir -p "$HOME/.local/bin"
tar --zstd -xf /tmp/bpf-linker-0.13.0.tar.zst -C "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"

bpf-linker --version
cargo xtask build
```

解包命令需要支持 zstd 的 tar 和 zstd 工具。构建成功后生成：

```text
artifacts/
├── amtracer         # Android ARM64 可执行文件
├── amtracer-ebpf.o  # 普通 uprobe 采集程序
└── amtracer-itrace.o # 指令 trace 采集程序
```

普通构建使用已提交的 UAPI 绑定，不需要父内核源码或单独运行 bindgen。`xtask` 包含绑定生成依赖；只有显式生成绑定时才需要可用的 libclang。`artifacts/` 和 `target/` 不进入 Git。

## 部署与快速开始

在主机上指定自己的设备序列号：

```sh
SERIAL=your-device-serial
adb -s "$SERIAL" shell mkdir -p /data/local/tmp/amtracer
adb -s "$SERIAL" push artifacts/amtracer artifacts/amtracer-ebpf.o /data/local/tmp/amtracer/
adb -s "$SERIAL" shell chmod 700 /data/local/tmp/amtracer/amtracer
adb -s "$SERIAL" shell
```

在设备的有权限 shell 中执行；普通 ADB shell 需先通过设备已有的 root 方式进入相应权限环境：

```sh
su
cd /data/local/tmp/amtracer

./amtracer doctor
./amtracer uprobe -p 1234 --probe 'libfoo.so+target_func' \
  --regs --duration 5 --json
```

示例中的 `1234`、库名、符号和地址均需替换为实际目标。`doctor` 显示架构、内核 BTF 文件是否存在及 ktools ABI / 功能位；其中 `ktools.error` 表示该接口不可用或访问失败，不等同于 uprobe 不可用。它不执行 BPF 加载或探针附加测试。

默认从可执行文件同目录加载 `amtracer-ebpf.o`，uprobe 也可用 `--object /path/to/amtracer-ebpf.o` 指定路径。所有命令的完整参数可通过 `./amtracer <命令> --help` 查看。

使用 `itrace` 时同样部署 `amtracer-itrace.o` 到可执行文件目录，或用该命令的 `--object` 指定。

## uprobe：定位、多探针与表达式

### 选择命中位置

| `--probe` 写法 | 含义 |
| --- | --- |
| `libfoo.so+0x1234` | ELF 虚拟地址 / 反汇编地址，经 PT_LOAD 转换为文件偏移 |
| `libfoo.so+target_func` | ELF dynsym / symtab 中的符号地址 |
| `libfoo.so+target_func+0x10` | 符号地址再加 0x10 字节 |
| `0x7a12345678` | 目标进程当前映射中的绝对虚拟地址 |

`libfoo.so+0x1234` 的数值不是直接传给内核的文件偏移。需要核对转换结果时，先运行：

```sh
./amtracer resolve -p 1234 --probe 'libfoo.so+0x1234'
```

输出包含 `path`、`elf_address` 和 `file_offset`。地址必须 4 字节对齐并落在可执行映射 / ELF 段中。库名有多个候选时会报错，可改用目标映射中的完整路径，例如 `'/data/local/tmp/libfoo.so+target_func'`。目标库需要已经加载，当前没有等待加载功能。

### 一次挂载多个探针

重复 `--probe` 即可，单次会话最多 **64 个**，可以混用三类定位方式：

```sh
./amtracer uprobe -p 1234 \
  --probe 'libfoo.so+func_a' \
  --probe 'libfoo.so+0x1234' \
  --probe '0x7a12345678' \
  --regs --stack --duration 10 --json
```

输出的 `probe` 字段按输入顺序从 **1** 编号。同一会话的探针使用同一组 `--print`、`--regs` 和栈配置，尚不支持逐探针配置。探针逐个安装；安装失败会释放本次已持有的挂载资源。

### 寄存器和内存表达式

`--regs` 输出 x0–x30、sp、pc、pstate；`--print` 可重复指定需要观察的值。表达式放在单引号中，避免 `*` 和括号被 shell 解释：

```sh
./amtracer uprobe -p 1234 --probe 'libfoo.so+target_func' \
  --print 'r13' \
  --print '*r13' \
  --print '*(r13 + 1W):u16' \
  --print '**x0' \
  --print 'cstr(x1, 128)' \
  --print 'bytes(x2, 32)' \
  --duration 5 --json
```

| 表达式 | 读取内容 |
| --- | --- |
| `r13` / `x13` | x13 的寄存器值；r13 是 x13 的别名 |
| `*r13` | x13 所指地址处的 u64 |
| `*(r13 + 1B)` | 地址加 1 字节，再读 u64 |
| `*(r13 + 1W)` | 地址加 2 字节，再读 u64 |
| `*(r13 + 1D)` | 地址加 4 字节，再读 u64 |
| `*(r13 + 1Q)` | 地址加 8 字节，再读 u64 |
| `*(r13 + 1W):u16` | 地址加 2 字节，最后一次读取为 u16 |
| `*(x0 - 8):i32` | 地址减 8 字节，读取有符号 i32 |
| `**x0` | 两层指针解引用 |
| `cstr(x1, 128)` | 读取有上限的 NUL 结尾字符串；128 包含终止符空间 |
| `bytes(x2, 32)` | 最多读取 32 字节，JSON 中为字节数值数组 |

**B / W / D / Q 只控制偏移单位，不改变读取宽度。** 默认解引用为 u64；类型后缀支持 `u8/u16/u32/u64` 和 `i8/i16/i32/i64`。可用寄存器为 `x0`–`x30`（别名 `r0`–`r30`）、`sp`、`pc`、`pstate`；ARM64 中的 `r13` 不是 SP。

当前每个表达式支持一条寄存器 / 指针链与常量加减，不支持 `x0 + x1` 这样的多链运算。每探针最多 **16 项表达式、4 层解引用、4 KiB 字符串 / 字节读取预算**。表达式只用于 uprobe。

结果的 `status` 区分 `ok`、`fault`、`truncated`、`overflow`。读取失败的标量为 `null`；跨页字节读取失败时可保留有效前缀，需结合 `length` 和 `status` 判断。整数同时输出 `decimal` 和 `hex`，字符串按 UTF-8 尽力展示。

### 原生调用栈

```sh
./amtracer uprobe -p 1234 --probe 'libfoo.so+target_func' \
  --stack --stack-bytes 8192 --duration 5 --json
```

uprobe 与 syscall 共用 framehop 解栈，使用 DWARF CFI / FP，输出 `stack.frames`、模块、符号、偏移、build ID 和 `stack.end`。栈窗口默认 **8192 字节**，范围 **1–16384 字节**，最多 **128 帧**。

解栈只从捕获的栈窗口读取内存，窗口不足时停止，不会事后从活进程补读。符号是否可见取决于原始 ELF；当前支持原生栈，Java / ART 栈不在支持范围内。

## 逐指令 trace

`itrace` 通过现有 UXN-uprobe 在 `recomp` 中为范围内每条原始指令激活 BRK 前缀。
命中后采集执行前状态，再执行当前指令的重定位 body。重定位展开出的辅助指令不会
单独产生事件。范围外代码不输出指令事件，返回范围后继续。

先预览点位，再挂载。范围左闭右开，起点沿用普通 uprobe 的地址语义：

```sh
./amtracer resolve -p 1234 --range 'libfoo.so+func..func_end'
./amtracer itrace -p 1234 --range 'libfoo.so+func..func_end' --duration 5 --json
./amtracer itrace -p 1234 --range 'libfoo.so+0x1200:0x40' --regs --count 1000 --json
./amtracer itrace -p 1234 --range '0x7a12345000..0x7a12345040' --duration 5
```

`START:BYTES` 使用显式字节长度，必须为正的 4 字节倍数。`START..END` 的 END
可省略起点已有的库名前缀；数字仍为 ELF 地址，符号可以加偏移。可重复 `--range`，
重叠点位按原始 inode 和文件偏移去重；最多 1024 个文件点位、4096 个已解析运行时地址。
每个位置仍使用一个 perf uprobe，共享 BPF 程序和配置；没有增加内核范围注册接口。
实际可挂载数量还受进程 FD 限额和内核页/代际预算约束，资源不足时整次安装回滚。

事件的 `source` 为 `instruction`，包含原始运行时 `pc`、`module`、`elf_address`、
`opcode`、反汇编 `instruction`、TID、`thread_epoch` 和 `sequence`。默认内核记录
为 64 字节；`--regs` 按线程记录 x0–x30、sp、pstate 的增量，PC 每条保留在事件头。
首条、丢失后的下一条成功记录，以及每隔 1024 次命中的检查点发送完整快照。
完整快照为 344 字节，增量为 `80 + 8 × 变更寄存器数` 字节，例如只变更 1 项时为 88 字节。
ringbuf 容量为 **32 MiB**；容量固定用于该次 itrace 会话，仍可能因持续慢输出而耗尽。
`--summary-only` 消费并校验事件，仅输出 stderr 统计，供衡量采集/消费开销使用。
指令模式暂不接入 `run --config`，也不在每条指令上采集表达式、内存窗口或调用栈。

`--regs` 的 JSONL 同样只输出变更值：`registers.kind` 为 `full` / `delta`，
`registers.base_sequence` 为 0 / 前一条已提交事件序号，`registers.values` 使用
`x0`…`x30`、`sp`、`pstate` 作为键。比如：

```json
{"kind":"delta","base_sequence":1,"values":{"x1":0}}
```

这段为 `registers` 字段的内容；没有变化时 `values` 为 `{}`。按 `tid` + `thread_epoch`
维护状态：`full` 替换全部值，`delta` 在基线序号匹配后覆盖对应值，PC 取当前事件。
值变为 0 也会显式输出；缺少基线时应等待完整快照，不能把旧状态接到增量上。
**这是 itrace 寄存器 JSON 格式变更**，不再使用旧的完整 `registers.x` 数组；
指令 ABI 升为 v2，需要一起更新工具和 `amtracer-itrace.o`。普通 uprobe 的格式保持现有约定。
变化表示两次采集状态的差异，可能包含范围外调用或信号处理的影响，不等同于上条指令的写集合。

事件表示执行前命中，不保证指令成功完成；故障重试可能重复 PC。序号只在同一
`tid` + `thread_epoch` 中比较；线程退出 hook 清理内核状态，避免 TID 重用串接。
`missed_before` 表示发现的序号缺口，之后事件的 `incomplete` 保持 true。
最终统计还包含 `ring_lost`、`state_failed`、`discarded`、`queued`、`incomplete`、
成功提交的载荷字节数 `submitted_bytes`（不含 ringbuf 内部头）和 `full_snapshots`；
序号检测不到最后一条之后的丢失，也不能证明 consumer 从未触发的点位没有遗漏。

安装时采集门控关闭；全部挂载、原始指令字节/映射复核和 UXN `INFO/STAT` 查询通过后才打印
`itrace: ready` 并开始采集。只读查询确认原页已有激活的 recomp，不手动注册/激活 UXN。
原生 BRK/XOL 回退会报错并回滚。运行中每 250 ms 检查映射和 recomp 代际，不能发现
所有瞬时变化。停止时关闭采集、卸载并消费剩余记录；`--count` 仍限制输出条数，
超出部分计入 `discarded`。采集中途进入或结束，可能得到一次调用的部分路径。

首版保守拒绝不支持的指令、异常指令、部分系统/认证指令，以及接触页包含排他指令的
范围。跨页或动态跳转形成的任意排他区仍不能证明安全；不能把它用于要求零扰动的
原子序列调试。仅支持当前映射的独立 AArch64 ELF、4 KiB 完整私有只读可执行页。
每线程状态和用户态观察表均有容量限制，耗尽时明确报告。原始 ELF 与私有代码可能
不一致、信号/exec、PAC/BTI、反调试和并发边界仍须设备验证。

**2026-11-25 已在 fuxi 上通过受控逐指令 smoke**：分支/循环、BL/BLR/RET、寄存器、
多线程、CPU 0/1/2 迁移、81 点位、跨页和访存异常恢复，共核对 601 条完整事件，
没有 ringbuf 丢失或序号缺口；排他/SVC/原生回退拒绝、count 和目标退出检查通过。
这项结果不覆盖任意用户代码、PAC/BTI 完整矩阵或持续高负载下零丢失。
同日旧版固定 336 字节记录、8 MiB 缓冲区的 60 组性能对照中，目标 1k/10k/50k 指令事件率下均无丢失；不节流的完整寄存器
JSONL 短突发出现约 43.35% ringbuf 丢失。数据及限制见
[fuxi 测试报告](docs/instruction-device-2026-11-25.md)。预留 NOP 的非命中开销尚未单独测量。
设备测试与性能复现见 [testing.md](docs/testing.md)，设计见 [instruction-trace.md](docs/instruction-trace.md)。

## syscall：过滤、参数与调用栈

```sh
./amtracer syscall -p 1234 --syscalls openat,read,write \
  --duration 5 --json

./amtracer syscall -p 1234 --syscalls getpid \
  --stack --stack-bytes 1024 --count 10 --json
```

`--syscalls` 接受逗号分隔的 AArch64 syscall 名称或十进制编号，例如 `openat,64`。既未指定过滤也未指定 capture 规则时，采集目标进程的全部系统调用。ENTER 和 EXIT 分别输出一条事件；`--count 10` 限制事件条数，不代表 10 次完整调用。

输出包含 `name`、`nr`、`phase`、六个原始 `args`、`return`、`errno`、`restart` 和 `duration_ns`。缺少可配对入口时，EXIT 的耗时为 `null`；内核 restart 返回值与 errno 分开处理。

### 自定义参数采集

```sh
./amtracer syscall -p 1234 \
  --capture openat:1:string:128 \
  --capture write:1:bytes:32 \
  --capture openat:stack:1024 \
  --duration 5 --json
```

| 规则 | 含义 |
| --- | --- |
| `SYSCALL:ARG:string[:BYTES]` | 读取字符串，默认 / 最大 256 字节 |
| `SYSCALL:ARG:bytes[:BYTES]` | 读取原始字节，默认 / 最大 256 字节 |
| `SYSCALL:ARG:sockaddr[:BYTES]` | 读取 sockaddr 字节，默认 / 最大 128 字节 |
| `SYSCALL:stack:BYTES` | 仅为该 syscall 采集栈窗口，1–16384 字节 |

参数编号为 **0–5**。`--capture` 可重复指定，最多 32 条规则；同一 syscall 的同一参数不能重复。规则会将对应 syscall 加入过滤列表，并覆盖驱动对该参数的内置入口采集。sockaddr 当前保留原始数据，不提供完整协议解码。

**自定义参数规则在 ENTER 时读取。** `write:1:bytes:32` 适合观察输入；`read:1:bytes:32` 只能看到调用前的缓冲区。驱动已有的 read 输出采集在 EXIT 中另行提供返回数据，完整返回缓冲区验收仍待补充。

`blobs` 包含参数编号、类型、地址、数据和 fault 标记。驱动 nofault 采集失败时如实标记；栈出现 `capture_fault` 时可尝试缩小 `--stack-bytes`。

## Binder：事务与回复关联

默认按事件发生进程过滤：

```sh
./amtracer binder -p 1234 --duration 5 --json
```

输出事务 ID、reply-to ID、code、flags、发送者、target handle、结果和最多 256 字节数据。数据被截断时标记 `truncated`；Android 13 Parcel 的 SYST / String16 interface token 在结构与长度有效时尽力解析，其他布局保留原始数据。

`outcome=submitted` 表示 Binder 已接受事务，不表示服务已回复；`failed` 的 `error` 可以为 0。驱动未提供结果能力时显示 `unknown`，不根据 errno 猜测成功。

### 捕获目标请求的服务端回复

```sh
./amtracer binder -p 1234 --with-replies --duration 5 --json
```

默认的单 PID 过滤无法保证收到另一进程发出的 reply。`--with-replies` 显式扩大为全局 Binder 采集，再由用户态只输出目标发起的请求及已确认匹配的回复。它要求驱动提供事务结果 / debug ID 能力，内核队列会承受其他进程的 Binder 流量。

| `correlation.status` | 含义 |
| --- | --- |
| `pending` | 已看到同步请求，等待后续配对 |
| `matched` | 回复的 `reply_to_id` 找到目标原请求；结果仍看 `outcome` |
| `reply_failed` | 找到原请求，但回复提交失败 |
| `not_expected` | oneway，不等待回复 |
| `failed_request` | 同步请求提交失败 |
| `unknown_outcome` | 没有足够结果信息建立待配对状态 |

`elapsed_ns` 仅表示请求与回复两个采集点的时间差，不能解释为服务内部执行耗时。无法确认归属的回复会被抑制。队列丢失、序号不连续、超时或容量淘汰会使关联失效；跨 CPU 时 reply 可能先于 request 入队，当前不会补配这种逆序记录。因此 `pending` 不代表确定没有回复。

## 混合会话

使用 `run --config` 组合任意非空来源集合。以下为设备端 `session.json` 示例：

```json
{
  "pid": 1234,
  "duration": 10,
  "count": 0,
  "uprobe": {
    "probes": ["libfoo.so+func_a", "libfoo.so+func_b"],
    "expressions": ["x0", "*r13"],
    "registers": true,
    "stack": true,
    "stack_bytes": 8192
  },
  "syscall": {
    "syscalls": ["openat", "write"],
    "captures": ["openat:1:string:128"],
    "stack": false
  },
  "binder": {
    "with_replies": false
  }
}
```

```sh
./amtracer run --config ./session.json > events.jsonl 2> trace.log
```

`pid` 为必填项；`duration` / `count` 默认 0，分别为不限时长 / 不限条数。只保留需要的 `uprobe`、`syscall`、`binder` 配置段即可，至少启用一项。未知字段会报错。完整示例见 [session-example.json](docs/session-example.json)，使用前需替换 PID 和探针位置。

混合配置中的 `registers` 对应单源命令 `--regs`，`expressions` 对应重复的 `--print`；`uprobe.object` 可指定 eBPF 对象路径。布尔项默认 false，栈窗口默认 8192 字节。

当前 `run` 通过子进程启动各单源命令，以有界通道汇总 JSONL；`duration` 和 `count` 为全局限制。任一来源结束或失败时会停止其他来源，启动失败会回收本次已启动的来源。来源之间不保证同时就绪，输出不按跨来源时间戳排序，也不建立 syscall / Binder / uprobe 间的因果关联。

## 输出与会话结束

| 选项 / 字段 | 说明 |
| --- | --- |
| `-p, --pid` | 目标进程 TGID，单源命令必填 |
| `--duration` | 持续秒数，默认 0 表示不限 |
| `--count` | 输出事件条数，默认 0 表示不限；多探针共用此上限 |
| `--json` | 每行一个 JSON 对象；省略时普通命令为多行 JSON，itrace 为指令文本 |
| `source` | `uprobe`、`instruction`、`syscall` 或 `binder` |
| `tgid` / `tid` | 进程 ID / 线程 ID |
| `timestamp_ns` | 内核单调时钟时间戳，单位纳秒，不是日历时间 |

混合会话始终输出 JSONL。事件写 stdout，诊断和统计写 stderr，可分别保存；itrace 提供独立的逐行指令文本视图。

Ctrl-C、达到时长 / 条数上限、目标退出或检测到身份变化时结束会话并释放本次资源。每种内核 trace 同时仅允许一个会话；已被占用时返回 `EBUSY`，工具不会接管它。

退出统计中的 `kernel_lost` 是内核侧丢失计数；`invalidated_pairs` 是清理的待配对状态数，两者含义不同。`queued` 表示驱动仍有未读记录，停止时不保证排空；`kernel_lost=0` 也不保证目标所有事件均已输出。

## 当前限制

- 仅面向 AArch64 原生进程。uprobe 需要可访问的独立 ELF 及原始映射 inode；不支持 APK 内直接映射的 so、匿名 / JIT 代码，不能通过解压出一个新文件替代原映射。
- 内存采集是命中时的尽力读取，其他线程可能并发修改；不构成全进程原子快照。表达式暂不支持多寄存器链组合或逐探针独立配置。
- 原生解栈受捕获窗口、CFI / FP、ELF 可读性影响；PAC / TBI 处理采用当前映射推导的启发式，完整配置矩阵尚未覆盖。
- 生命周期以 250 ms 间隔检查启动时间、可执行文件身份及相关映射。探针映射变化时停止；启用栈回溯时映射变化会刷新缓存。瞬时变化、同一可执行文件的 exec、队列旧事件与新映射的一致性尚不能完整保证。
- Binder 逆序回复补配、失败回复的设备覆盖、队列丢失压力、混合会话慢输出 / EBUSY 矩阵及性能基准尚未完成。当前不承诺固定开销或零丢失。

## 开发与验证

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo xtask build
```

更新 UAPI 是显式操作；仅在准备同步驱动协议时执行，需配置 NDK 和 libclang：

```sh
cargo xtask sync-uapi /path/to/kernel/common
# 或仅从仓库内已有头文件重新生成绑定与 syscall 名称表
cargo xtask gen-uapi
```

[uapi/SOURCE.md](uapi/SOURCE.md) 保存内核头来源和哈希，生成绑定包含 ARM64 ABI 布局断言。源码按以下边界组织：

```text
crates/amtracer/       CLI、地址解析、表达式、驱动接入、解栈与会话管理
crates/amtracer-ebpf/  uprobe 命中时的寄存器、栈及内存采集
crates/amtracer-abi/   用户态与 eBPF 共用的固定布局
xtask/                Android / eBPF 构建、UAPI 同步和生成
uapi/                 固化的内核 UAPI
tests/                主机外的设备 smoke 脚本与受控 fixture
docs/                 设计、roadmap、实施与验证记录
```

2026-11-24 的验证包含 27 项主机测试，以及 fuxi 上的多探针、三类地址定位、表达式、原生栈、syscall 参数、Binder 成功 / 失败事务、双来源混合会话、全局 count 和部分启动失败回收。三路同时产生活跃事件、完整生命周期及压力矩阵仍待补齐。

设备测试命令、前置条件和脚本执行顺序见 [测试指南](docs/testing.md)。[验证清单](docs/validation-2026-11-24.json) 记录工具链、二进制和报告哈希；原始报告保存在本地 `artifacts/`，未随源码提交。

进一步阅读：[整体设计](docs/design.md) · [实施记录](docs/implementation.md) · [roadmap](docs/roadmap.md)。
