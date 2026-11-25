# 实施记录

日期：2026-11-24。设计目标见 design.md，未列为完成的项目仍按 roadmap.md 推进。

## 已落地

* 独立 main 仓库、Cargo workspace、Android/Aya 构建和固定 UAPI 绑定。
* 独立 ELF 的三种 uprobe 定位、cookie、TGID 过滤、完整 AArch64 通用寄存器与栈窗口。
  不支持 APK 直接映射的库。
* syscall_trace v2、binder_trace v3 会话打开、配置、读取、停止与关闭；使用既有
  PR_KTOOLS，不增加 /dev 或修改内核。
* uprobe 表达式：一条寄存器/指针链加减常量、负偏移、四层解引用、八种整数类型、
  bytes/cstr、16 项/4 KiB 预算；多条独立寄存器链的组合尚不支持。
* 内存故障不伪装成成功的零；字节读取跨页失败保留有效前缀；字符串区分截断。

## 验证

在指定 fuxi（282eb4e4）、Linux 5.15.167、SELinux Enforcing 上，以工具自行创建的
native fixture 验证符号/绝对地址 uprobe、x13、getpid ENTER/EXIT、Binder 会话开关。
16 项表达式同时验证 B/W/D/Q、带类型读取、指针链、字符串、截断、跨页部分复制、
fault、overflow。脚本为 tests/device_smoke.py，原始输出为本地 artifacts/device-smoke.json。

表达式执行使用独立的 BPF 全局函数，使 5.15 校验器只验证一次有界解释过程。
临时 map 尾部保留 4 KiB 边界空间，使目标偏移和读取长度可独立验证；输出长度仅包含
实际有效数据，尾部空间不发送。语法与预算在用户态检查，BPF 再做边界校验。

## 待完成

完整 syscall 返回缓冲区语义与丢失压力矩阵、混合会话、有界处理队列、生命周期完整矩阵及性能基准。

## syscall 参数规则

用户态已绑定现有 `SCT_IOC_SET_CAPTURE_RULES`，支持重复的
`--capture SYSCALL:ARG:KIND[:BYTES]`（string/bytes/sockaddr）和
`--capture SYSCALL:stack:BYTES`。参数规则由驱动在 ENTER 读取，同一参数会覆盖其内置规则；
read 等输出缓冲区只能看到调用前内容。已加入对规则数量、长度、参数范围和重复项的校验，
事件 JSON 输出 blob 类型、地址、数据和 fault 状态；capture 规则会自动扩展 syscall 过滤
列表。主机单测覆盖解析、限制、重复项和过滤扩展。fuxi（282eb4e4）受控 fixture 已验证
openat `/dev/null` 路径与 write 输入数据，12 个事件均正确，kernel_lost=0、
invalidated_pairs=0；原始报告为 artifacts/syscall-capture-smoke.json。自定义规则只在 ENTER
采集；驱动原有的 read 输出捕获仍在 EXIT 阶段执行。队列丢失压力矩阵尚未完成。

## 进程生命周期

三类会话以 250 ms 为间隔检查目标启动时间与可执行文件身份，并在设置结束后复核。
在事件持续到达时也会检查，发现退出或身份变化后结束会话。fuxi 的受控进程退出测试
验证了 uprobe、syscall 和 Binder 会话退出，以及后两者可以再次打开；脚本为
`tests/process_smoke.py`。uprobe 会话记录每个探针对应的可执行映射，映射变化时停止；
uprobe 和 syscall 在启用栈回溯时随可执行映射变化重建缓存。fuxi 上的
`tests/mapping_smoke.py` 验证 dlopen 后 syscall 栈解析新库，dlclose 后 uprobe 会话退出。
轮询不能保证发现瞬时变化，不覆盖同一可执行文件的 exec；队列中的旧事件也可能在缓存
更新后按新的映射解析，因此不能保证动态变化期间的栈符号完全准确。

## 快照解栈阶段

framehop 已接入 uprobe 和 syscall；从原始映射 inode 读取 ELF、CFI 和符号，按照
PT_LOAD 的文件/虚拟地址求 load bias，输出当前 PC/返回地址、模块偏移、符号和 build ID。
仅使用捕获窗口，最多 128 帧。返回地址 mask 从目标可执行映射推导，并验证每帧属于
可执行映射；这是当前启发式方案，不宣称已覆盖所有 PAC/TBI 配置。

syscall blob 校验表、数据偏移、有效长度、重叠和栈地址；展示字符串/原始字节。
入口配对限 4096 线程、事件时间 300 秒过期；丢失使旧配对失效，restart 与 errno 分离。

主机 11 项测试通过。实机有/无帧指针两个 fixture 均验证 5 层递归与线程入口，
uprobe 9 帧、syscall 512 字节窗口回溯包含 worker。证据分别保存于
artifacts/device-smoke.json 和 artifacts/device-smoke-no-fp.json。

## 驱动事件解码阶段

从固化的 ARM64/asm-generic UAPI 生成 304 项 syscall 名称表，保留源文件哈希。
过滤和事件显示使用同一表；未包含的编号仍可直接指定。

Binder 输出 sequence、target_handle、oneway 和原始数据；识别 Android 13 的
SYST/String16 interface token，严格检查长度、UTF-16、结束符，未知布局保持 raw。
读取 feature 后决定 outcome 是否可用，不以 error==0 推断成功。

受控进程向无效 Binder 句柄发送 6 次事务（交替同步/oneway），验证 FAILED/-EINVAL、
真实发送者、320→256 字节截断和完整 interface token。请求不发往任何系统服务。
证据为 artifacts/binder-smoke.json。该路径验证失败 Binder 事务，不替代成功请求/回复测试。
主机测试增至 13 项；依赖关闭未使用的 Mach-O/PE 特性，移除未使用的直接依赖。
实机另验证 ELF 偏移、符号内偏移、多探针及已有和新建线程；字符串刚好放入缓冲区
时不标为截断。用户态和 eBPF 的 Clippy 均通过。构建产物、三份原始测试报告的哈希及
工具链版本保存在 validation-2026-11-24.json；原始报告在本地 artifacts 目录。

## Binder 成功事务与回复关联

Binder CLI 增加显式 `--with-replies`。默认模式仍保留原有事件过滤和 JSON 形状；启用后
驱动按全局事件范围采集，用户态只输出目标进程发起的事务和确认属于该事务的回复。
其他进程事务只进入有界关联表，不输出；目标进程作为服务端回复其他进程请求时也会抑制，
避免将它误配为目标请求。同步回复按 `reply_to_debug_id` 配对；oneway、FAILED、未知结果
分别处理。丢失计数变化、序号不连续、超时和 4096 项容量上限会清理待配对项并统计
`invalidated_pairs`。请求到回复的时间差是两个采集点之差，不表示服务内部执行耗时。

新增 binderfs 私有 client/service fixture 和设备脚本，不连接系统 Binder 服务。fuxi
（282eb4e4，boot ID `718edf5f-4e39-44e5-94b5-a34ebe95725c`）验证一条成功同步请求及回复
（通过 debug ID 配对，93.386 µs 采集点差）、两条 oneway；同时重跑原有 6 条失败请求测试，
默认模式的事件仍为 FAILED/-EINVAL。两个测试均为 kernel_lost=0、invalidated_pairs=0。
原始报告是 artifacts/binder-pair-smoke.json 与 artifacts/binder-smoke.json，哈希见
validation-2026-11-24.json。配对测试退出时内核队列尚有 1 条未读取记录，因此不能据此声称
队列完全排空或完成压力验收；失败回复、丢失压力和不同并发调用场景仍待设备覆盖。
主机测试覆盖回复成功/失败、oneway、未知能力、无关进程请求抑制、序号重复和丢失失效。
驱动的事件在事务完成后入队，跨 CPU 时回复记录可能先于请求记录；当前未暂存提前到达的
回复，这种情况下会漏掉关联，不能将 `pending` 直接视为服务没有回复。

## 混合会话初版

`run --config` 读取 JSON 配置，按需启动 uprobe、syscall、Binder 三种现有 CLI 子进程；
supervisor 以有界 512 行通道合并 JSONL，统一执行全局 duration/count，转发 stderr，并在
某个来源退出、输出损坏或收到停止信号时通知其他来源退出。启动失败会终止已启动的 worker。
单源命令和内核采集实现保持独立。配置字段见 docs/session-example.json。

当前不提供跨来源时间排序或统一内核事件队列；接收顺序只是用户态排队顺序。fuxi 设备
smoke 验证 uprobe+syscall 同时采集，输出 25 条 uprobe、618 条 syscall，内核丢失均为 0；
另验证 syscall+空闲 Binder 的全局 `count=12` 恰好输出 12 条，两个 worker 均正常关闭。
无效 uprobe 库导致启动失败时，syscall worker 退出，随后能立即重新打开 syscall 会话。
前两次 syscall 停止时内核队列各有 2 条未读取记录，不能据此声称停止时排空队列。原始报告为
artifacts/session-smoke.json，哈希见 validation-2026-11-24.json。Binder 可按配置加入，但 Binder 全局回复模式
仍受其特权和队列负载限制。慢输出背压、其他 worker 启动中途失败、EBUSY 和生命周期压力尚未
完成设备矩阵。

下一项为设备正确性矩阵和性能基准，混合会话验收仍继续补充。

## recomp 指令 trace

新增独立 `itrace` 命令、`resolve --range` 与 `amtracer-itrace.o`。范围支持
`START..END`/`START:BYTES`，按原始文件位置去重，预先反汇编、检查映射/段/对齐及
不支持指令。1024 个文件点位、4096 个运行时地址上限与普通 uprobe 的 64 项配置独立。
不修改内核，不增加 /dev，不手动注册或激活 UXN；通过现有 prctl INFO/STAT 只读确认
每个源页已激活 recomp，回退原生 BRK/XOL 时拒绝启动。

指令事件为独立 ABI v1，默认 64 字节、通用寄存器模式 336 字节；采集门控在全部挂载
后开启。按 TID 生成序号，raw sched_process_exit 清理状态，epoch 区分 TID 重用。
解析器检查完整布局、flags、cookie/PC、寄存器 PC 和线程序号。停止时关闭采集、卸载、
消费剩余 ringbuf；count 超出部分记 discarded，序号、ringbuf 和线程状态丢失分开统计。
输出使用有界缓冲，提供文本、JSONL 和 summary-only；表达式/内存/栈和混合会话接入
不在本阶段范围。

提交链：`e00611d` 设计，`ae96a5b` 范围，`d3baca4` 事件/BPF，`edec649` 挂载/输出，
`852605b` 后端确认与清理校验，`cedb2a8` fixture 和测试/基准脚本，
`4f2b6e8` 激活前复核文件指令字节，拒绝解析后已变化的反汇编来源。

2026-11-24 主机 34 项测试、fmt、用户态与 eBPF Clippy、Android/eBPF release 构建通过。
Android fixture 使用 NDK 编译并以 Unicorn 对照 4 组真实指令路径；Linux fixture
在 QEMU 下通过 7 组线程、访存异常恢复、CPU 迁移、跨页调用和节流命令。原始结果
`artifacts/instruction-host.json` 明确标记 `kernel_uprobe_verified=false`。
本次工具链、产物/报告哈希见 [validation-instruction-2026-11-24.json](validation-instruction-2026-11-24.json)。

2026-11-24 指定 fuxi（282eb4e4）不在 ADB，用户确认暂不可用，当日没有指令 trace
实机或性能数据。2026-11-25 设备恢复后，原版产物无需代码修复通过设备 smoke，验证
5.15 verifier/UXN 分发、寄存器、分支/循环、BL/BLR/RET、多线程、CPU 0/1/2 迁移、
81 点位、跨页、两次 SIGSEGV 恢复、排他/SVC/原生回退拒绝，以及 count 和目标退出。
7 个完整路径用例共输出 601 条事件，ring_lost/state_failed/sequence_missing/
discarded/queued 均为 0；count=7 用例输出 7 条，多余 20 条记 discarded 并设置
incomplete=true。设备 boot ID 为 `78f0daf5-9bf8-47b7-9a59-3d54eed95b53`，SELinux
Enforcing。原始报告 `artifacts/instruction-smoke-2026-11-25.json`，PC/寄存器 JSONL
在 `artifacts/instruction-smoke/`。本次结果仍不覆盖完整 PAC/BTI、fork/exec 或压力矩阵。

性能脚本同日完成 60 组（0/1k/10k/50k 目标事件率 × 基线/PC/regs/PC JSONL/regs JSONL
× 三次）。三个节流档的全部 trace 用例无丢失；不节流的完整寄存器 JSONL 三次共丢失
62,424/144,000（43.35%），正确设置 incomplete。全部性能用例发生 2,039,040 次采集，
成功提交 1,976,616 条；state_failed、queued、discarded 均为 0。原始报告为
`artifacts/instruction-bench-2026-11-25.json`。详细延迟/吞吐、产物哈希和测试边界见
[设备报告](instruction-device-2026-11-25.md) 与
[验证清单](validation-instruction-device-2026-11-25.json)。未固定 CPU/频率，短突发结果
不能当持续吞吐上限；没有单独测量预留 NOP 或与原生 BRK/XOL/stackplz 对照。
