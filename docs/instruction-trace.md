# recomp 指令追踪

日期：2026-11-24。用户确认按 Git 提交逐步实现。此文件记录首版边界；设备结果另记。

## 执行语义

沿用现有 UXN-uprobe：原页执行权限异常跳到 recomp，范围内每条原始指令的
NOP/BRK 前缀变为 BRK，采集执行前状态，再执行当前指令的 relocated body。
同页分支进入目标前缀，跨页按现有重编译器处理。不采集重定位产生的辅助指令。
事件表示命中，不代表退休；故障重试可能重复同一 PC。

首版命令为 `itrace`，重复 `--range START..END`，区间左闭右开。START 沿用
uprobe 的库名+ELF VA、符号、符号+偏移、绝对 VA；END 为同库 ELF VA、符号或
绝对 VA。也支持 `--range START:BYTES`，长度显式采用字节。解析后检查映射、
原始 inode、可执行 PT_LOAD、4 字节对齐、溢出、重复和资源预算。

沿用 Aya 单点 perf 挂载，每个位置有 consumer，所有位置共享一个配置与采集程序；
不把范围误称为单个 perf 事件。不增加 /dev 或内核范围控制接口，不修改普通 uprobe
的事件 ABI。默认上限 1024 个唯一位置，错误报告具体点位；挂载失败释放已安装位置。
普通 uprobe 的 64 项限制继续独立使用。

trace 需要完整覆盖已声明范围：解码失败、已知不支持指令、排他序列风险均在挂载前
拒绝，不能静默跳过。目标 Linux 5.15 原生 uprobe 的指令检查仍然生效。仅保证
经验证的指令类别；不能因 recomp 能复制某条指令就绕过内核检查。首版保守拒绝接触页
中的排他指令，避免从排他序列中间插入 BRK；不能证明任意动态控制流的原子区边界。

现有内核可能在 recomp 建立失败时回退到原页 BRK/XOL。工具应报告实际可确认的
UXN 后端状态，不声称标准 uprobe 挂载成功必然使用 recomp；若无法确认范围所需
页面已激活 UXN，则拒绝启动采集。工具不手动注册或激活 UXN。

范围外代码不输出指令事件，返回后继续。已有线程和新线程按实际挂载能力验证；线程内
序号不比较为跨线程全局执行顺序。采集启动前的执行不属于 trace，安装过程不开启采集。

## 采集和输出

独立紧凑 ABI，固定头包含版本、长度、TGID/TID、CPU、时间、cookie、原始 PC、
线程内序号，按配置附加通用寄存器增量（v2，见下节）。默认不读取栈或表达式。每条指令的内存表达式与
栈窗口另行设计；普通 uprobe 已有功能保持不变。

线程序号在发送前递增，发送失败留下缺口；另统计 ringbuf 丢失和线程状态分配失败。
线程表有固定容量，不通过 LRU 静默重置序号。TID 重用不能与旧执行串拼为一个线程。
消费端检查 ABI、点位归属与序号，丢失后标记 trace 不完整，不补造事件或执行后结果。
序号只覆盖采集程序实际执行；不能检测没有触发 consumer 的指令遗漏。

解析原始 ELF 代码并预先反汇编，输出原始 PC、模块/ELF 偏移、opcode 和汇编。
单独维护范围点位表，避免每条事件重复读 ELF 或反汇编。stdout 为文本或 JSONL，
诊断、ready 和统计写 stderr。停止时先关闭采集，再排空已提交记录并报告未输出记录；
count、目标退出、映射变化、信号、输出错误均释放挂载资源。

## 提交与检查

1. `docs: define recomp instruction tracing semantics`：本设计与计划。
2. `feat: resolve and validate arm64 instruction ranges`：范围解析、去重、边界和指令检查；主机测试。
3. `feat: capture compact instruction trace events`：ABI、BPF 配置门控、线程序号、可选寄存器和丢失；eBPF 构建。
4. `feat: attach and render instruction trace sessions`：CLI、Aya 挂载、后端确认、输出与清理；主机与 Android 构建。
5. `test: add instruction trace fixtures and performance harness`：受控分支、循环、调用/返回、线程、故障、挂卸和性能脚本。
6. `docs: record instruction trace validation and usage`：实际检查结果、限制、复现方法和 README。

每个提交完成相关检查后及时提交。真机只使用 `adb -s 282eb4e4`，不刷机。
设备缺席时保留脚本和准确的未验证状态，不将主机测试代替设备验收。

性能区分安装时间、目标吞吐、PC/寄存器采集、消费/格式化开销及丢失；保留设备、
内核、boot ID、提交、命令和原始结果。是否增加按页批量启用或范围级 consumer，
在这次数据的基础上单独决定。

## 实施状态

设计、范围解析、紧凑 ABI/BPF、CLI 挂载、UXN 只读确认、停止关闭/卸载/消费、
序号校验以及受控 fixture/smoke/基准脚本均已提交。退出 hook 使用 raw tracepoint，
覆盖所有 CPU，不依赖挂载 tracefs。`--summary-only` 用于单独衡量采集与消费。

主机共有 34 项测试通过，用户态及 eBPF Clippy、Android/eBPF release 构建通过。
Unicorn 验证编译后 Android fixture 的实际指令路径，QEMU 验证 Linux fixture 协议、
线程、信号恢复与迁移。这些不运行目标内核，不能验证 BPF verifier、uprobe consumer
或 UXN BRK 分发。2026-11-24 用户确认设备暂不可用，当日未执行设备验收。

2026-11-25 设备恢复连接，`282eb4e4`、Linux 5.15.167、SELinux Enforcing、boot ID
`78f0daf5-9bf8-47b7-9a59-3d54eed95b53`。原版本无需代码修复即通过设备 smoke，
验证了 5.15 verifier、raw exit hook、UXN 激活和 BRK consumer 路径。完整路径用例
共 601 条事件，ring_lost/state_failed/sequence_missing/discarded/queued 均为 0。
count=7 另外准确输出 7 条并报告丢弃记录；目标退出用例正常结束。任意指令、PAC/BTI、
信号/exec 压力和完全无丢失的吞吐上限仍不能从 smoke 推导。

同日性能对照共 60 组：目标 1k/10k/50k 指令事件率下均无丢失；不节流的完整寄存器
JSONL 短突发平均丢失 43.35%，工具正确报告。明细和限制见
[设备报告](instruction-device-2026-11-25.md)。本轮未单独测量非命中 NOP 的开销，
也未将短突发零丢失解释为持续性能保证。

当前 UXN STAT 只返回最多 32 个 site；工具按页确认 active/recomp/generation，再依赖
各位置标准 uprobe 的成功安装确认绑定。不会把截断的 STAT sites 当作完整点位表。
查询与映射监控是周期性检测；不能宣称任意瞬时变化下无遗漏。

## 寄存器增量与缓冲区（2026-11-25）

按用户要求将 itrace 的 `--regs` 改为增量，ringbuf 从 8 MiB 增至 32 MiB。
不新增 CLI 模式或内核接口；普通 uprobe ABI 不变。指令独立 ABI 由 v1 升至 v2，
工具和采集对象需成套更新，旧版本事件明确拒绝。

每线程维护 epoch、尝试序号、最近成功提交序号、最近完整快照序号，以及 x0–x30、SP、
PSTATE 共 33 项基线。PC 每条位于 64 字节头，不再重复存入寄存器载荷。寄存器前缀
为 64 位 `base_sequence` 和 64 位变更位图，后接按位从低到高排列的值。
位 0–30 为 x0–x30，位 31 为 SP，位 32 为 PSTATE，其余位必须为 0。

| 记录 | 载荷字节数（不含 ringbuf 内部头） |
| --- | --- |
| 仅 PC | 64 |
| 无寄存器变化 | 80 |
| 1 项变化 | 88 |
| 3 项变化 | 104 |
| 完整快照 / 全 33 项变化 | 344 |

首条、距最近成功完整快照 1024 次命中，以及发送失败后的恢复记录必须为完整快照：
设置 FULL 标志、`base_sequence=0`、位图含全部 33 项。增量的基线序号等于该线程
最近成功提交序号；序号在发送前递增。只有成功提交才更新寄存器基线；失败时置强制
完整状态，连续失败不能解除。完整快照恢复寄存器可解码性，不会撤销已发生的丢失或
将 trace 改回完整。线程退出清理与跨 CPU 的序号规则保持一致，不使用每 CPU 基线。

消费端验证标志、位图、长度、完整快照/基线约束；增量必须接续同 epoch 的前一条事件，
否则终止并报告不完整。JSONL 与文本输出同样采用增量，避免恢复完整 JSON 后再次放大
输出；JSON `registers` 含 `kind`、`base_sequence`、按寄存器名称索引的 `values`。
首条和检查点输出所有值，包括 0；普通增量只含真正变化的值，空变化输出空对象。

新增统计 `submitted_bytes` 与 `full_snapshots`。ThreadState 从 16 增至 296 字节，
4096 项固定表的值空间约 1.16 MiB（不含哈希表开销），另外增加 24 MiB ringbuf 容量。
寄存器仍需逐次读取比较，陷阱数量保持原有行为；压缩收益须通过设备测量，不能直接
解释为同等比例的 CPU 降耗或持续零丢失能力。

实施分为两个提交：先提交 ABI、BPF、解码输出、单元和设备恢复测试，再记录同负载的
实机性能结果。测试覆盖初始/周期完整快照、0 值、空增量、SP/PSTATE/全掩码解码、
线程/迁移、非法基线/长度/位图、缓冲区满后的多次失败与恢复。

实现提交 `3634c3a` 已通过 38 项主机测试、用户态/eBPF Clippy、Android/eBPF 构建，
fuxi smoke 和写满缓冲区后的恢复测试。60 组同参数性能用例共 2,039,040 条事件均
无丢失；旧版丢失 43.35% 的不节流寄存器 JSONL 三轮，新版完整输出 144,000 条。
平均载荷减少 73.34%，单条 JSON 减少 40.08%；组合优化的独立贡献未拆分，CPU
降耗和持续零丢失不由该结果保证，见[增量设备报告](instruction-delta-2026-11-25.md)。
