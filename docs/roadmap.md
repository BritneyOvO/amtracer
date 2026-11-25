# 提交和验收计划

日期：2026-11-24。功能边界以 [design.md](design.md) 为准。

| 顺序 | 提交主题 | 验收 |
| --- | --- | --- |
| 1 | docs: define architecture and semantics | 独立仓库、架构、地址、表达式及测试计划可评审 |
| 2 | build: bootstrap android aya workspace | Android 构建；受控进程最小 Aya uprobe 加载命中 |
| 3 | feat: add ktools session bindings | UAPI 来源、ABI 布局、权限错误、EBUSY、关闭路径 |
| 4 | feat: resolve arm64 probe targets | 独立 ELF 库偏移/符号/绝对 VA 一致；多 PT_LOAD、歧义 |
| 5 | feat: capture uprobe registers | cookie、多探针、全部通用寄存器、线程与跨 CPU、挂卸 |
| 6 | feat: compile debug expressions | 优先级、嵌套、类型、负偏移、溢出和错误定位 |
| 7 | feat: capture uprobe memory | 标量、字符串、字节、指针链、跨页/缺页/截断 |
| 8 | feat: unwind native stack snapshots | CFI/FP、符号化、无 FP、递归、PAC、中间指令 |
| 9 | feat: consume syscall trace events | 参数规则和受控输入设备验证已完成；返回缓冲区语义及丢失矩阵待补 |
| 10 | feat: consume binder trace events | 已覆盖同步成功/失败、oneway、数据与顺序正常时的请求/回复关联；逆序关联和丢失压力待补 |
| 11 | feat: integrate tracing sessions | 初版 JSON 配置、跨来源 JSONL、全局 duration/count 和退出传播已实现；双来源、count 和 uprobe 启动失败回滚真机 smoke 已通过，慢输出、EBUSY 和生命周期矩阵待补 |
| 12 | test: add device correctness and benchmarks | 可复现真机正确性和性能报告 |
| 13 | feat: add recomp instruction tracing | 主机与构建通过；2026-11-25 fuxi 受控 smoke 通过，601 条完整事件无丢失；性能及完整边界矩阵见 instruction-trace.md |

允许按依赖关系拆分较大的提交；每项状态在实施记录中更新，未完成验收不得标为通过。

## 测试矩阵

* 主机：表达式与地址转换、恶意/截断事件、ABI 布局、配对与丢失、缓存失效。
* 构建：cargo fmt --check、clippy（用户态和 ABI）、cargo test、AArch64 Android release、
  bpfel release，记录工具链和依赖锁文件。
* uprobe 设备样例：可控 ELF/so，三种定位、递归、不同线程、跨 CPU、符号内偏移、
  有/无 FP、PAC、跨页内存、字符串截断、重复挂卸与目标退出。
* syscall：受控子进程的 openat/read/write/ioctl、errno、输出容量、入口/返回过滤、
  栈、线程退出与队列丢失。不得抢占已有 trace 会话。
* Binder：受控 client/service 的同步成功与回复 ID 配对、oneway，以及原有失败事务、截断和 interface token；队列丢失/序号缺口的失效行为有主机单测。失败回复和 Binder 队列压力矩阵仍待设备覆盖。
* 生命周期：Ctrl-C、启动中途失败、慢输出、进程退出、exec、映射改变与资源上限。

真机使用指定设备 `adb -s 282eb4e4`，不操作其他在线设备。工具验证不需要刷机。

## 性能基准

基线、uprobe 空事件、通用寄存器、内存表达式、8/16 KiB 栈窗口、CFI/FP、syscall、
Binder、混合追踪分别测量。区分采集本身、解栈符号化、文本/JSONL 输出的开销。

受控事件率包括可达到的 1k/10k/50k 次每秒，预热后每组重复三次，记录：

* 目标程序吞吐与耗时增量，p50/p95/p99。
* 工具 CPU、RSS、输出字节、事件吞吐。
* 每层丢失数量及比例，栈完整率与截断原因。
* 冷/热 maps、ELF 和符号缓存。
* 原版 stackplz 的等价 uprobe 配置对比。

保存设备 boot ID、内核版本、构建提交、工具链、命令和原始数据；没有实测不得填性能数字。
