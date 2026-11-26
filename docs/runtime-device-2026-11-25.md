# 运行时指令：fuxi 功能验收与性能对照

2026-11-25，在 fuxi `282eb4e4` 上刷入运行时指令内核，动态解密页的普通 uprobe 和 itrace 均通过。新旧内核的 120 组逐指令基准包含 96 组实际追踪，合计 **7,223,040 次命中，无 ringbuf 丢失或序号缺口**。另有一次主动暂停消费者的丢失恢复测试，单独记录，不能计为零丢失样本。

## 设备和产物

设备为 Android 13、ARM64 Linux 5.15.167，SELinux Enforcing。所有 ADB/fastboot 操作均指定 `282eb4e4`。测试只使用本仓库和内核中的受控夹具，没有在游戏进程上重复危险安装。

| 项目 | 标识 |
| --- | --- |
| 新内核源码 | `5805d4b63`，后续提交仅测试和文档 |
| 新 boot_a SHA-256 | `3941f3c05fc47edd3cef84a0777c4ab2eb4489fef6f9cbbbc5edb1e1aff77a59` |
| 旧 boot_a 备份 SHA-256 | `e8b9386ab11711455cd688d7a50b4bad986d4495bf2d30fa10afec30b8ff9c17` |
| amtracer SHA-256 | `ca6f69563d0ce5e452cb9a5c105825d9fb38281286309b80e449e9ce47ac28ff` |
| itrace BPF SHA-256 | `8e39122cd55e3887dee59a77cf34c7ce0472852b9c908d96d85a4223e40a6793` |
| perf 基准夹具 SHA-256 | `6792c1a575d7a1c9b31d06aa19d6a552b8e5efa46f924a136bc8c3c2a66d99f7` |
| 旧内核首轮 boot ID | `78f0daf5-9bf8-47b7-9a59-3d54eed95b53` |
| 新内核功能/首轮基准 boot ID | `97b60927-5067-449e-b391-c5d23cb226f0` |
| 旧内核同频基准 boot ID | `c6c706fb-1197-4dff-bee7-b31602c269c9` |
| 最终新内核 boot ID | `854ad72b-b404-4311-b277-1200b1a4e1df` |

新旧内核保留同一个 release 字符串，不能用 `uname` 区分；每次刷写均核对设备型号、槽位、镜像及分区哈希，并确认 boot ID 改变。最终保留新内核，CPU 4 所在簇频率上下限恢复为测试前的 1920000 / 2592000 kHz，温控没有改动。

## 功能结果

| 测试 | 结果与边界 |
| --- | --- |
| `uxn_uprobe_runtime_test` | 零命中卸载保留明文；同 inode 双别名和不同 mm；重复/返回 consumer；USDT 失败回滚；不安全原生回退明确拒绝，原页未损坏 |
| `uxn_uprobe_auto_test` | 自动挂卸、fork 过滤、退休代码继续执行、重新挂点、运行中循环加点、先挂后 mmap、munmap、原生回退通过 |
| `uxn_uprobe_test` / `uxn_brk_test` | 原始 PC/寄存器、USDT、显式/自动共存、entry/return、多点、fork、NO_PREFIX 和保护条件通过 |
| `uxn_uprobe_fault_test` | 只读写异常不破坏探针；信号 PC/si_addr、sigreturn 重试；源 PTE 消失和截断；失败 image 清理通过 |
| 私有明文 itrace | 两轮挂卸各 12 条；同 inode/offset 的两个别名分别输出 `MOV X0,#42` / `MOV X0,#77`，文件仍为密文 `0x74959469`；卸载后执行正确 |
| 私有明文普通 uprobe | 绝对地址、`r0`、`*sp`、代码字节、全寄存器和原生栈通过；`--count 3` 精确输出 3 条，`kernel_lost=0` |
| 原有 itrace smoke | 601 条精确 PC/寄存器路径事件，含线程、CPU 迁移、81 点、跨页和异常恢复；无意外丢失；排他/SVC/原生回退拒绝、count、目标退出通过 |
| 普通工具 smoke | 三种定位、符号内偏移、16 个表达式、跨页字符串、多探针、多线程和 9 帧调用栈通过；syscall 采集/栈通过；Binder 会话开关通过，本轮没有制造 Binder 事务 |
| 最终刷回复验 | 私有明文 itrace 两轮和普通 uprobe 再次通过 |

601 条统计只包括完整路径验收，不含 count 的主动截断样本。count 样本输出 7 条时，允许已经在途的记录按既有统计记为 discarded/incomplete，不能误报为环形缓冲区丢失。

寄存器增量测试收到 2400 条，3 次完整快照、699 条空增量，无丢失。恢复测试主动 `SIGSTOP` 消费者，使 720288 次命中中 375003 条写入失败；恢复后收到 345285 条，序号缺口恰好等于丢失数，1 次缺口通过完整快照重新同步，338 次完整快照，无 `state_failed/discarded/queued`，`incomplete=true` 保留丢失事实。它证明能恢复后续寄存器状态，不能恢复已经丢掉的事件。

## 固定 CPU/频率的内核成本

同一夹具固定 CPU 4、临时设置该簇 min=max=1920000 kHz。新内核测完后刷回备份旧内核，再按同样参数测量；每版 3 轮，每个进程预热 1000 次，然后 7 × 20000 次调用。每组记录实际频率并验证后端、原页字节、返回值和精确 perf 计数。各版每组结束后的频率均为 1920000 kHz。

下表是每项 21 个批次的 CPU 时间/调用中位数，包含间接调用和探针路径。它不加载 BPF，不含 JSON 和解栈。页数表示同一个进程同时挂点的页数，每次只调用最后一页。

| 路径 | 旧版 ns/调用 | 新版 ns/调用 | 新相对旧 |
| --- | ---: | ---: | ---: |
| 无探针 | 2.112 | 2.112 | 约 0% |
| 原生 BRK/XOL，1 页 | 1453.4 | 1511.9 | +4.0% |
| UXN 命中，1 页 | 943.7 | 913.6 | −3.2% |
| UXN 命中，64 页 | 1069.6 | 985.6 | −7.9% |
| UXN 同页非 site，1 页 | 179.0 | 212.6 | +18.8% |
| UXN 同页非 site，64 页 | 222.7 | 205.2 | −7.9% |

本夹具的非 site 函数每次由原页进入 recomp，因此包含一次 UXN 异常和短函数执行；不能把它等同于一条 NOP 的成本。单页非 site 新增约 34 ns，原生 BRK 也测到上升，不能概括为所有路径没有回退。即使同频，后台负载、缓存、VMA 布局及温度仍未完全控制；仅三轮顺序 A/B 不能证明这些百分比都是代码变更的因果效果。

刷回新内核后再跑三轮，保留复测全部数据。普通 UXN 1 页命中为 946.4 ns，64 页为 995.1 ns；原生为 1521.2 ns；同页非 site 分别为 210.4 / 212.7 ns。因此单页命中相对旧版应看作接近持平至略低，不能仅凭第一轮的 −3.2% 宣称稳定提速。

同一复测还交错运行私有明文模式，页内指令与文件不同，返回值仍逐次校验：

| 新内核路径 | 命中 ns/调用 | 同页非 site ns/调用 | 首次逐页安装 µs |
| --- | ---: | ---: | ---: |
| 普通 UXN，1 页 | 946.4 | 210.4 | 307.08 |
| 私有明文 UXN，1 页 | 927.7 | 196.9 | 364.58 |
| 普通 UXN，64 页 | 995.1 | 212.7 | 98.46 |
| 私有明文 UXN，64 页 | 1019.0 | 206.6 | 95.60 |

私有明文没有旧版可安全执行的等价基线；这里只有新版内的比较。命中成本接近普通 UXN，本轮没有看到数量级增加。

安装/卸载为 wall time 中位数，单位 µs。多页安装的数字是该组所有页的逐页安装中位数；同页加点/减点各 32 次，与首次构建分开测量。

| 路径 | 首次逐页安装 旧→新 | 同页加点 旧→新 | 同页减点 旧→新 | 关闭原 site 旧→新 |
| --- | ---: | ---: | ---: | ---: |
| 原生，1 页 | 440.52→396.93 | 18.31→18.33 | 80.81→88.52 | 14010.26→13729.48 |
| UXN，1 页 | 341.35→439.12 | 33.75→38.52 | 85.70→74.84 | 15654.38→13692.66 |
| UXN，64 页 | 89.90→91.93 | 50.62→45.34 | 98.62→93.20 | 92.53→90.55 |

单页首次安装本轮高约 28.6%，多页逐页安装高约 2.3%。关闭时间包含 perf 同步等待，多页中位数与最后一个 FD 的时间含义不同，不能当作纯 UXN 资源回收耗时。原始批次、分轮中位数和范围见验证清单与本地报告。

最终复测的首次安装为单页 307.08 µs、64 页逐页 98.46 µs；同页加点分别为 32.47 / 71.69 µs，减点 88.36 / 119.30 µs，关闭 16093.28 / 83.98 µs。安装/加点/关闭的批间波动明显，第一轮单页安装的 +28.6% 不能认定为稳定回退，也不能略去这组升高数据。

## amtracer 端到端吞吐

新旧内核使用相同 amtracer、BPF 和 fixture。每版 60 组：baseline、PC summary、regs summary、PC JSONL、regs JSONL，事件率为不节流、1k、10k、50k，各重复三次。不节流每组为 10000 次函数调用，每次 24 个事件。此组没有固定 CPU/频率。

| 不节流模式 | 旧版 事件/秒 | 新版 事件/秒 |
| --- | ---: | ---: |
| PC，仅汇总 | 846761 | 887269 |
| 寄存器，仅汇总 | 660619 | 683108 |
| PC，JSONL | 1306884 | 1442986 |
| 寄存器，JSONL | 1014388 | 1086276 |

每版实际追踪 48 组、3,611,520 次命中，`hits=received=expected`，`ring_lost/state_failed/sequence_missing/discarded/queued` 全为 0。1k 档受每次 24 条的粒度影响约为 984 条/秒，10k/50k 档接近期望值。17 个点安装耗时中位数旧 7.994 ms、新 7.639 ms；工具 RSS 中位数约 69.4 / 69.5 MiB。

吞吐用目标函数执行时段计算，消费者可在突发结束后继续排空输出。JSONL 样本比 summary 数字高受调度、频率、缓冲和并行消费影响，不能解释为格式化能提速，也不能将短突发零丢失外推为持续满速保证。首轮另有未锁频的 perf 数据，旧版频率与新版不同，仅留作参考，正式内核对照使用上面的同频数据。

后续将每轮扩大到 2400 万条并重复三次，PC/寄存器汇总中位数为 863509 / 686239 insn/s，合计 1.44 亿条零丢失；不节流 JSONL 经 ADB 输出分别丢失 92.26% / 94.64%。详见 [长批次吞吐报告](insn-throughput-2026-11-25.md)，不能用本节短突发数据代替持续输出能力。

## 发现的限制和日志

128 页布局在旧/新内核均出现过 `uxn_probe: tail exit out of B range ... off=8192`，随后原生回退导致后端断言失败。失败报告保留，不混入 UXN 成功样本。它表明当前近址分配/页尾跳转存在布局限制，不证明 mm 退出清理泄漏；增加组间延迟不能保证解决。动态差异页无法安全回退时应报错，itrace 必须拒绝原生回退。

功能测试前新内核启动已经有 5 条内核 WARNING：3 条 `spmi-pmic-arb`、1 条 `device_links_driver_bound`、1 条显示初始化中的 `__alloc_pages`。功能测试后数量和调用点未增加，没有新增 BUG/Oops/panic；日志也包含已有的 linker 和 unprivileged eBPF 警告，不能称作启动完全无告警。真实内核 ENOMEM 分配故障注入、持续 RWX/JIT、完整 PAC/BTI 矩阵及 Binder 压力不在本轮覆盖范围。

## 复现和原始记录

在 DebugPlz 仓库运行，先按构建文档生成相同工具和夹具：

```sh
python3 tests/runtime_smoke.py --serial 282eb4e4 --output artifacts/runtime-device-check
python3 tests/instruction_smoke.py --serial 282eb4e4 --report artifacts/instruction-check.json
python3 tests/instruction_delta.py --serial 282eb4e4 --report artifacts/delta-check.json
python3 tests/instruction_bench.py --serial 282eb4e4 --report artifacts/instruction-bench.json \
  --seconds 1 --repeats 3 --event-rates 0,1000,10000,50000 \
  --modes baseline,pc,regs,pc-json,regs-json --unpaced-rounds 10000
```

内核同频基准在 `common-runtime-insns` 运行：

```sh
make -C drivers/ktools/stealth/tests android_uprobe_bench
python3 drivers/ktools/stealth/tests/uprobe_bench.py --serial 282eb4e4 \
  --pages 1,64 --frequency 1920000 --report /path/to/locked-uprobe.json
```

新内核可加 `--runtime` 测私有内存/文件不同的稳定 RX 页面；旧内核不要运行这个模式。`--pages 128` 显式启用已知可能失败的布局压力项。频率不可用、变化或恢复失败时脚本报错并保留记录。

workspace 根目录下 `out/ktools-tests/uxn-runtime-20261125/device/` 保存刷机日志、boot 验证、5 个内核夹具输出、dmesg、旧/新 perf 及同频报告；`common/tools/amtracer/artifacts/runtime-device-20261125/` 保存解析、普通 uprobe、itrace、delta 和端到端 JSONL。报告哈希、设备标识和聚合数据见 [validation-runtime-device-2026-11-25.json](validation-runtime-device-2026-11-25.json)。原始输出和二进制不进入 Git。
