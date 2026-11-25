# fuxi 指令 trace 验证

日期：2026-11-25。设备 `282eb4e4`，Android ARM64、Linux 5.15.167，SELinux Enforcing。
Boot ID：`78f0daf5-9bf8-47b7-9a59-3d54eed95b53`。代码版本 `8514ab2`，工具/对象与
2026-11-24 构建哈希一致；本次重新构建工具与 fixture，没有修改内核或采集代码。
命令、产物/报告哈希与逐组统计见
[validation-instruction-device-2026-11-25.json](validation-instruction-device-2026-11-25.json)。

## 正确性

```sh
cargo xtask build
python3 tests/instruction_smoke.py --serial 282eb4e4 \
  --report artifacts/instruction-smoke-2026-11-25.json
```

| 用例 | 事件数 | 核对结果 |
| --- | ---: | --- |
| 非零分支、三次循环、BL/BLR/RET、寄存器 | 72 | 三次调用的全部 PC、原始 LR 和返回值正确 |
| 零分支、寄存器 | 63 | 分支路径、间接调用与返回值正确 |
| 已有线程与两个新线程 | 216 | 每线程 PC 顺序及序号正确 |
| 同一线程跨 CPU | 72 | CPU 0/1/2，序号连续 |
| 80 NOP + RET | 162 | 81 个唯一点位，超过普通 uprobe 的 64 点限制 |
| 跨原始页面调用 | 12 | 两页共六个点位，进入/返回顺序正确 |
| 两次非法地址 load + 信号恢复 | 4 | SIGSEGV 中 PC 为原始地址，恢复后继续 RET |

以上 601 条事件的 `ring_lost`、`state_failed`、`sequence_missing`、`discarded`、
`queued` 均为 0，最终 `incomplete=false`。重复范围去重、raw exit hook、UXN v4
查询以及两个 BPF 程序通过目标 5.15 verifier。

排他指令所在页、SVC 位置均在预检时拒绝。包含不可重定位认证调用的测试页触发内核
原生后端回退，工具检测没有激活的 UXN recomp 后拒绝启动，目标仍可继续调用。
`count=7` 恰好输出七条，另二十条记作 `discarded`，设置 `incomplete=true`。
目标正常退出时工具自动结束。多轮安装、卸载与 Ctrl-C 正常完成。

## 性能

```sh
python3 -u tests/instruction_bench.py --serial 282eb4e4 \
  --report artifacts/instruction-bench-2026-11-25.json \
  --seconds 2 --repeats 3 --modes baseline,pc,regs,pc-json,regs-json
```

共 60 组：四档事件率 × 五种模式 × 三次。每次调用执行 24 条被追踪原始指令。
PC/regs 为 summary-only，仍采集、消费及校验事件，省略每条事件格式化和输出。
JSONL 经 ADB 保存到主机本地文件。每组使用新目标 mm，先预热再安装。

| 目标指令事件率 | 实际事件率约值 | 四种 trace 模式，每种三次 |
| ---: | ---: | --- |
| 1,000/s | 984/s | 无丢失 |
| 10,000/s | 9,980/s | 无丢失 |
| 50,000/s | 49,984/s | 无丢失 |

固定速率用例通过 sleep 控制调用间隔，达到速率不代表目标调用没有变慢。
以目标约 50k/s 档为例，三次运行的调用延迟中位数如下：

| 模式 | 每次调用 p50 | 每次调用 p95 | 每次调用 p99 |
| --- | ---: | ---: | ---: |
| 未挂载 | 0.157 µs | 0.313 µs | 0.469 µs |
| PC，summary-only | 118.021 µs | 180.000 µs | 224.428 µs |
| 通用寄存器，summary-only | 81.614 µs | 182.292 µs | 224.375 µs |
| PC，JSONL | 102.031 µs | 174.740 µs | 222.239 µs |
| 通用寄存器，JSONL | 100.989 µs | 141.510 µs | 179.062 µs |

这些为每组最多 1024 个均匀采样调用的分位数，再取三次运行的中位数。
没有固定 CPU、频率、温度或后台负载，表中的模式差异不能解释为寄存器模式比 PC 模式
更快。目标是一个极短汇编函数，数百倍的调用延迟变化不能作为普通应用整体降速比例。

不节流用例每组 2000 次调用，产生 48,000 条指令事件，是短突发：

| 模式 | 三次目标产生事件率中位数 | 三次 ringbuf 丢失 |
| --- | ---: | ---: |
| PC，summary-only | 777,768/s | 0 |
| 通用寄存器，summary-only | 763,479/s | 0 |
| PC，JSONL | 1,233,020/s | 0 |
| 通用寄存器，JSONL | 1,194,787/s | 62,424 / 144,000（43.35%） |

最后一种模式三次丢失比例为 42.8125%、43.61875%、43.61875%，均正确报告
`incomplete=true`。表中速率是目标产生率，包含未成功提交的事件，不能当作有效输出率。
其他模式零丢失仅适用于这段短突发，不证明能长期维持该吞吐。JSONL 模式更高的目标
产生率不能作为优化结论：调度/频率未控制，丢弃也会改变采集负担。

全部性能用例共发生 2,039,040 次指令采集，成功提交 1,976,616 条，ringbuf 丢失
62,424 条；线程状态分配失败、停止排空后的 queued/discarded 均为 0。
17 点安装所报告的 setup_ns 约为 1.68–3.96 ms，包含 uprobe 加载/安装及后端复核，
不含完整进程启动/ELF 解析。工具停止前读取的峰值 RSS 中位数约 21.3–21.7 MiB。
工具 CPU ticks 和峰值 RSS 的采样不包含所有停止排空阶段，原始 CLK_TCK=100。

## 清理与边界

测试完成后，自己创建的 trace/fixture 进程和随机临时目录全部清理，设备 boot ID
与测试前相同。测试未刷机，也未操作其他设备或系统目标进程。

仍未单独测量“每条原始指令预留 NOP”的非命中开销，未做原生 BRK/XOL、stackplz
对照，也未覆盖 1024 点、完整 PAC/BTI、fork/exec、慢输出压力和故障注入矩阵。
这次确认受控逐指令 trace 能运行，并测得高输出负载下的实际丢失边界。
