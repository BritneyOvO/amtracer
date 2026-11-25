# 逐指令 trace：长批次 insn/s 实测

2026-11-25，fuxi `282eb4e4`，运行时指令新版内核。每种模式三轮，每轮 100 万次受控函数调用，每次执行 24 条被追踪的原始指令，即每轮 **2400 万次命中**。单线程、17 个唯一点位；循环和子函数重复执行按实际次数计数。

## 结果

`insn/s = 实际命中次数 / 目标执行耗时`。汇总模式仍加载 BPF、采集和校验记录，只省去逐条格式化与输出。下面的中位数来自三轮，范围为三轮最小/最大值。

| 模式 | 命中 insn/s 中位数 | 三轮范围 | 接收 / 命中总数 | ring 丢失率 |
| --- | ---: | ---: | ---: | ---: |
| 仅 PC，汇总 | 863,509 | 795,779–871,890 | 72,000,000 / 72,000,000 | 0.0000% |
| 寄存器增量，汇总 | 686,239 | 668,265–687,787 | 72,000,000 / 72,000,000 | 0.0000% |
| PC JSONL，经 ADB | 1,491,357 | 1,387,163–1,516,461 | 5,574,360 / 72,000,000 | 92.2578% |
| 寄存器增量 JSONL，经 ADB | 1,420,095 | 1,390,160–1,441,722 | 3,856,882 / 72,000,000 | 94.6432% |

仅 PC 和寄存器汇总合计 1.44 亿次命中，全部收到，`ring_lost/state_failed/sequence_missing/discarded/queued` 为 0。每次调用的返回值也验证通过。

JSONL 两项是命中速度，**不能当成完整记录吞吐**。不节流生产下，格式化及 ADB 输出链路来不及消费，ringbuf 填满后出现大量丢失。本次没有隔离格式化、USB 和主机接收的独立贡献，不能仅凭这些样本归因于某一组件。

接收总数包含目标停下后排空缓冲区收到的记录；本测试的分母是目标执行时段，没有单独计时末尾排空，因此不把 `received / 目标耗时` 当成持续输出容量。序号缺口只在后续收到事件时可见，末尾没有后续事件的丢失仍由内核 `ring_lost` 保留总数。`incomplete=true` 表明 JSONL 不是完整轨迹。

此前 [实机报告](runtime-device-2026-11-25.md) 的不节流样本每轮仅 10000 次调用、24 万条事件，属于短突发，可在结束后继续排空。本次扩大到 100 倍长批次后显示了输出瓶颈；此前短突发零丢失不能外推为持续满速输出保证。

## 方法与边界

- 使用现有 `tests/instruction_bench.py` 和 `tests/instruction_device.py`，没有修改 Rust、BPF 或内核代码。
- JSONL 文件预先建立指向主机 `/dev/null` 的软链接，仍经过设备 JSON 序列化和 ADB USB 传输；不测主机磁盘写入，也不是设备端直接丢弃输出。
- 默认 Android 调度，不固定 CPU 和频率；CPU 4 所在簇仍保持 1920000–2592000 kHz，不改温控。这是本设备当次工作负载下的测量，不能视为所有指令、线程数和设备的保证。
- `--seconds 9` 只给不节流组提供 90 秒的主机等待上限；每轮长度仍由 `--unpaced-rounds 1000000` 决定，不是固定 9 秒采样。
- 启动时发现旧的 30 秒等待上限不适合长批次，手动中断预检后增加上限。预检原始报告保留，未计入正式样本。
- 测试结束 boot ID、boot_a 哈希、频率上下限不变；本轮没有新内核 WARNING、BUG/Oops/panic，也没有夹具进程残留。

## 复现

在 amtracer 仓库准备好工具和指令 fixture 后运行：

```sh
python3 - <<'PY'
from pathlib import Path
p = Path("artifacts/insn-throughput-check")
p.mkdir(parents=True, exist_ok=False)
for repeat in range(3):
    for mode in ("pc-json", "regs-json"):
        (p / f"0-{repeat}-{mode}.jsonl").symlink_to("/dev/null")
PY
python3 -u tests/instruction_bench.py --serial 282eb4e4 \
  --report artifacts/insn-throughput-check.json --seconds 9 --repeats 3 \
  --event-rates 0 --modes baseline,pc,regs,pc-json,regs-json \
  --unpaced-rounds 1000000
```

原始统计、stderr 和设备日志位于本地 `artifacts/insn-throughput-20261125*`，没有保存被丢弃的 JSONL 内容。各轮耗时、命中/接收/丢失、工具与原始报告哈希见 [验证清单](validation-insn-throughput-2026-11-25.json)。二进制和原始输出不进入 Git。
