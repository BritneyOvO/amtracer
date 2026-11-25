# fuxi 寄存器增量与 32 MiB 缓冲区验证

2026-11-25，设备 `282eb4e4`、Linux 5.15.167、SELinux Enforcing，boot ID
`78f0daf5-9bf8-47b7-9a59-3d54eed95b53`。实现提交 `3634c3a`：itrace ABI v2、
按线程压缩 x0–x30/SP/PSTATE，ringbuf 从 8 MiB 增至 32 MiB。

同一不节流负载的三轮寄存器 JSONL 全部输出 144,000 条，丢失率由旧配置的
43.35% 降至本轮 0；这是增量编码和扩大缓冲区的组合结果。未分别测量两项措施对
丢失率的贡献，也不能将短突发零丢失解释为持续吞吐保证。

产物、源文件、原始报告和 JSONL/stderr 哈希及逐组统计见
[验证清单](validation-instruction-delta-2026-11-25.json)。旧配置结果保留在
[原设备报告](instruction-device-2026-11-25.md)。

## 构建与正确性

38 项主机测试、rustfmt、用户态/eBPF Clippy、Android/eBPF release 构建通过。
两个 BPF 程序在目标 5.15 verifier 上通过。普通 uprobe 的 ABI 和事件格式未改。

```sh
cargo xtask build
python3 tests/instruction_smoke.py --serial 282eb4e4 \
  --report artifacts/instruction-smoke-delta-2026-11-25.json
python3 tests/instruction_delta.py --serial 282eb4e4 \
  --report artifacts/instruction-delta-2026-11-25.json
```

smoke 保留分支/循环、BL/BLR/RET、多线程、CPU 0/1/2 迁移、81 点位、跨页和故障
恢复，共核对 601 条完整路径事件，无丢失。新增按线程重建增量，并针对受控汇编中
连续采集的相邻指令核对全部 33 项状态，包括 PSTATE、保持不变的寄存器和值变为 0。
范围外 C 代码的寄存器变化不归因于前一条受追踪指令。

独立检查点用例产生 2,400 条，完整快照恰好位于序号 1、1025、2049；699 条增量
没有寄存器变化，载荷共 216,016 字节。没有序号缺口或未排空记录。

丢失注入仅 SIGSTOP 自己的消费进程，BPF 保持挂载，产生足够多的事件写满 32 MiB
ringbuf；随后 SIGCONT、等待输出排空，再驱动受控目标。没有暂停系统目标或修改内核。

| 丢失恢复用例 | 数量 |
| --- | ---: |
| 命中 | 720,288 |
| 成功提交并输出 | 345,286 |
| ringbuf 满导致丢失 | 375,002 |
| 消费端序号缺口 | 375,002 |
| 完整快照 | 338 |
| 成功提交载荷字节 | 30,820,864 |
| state_failed / queued / discarded | 0 / 0 / 0 |

连续发送失败后，恢复记录为完整快照，随后增量基线匹配，全部可见的连续指令状态
正确。最后序号为 720,288，与总命中一致；最终 `incomplete=true`，不会因为状态恢复
而掩盖丢失。检查点和丢失用例分别从输出重算载荷字节与快照数，与 BPF 统计一致。

smoke 和恢复测试在提交前执行，其报告记录的 HEAD 是前一个提交；验证清单记录了
随后提交为 `3634c3a` 的源文件哈希。基准在该提交后执行，三类测试的二进制/对象哈希一致。

## 性能对照

```sh
python3 -u tests/instruction_bench.py --serial 282eb4e4 \
  --report artifacts/instruction-bench-delta-2026-11-25.json \
  --seconds 2 --repeats 3 --modes baseline,pc,regs,pc-json,regs-json
```

与原基准使用相同 fixture 和参数：每次调用 24 条指令，四档事件率、五种模式各三次，
共 60 组。每组创建新目标 mm，预热后安装。summary-only 仍消费和校验，JSONL 经
ADB 保存到主机文件。不节流组每轮 2,000 次调用，产生 48,000 条事件。

| 不节流 regs-json 三轮 | 旧配置 | 增量 + 32 MiB |
| --- | ---: | ---: |
| ringbuf | 8 MiB | 32 MiB |
| 每条二进制载荷 | 336 B | 平均 89.577 B |
| 每条已输出 JSON | 平均 688.711 B | 平均 412.654 B |
| 命中 | 144,000 | 144,000 |
| 成功提交/输出 | 81,576 | 144,000 |
| ringbuf 丢失 | 62,424（43.35%） | 0 |

二进制载荷平均减少 73.34%，单条 JSON 平均减少 40.08%。JSON 按实际输出条数
归一化；旧版缺失的记录未参与旧版输出平均值，不能从总输出文件大小直接比较压缩率。
新版每轮约 4.30 MB 二进制载荷、19.81 MB JSON，共 47 个完整快照。

全部 60 组累计命中并成功提交 **2,039,040 条**，ring_lost、state_failed、
sequence_missing、queued、discarded 均为 0，最终均 `incomplete=false`。
目标 1k/10k/50k 事件率分别实际约 984/9,983/49,983 条/s，四种 trace 模式均无丢失。

| 不节流模式 | 旧版事件产生率中位数 | 新版事件产生率中位数 |
| --- | ---: | ---: |
| PC，summary-only | 777,768/s | 777,825/s |
| 寄存器，summary-only | 763,479/s | 623,913/s |
| PC，JSONL | 1,233,020/s | 1,318,436/s |
| 寄存器，JSONL | 1,194,787/s | 981,224/s |

这些是目标产生率，旧版包含丢失事件，并非有效输出率。增量增加寄存器比较、打包和
基线维护成本，没有减少 BRK/异常次数。本次寄存器模式的目标产生率低于旧版；没有
固定 CPU、频率、温度和后台负载，不能把该差值全部归因于增量，也不能声称 CPU 或
目标延迟得到改善。压缩的明确收益是记录体积缩小和本轮输出完整。

新版 17 点安装的 setup_ns 约 5.63–9.25 ms，包含 BPF 加载、挂载和后端复核。
工具停止前峰值 RSS 的各模式中位数约 69.4 MiB，旧版约 21.3–21.7 MiB。
扩大 ringbuf 会增加内存占用；RSS 不能等同于独占物理内存或内核全部开销。
ThreadState 值空间另由每项 16 B 增至 296 B，4096 项约 1.16 MiB，不含哈希开销。

## 清理与边界

完成后测试进程和随机临时目录均已清理，boot ID 未变。没有刷机、修改配套内核或
操作其他设备。本轮覆盖缓冲区满和连续发送失败的恢复，不覆盖任意信号/fork/exec
压力、完整 PAC/BTI 或长期慢输出矩阵。检查点用于重新建立寄存器状态，不补回已经
丢失的指令事件，也不将执行前命中解释为指令已退休。
