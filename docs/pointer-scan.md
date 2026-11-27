# 指针链扫描 (`scan pointer`)

`scan pointer` 支持**在线目标进程内存扫描**（`-p/--pid`）与**离线导出快照扫描**（`--input`），从目标地址反向回溯到模块根段并输出 `DPTR` v1 二进制结果。

## 在线进程扫描

```sh
debugplz scan pointer 0x7a12345678 0x7a12345690 -p 1234 \
  --bits 64 --depth 4 --max-offset 0x400 \
  --modules libgame.so,libengine.so:0x7000000000-0x7000100000 \
  --reader syscall --layer-limits 1:0x40,2:0x100 \
  --auto-offset --budget-ms 500 \
  --align4 --cross-page-step4 --negative-offsets --pagemap --restricted \
  --output chains.out --norm pointers.norm
```

## 离线快照扫描

```sh
debugplz scan pointer 0x3008 0x3020 --input pointers.json \
  --bits 64 --depth 4 --max-offset 256 --modules libsample.so \
  --layer-limits 1:0x40,2:0x100 --auto-offset --budget-ms 100 \
  --output chains.out --norm pointers.norm
```

`pointers.json` 示例：

```json
{
  "version": 1,
  "segments": [
    {"module":"libsample.so","segment":".data","start":"0x1000","end":"0x1100"}
  ],
  "pointers": [
    {"address":"0x1010","value":"0x2000"},
    {"address":"0x2020","value":"0x3000"}
  ]
}
```

## 算法流程

从每个目标地址 $A$ 反向回溯：

1. **扫描内存槽位**：遍历目标进程可读 VMA（开启 `--restricted` 时包含受限区；开启 `--pagemap` 时先查询 `/proc/<pid>/pagemap` 跳过未驻留页），提取所有非零且符合对齐约束的 4/8 字节指针位置与值。
2. **候选匹配与模块解析**：在每一层查找值满足 $A - \text{offset}$ 的候选槽位，并判断命中地址是否落入目标模块根段（计算所属模块、段与段内偏移）。
3. **多层递归回溯**：若未到达模块根且未超过 `--depth`，将命中槽位地址作为新目标继续向上回溯，自动排除环路与重复槽位。
4. **输出完整链**：命中模块根段后输出完整指针链；从根槽位开始，每级先解引用再加该级偏移，最后一级只加偏移、不解引用，直接得到目标地址。

## 参数与高级开关

| 选项 | 行为 |
| --- | --- |
| `<TARGET...>` | 一个或多个目标地址，支持十进制与 `0x` 十六进制 |
| `-p, --pid PID` | 在线扫描目标进程内存（与 `--input` 二选一） |
| `--input PATH` | 从离线 JSON 快照读取模块段与指针槽（与 `--pid` 二选一） |
| `--bits 32\|64` | 指针宽度，默认 64 位 |
| `--depth 0..256` | 最大解引用层数，默认 4。深度为 0 时仅输出本身位于模块根段内的目标 |
| `--max-offset N` | 每层默认偏移上限，默认 `0x400`（支持十进制与 `0x` 十六进制） |
| `--modules SPEC,...` | 模块范围列表：支持模块名（`libfoo.so`）、带范围模块（`libfoo.so:0x1000-0x2000`）或纯地址范围（`0x1000-0x2000`） |
| `--reader SPEC` | 在线内存读取器：`syscall`（默认，`process_vm_readv`）、`pread`（`/proc/PID/mem`）或自定义 `.so` 路径（导出 `debugplz_read_mem` / `read_mem`） |
| `-o, --output PATH` | 二进制链结果输出路径（须为新文件） |
| `--norm PATH` | 同时保存归一化、排序去重后的 JSON 快照，可再次作为 `--input` 使用 |
| `--auto-offset` | 每一层按 `\|offset\|` 从小到大优先回溯 |
| `--budget-ms N` | 回溯时间预算（毫秒），超时后保留已找到的完整链并标记 `complete=false` |
| `--layer-limits L:N,...` | 逐层偏移上限（如 `1:0x40,2:0x100`），最靠近目标的一层为第 1 层 |
| `--align4` | 按 4 字节步进扫描槽位（默认按指针宽度 4/8 字节对齐） |
| `--cross-page-step4` | 64 位扫描时在相邻可读页边界额外以 4 字节步进拼接跨页槽位（如页尾 `0xffc`） |
| `--negative-offsets` | 允许负偏移，范围仍受当前层偏移上限约束 |
| `--pagemap` | 读取前查询 `/proc/PID/pagemap` 页表驻留位，跳过缺页区域 |
| `--restricted` | 同时尝试读取受限映射区（如 `---p` / `--xp`），`syscall` 模式下自动回退尝试 `ktools` `rwmem` |

成功时 stdout 输出 `{"chains":2,"complete":true}` 摘要。

## DPTR v1 二进制布局

整数均为小端，字段之间无填充。模块表下标从 0 开始。

| 部分 | 字段顺序 |
| --- | --- |
| 文件头 | `DPTR`，版本 `u16`，位数 `u8`，保留字节 `u8=0`，段数 `u32` |
| 每个段 | 模块名 UTF-8 字节长 `u32` 和名称，段名 UTF-8 字节长 `u32` 和名称 |
| 每条链 | 标记 `u8=1`，目标地址 `u64`，根段下标 `u32`，根在段内的偏移 `u64`，偏移数 `u16`，按根到目标排列的 `i64` 偏移 |
| 文件尾 | 标记 `u8=0`，完整标志 `u8`（完整为 1，超预算为 0），链条数 `u64` |

读结果时须校验文件尾，缺少文件尾表示写入未完成。
