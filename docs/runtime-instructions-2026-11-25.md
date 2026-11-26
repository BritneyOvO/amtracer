# UXN 运行时指令准备与验证

日期：2026-11-25。目标是让稳定的私有 RX 解密代码使用进程内存中的实际指令；文件继续承担 perf/uprobe 的 inode、偏移及符号定位。

## 实现与提交

内核改动在独立 worktree `common-runtime-insns`、分支 `uxn/runtime-insns`。原 `common` 工作目录有大量先前改动，未直接覆盖。`90f789eb7` 是这些既有源码的前置快照，不能当成本轮功能提交。

| 仓库 | 提交 | 内容 |
| --- | --- | --- |
| kernel | `b3eb7b3c9` | 原生 BRK 写入前比较内存指令和已准备的原生指令，差异返回 ESTALE |
| kernel | `e55ce2472` | UXN 在文件分析前准备；局部架构解码、整页复核、独立命中与解绑 |
| kernel | `a7d7c6977` | 安装/计数回滚主机验证及动态代码设备夹具 |
| amtracer | `f567fe8` | 从进程内存规划 itrace，整页及映射复核，按实际 PC 输出指令 |
| amtracer | `a4396df` | 同 inode 不同私有明文的设备解析及 hook 脚本 |
| kernel | `5805d4b63` | 未对齐安装失败后的清理不能删除相邻有效绑定 |

内核为每个 `(mm, 原页)` 保存 snapshot、offset_map、绑定 bitmap 和 generation。临时 `arch_uprobe` 只验证真实站点指令，不写入 inode 范围共享的原生缓存。成功 UXN 路径不需要读文件指令，也不需要 `UPROBE_COPY_INSN`。卸载先清除 UXN 绑定、处理 USDT 并退役 generation；原页没有文件指令恢复操作。旧 recomp 仍保留到 mm 退出。

UXN 不适用时保留原生路径，但原生文件分析必须成功，并且待写位置的内存指令必须等于原生缓存。动态差异不能静默降级；准备/激活冲突、快照过期和回滚失败有明确错误。注册失败后的全局清理不会拿未初始化的原生缓存恢复指令。

没有新增 `/dev`、UAPI、用户态注册流程，也没有修改 KernelSU。文件与内存不同本身不再是 UXN 拒绝条件；无法安全执行时才失败。

## 已完成验证

| 项目 | 结果 |
| --- | --- |
| 内核 A64 编码/分类及生产 emitter、lookup、binding、dispatch 提取执行 | 27 项重编译测试通过 |
| 生命周期主机故障注入 | ASan/UBSan、清理 ENOMEM 重试、mm 退出、缺失/坏 PTE 通过 |
| 生产安装/卸载函数提取执行 | 内存优先、重复绑定、USDT 计数失败回滚、清理错误、不准备原生缓存时跳过恢复通过 |
| ARM64 内核 | ThinLTO、CFI、BTF 的完整 Image 构建通过 |
| 编译分支 | STEALTH 关闭时编译 uprobes；STEALTH 开启而 UPROBES 关闭时编译 uxn_track，通过 |
| amtracer 主机 | 39 项测试、fmt、用户态及 eBPF clippy 通过 |
| amtracer 构建 | AArch64 Android release、bpfel release 通过 |
| fuxi 运行时解析 | 两个私有映射分别输出 MOV X0,#42 / MOV X0,#77，文件仍为 `0x74959469`；符号与绝对地址预览通过 |
| fuxi 原有逐指令 smoke | 601 条完整路径事件；分支/循环、调用/返回、线程、迁移、多站点、跨页、异常恢复通过；无 ringbuf 丢失或序号缺口；拒绝、count、目标退出通过 |
| fuxi 新内核设备夹具 | runtime、auto、uprobe、BRK、fault 五组全部通过 |
| fuxi 私有解密 hook | 同 inode 不同明文的 itrace 两轮挂卸及普通 uprobe 的寄存器、内存、调用栈、count 通过；最终刷回新内核后复验通过 |
| 新旧内核性能 | 固定 CPU/1.92 GHz 的 perf 对照和 120 组端到端基准完成；逐指令实际追踪 7,223,040 次命中无丢失；详见独立报告 |

新内核已刷入并完成动态解密 hook 的端到端验收；最终 boot ID 为 `854ad72b-b404-4311-b277-1200b1a4e1df`，SELinux Enforcing，分区哈希已核对。功能、丢失恢复、同频成本、新旧端到端对照，以及 128 页布局失败和性能升高项见 [实机报告](runtime-device-2026-11-25.md)。主机注入仍不能当成实机内核 ENOMEM 注入。

主机真实 mmap 测试还验证：文件代码变化不影响已有私有明文；目标指令变化、同页其他位置变化或映射权限变化会使准备复核失败；文件中的排他指令不干扰已经解密的内存页检查，内存排他指令会拒绝；同文件偏移不同 PC 的事件输出使用各自指令。

## 构建产物与原始记录

工作区根目录为 `/root/Kernel/common-android13-5.15-2024-11`。

| 产物 | 位置 |
| --- | --- |
| 内核 Image | `out/uxn-runtime-kernel/arch/arm64/boot/Image` |
| 可刷入 boot 镜像 | `out/ktools-tests/uxn-runtime-20261125/new-boot.img` |
| 当前 boot_a 备份 | `out/ktools-tests/uxn-runtime-20261125/boot-before.img` |
| 构建与哈希清单 | `out/ktools-tests/uxn-runtime-20261125/manifest.json` |
| 内核构建/主机日志 | `out/ktools-tests/uxn-runtime-20261125/` |
| 工具与采集对象 | `common/tools/amtracer/artifacts/amtracer`、`amtracer-itrace.o` |
| 设备 hook 报告 | `artifacts/runtime-device-20261125/after-runtime-full-pass/runtime-report.json`、`final-runtime/runtime-report.json` |
| 601 条 smoke 报告 | `artifacts/runtime-device-20261125/after-instruction-smoke.json`，原始事件在同名目录 |

最终内核源码提交为 `5805d4b63`，版本字符串保持 `5.15.167-android13-8-00014-gbf0a81a7f319-ab13297889`。独立 boot 镜像使用本轮从设备读取的 boot_a 打包；再次解包后确认内核与构建 Image 完全一致。

* Image SHA-256：`ee96592e993b52f68ee69e4dcab48508602fd10f80eee3777d8f72f432b86bda`
* new-boot.img SHA-256：`3941f3c05fc47edd3cef84a0777c4ab2eb4489fef6f9cbbbc5edb1e1aff77a59`
* boot-before.img SHA-256：`e8b9386ab11711455cd688d7a50b4bad986d4495bf2d30fa10afec30b8ff9c17`

二进制、设备原始输出及被分析应用内容不进入 Git。

## 复现命令

在 DebugPlz 仓库构建设备夹具，NDK 路径按实际环境设置：

```sh
ANDROID_NDK_HOME=/path/to/android-ndk
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang" \
  -O2 -Wall -Wextra -Werror -fPIE -pie -Wl,-z,max-page-size=4096 \
  tests/fixtures/runtime.c tests/fixtures/runtime.S \
  -o target/debugplz-runtime-fixture
cargo xtask build
python3 tests/runtime_smoke.py --serial 282eb4e4 \
  --output artifacts/runtime-resolve --resolve-only
```

新内核运行后，去掉 `--resolve-only` 执行两轮挂卸、双别名事件序列，以及普通 uprobe 的寄存器/内存/栈采集和卸载后明文执行：

```sh
python3 tests/runtime_smoke.py --serial 282eb4e4 \
  --output artifacts/runtime-hook
```

内核设备测试在 `common-runtime-insns` 中构建，运行需 perf/prctl 权限：

```sh
make -C drivers/ktools/stealth/tests android_uprobe_runtime
adb -s 282eb4e4 push drivers/ktools/stealth/tests/uxn_uprobe_runtime_test /data/local/tmp/
adb -s 282eb4e4 shell 'chmod 755 /data/local/tmp/uxn_uprobe_runtime_test && /data/local/tmp/uxn_uprobe_runtime_test'
```

它覆盖零命中卸载、同 inode 双别名、不同 mm 同时挂点、重复与返回 consumer、USDT 安装失败回滚，以及动态指令无法重编译时不安全原生回退拒绝。失败时应检查输出和清理，再评估真实目标；不得在旧内核上把这组危险回退当作正常验收。

持续 RWX 自修改、匿名 JIT、外部并发改码及完整 PAC/BTI 矩阵不在本次完成范围。mmap 锁与前后字节复核不能证明任意时刻代码不变，资源、指令和权限限制仍然有效。
