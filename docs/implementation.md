# 实施记录

日期：2026-11-24。设计目标见 design.md，未列为完成的项目仍按 roadmap.md 推进。

## 已落地

* 独立 main 仓库、Cargo workspace、Android/Aya 构建和固定 UAPI 绑定。
* 三种 uprobe 定位、cookie、TGID 过滤、完整 AArch64 通用寄存器与栈窗口。
  APK 映射与动态映射生命周期尚待完善。
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

Binder 成功事务与请求/回复关联、完整 syscall 参数语义、APK、
混合会话、有界处理队列、生命周期完整矩阵及性能基准。
当前验证不能代替这些验收，尤其不能将失败请求测试当成成功请求/回复测试。

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
证据为 artifacts/binder-smoke.json。此路径尚不覆盖成功 Binder 事务和回复配对。
主机测试增至 13 项；依赖关闭未使用的 Mach-O/PE 特性，移除未使用的直接依赖。
实机另验证 ELF 偏移、符号内偏移、多探针及已有和新建线程；字符串刚好放入缓冲区
时不标为截断。用户态和 eBPF 的 Clippy 均通过。构建产物、三份原始测试报告的哈希及
工具链版本保存在 validation-2026-11-24.json；原始报告在本地 artifacts 目录。
