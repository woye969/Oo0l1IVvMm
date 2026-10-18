# Seagull Deobfuscator for IDA Pro 9.1

**用法：把两个 .py 装进 IDA 的 plugins 目录，重启 IDA，在混淆函数上按 F5。**
无需脚本、无需菜单操作——插件自动识别"比较链 + 编码跳转表"式控制流平坦化，
把每个状态转移解析成直达边，F5 直接显示反混淆后的伪代码。

## 安装

- 运行 `install_seagull_ida91.ps1`（默认装入 `IDA Professional 9.1\plugins`），
  或手工复制 `ida_seagull_deob.py`、`seagull_core.py`、`vendor\capstone\`。
- `ida_seagull_deob.py`：F5 恢复钩子、微码直达边/条件拆分重写、IDA 动作
- `seagull_core.py`：x86-64 抽象解释器 + 分发链具体解析器（自动发现状态寄存器/
  解码钥寄存器，无样本硬编码）
- 需要 Hex-Rays x64 反编译器；Capstone 5 随插件附带

## 它解决什么

针对这类平坦化（本插件自动识别，不需要配置）：

- 每个状态块尾部内联分发：`cmp 状态reg, K; jl 选偏移A/B; 查全局表;
  add 解码钥reg; jmp reg`，未命中跳下一 stub，形成线性比较链
- 状态值可能藏在**栈槽**里（经未知地址的存储会把抽象解释器的内存模型打掉，
  纯 valrange 的 unflattener 因此失败——本插件用"单写者常量槽 sticky 内存
  模型"解决）
- 原始 if/else 被折进状态计算（cmov）——插件按状态值做 **jz 条件拆分**重建分支
- 条件跳转直接进入分发链（je/js）——保留条件、仅改 taken 目标

工作流程（全部自动）：递归解码物化指令边界 → 有限 `ijmp` 提升为 jtbl →
对每个状态更新点用其具体 `(状态值, 解码钥)` **重新执行分发链**直到真实状态块 →
微码层改写为直达边/条件边（两阶段：先插完全部块再用最终 serial 写指令，
避免重编号腐蚀）→ glbopt 删除不可达的分发链 → unflat 叠加做 valrange 级收尾。

## 验证结果（`check` 样本，2026-10-18）

| 指标 | 原始 F5 | 插件 F5 (GUI) | 插件 decompile (批处理) |
|---|---|---|---|
| 伪代码长度 | 98,390 | **2,965** | 19,812 |
| switch | 175 | **0** | **0** |
| goto | 131 | **0** | 15 |
| 查表分发 | 遍布 | **0** | **0** |
| JUMPOUT | 多处 | 0 | 0 |

GUI 版含 unflat 叠加（valrange 合并，最简）；批处理版为保守完整版。
恢复出的代码可见：8 次循环的函数指针异或解密、带参数的解码调用、
原始阈值比较（15946/25560/…）、`while(1)+if/else` 状态循环。

**诚实性说明**：历史上"98KB→2.2KB"的记录是假阳性（当时钩子未装上，第一个
`jmp rdx` 后的代码不可达被丢弃）。现在的指标都在钩子实际生效的完整输出上
统计。hrtng 的 unflat 汇报部分前驱解析失败（"pseudocode may be incorrect"），
GUI 最简版可能丢个别路径；需要保守版本时用 `ida_hexrays.decompile()` 或
禁用 unflat。

## 菜单动作（可选）

`Edit → Plugins → Seagull Deobfuscator`：scan current/all functions、
recover encoded CFG targets（生成注释与 JSON 报告，不改数据库）。

## 版本记录

- 0.7.0：完整链解析 + 微码直达边/jz 条件拆分 + glbopt 死链删除；两阶段
  serial 处理修复重编号腐蚀；fallthrough 型站点插入显式 goto 块；jcc 型
  站点保留条件仅改 taken 边；状态/钥寄存器自动发现（通用化）。
- 0.6.0：走链解析器原型（sticky 栈槽 + 按值拆分）。
- 0.5.x：物化 + unflat 接入 + 有限 jtbl 提升。

## 插件生态与全能模式（v0.8.0）

本机 IDA 9.1 里的反混淆引擎盘点（全能模式的分工基础）：

| 引擎 | 擅长 | 机制 | 全能模式角色 |
|---|---|---|---|
| **Seagull**（本插件） | 比较链+查表式平坦化、截断函数修复、反反汇编 | 递归解码物化 + 具体走链解析 + 微码直达边/jz 拆分 + glbopt 死链删除 | 结构层（自动） |
| **unflat/new_unflattener** + flatPlugin | 经典 OLLVM 中央分发器 | 微码 VALRANGE + 状态赋值匹配（deflat 1-4 级）+ RemoveDeadCode(BCF) | 控制流第二引擎（自动） |
| **D-810** | MBA 算术混淆、常量折叠、不透明谓词、Z3 SMT | 177 条指令规则 + JumpFixer（instruction_only profile） | 指令层（自动） |
| **hrtng.dll** (bes tools) | 通用分发器（valrange 前驱解析） | 闭源微码 unflattener，`[hrt] Enable/Disable Unflattener` 开关 | 旁路第三引擎（手动开关） |
| E-Decompiler.dll | - | 加载失败（版本不匹配），忽略 | - |

冲突防护：三个控制流重写器并存会互相破坏——全能模式只自动启用 D-810 的
**指令级** profile（无 Unflattener 块规则）；需要 D-810 的 switch-case 反平坦化
时用菜单单独切换（用后自动恢复你原来的 profile 选择）。

新增菜单（Edit → Plugins）：
- `Seagull: all-around mode` —— 一键武装全栈并刷新当前函数
- `Seagull: toggle D-810 instruction simplifier` —— 开关 MBA/常量/不透明谓词
- `Seagull: D-810 switch-case unflattener` —— 切到 switch-case profile

## 适用范围与边界

针对静态可解析的跳转表与状态机式平坦化。运行时解密表、自修改代码、完整 VM、
依赖用户输入的动态目标仍需动态分析；这些场景保留原始 `ijmp` 不伪造边。
分析器目前按函数区域独立工作；跨函数共享 trampoline 属于同一函数区域内时
可正确处理（如本样本 0x40121F 蹦床）。
