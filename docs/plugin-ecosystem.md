# 插件生态与全能模式分工 / Plugin Ecosystem

Seagull 是一个编排型插件：它自带结构层恢复引擎，并把本机已有的优秀反混淆
引擎按"分工不冲突"的原则组织起来。

| 引擎 | 擅长 | 机制 | 全能模式角色 |
|---|---|---|---|
| **Seagull** | 比较链+查表式平坦化、截断函数修复 | 递归解码物化 + 具体走链解析 + 微码直达边/jz 拆分 + glbopt 死链删除 | 结构层（武装后自动） |
| **unflat/new_unflattener**（+ flatPlugin 前端） | 经典 OLLVM 中央分发器 | 微码 VALRANGE + 状态赋值匹配（deflat 1-4 级）+ RemoveDeadCode | 控制流第二引擎 |
| **D-810** | MBA 算术混淆、常量折叠、不透明谓词、Z3 SMT | instruction_only profile：177 条指令规则 + JumpFixer | 指令层 |
| **hrtng.dll**（bes tools） | 通用分发器（valrange 前驱解析） | 闭源微码 unflattener，自带 `[hrt] Enable/Disable` 开关 | 旁路第三引擎（用户手动控制，Seagull 不触碰） |

## 冲突防护

- 三个控制流重写器同时跑会互相破坏微码，因此全能模式只自动启用 D-810 的
  **指令级** profile（不含 Unflattener 块规则）；需要 D-810 的
  switch-case 反平坦化时经菜单单独切换，用完自动恢复用户原 profile。
- 检测到用户自行启动 D-810 GUI 时，Seagull 自动让位（单实例原则）。
- D-810 的 `start_d810()` 会持久化 profile 索引，Seagull 使用后立即恢复。

## 手动模式（v0.9.0 起）

一切自动行为默认关闭：不武装时 F5 为原生速度，导航不触发分析。点击
`Edit → Plugins → Seagull Deobfuscator`（或菜单/快捷键）武装整条链；
再点一次解除。
