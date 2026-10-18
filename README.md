# Seagull Deobfuscator

IDA Pro 9.x (Hex-Rays x64) 反混淆插件 / An IDA Pro deobfuscation plugin for
control-flow-flattened code. **手动启用、零常驻开销**：不点击插件时，F5 就是原生
Hex-Rays 的速度；点击后武装整条恢复链，再按 F5 直接看到反混淆后的伪代码。

An all-around, **opt-in** deobfuscation stack: disarmed by default (vanilla F5
speed), armed with one click.

## 它解决什么 / What it solves

针对如下几类控制流平坦化（自动识别，无需配置）：

1. **比较链 + 编码跳转表式分发**（本插件独创能力）：每个状态块尾部内联
   `cmp 状态reg, K; jl 选偏移; 查全局表; add 解码钥reg; jmp reg`，
   未命中落入下一 stub。状态值常藏在**栈槽**（单写常量），原始 if/else 被折进
   `cmov`，还有 `je/js` 直接跳进链头——这些让 valrange 类 unflattener 失败的
   形态，本插件用"具体走链解析"静态恢复。
2. **经典 OLLVM 中央分发器**：通过编排 unflat/new_unflattener（valrange）处理。
3. **截断函数修复**：IDA 在第一个间接跳转处截断函数时，递归解码物化真实指令
   边界并重建函数范围。
4. **算术混淆（MBA）/ 常量折叠 / 不透明谓词**：编排 D-810 的 177 条指令级规则
   （含 Z3 SMT）处理——仅指令级 profile，不与其余控制流引擎冲突。

## 实测效果 / Results

对一处 OLLVM 变种样本（约 48 KB 的平坦化 `main`）：

| 指标 | 原始 F5 | Seagull 武装后 F5 |
|---|---|---|
| 伪代码长度 | 98,390 字符 | **2,965 字符** |
| switch（分发器） | 175 | **0** |
| goto | 131 | **0** |
| 编码查表 | 遍布全文 | **0** |

恢复出原始 `if/else`、循环、调用参数与真实常量。

## 安装 / Install

```
# 方式一：脚本（默认装入 IDA 程序 plugins 目录）
powershell -ExecutionPolicy Bypass -File install_seagull_ida91.ps1 [-IdaRoot <IDA目录>]

# 方式二：手工复制 ida_seagull_deob.py 与 seagull_core.py 到 IDA 的 plugins 目录
```

依赖：Hex-Rays x64 反编译器；Capstone 5（三种途径任选）：

1. 放入 `plugins/vendor/capstone/`（本仓库不含，请自行复制）；
2. `set SEAGULL_CAPSTONE_PATH=<含 capstone 包的目录>`；
3. 已能被 IDA 的 Python `import capstone` 即可。

可选协同插件（存在则自动编排，缺失则跳过，不强依赖）：
[unflat/new_unflattener]、[D-810]。详见 `docs/plugin-ecosystem.md`。

## 使用 / Usage（手动模式）

1. 打开样本，**Edit → Plugins → Seagull Deobfuscator**（或菜单
   `Seagull: arm/disarm all-around deobfuscation`，快捷键
   `Ctrl+Shift+Alt+D`）→ 武装。
2. 在目标函数上按 **F5** → 反混淆后的伪代码。
3. 再点一次 → 解除武装，F5 恢复原生速度。分析结果按函数缓存。

其它菜单动作：`scan current/all functions`（注释+JSON 报告）、
`recover encoded CFG targets`、`toggle D-810 instruction simplifier`、
`D-810 switch-case unflattener`。

## 原理 / How it works

1. **递归解码物化**：x86-64 有界抽象解释器（自研 `seagull_core`）从函数入口
   解码，把所有真实指令边界写回 IDB，修复截断。
2. **有限 jtbl 提升**：把抽象解释器解析出的间接跳转提升为微码 `m_jtbl`，
   消灭 `JUMPOUT`。
3. **分发链具体解析**（`resolve_chain`）：两遍分析 + 单写者常量栈槽 sticky
   内存模型；对每个状态更新点，用该点的具体 `(状态值, 解码钥)` 单值重新执行
   分发链直到真实状态块。汇合点（cmov 数据依赖）得到"值→目标"对。
4. **微码重写**：单值站点改直达边；汇合点插 `m_jz` 链重建原始分支；jcc 站点
   保留条件只改 taken 边；fallthrough 站点插显式 goto 块。两阶段 serial 处理
   防块重编号腐蚀。
5. **死链删除**：glbopt 阶段删除已无入边的整条分发链。
6. **编排层**：unflat（经典分发器）与 D-810（指令级 MBA）按分工同时武装，
   互不冲突；D-810 的 profile 选择在使用后自动恢复。

## 兼容性 / Compatibility

- IDA Pro 9.x + Hex-Rays（在 9.1.0.250226 上开发验证）；7.4+ 理论可用未验证。
- 不修改原始二进制字节；仅物化指令边界与函数范围（数据库层修复）。
- 遇到无法静态解析的形态（运行时解密表、自修改、VM）保守保留 `ijmp`，
  不伪造边。

## License

MIT。Inspired by and interoperates with the D-810 and unflat projects
(their code is not included; they remain the property of their authors).
