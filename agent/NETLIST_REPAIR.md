# 自动网表修复与 EQY

2026-10-06：已实现受限的自动修复流程，入口在 `scan_agent.py`，具体操作在 `netlist_repair.py`。这项能力已完成小电路及真实 sky130 库验证，实际 Public/Hidden 网表修复质量仍需验证。

1. Task 2 原始 Dofile 先原样运行。Task 1 或明确禁止修改网表的 case 拒绝任何编辑。
2. 模型只能提出一到四个局部、唯一的字面替换，每个不超过 32 行，附实际上一轮诊断原文和无法只用配置修复的原因。不能修改模块接口、库或证明脚本。
3. 输入保持只读，候选副本写入 `netlist_versions/Rn/`。匹配不存在或不唯一的提议被拒绝。
4. 固定 EQY 配置用原始输入作 gold、候选作 gate，导入功能 Liberty 模型并检查层级。分别证明任务顶层和每个被编辑模块，覆盖未被当前顶层引用的辅助模块。证明不接受模型提供的假设，不使用 `read_liberty -lib` 的黑盒模型。
5. 所有证明均实际退出码 0 且存在 EQY PASS 标记，才把候选路径提供给后续 ScanInsertion。保存完整日志、配置、实际 Verilog diff 和 F 编号；`lec_ref` 指向实际日志拼接的 `aggregate.log`，另保留各项 `lec_refs`。
6. FAIL、UNPROVEN、ERROR 或超时均保留现场并拒绝候选。此版本遇到拒绝会保留最后实际工具轮次及失败原因；尚未实现拒绝后连续生成多个网表修复方案。
7. 候选和实际证明文件在 ScanInsertion 前后核对 SHA-256 和链接目标，记录在 `runs/Rn/llm_protected_repair_fingerprints.json`。发现改变即阻断本轮通过；原始工具退出状态仍按实际保存。这是前后完整性检查，不是额外的操作系统写保护。

## 验证范围与限制

`scripts/check_netlist_repair.py` 实际验证副本生成、等价改动通过、非等价改动拒绝、原始文件不变及 diff/LEC 记录。使用真实 sky130 库的 AND 门重写也通过；包含未建模时钟门控单元的反例被拒绝，未通过黑盒化绕开证明。另一个只改变未被顶层使用的辅助模块功能的候选，顶层证明虽 PASS，辅助模块证明 FAIL，最终同样被拒绝。

部分 sky130 ICG 的 Liberty 输出没有 Yosys 能识别的 function 描述。导入时可跳过库里未使用的这类单元；如果实际设计使用它，层级检查必须失败。包含这类单元的整网表证明仍需要经核对的功能模型。本流程因此可能拒绝本来等价的候选，不会把未证明的编辑当成成功。

EQY 当前使用 SAT 归纳策略，默认最多 180 秒，受剩余 case 时间约束；复杂设计可能 UNPROVEN。初始化、源文件扫描与最终复制仍需加强全局截止保障。完整扫描结构及需求语义核验仍是独立待办。

在开发容器中运行：

```bash
python3 scripts/check_netlist_repair.py
python3 scripts/check_netlist_repair.py --lib public_cases/task_2/case3/input/lib/sky130.lib
```

配置依据：[Yosys Liberty 导入](https://yosyshq.readthedocs.io/projects/yosys/en/latest/cmd/index_frontends.html#read-liberty-read-cells-from-liberty-file)、[EQY 比较流程](https://yosyshq.readthedocs.io/projects/eqy/en/latest/quickstart.html)、[SAT 归纳策略](https://yosyshq.readthedocs.io/projects/eqy/en/latest/strategies.html)。
