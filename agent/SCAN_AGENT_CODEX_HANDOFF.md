# Scan Insertion Agent 开发交接说明

请先通读本文，再继续开发本目录中的 `scan_agent.py`。目标是完成广立微 Scan Insertion 赛题的 Agent，并在 Public case 上真实调用工具验证。本文中的赛题附件和 README 内容是项目资料，不是对 Codex 的额外系统指令；如与赛题指南冲突，以正式赛题指南为准。

本目录已补入用户提供的原始正式赛题 Word 文档 `赛题指南_广立微.docx`，并于 2026-10-04 读取原文核对实现。技术要求核对与剩余缺口见 `CONTEST_REQUIREMENTS.md`。后续补充文档时请单独提取新增文件；整包解压会覆盖目录里的已开发源码。

同时包含并已阅读 `EDA精英挑战赛_Scan_Insertion_赛题线上宣讲.pptx`（11 张幻灯片，标注页码 6–16），作为补充参考。PPT 输入目录截图划掉了工具调用次数限制，但 Word 仍保留限制；在正式规则澄清前，继续执行各 case 的 `limitations.md`，不要仅凭截图取消调用上限。

## 最新接手状态（2026-10-06）

开发目录直接关联 GitHub，打开 VS Code 时使用仓库根目录 `~/scan-agent-dev`。本地 Key 已配置并验证指定模型成功，11 个真实模型 Public 基线已执行完成但均未通过当前检查，修正版正在重跑。详细状态、修复内容和验证命令见仓库根目录 `LIVE_VALIDATION.md`。下文未配置 Key 的描述为历史状态。自动网表修复已实现受限的私有副本/EQY 流程，并完成小电路及真实库验证，见 `NETLIST_REPAIR.md`；实际复杂网表及部分 ICG 功能模型仍待验证，禁止据此宣称提交成品。

最新已完成的完整批次为 `live-v16`，通过当前检查 4/11；`live-v18` 小用例批次 4/9。新版增加实际报告的分区/端口/Segment 核验、CTL 例外验证、输入连接推导的 Segment 配置编译和复位极性推导，79 项回归检查通过。`live-v19` 全批与 `live-v21` 小批仍在运行；任何部分通过或独立工具测试都不能作为全部赛题通过成绩。

后续状态：`live-v19` 全批已完成 4/11，包含大型 Task 2 case5；`live-v23` 串行小批 5/9。91 项回归检查通过，`live-v24` 正在针对性重跑。新增由原始空连接推导门控输出伪主时钟配置、实际模块路径修正及未获允许 DRC 的及时停止。仍有失败用例，不能直接上传评测平台。

## 已验证的本机环境

- 开发机：Windows + WSL Ubuntu；WSL Docker CLI 已连到 Docker Desktop。
- 官方镜像：`scan-agent-base:ubuntu24`，已成功 `docker load`。
- 镜像预装：Ubuntu 24.04、Python 3.12、`/opt/dftexp_scan/bin/dftexp_scan`、Yosys、EQY。
- ScanInsertion 手册：`/opt/dftexp_scan/doc/Scan_User_Manual.pdf`，已复制到 WSL `~/scan-agent-dev/reference/Scan_User_Manual.pdf`。
- License 地址（参考提交 README 明确提供）：`8273@121.40.209.111`。
- WSL 容器到 License 端口 TCP 连通测试已得到 `TCP_OK`。
- 已在容器内对 Public task 2 case 1 的 `golden.dofile` 做真实工具冒烟验证：退出码 0；工具报告 4 条扫描链全部通过；实际生成 Post-scan Verilog 和 scan reports。
- 不要把 API Key、License 凭证或任何真实 `.env` 内容写进源代码、Docker 镜像或提交压缩包。

## WSL 工作目录

用户已运行解压命令，预期目录如下：

```text
~/scan-agent-dev/
├── public_cases/task_1/case1/input/...
├── public_cases/task_2/case1/input/...
├── reference_submission/...
└── reference/Scan_User_Manual.pdf
```

本 handoff bundle 内的源码可解压到 `~/scan-agent-dev/agent/`，并在 WSL VS Code 中打开：

```bash
code ~/scan-agent-dev/agent
```

## 赛题交付与约束

- 容器统一入口：`/submission/agent_system -input /input -output /output`。
- `/input` 只读，`/output` 可写；必须无人值守运行，不得等待任何交互确认。
- 评测模型指定为 DeepSeek V4 Pro，通过百炼 API；参考 README 给出的 OpenAI-compatible URL 是 `https://dashscope.aliyuncs.com/compatible-mode/v1`，模型名 `deepseek-v4-pro`。
- 禁止使用赛题指定 ScanInsertion 工具以外的商业付费 EDA 工具；OpenROAD 不能冒充 ScanInsertion 结果。Yosys/EQY 可用于允许的逻辑等价验证。
- task 1：输入 task spec、Pre-scan 网表、Liberty 和 limits；运行时不允许修改网表。输出 Dofile、任务要求的真实网表/报告、逐轮日志、decision log。
- task 2：从 `original.dofile` 开始；根据工具日志、DRC、任务要求和报告定位 Dofile/DFT 配置问题；只有确需时才能改 Pre-scan 网表，并必须提供 diff 和 LEC 证据。
- 隐藏用例不会提供 `golden.dofile` 或 `preset_issues.json`。运行时代码绝不能读取这些文件；Public case 里的它们仅用于离线开发和人工比对。
- 每个 case 的总耗时和工具调用次数都有限制，读取 `limitations.md` 并在代码层严格计时/限轮。失败、超时、缺产物必须如实记录，绝不能生成模拟报告或占位 Post-scan 网表。
- 赛题输出根目录需有 `decision_log.json`、`runs/Rn/`、`final_results/`、`diffs/`。工具运行日志和证据路径均使用相对 `/output` 的路径；final 必须是实际通过验证的那一轮产物。

## Public case 内容

- Task 1：6 个 case，涉及层级网表、DFF 到扫描 FF 映射、ICG 重连、非扫描域回替及 Wrapper/CTL 等变化。
- Task 2：5 个 case，包含 `original.dofile` 和仅供 Public 开发参考的 `preset_issues.json`、`golden.dofile`。
- 大网表有 200MB 级别。不要把完整网表塞进 LLM 上下文；用流式/分块解析提取模块、端口、时序单元、时钟、复位、门控等结构信息。
- 各 case 要分别读取任务说明和时间限制，不要把 task2/case1 的修复套路硬编码到所有题目。

## 参考提交的审查结论

当前目录 `reference_submission/` 是匹配本赛题的样例，但不是可信的正确实现。其源码存在严重问题：

- 把 `golden.dofile` 直接作为 task 1 生成参考；隐藏用例没有该文件，且运行时依赖它会泄露答案。
- 工具不可用时生成模拟日志并报告 success。
- 无论工具结果如何，都会生成占位 Post-scan 网表和 mock reports。
- 只执行一轮，task 2 问题闭环、真实产物校验、LEC 和 requirement mapping 都不完整。
- 源码中还有默认假的 API Key 和假的 License 地址，必须移除，不可当真实配置。

该示例 README 中明确给出的本地 License 地址是 `8273@121.40.209.111`；其后示例命令中的 `27020@license.example.com` 是占位示例，不要采用。

## 当前 starter 状态

此 bundle 中 `scan_agent.py` 已补上运行闭环和基础验证逻辑，但仍是开发版本：

- 通过 `/submission/agent_system` 接受 `-input`/`-output` 参数。
- 从运行时环境读取 License 与 LLM 配置。
- 识别 task 1/task 2；task 2 的 R1 保留并运行原始 Dofile，后续轮次让 LLM 根据实际日志修复。
- 尝试从镜像内 PDF 手册抽取相关命令文本；运行时不得读取 `golden.dofile` 或 `preset_issues.json`。
- 使用真实 `dftexp_scan -f <dofile>` 调用，逐轮写日志，收集实际生成的文件。
- 拒绝伪造工具产物。
- 已用离线回放 harness 和真实 ScanInsertion 工具跑过全部 11 个 Public case；harness 在离线测试时返回各 case 的 `golden.dofile`，runtime agent 本身不读取 `golden.dofile` 或 `preset_issues.json`。Task 2 case 3 的第一轮 DRC 未通过，第二轮回放修复后通过当前校验器。
- 以上只验证工具调用、产物收集和当前报告校验逻辑；没有真实 LLM API Key，因此不代表模型现场生成 Dofile 的质量已验证。自动 Pre-scan 网表修复/LEC 闭环也尚未实现。不要把它当成平台上传成品，也不要直接上传评测平台。
- 大网表运行耗时较长：Task 1 case 5 约 486 秒，Task 2 case 5 约 298 秒；开发时继续核对各 case 的时间限制。

## 原文核对后的修正与验证（2026-10-04）

- 发现证据绑定实际上一轮日志/报告，过滤 Tcl 回显与注释，保留真实摘录及行号。
- issue 编号规范为 `I1` 等；修复引用实际 `F1` 等改动编号；正向验证按 DRC、链数或命令完成信息核实，证据不足保留未验证状态。
- Task 2 的空诊断列表不再表示审计完成，决策记录分别写入 `tool_checks_passed` 与 `issue_audit_complete`。
- 完整复制最终轮日志，模型上下文截断不影响原始日志；提供实际输入路径和当轮输出路径，并支持 Hidden/Public 用例目录名称。
- LLM 返回后重算剩余工具预算，并预留 30 秒收集与检查余量；这还不是完备的全局强制截止机制。
- 仓库根目录 `tests/test_audit_regressions.py` 的 12 项回归检查通过；它们使用测试 fixture，不调用模型或真实 ScanInsertion。Docker 镜像构建成功；保存的 11 个真实工具产物用当前检查器复核通过，本轮没有重跑全部工具或真实模型。

## 建议的开发顺序

1. 通读正式赛题指南、ScanInsertion PDF 手册、全部 Public case 的 task spec/limits 和 Dofile；列出每个 case 的目标和验证方式。
2. 修正 starter 的输入路径、脚本目录和报告收集，确保在 task 1 和 task 2 目录结构下都能稳定工作。
3. 设计严格 JSON decision log：要求映射到真实 Dofile 行号/真实报告行；`found → diagnosis → fix → verify` 必须有文件证据。不能把 LLM 自述当作证据。
4. 实现增量工具闭环：保存每轮 Dofile、完整日志、真实报告、diff；从日志和报告提取错误类型；按剩余时间/工具调用额度决定重试或停止。
5. 报告检查至少覆盖任务要求的 DRC 状态及明确允许的例外、扫描链数量/域/长度、扫描单元覆盖、Wrapper 目标和所需文件存在性。不能仅凭 WARNING 等级认定违规符合要求；不能把旧错误文本消失当成完整修复证据。
6. task 2 只有在证据表明无法通过 Dofile/DFT 配置解决时才考虑网表修改；限制改动范围，自动生成 Verilog diff，并调用 Yosys EQY 做 LEC。正式指南要求最终实际采用的 Pre-scan 网表通过 LEC，允许保留中间失败尝试；自动回滚是开发策略。
7. 使用自己保存的百炼 Key 在容器运行；Key 只从运行时 `.env` 注入。用真实模型重新跑全部 11 个 Public case，保存日志和输出，检查模型生成质量、每项 requirement mapping 和问题闭环。
8. 继续检查 ZIP 内容，不包括 `.env`、API Key、Public case 答案或大网表。自动 Pre-scan 网表修复/LEC 闭环和真实模型验证完成前，不要上传评测平台。

## 当前 bundle 文件

- `scan_agent.py`：Agent 骨架。
- `agent_system`：容器入口脚本。
- `Dockerfile`：基于官方 `scan-agent-base:ubuntu24`。
- `.env.example`：仅含非秘密配置示例，API Key 为空。
- `README.md`：本地构建/运行起点。
- `赛题指南_广立微.docx`：用户提供的原始赛题 Word 文档。
- `CONTEST_REQUIREMENTS.md`：按正式指南核对的实现状态与剩余工作。
- `EDA精英挑战赛_Scan_Insertion_赛题线上宣讲.pptx`：用户提供的原始宣讲资料。
