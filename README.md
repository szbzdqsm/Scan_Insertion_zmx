# Scan Insertion Agent

2026-10-10 平台6/11回归已修复：**v69同一官方包镜像完整Public 11/11、624项回归及Ruff通过**，逐例累计1344.92秒，全部在预算内。修复Wrapper全局启用/样式、固定链数及裸命令、实际命令/规则审计、无效可选映射和Liberty latch/FF类别预检查。详见 [平台回归修复](PLATFORM_FAILURE_FIX.md) 与 [验证记录](LIVE_VALIDATION.md)。本地通过范围与Hidden/正式评分分开记录。

本轮最新结果：v60 Task1 case3/case5 分别31.41/377.03秒；v61 Task2 case5 647.56秒；v63 Task1 case4 33.90秒；v64 Task1 case1 36.41秒，各按对应检查通过。584项回归与Ruff通过。结果分属不同固定镜像，不能合并为新版全量成绩；当前默认开发镜像更新为v64，旧完整基线保留。

2026-10-10 平台结果复核：平台评分输出明确 11/11 仅覆盖格式与运行。新发现并修复 I/W 分别计数、ICG 指定控制口、子树排除例外、局部 FF 回替范围和 TAP 域排除遗漏；加入真实结构检查、源解析优化与命令阶段观测。旧 v56 全批记录保留，其检查范围没有覆盖这些新发现。详见 [平台结果复核](PLATFORM_RESULT_REVIEW.md)。本轮仅重跑受影响用例，不作为新版完整 Public 成绩。

开发源码位于 [agent/](agent/README.md)，正式 Word 和宣讲 PPT 也保存在该目录。[要求核对](agent/CONTEST_REQUIREMENTS.md)和[主办方 Q&A 核对](agent/CONTEST_QA.md)记录规则与待办；当前仍是开发版本。

2026-10-09 可选映射修复：Task 2 的映射现也必须绑定实际 Tcl，显式空数组可清空旧映射，最终发布再次校验。**22 项小范围检查、Ruff、Task 2 case3 单例及独立引用复核通过**，新结果 6 条映射均有行号。已按官方参考结构生成本地 `submission.zip`；详见[打包说明](SUBMISSION_PACKAGING.md)与[验证记录](LIVE_VALIDATION.md)。本次未做全批重跑，完整基线仍是 v56。

2026-10-08 完整重跑：**同一固定 v56 镜像真实 Public 11/11、466 项回归及 Ruff 通过**，全部未越时，默认镜像已更新为 v56。修复了重跑发现的通用审计、Tcl 预检查及任务残余规则问题。实际文件/问题引用独立复核无矛盾；Task 2 case3 一条可选映射缺行号，保留未确定。累计清理 22 份旧日志约 232 MiB。逐例结果、失败历史及范围见 [验证记录](LIVE_VALIDATION.md)和[通用优化记录](GENERALIZATION.md)。

2026-10-07 整体优化：共用结构扫描、实际库映射预检查、按需完整帮助、独立产物复制、完成轮次校验复用和分阶段计时；修正链数证据与实际空集合错误变体。**357 项回归检查、Ruff 及固定 v46 镜像完整 Public 11/11 通过当前验收**。本地默认镜像已更新为 v46。Hidden 和完整扫描语义仍有独立验证边界，见要求核对。

本轮另清理 45 份过时/重复日志（约 840 MiB），删除均记录 SHA 清单。解析吞吐改善已同输入证明，Task 1 case5 本批更快，但完整批次总耗时比 v39 高约 25%，主要受模型和额外 EDA 重试影响；详见 [性能记录](PERFORMANCE.md)。

## VS Code + WSL 开发

用 VS Code 的 WSL 窗口打开整个 `~/scan-agent-dev`。仓库内已有 Python 环境选择、Ruff、测试发现、调试和任务配置。当前本机已建立 `.venv` 并安装依赖；换机器时执行：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
cp agent/.env.example agent/.env
```

在私有 `agent/.env` 中填写 `LLM_API_KEY`，保留赛题指定模型 `deepseek-v4-pro`。`.env`、虚拟环境、Public cases 和生成结果已忽略。工具参数和 License 在容器运行时注入，不写入镜像。

按 `Ctrl+Shift+P`，选择 `Tasks: Run Task`：

- `Scan: 环境检查`：检查依赖、Docker 和配置状态，不显示凭据。
- `Scan: 审计回归检查`：运行 unittest 回归检查。
- `Scan: Python 静态检查`：运行 Ruff。
- `Scan: EQY 后端验证（Dev Container）`：实际验证等价和不等价的小电路，保留完整日志。
- `Scan: 构建运行镜像（WSL）`：构建 `scan-agent-dev:local`。
- `Scan: 最小模型调用验证（WSL）`：检查本地 Key 能否调用指定模型，记录脱敏结果。
- `Scan: 完整 Public 验证（WSL，调用模型）`：先验证模型并构建镜像，再运行 11 个 Public case；调用模型会使用 API 额度，大型用例可能运行数十分钟。
- `Scan: 运行一个 case（WSL）`：输入 case 路径，自动构建镜像、挂载只读输入，并创建新的 `outputs/` 子目录。

按 F5 可调试回归检查。实际 case 运行会调用真实工具和指定模型，需先填写自己的 Key。

## 使用官方容器开发

已提供 `.devcontainer/devcontainer.json`。在 WSL 窗口运行 `Dev Containers: Reopen in Container`，即可使用官方 Ubuntu 24 基础环境中的 Python 3.12、ScanInsertion、Yosys 和 EQY。开发容器使用普通 `ubuntu` 用户，代码检查与测试任务会自动选择容器 Python。

本地 WSL 的 Python 3.10 虚拟环境用于编辑和回归检查；实际赛题运行使用容器 Python 3.12。Dev Container 中的模型 Key 仍需通过运行时配置提供。构建/运行 Docker 的任务在 WSL 窗口执行，开发容器不挂载 Docker socket。

```bash
bash scripts/project_python.sh scripts/check_environment.py
bash scripts/project_python.sh -m unittest discover -s tests -p 'test_*.py' -v
docker build -t scan-agent-dev:local -f agent/Dockerfile agent
.venv/bin/python scripts/run_case.py public_cases/task_2/case1
```

当前目录已直接关联 GitHub，后续 Git 操作在 `~/scan-agent-dev` 执行。[ENVIRONMENT.md](ENVIRONMENT.md)记录安装与验证情况。`reference_submission/` 保留为参考资料，实际开发入口是 `agent/scan_agent.py`。

## 真实模型验证

本地百炼 Key 已验证可调用 `deepseek-v4-pro`。真实模型的完整 Public 基线已跑完，修正版持续重跑。每个版本的实际结果与未完成能力见 [LIVE_VALIDATION.md](LIVE_VALIDATION.md)，不同版本的结果不可合并成全批成绩。

```bash
.venv/bin/python scripts/check_model.py
docker build -t scan-agent-dev:local agent
.venv/bin/python scripts/run_public_cases.py --jobs 1
# 指定用例重试
.venv/bin/python scripts/run_public_cases.py --select task_1/case2 task_2/case1
# 使用相同固定镜像补齐一个已结束子集批次；保留已有结果，不重复执行
.venv/bin/python scripts/run_public_cases.py --image scan-agent:live-v37 --resume-batch outputs/已有批次
```

Public 验证脚本隐藏答案文件，固定本批镜像 ID，以普通用户运行容器，保留全部尝试和 `summary.json`。摘要里的通过表示当前 Agent 检查通过，完整扫描语义仍需独立核验。
