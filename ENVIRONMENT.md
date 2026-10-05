# 开发环境检查（2026-10-04）

## 后续更新（2026-10-06）

本地私有 `agent/.env` 已配置百炼 Key，最小指定模型调用已成功。真实模型已完成 11 个 Public 基线验证，并在修复后重跑；结果见 [LIVE_VALIDATION.md](LIVE_VALIDATION.md)。下文中「API Key 为空」和「未调用模型」描述的是 10 月 4 日的环境检查状态。

运行镜像新增当前工具的构建期命令帮助缓存。Public 验证任务隐藏答案、固定镜像 ID、串行运行大网表；普通用户、只读输入和凭据运行时注入方式已沿用。

后续已实现受限的私有网表编辑/EQY 流程，真实 sky130 小电路的等价与反例检查通过；未建模 ICG 会阻止证明，见 [修复说明](agent/NETLIST_REPAIR.md)。大用例串行限制现已跨批次生效，避免多个终端同时占满本机内存。

工作目录为 `~/scan-agent-dev`，已恢复该目录与 `szbzdqsm/Scan_Insertion_zmx` 的 Git 关联。此处直接提交开发改动，无需再同步到临时仓库。Public cases、手册、私有配置和生成结果不提交。

## 安装与配置

| 组件 | 状态 |
| --- | --- |
| WSL Ubuntu 22.04、Python 3.10.12、Git 2.34.1 | 原已安装 |
| Docker 29.8.1、官方 `scan-agent-base:ubuntu24` | 原已安装且可访问 |
| `.venv` | 本轮新建，安装 OpenAI SDK 3.24.0、pypdf 6.19.0、Ruff 0.16.10 |
| Python、Pylance、Debugpy、Python Environments | VS Code 的 WSL 侧原已安装 |
| Ruff 2026.84.0、Verilog HDL 1.29.0 | 本轮安装到 WSL 扩展服务 |
| Dev Containers 0.469.0 | 本轮安装到 Windows 侧 VS Code |
| ScanInsertion、Yosys 0.68+58、EQY | 官方镜像原有；本轮检查实际调用 |
| GNU Make | 官方基础镜像缺少，导致 EQY 证明阶段失败；本轮加入开发与运行 Dockerfile |

WSL 已有 g++、Make 和 CMake，可满足已装 C++ 扩展的基础命令需求。当前 Agent 使用 Python/Tcl，赛题工具在容器内运行。Verilog 扩展用于语法支持，当前关闭需要额外工具的自动 lint 和 Ctags；它们不是 ScanInsertion 的运行依赖。

`.vscode/` 配置了解释器选择、unittest 发现、Ruff、调试和任务。大网表与结果目录不参与文件监视及默认搜索；开发容器使用已有普通 `ubuntu` 用户和 Python 3.12，避免把宿主机 Python 3.10 的虚拟环境当作容器解释器。

两个 Docker 构建上下文均使用白名单，排除 `.env`、原始赛题资料、网表和生成结果。运行任务通过 Docker `--env-file` 注入私有参数，输入只读，输出写入新的时间戳目录。WSL 单 case 任务以当前用户的 UID/GID 运行，生成文件可直接在 VS Code 中编辑和清理。

## 配置与剩余工作

- 已创建私有 `agent/.env`，API Key 保持为空；需要用户在本地填写百炼 Key。检查脚本只报告是否已设置，不显示值。
- 运行时已校验 `LLM_MODEL` 必须为 `deepseek-v4-pro`，避免误用其他模型。
- EQY 工具后端的环境验证与实际 Task 2 的自动网表修复/LEC 工作流是两个开发事项；自动修复工作流仍未实现。
- 完整模型 Public-case 验证、扫描结构语义验证和全局截止保障仍见 [要求核对](agent/CONTEST_REQUIREMENTS.md)。

## 本轮验证结果

- WSL 与开发容器环境检查均无缺失项；Docker 服务可访问，许可证已配置。宿主机约 15 GiB 内存、22 个可用 CPU、915 GB 可用磁盘，无需调整资源。
- `scan-agent-dev:vscode` 和 `scan-agent-dev:local` 均已重新构建成功，含 GNU Make。
- Python 3.10（WSL）与 3.12（开发容器）各通过 16 项回归检查；Ruff、`pip check`、配置 JSON 解析与启动脚本语法检查通过。
- EQY 实际后端验证：等价电路 `PASS`、退出码 0；不等价电路 `FAIL`、退出码 2。完整证明与日志保存于 `outputs/eqy-smoke-20261004T113130692334Z/`。
- 新运行镜像以普通用户 UID/GID 1000 执行保存的 Task 2 case3 成功脚本：许可证认证成功、工具退出码 0、扫描链检查 `Success: 5 / Fail: 0`，导出 365053 字节的扫描网表，文件归当前 WSL 用户所有。日志保存在 `/tmp/scan-environment-vqeniaki/nonroot-scan.log`。
- 上述工具环境检查未调用模型；API Key 仍为空，因此没有完成真实模型的全部 Public-case 验证。开发容器已通过等效 Docker 运行验证，尚未切换当前 VS Code 会话。

## 使用方式与来源

在 WSL 窗口的任务菜单运行环境检查、静态检查、审计回归检查、镜像构建或单 case 运行。进入容器后可运行 `Scan: EQY 后端验证（Dev Container）`，它用等价和不等价的小电路实际调用 EQY，并将完整日志保存在 `outputs/eqy-smoke-*`。

配置依据：[VS Code Python 环境](https://code.visualstudio.com/docs/python/environments)、[WSL 中使用 Dev Containers](https://code.visualstudio.com/docs/devcontainers/containers#_open-a-wsl-2-folder-in-a-container-on-windows)、[Ruff 编辑器设置](https://docs.astral.sh/ruff/editors/setup/)、[Verilog 扩展说明](https://marketplace.visualstudio.com/items?itemName=mshr-h.VerilogHDL)、[EQY SAT 策略](https://yosyshq.readthedocs.io/projects/eqy/en/latest/strategies.html)。
