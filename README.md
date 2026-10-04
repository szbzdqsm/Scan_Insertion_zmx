# Scan Insertion Agent

开发源码位于 [agent/](agent/README.md)，正式 Word 和宣讲 PPT 也保存在该目录。[要求核对](agent/CONTEST_REQUIREMENTS.md)记录已实现内容和待办；当前仍是开发版本。

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
