# Scan Insertion Agent - 参考提交示例

## 提交说明

本示例展示了如何构建一个基于大语言模型的 Scan Insertion Agent，完全符合赛题指南要求的输出格式。

---

## 文件结构

```
submission.zip
├── .env                         # 环境变量配置（必需）
├── Dockerfile                   # Docker 构建文件（必需）
├── submission/                  # Agent 代码目录（必需）
│   ├── agent_system            # 入口脚本（必需，有执行权限）
│   ├── scan_agent.py           # Agent 主程序
│   └── requirements.txt        # Python 依赖
└── README.md                   # 本文件（可选）
```

---

## Docker 基础镜像说明

### 镜像信息
- **镜像名称**：`scan-agent-base:ubuntu24`
- **基础系统**：Ubuntu 24.04

### 镜像已包含的组件

#### 1. 系统环境
- Ubuntu 24.04 LTS
- Python 3.12.x
- 常用系统工具（bash, git, curl, etc.）

#### 2. EDA 工具
- **dftexp_scan**：广立微 Scan Insertion 工具
- **Yosys**：开源综合工具（用于逻辑等价性验证）
- **Yosys EQY**：逻辑等价性检查工具

#### 3. Python 环境
- Python 3.12（系统自带）
- pip（包管理器）

** 重要提示：**
- 镜像**不包含**任何第三方 Python 库（如 openai, requests 等）
- 参赛队需要在 `requirements.txt` 中声明所有依赖
- 依赖会在 Docker 构建时通过 `pip install` 安装

---

## 快速开始

### 1. 配置环境变量

编辑 `.env` 文件，填入相关配置：

```bash
# Scan Insertion License Server（组委会提供，参赛队本地测试时也统一使用以下内容）
SCANINSERTION_LICENSE_SERVER=8273@121.40.209.111

# 大模型 API 配置（URL以及model名称已强制固定，参赛队只需填写自己的key即可）
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
LLM_API_KEY=sk-your-api-key-here
LLM_MODEL=deepseek-v4-pro
```

**注意**：
- 不要在代码中硬编码这些值
- `.env` 文件必须在提交包根目录
- License Server 地址、URL以及model名称在评测时由组委会统一配置
- 参赛队可以只在.env中填写LLM_API_KEY=sk-your-api-key-here

---

### 2. 打包提交

按照“文件结构”的组织形式打包成.zip
---

### 3. 上传到评测平台
1. 登录评测平台
2. 进入提交页面
3. 上传 `submission.zip`
4. 等待评测结果

---

## 实现说明

### Agent 工作流程

```
输入 → [1] 理解任务 → [2] 生成 Dofile → [3] 运行工具 → [4] 保存结果 → 输出
         ↓ LLM            ↓ LLM              ↓ dftexp_scan      ↓
     task_spec.md      工具手册检索          DRC/Scan          decision_log.json
```

### 核心组件

#### 1. agent_system（入口脚本）
- 解析命令行参数（`-input`, `-output`）
- 调用 Python Agent
- 兼容单横线和双横线参数格式

#### 2. scan_agent.py（主程序）
- **任务理解**：使用 LLM 分析 task_spec.md
- **Dofile 生成**：使用 LLM 生成 dftexp_scan 命令
- **工具运行**：执行 Scan Insertion 工具
- **结果整理**：生成决策日志和最终输出

#### 3. LLM 调用
```python
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get('LLM_API_KEY'),
    base_url=os.environ.get('LLM_BASE_URL')
)

response = client.chat.completions.create(
    model=os.environ.get('LLM_MODEL'),
    messages=[...]
)
```

---

## 输出文件结构（重要！）

### 完整输出目录结构

按照赛题指南要求，Agent 必须生成以下结构：（以下示例仅供参考，若有出入，具体参照赛题指南）

```
output/
├── decision_log.json              # 决策记录（必需）
│
├── runs/                          # 按轮次隔开的每次工具运行产物
│   ├── R1/                        # 第一轮运行
│   │   ├── R1.log                 # 本轮完整运行日志
│   │   ├── deliverables/          # 本轮生成的交付物
│   │   │   └── R1.dofile          # 本轮使用的 dofile
│   │   ├── output/                # 本轮工具输出目录
│   │   │   ├── post_connect_icg.v  # 连接 ICG 后的网表
│   │   │   ├── post_replace_sff.v  # 替换 SFF 后的网表
│   │   │   └── post_replace_unscan.v # 回替后的网表
│   │   └── reports/               # 本轮实际生成的各类报告（工具若未生成则为空）
│   │       └── ...                # （如工具生成了报告文件）
│   ├── R2/                        # 第二轮运行（如有多轮）
│   │   └── ...
│   └── ...
│
├── final_results/                 # Agent 系统声明的"最终采用轮次"的正式拷贝
│   ├── final.log                  # 最终完整运行日志
│   ├── deliverables/              # 最终生成的交付物
│   │   ├── final.dofile           # 最终使用的 dofile
│   │   └── post_scan.v            # 最终生成的 Post-scan 网表
│   └── reports/                   # 最终各类报告
│       ├── drc.rpt                # DRC 报告
│       ├── scan_signal.rpt        # Scan Signal 报告
│       ├── scan_element.rpt       # Scan Element 报告
│       ├── scan_configuration.rpt # Scan Configuration 报告
│       ├── scan_chain.rpt         # Scan Chain 报告
│       ├── scan_chain_cell.rpt    # Scan Chain Cell 报告
│       ├── wrapper_configuration.rpt    # Wrapper Configuration 报告
│       └── wrapper_implementation.rpt   # Wrapper Implementation 报告
│
└── diffs/                         # Dofile 各版本间的 diff（如有多轮）
    ├── dofile_R1_to_R2.diff
    └── dofile_R2_to_R3.diff
```

### decision_log.json 格式（任务一）

```json
{
  "case_id": "case_7",
  "task": "task1",
  "final_run": "R3",
  "summary": "任务目标、最终是否完成、关键配置概述、共运行几轮...",
  
  "requirement_mapping": [
    {
      "requirement": "扫描链数量为 8 条,长度尽量均衡",
      "dft_config": "set_scan_cfg -chain_count 8 ...",
      "config_ref": {
        "source": "final_results/deliverables/final.dofile",
        "locator": "L40"
      }
    }
  ],
  
  "issue_resolutions": [],
  
  "tool_runs": [
    {
      "tool_call_id": "R1",
      "log_file": "runs/R1/R1.log",
      "exit_status": "completed"
    }
  ],
  
  "file_changes": []
}
```

**重要说明：**
- 所有路径使用相对路径（相对于 `-output` 目录）
- 文件命名必须严格遵循赛题指南（`R1`, `R2`, 不是 `run_1`, `run_2`）
- `final_results/` 必须包含 `deliverables/` 和 `reports/` 子目录

**关于报告文件：**
- `runs/R{n}/reports/` 目录用于存放工具实际生成的报告文件
- 如果工具在运行时未生成报告文件，该目录可以为空（这是正常的）
- `final_results/reports/` 中的报告可以从工具输出复制，或由 Agent 系统生成
- 参考 golden.dofile 可以看到，基线算法也不包含报告生成命令
- 评测主要关注 dofile 质量和最终网表质量，报告文件为辅助参考

---

## 本地测试

### 使用本赛题官方 Docker 镜像

```bash
# 1. 加载基础镜像（组委会提供——见平台赛题详情页“资源下载”）
docker load -i scan-agent-base-ubuntu24.tar

# 2. 构建你的 Agent 镜像
docker build -t my-agent:latest .

# 3. 准备测试数据
# 将 public_case_1/ 放在某个目录，例如 /path/to/test_data/

# 4. 运行测试
docker run --rm \
  -e SCANINSERTION_LICENSE_SERVER="27020@license.example.com" \
  -e LLM_BASE_URL="https://dashscope.aliyuncs.com/compatible-mode/v1" \
  -e LLM_API_KEY="sk-your-key" \
  -e LLM_MODEL="deepseek-v4-pro" \
  -v /path/to/test_data/public_case_1/input:/input:ro \
  -v /path/to/test_data/public_case_1/output:/output:rw \
  --network bridge \
  my-agent:latest \
  -input /input \
  -output /output

# 5. 查看输出
tree /path/to/test_data/public_case_1/output/
cat /path/to/test_data/public_case_1/output/decision_log.json
```

---

## 依赖版本说明

### requirements.txt

本示例使用的依赖：

```
openai>=1.0.0
```

### 版本兼容性建议

####  依赖版本匹配原则

**重要**：参赛队需要自行确保 `requirements.txt` 中的依赖版本与基础镜像兼容。

**建议做法：**

1. **使用版本范围而非固定版本**
   ```
   # 推荐
   openai>=1.0.0
   
   # 不推荐（可能导致兼容性问题）
   openai==1.12.0
   ```

2. **本地测试时使用相同的基础镜像**
   ```bash
   # 确保本地测试和评测环境一致
   docker build -t test-agent .
   docker run test-agent ...
   ```

3. **如果遇到版本冲突**
   ```bash
   # 在容器内检查已安装的包
   docker run --rm scan-agent-base:ubuntu24 pip list
   
   # 根据输出调整 requirements.txt
   ```

#### 常见依赖说明

| 依赖包 | 用途 | 建议版本 | 说明 |
|--------|------|---------|------|
| `openai` | LLM API 客户端 | `>=1.0.0` | 必需，用于调用 DeepSeek API |
| `requests` | HTTP 请求库 | `>=2.28.0` | 可选，如需直接 HTTP 调用 |
| `numpy` | 数值计算 | `>=1.24.0` | 可选，如需数据处理 |
| `pandas` | 数据分析 | `>=2.0.0` | 可选，如需处理 CSV |

**尽量避免安装以下包：**
- 大型深度学习框架（PyTorch, TensorFlow）- 会显著增加构建时间
- 不必要的 GUI 工具包
- 与基础镜像冲突的系统级依赖

---

## 评分标准

### 任务一（60分 + 20分 + 15分 + 5分）

1. **Dofile 生成正确性**（60分）
   - 按错误点扣分制
   - 每个独立错误点扣5分

2. **决策记录可解释性**（20分）
   - decision_log.json 结构完整
   - 任务-配置映射可追溯
   - 问题闭环真实性

3. **运行效率**（15分）
   - 总运行时间（5分）
   - 工具调用次数（5分）
   - Token 使用量（5分）

4. **输出完整性**（5分）
   - 目录结构符合规范
   - 文件命名正确

---

## 常见问题

### 1. Docker 构建失败

**错误**：
```
ERROR: Could not find a version that satisfies the requirement xxx
```

**解决**：
- 检查 requirements.txt 的包名和版本号
- 确保版本号与基础镜像兼容
- 使用版本范围（`>=x.x.x`）而非固定版本

### 2. 环境变量未加载

**错误**：
```
LLM_API_KEY not found
```

**解决**：
- 确保 `.env` 文件在提交包根目录
- 确保环境变量通过 `os.environ.get()` 读取

### 3. License Server 连接失败

**错误**：
```
License check failed
```

**解决**：
- 确认 License Server 地址正确
- 确认网络可以访问 License Server
- 联系企业确认 License 有效

### 4. 输出文件结构不符合要求

**错误**：
```
输出目录结构不符合赛题指南
```

**解决**：
- 仔细阅读本 README 的"输出文件结构"部分
- 确保使用 `R1`, `R2` 而不是 `run_1`, `run_2`
- 确保有 `deliverables/` 和 `reports/` 子目录
- 确保生成 `diffs/` 目录（如有多轮）

---

## 获取帮助

### 查看日志

评测完成后，下载以下文件查看详细信息：
- `container.log`：容器运行日志
- `build.log`：Docker 构建日志
- `ingestion_summary.json`：评测摘要

### 调试技巧

1. **本地测试**：使用官方 Docker 镜像本地运行
2. **查看日志**：在代码中添加 `print()` 输出调试信息
3. **增量测试**：先测试小案例（task_1/case1）
4. **检查输出**：用 `tree` 命令查看输出目录结构

---

## 参考资源

- **赛题指南**：详细的任务说明和评分标准
- **工具手册**：广立微 Scan Insertion 工具用户手册
- **Public Cases**：用于开发调试的公开测试用例

---