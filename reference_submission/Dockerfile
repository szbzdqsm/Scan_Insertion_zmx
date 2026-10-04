# ============================================================================
# Scan Insertion Agent Dockerfile - 参考示例
# ============================================================================
#
# 基于企业提供的基础镜像，包含：
#   - Ubuntu 24.04
#   - Python 3.12
#   - Yosys + EQY (逻辑等价性验证)
#   - dftexp_scan (Scan Insertion 工具)
#
# 构建命令：
#   docker build -t my-scan-agent .
#
# 本地测试：
#   docker run --rm \
#     -v /path/to/input:/input:ro \
#     -v /path/to/output:/output:rw \
#     my-scan-agent \
#     -input /input \
#     -output /output
# ============================================================================

FROM scan-agent-base:ubuntu24

# ============================================================================
# 安装 Python 依赖
# ============================================================================

# 复制依赖列表
COPY submission/requirements.txt /tmp/requirements.txt

# 使用清华镜像加速安装（国内网络环境）
RUN pip3 install --no-cache-dir --break-system-packages \
    -i https://pypi.tuna.tsinghua.edu.cn/simple \
    -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# ============================================================================
# 复制 Agent 代码
# ============================================================================

# 清空基础镜像的占位脚本
RUN rm -rf /submission/*

# 复制所有代码文件
COPY submission/ /submission/

# 设置执行权限
RUN chmod +x /submission/agent_system

# ============================================================================
# 验证安装（可选，用于调试）
# ============================================================================

# 验证 Python 和依赖
RUN python3 --version && \
    python3 -c "import openai; print('openai installed')"

# ============================================================================
# 容器配置
# ============================================================================

# 工作目录
WORKDIR /work

# 入口点（必须保持，Codabench 会调用此脚本）
ENTRYPOINT ["/submission/agent_system"]

# ============================================================================
# 元数据
# ============================================================================

LABEL maintainer="your-email@example.com"
LABEL description="Scan Insertion Agent - Reference Implementation"
LABEL version="1.0"
