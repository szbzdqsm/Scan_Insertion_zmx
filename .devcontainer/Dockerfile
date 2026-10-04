FROM scan-agent-base:ubuntu24

RUN apt-get update && apt-get install -y --no-install-recommends make \
    && rm -rf /var/lib/apt/lists/*

COPY agent/requirements.txt /tmp/scan-dev/agent/requirements.txt
COPY requirements-dev.txt /tmp/scan-dev/requirements-dev.txt
RUN cd /tmp/scan-dev && pip3 install --no-cache-dir --break-system-packages \
      -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements-dev.txt \
    && rm -rf /tmp/scan-dev

WORKDIR /workspaces/scan-agent-dev
