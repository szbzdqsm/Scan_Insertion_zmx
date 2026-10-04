FROM scan-agent-base:ubuntu24

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages \
      -i https://pypi.tuna.tsinghua.edu.cn/simple -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

RUN rm -f /submission/agent_system
COPY agent_system /submission/agent_system
COPY scan_agent.py /submission/scan_agent.py
RUN chmod +x /submission/agent_system

WORKDIR /work
ENTRYPOINT ["/submission/agent_system"]
