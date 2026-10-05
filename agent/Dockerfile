FROM scan-agent-base:ubuntu24

RUN apt-get update && apt-get install -y --no-install-recommends make \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages \
      -i https://pypi.tuna.tsinghua.edu.cn/simple -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

RUN rm -f /submission/agent_system
COPY agent_system /submission/agent_system
COPY scan_agent.py /submission/scan_agent.py
COPY netlist_repair.py /submission/netlist_repair.py
COPY extract_tool_help.py /submission/extract_tool_help.py
RUN python3 /submission/extract_tool_help.py --output /submission/tool_help.json
RUN chmod +x /submission/agent_system

WORKDIR /work
ENTRYPOINT ["/submission/agent_system"]
