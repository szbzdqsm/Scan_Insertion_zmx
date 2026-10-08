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
COPY netlist_structure.py /submission/netlist_structure.py
COPY report_validation.py /submission/report_validation.py
COPY dofile_recipe.py /submission/dofile_recipe.py
COPY floating_inputs.py /submission/floating_inputs.py
COPY contest_rules.py /submission/contest_rules.py
COPY drc_validation.py /submission/drc_validation.py
COPY scan_exclusion_evidence.py /submission/scan_exclusion_evidence.py
COPY clock_latch_context.py /submission/clock_latch_context.py
COPY model_script_view.py /submission/model_script_view.py
COPY drc_retry_preflight.py /submission/drc_retry_preflight.py
COPY wrapper_validation.py /submission/wrapper_validation.py
COPY clock_association_recipe.py /submission/clock_association_recipe.py
COPY mode_control_context.py /submission/mode_control_context.py
COPY insertion_evidence.py /submission/insertion_evidence.py
COPY shift_report_recipe.py /submission/shift_report_recipe.py
COPY artifact_operations.py /submission/artifact_operations.py
COPY help_selection.py /submission/help_selection.py
COPY runtime_limits.py /submission/runtime_limits.py
COPY audit_refresh.py /submission/audit_refresh.py
COPY case_deadline.py /submission/case_deadline.py
COPY original_dofile.py /submission/original_dofile.py
COPY repair_deliverables.py /submission/repair_deliverables.py
COPY source_hierarchy.py /submission/source_hierarchy.py
COPY tool_process.py /submission/tool_process.py
COPY agent_runner.py /submission/agent_runner.py
COPY extract_tool_help.py /submission/extract_tool_help.py
RUN python3 /submission/extract_tool_help.py --output /submission/tool_help.json
RUN chmod +x /submission/agent_system

WORKDIR /work
ENTRYPOINT ["/submission/agent_system"]
