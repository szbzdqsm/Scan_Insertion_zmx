FROM scan-agent-dev:audit-prestate-action-25c7b17b-20261031
COPY command_error_evidence.py drc_validation.py completion_policy.py scan_agent.py /submission/
USER root
WORKDIR /work
ENTRYPOINT ["/submission/agent_system"]
