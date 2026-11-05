FROM scan-agent-fixed-official:9db0736a60bba851a848e20792202fe21ece0ba87a56944abf0003dafc5301d9
# Fixed official image ID: sha256:9db0736a60bba851a848e20792202fe21ece0ba87a56944abf0003dafc5301d9
USER root
RUN --network=none --mount=type=bind,source=.,target=/mnt,readonly PYTHONDONTWRITEBYTECODE=1 python3 /mnt/apply_delta.py
