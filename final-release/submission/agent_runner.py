"""Formal input-marker entry; local readiness observation is not platform t1."""
import time

ENTRY_MONOTONIC = time.monotonic()
ENTRY_UTC = time.time()
print('[startup] version=1104-marker-v1 mode=marker input_marker=case_upload_marker clock=local-marker-observation', flush=True)

if __name__ == '__main__':
    from preloaded_startup import run
    raise SystemExit(run(ENTRY_MONOTONIC, ENTRY_UTC))
