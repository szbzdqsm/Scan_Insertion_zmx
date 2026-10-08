"""Include module initialization in the official entry point's case clock."""
import time

_agent_started_at = time.monotonic()

from scan_agent import main  # noqa: E402


if __name__ == '__main__':
    raise SystemExit(main(started_at=_agent_started_at))
