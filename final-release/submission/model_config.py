"""Environment-only gateway configuration, with no client/model fallback."""
from __future__ import annotations

import os
from urllib.parse import urlsplit, urlunsplit


def model():
    value = os.environ.get('LLM_MODEL', '').strip()
    # This is a whitelist check, not a request default: the actual request uses
    # the environment value. Missing/other versions fail explicitly.
    if value != 'deepseek-v4-pro-0813':
        raise ValueError('LLM_MODEL missing or outside the 10.22 contest whitelist')
    return value


def gateway_url(value):
    parts = urlsplit(value.strip())
    if (parts.scheme not in {'http', 'https'} or not parts.netloc or parts.username
            or parts.password or parts.query or parts.fragment):
        raise ValueError('LLM_BASE_URL must be an HTTP(S) gateway base without credentials/query')
    path = parts.path.rstrip('/')
    if path.endswith('/chat/completions') or '/v1/v1' in path:
        raise ValueError('LLM_BASE_URL must not be a completions endpoint or duplicate v1')
    if not path.endswith('/v1'):
        path += '/v1'
    return urlunsplit((parts.scheme, parts.netloc, path, '', ''))


def settings():
    selected = model()
    key = os.environ.get('LLM_API_KEY', '').strip()
    base = os.environ.get('LLM_BASE_URL', '').strip()
    if not key or not base:
        raise ValueError('LLM_API_KEY and LLM_BASE_URL must be injected at runtime')
    return selected, key, gateway_url(base)


def require_model_requests():
    if os.environ.get('AGENT_DISABLE_MODEL_REQUESTS') == '1':
        raise RuntimeError('Model requests prohibited for this developer validation')
