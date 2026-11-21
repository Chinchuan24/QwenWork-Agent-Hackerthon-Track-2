"""Shared provider metadata; never reads dotenv or performs network I/O."""
import ipaddress
import re
from urllib.parse import urlsplit

ENDPOINTS = {
    'qwen': ('https://dashscope-intl.aliyuncs.com/compatible-mode/v1', 'qwen-max', 'AEGIS_QWEN_API_KEY'),
    'deepseek': ('https://api.deepseek.com', 'deepseek-chat', 'DEEPSEEK_API_KEY'),
}

def resolve(env, public=False):
    name = env.get('AEGIS_MODEL_PROVIDER') or ('qwen' if public else ('deepseek' if env.get('DEEPSEEK_API_KEY') else 'qwen' if env.get('AEGIS_QWEN_API_KEY') else 'scripted'))
    if name == 'scripted' and not public:
        return name, '', '', ''
    if name in ENDPOINTS:
        base, model, keyname = ENDPOINTS[name]
    elif name == 'openai-compatible' and not public:
        base, model, keyname = env.get('AEGIS_MODEL_BASE_URL', ''), '', 'AEGIS_MODEL_API_KEY'
    else:
        raise ValueError('Unsupported model provider')
    model = env.get('AEGIS_MODEL_NAME') or env.get('AEGIS_LIVE_MODEL') or model
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,80}', model):
        raise ValueError('Invalid model identifier')
    url = urlsplit(base)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.port not in (None, 443) or not re.fullmatch(r'[A-Za-z0-9.-]+', url.hostname) or '.' not in url.hostname or url.hostname.endswith(('.local', '.localhost')):
        raise ValueError('Model endpoint requires trusted public HTTPS hostname on port 443')
    try:
        ipaddress.ip_address(url.hostname)
    except ValueError:
        pass
    else:
        raise ValueError('IP endpoints refused')
    key = env.get(keyname, '')
    if key and (key in model or key in base):
        raise ValueError('Credential must not appear in model metadata')
    if any(ord(c) < 33 or ord(c) > 126 for c in key):
        raise ValueError('Invalid credential format')
    return name, base.rstrip('/'), model, key
