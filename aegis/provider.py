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

def open_pinned(request, timeout):
    """Resolve once, reject every nonpublic answer, pin TCP while preserving TLS SNI."""
    import http.client
    import socket
    import ssl
    url = urlsplit(request.full_url)
    if url.scheme != 'https' or url.port not in (None, 443) or url.username or url.password:
        raise ValueError('HTTPS endpoint refused')
    addresses = socket.getaddrinfo(url.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
        raise ValueError('Nonpublic model DNS refused')
    address = addresses[0][4][0]
    class Pinned(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection((address, 443), self.timeout)
            try:
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            except BaseException:
                sock.close()
                raise
    connection = Pinned(url.hostname, timeout=timeout, context=ssl.create_default_context())
    try:
        connection.request(request.get_method(), url.path or '/', body=request.data, headers=dict(request.header_items()))
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('Model HTTP request refused')
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                response.close()
                connection.close()
            def read(self, limit):
                return response.read(limit)
        return Response()
    except BaseException:
        connection.close()
        raise
