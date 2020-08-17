import asyncio
import logging
import os
import re
import sys
import traceback
from typing import List, Optional, Union
from urllib.parse import urljoin

import aiohttp
from aiohttp import web
from multidict import CIMultiDict

logger = logging.getLogger("proxy")

FLAG_REGEXP = r'[A-Z0-9]{31}(=|%[Dd])'

ALLOWED_USER_AGENT_REGEXP = ''
METHODS_WHITELIST = []
METHODS_BLACKLIST = []

REQ_BAD_WORDS_IN_URL: List[str] = [
    'SELECT+', 'UNION+',
]
REQ_BAD_WORDS_IN_BODY: List[Union[str, bytes]] = [
    '.__class__.', '.__subclasses__()',
    # '.__globals__.', '.__builtins__.',
    # "['__globals__']", "['__builtins__']", '["__globals__"]', '["__builtins__"]',
    # '\\x5f\\x5fglobals\\x5f\\x5f', '\\x5f\\x5fbuiltins\\x5f\\x5f',
    'SELECT+', 'UNION+', 'SELECT%20', 'UNION%20', 'SELECT ', 'UNION ',
    'cat%20./', 'cat ./', 'cat%20/', 'cat /',
    '/usr/bin/', '/bin/bash', '/bin/sh', 'sh -c ',
    # "system('", "eval('", "exec('", 'system("', 'eval("', 'exec("',
]
REQ_BAD_WORDS_IN_HEADERS: List[str] = []

RESP_BAD_WORDS_IN_URL: List[str] = []
RESP_BAD_WORDS_IN_BODY: List[Union[str, bytes]] = []
RESP_BAD_WORDS_IN_HEADERS: List[str] = []
RESP_MAX_ALLOWED_FLAGS = 20


async def proxy(request):
    url = urljoin(remote_url, request.path_qs)
    method = request.method
    headers = request.headers

    body = None
    if request.can_read_body:
        body = await request.read()

    method, url, headers, body, drop = process_request(method, url, headers, body)
    if drop:
        return web.Response(text='[filtered]', headers={'Server': 'nginx'})

    # logger.info("Requesting to: %s", url)
    if remote_https and remote_https_disable_check:
        connector = aiohttp.TCPConnector(verify_ssl=False)
        async with aiohttp.request(url=url, method=method, headers=headers, data=body, connector=connector) as res:
            rbody = await res.read()
        if connector:
            connector.close()
    else:
        session = aiohttp.ClientSession()
        # async with aiohttp.ClientSession() as session:
        async with session.request(url=url, method=method, headers=headers, data=body) as res:
            rbody = await res.read()
        if session:
            session.close()

    # logger.info("Got a response from: %s", url)

    rheaders = CIMultiDict(res.headers)
    # aiohttp return uncompressed response
    # so removing compress mark and compressed length
    for h in ['content-encoding', 'content-length']:
        if h in rheaders:
            del rheaders[h]

    rstatus = res.status

    rstatus, rheaders, rbody = process_response(method, url, headers, body, rstatus, rheaders, rbody)

    return web.Response(body=rbody, status=rstatus, headers=rheaders)


def process_request(method: str, url: str, headers: dict, body: Optional[bytes]):
    drop = False
    try:
        if METHODS_WHITELIST and method.upper() not in METHODS_WHITELIST:
            drop = True

        if METHODS_BLACKLIST and method.upper() in METHODS_BLACKLIST:
            drop = True

        for word in REQ_BAD_WORDS_IN_URL:
            if word in url:
                drop = True
                break

        for word in REQ_BAD_WORDS_IN_BODY:
            if isinstance(word, str):
                word = word.encode()
            if body and word in body:
                drop = True
                break

        for word in REQ_BAD_WORDS_IN_HEADERS:
            if word in str(headers):
                drop = True
                break

        if ALLOWED_USER_AGENT_REGEXP:
            user_agent = headers.get('User-Agent')
            if not re.match(ALLOWED_USER_AGENT_REGEXP, user_agent):
                drop = True

        # if not drop:
        #    print(body)

        # drop request
        # if 'key1' in url.lower():
        #     drop = True

    except:
        traceback.print_exception(*sys.exc_info())
    return method, url, headers, body, drop


def process_response(
    method: str, url: str, headers: dict, body: Optional[bytes], rstatus: int, rheaders: dict, rbody: bytes,
):
    try:
        for word in RESP_BAD_WORDS_IN_URL:
            if word in url:
                rbody = '[filtered]'
                break

        for word in RESP_BAD_WORDS_IN_BODY:
            if isinstance(word, str):
                word = word.encode()
            if rbody and word in rbody:
                rbody = '[filtered]'
                break

        for word in RESP_BAD_WORDS_IN_HEADERS:
            if word in str(rheaders):
                rbody = '[filtered]'
                break

        if RESP_MAX_ALLOWED_FLAGS > 0:
            flags = len(re.findall(FLAG_REGEXP, rbody))
            if flags > RESP_MAX_ALLOWED_FLAGS:
                rbody = '[filtered]'

        # modified response after sending request
        # if 'httpie' in headers.get('user-agent').lower():
        #     rstatus = 504
        #     rbody = '.!..'

        # if 'marker_search.py' in rbody.decode():
        #     rbody = b'N'

    except:
        traceback.print_exception(*sys.exc_info())
    return rstatus, rheaders, rbody


if __name__ == "__main__":
    bind_address = os.environ.get('PROXY_BIND_ADDR', '0.0.0.0')
    bind_port = int(os.environ.get('PROXY_BIND_PORT', 9000))
    remote_address = os.environ['PROXY_REMOTE_ADDR']
    remote_port = int(os.environ['PROXY_REMOTE_PORT'])
    remote_https = os.environ['PROXY_REMOTE_HTTPS'].strip().lower() in ['1', 'true']
    remote_https_disable_check = os.environ['PROXY_REMOTE_HTTPS_CHECK'].strip().lower() in ['1', 'true']

    bind_https = os.environ['PROXY_BIND_HTTPS'].strip().lower() in ['1', 'true']
    https_key_path = './proxy.key'
    https_crt_path = './proxy.crt'

    s = ''
    if remote_https:
        s = 's'
    remote_url = 'http%s://%s:%s' % (s, remote_address, remote_port)

    logging.root.setLevel(logging.INFO)
    logging.root.addHandler(logging.StreamHandler())

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', proxy)

    ssl_context = None
    if bind_https:
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ssl_context.load_cert_chain(https_crt_path, https_key_path)

    loop = asyncio.get_event_loop()
    f = loop.create_server(app.make_handler(), bind_address, bind_port, ssl=ssl_context)
    srv = loop.run_until_complete(f)
    print('serving on', srv.sockets[0].getsockname())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


# usage
# apt install python3-virtualenv virtualenv
# virtualenv -p python3 venv
# source venv/bin/activate
# pip3 install aiohttp
# python3 proxy.py
