import asyncio
import os
import re
import sys
import traceback
from typing import List, Union

BUFSIZE = 4096
FLAG_REGEXP = b'[A-Z0-9]{31}(=|%[Dd])'

REQ_BAD_WORDS: List[Union[str, bytes]] = [
    'cat ./', 'cat%20./', 'cat%20/', 'cat /',
    '/usr/bin/', '/bin/bash', '/bin/sh', 'sh -c ',
    '..%2f..%2f', '..%2F..%2F', '..%5c..%5c', '..%5C..%5C', '../../', '..\\..\\',
]
RESP_BAD_WORDS: List[Union[str, bytes]] = []
RESP_MAX_ALLOWED_FLAGS = 10

# def hexdump(data, length=16):
#     filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
#     lines = []
#     digits = 4 if isinstance(data, str) else 2
#     for c in range(0, len(data), length):
#         chars = data[c:c+length]
#         hex = ' '.join(["%0*x" % (digits, (x)) for x in chars])
#         printable = ''.join(["%s" % (((x) <= 127 and filter[(x)]) or '.') for x in chars])
#         lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
#     print(''.join(lines))


async def pipe(reader, writer, is_from_server, buf):
    try:
        while not reader.at_eof():
            data = await reader.read(2048)
            from_addr, from_port = writer.get_extra_info('sockname')
            to_addr, to_port = writer.get_extra_info('peername')
            buf[int(is_from_server)] = (buf[int(is_from_server)] + data)[-BUFSIZE:]
            data = process_data(data, from_addr, from_port, to_addr, to_port, is_from_server, buf)
            if data is None:
                data = b''
                writer.close()
            # if is_from_server:
            #     name = 'server'
            # else:
            #     name = 'client'
            # print(f'Received {len(data)} bytes from {name} ({from_addr}:{from_port} -> {to_addr}:{to_port})')
            # hexdump(data)
            writer.write(data)
    finally:
        writer.close()


async def handle_client(local_reader, local_writer):
    buf = [b'', b'']
    try:
        remote_reader, remote_writer = await asyncio.open_connection(remote_address, remote_port)
        pipe1 = pipe(local_reader, remote_writer, False, buf)
        pipe2 = pipe(remote_reader, local_writer, True, buf)
        await asyncio.gather(pipe1, pipe2)
    finally:
        local_writer.close()


def process_data(
    data: bytes, from_addr: str, from_port: int, to_addr: str, to_port: int, is_from_server: bool, buf: List[bytes],
):
    # buf[0] - last BUFSIZE bytes from client to server
    # buf[1] - last BUFSIZE bytes from server to client
    # buf contains non-modified bytes
    # return None -> drop connection

    try:
        if RESP_MAX_ALLOWED_FLAGS > 0 and is_from_server:
            flags_from_server = len(re.findall(FLAG_REGEXP, buf[1]))
            if flags_from_server > RESP_MAX_ALLOWED_FLAGS:
                print('Leak of %s flags blocked' % flags_from_server)
                return None

        if is_from_server:
            for word in RESP_BAD_WORDS:
                if isinstance(word, str):
                    word = word.encode(errors='ignore')
                if word in buf[1]:
                    print('Response blocked by word "%s"' % word)
                    return None
                pass
        else:
            for word in REQ_BAD_WORDS:
                if isinstance(word, str):
                    word = word.encode(errors='ignore')
                if word in buf[0]:
                    print('Request blocked by word "%s"' % word)
                    return None

        # checker doesn't click on mines
        # if is_from_server and b'KABOOOOM!' in data:
        #     return None

        # too fast win
        # if is_from_server and b'Y O U   W I N   ! ! !' in data and len(buf[0]) < 50:
        #     return None
        
        # too long save -> leaked field
        # if is_from_server:
        #     r = re.findall(b'\(\d+, \d+\), ', buf[1])
        #     if len(r) > 250:
        #         return None

        # weather search (search anything with '=' at the end -> disconnect)
        # if not is_from_server:
        #     commands = buf[0].replace(b'\r', b'\n').split(b'\n')
        #     commands = [c for c in commands if len(c)]
        #     for i in range(1, len(commands)):
        #         cmd1 = commands[i-1]
        #         cmd2 = commands[i]
        #         if cmd1 == b'3' and cmd2.endswith(b'='):
        #             return None
        #     print(commands)

        # flags_from_server = len(re.findall(b'[A-Z0-9]{31}=', buf[1]))
        # if flags_from_server >= 2:
        #     print(f'leaked {flags_from_server} flags')
        #     return None

    except:
        traceback.print_exception(*sys.exc_info())
    return data


if __name__ == '__main__':
    bind_address = os.environ.get('PROXY_BIND_ADDR', '0.0.0.0')
    bind_port = int(os.environ.get('PROXY_BIND_PORT', 9000))
    remote_address = os.environ['PROXY_REMOTE_ADDR']
    remote_port = int(os.environ['PROXY_REMOTE_PORT'])

    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_client, bind_address, bind_port, loop=loop)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
