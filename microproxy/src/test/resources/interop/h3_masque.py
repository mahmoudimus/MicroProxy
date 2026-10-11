"""An aioquic HTTP/3 client of MicroProxy's forward-proxy HTTP/3 listener: CONNECT, WebSockets
and CONNECT-UDP (MASQUE), the peer of MicroProxy's interop tests.

On one connection it runs the scenarios it is given targets for, and prints one "RESULT <json>"
line: a CONNECT to a TCP echo server (--tcp-target), whose bytes come back after the stream's end;
a WebSocket over extended CONNECT (RFC 9220) to a WebSocket echo server (--ws-target); and
CONNECT-UDP (RFC 9298) to a UDP echo server (--udp-target), its payloads in QUIC DATAGRAM frames
(HTTP Datagrams, RFC 9297) and then in DATAGRAM capsules on the stream, and again on a second
connection that takes no HTTP/3 datagrams, with capsules both ways.
"""

import argparse
import asyncio
import contextlib
import json
import os
import socket
import ssl
import struct

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer, encode_uint_var
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DatagramReceived, DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamReset


class Stream:
    def __init__(self):
        self.headers = asyncio.get_running_loop().create_future()
        self.data = asyncio.Queue()
        self.datagrams = asyncio.Queue()
        self.ended = False
        # DATA read from the queue and not yet consumed.
        self.buffer = b""


class MasqueClient(QuicConnectionProtocol):
    def __init__(self, *args, datagrams=True, **kwargs):
        super().__init__(*args, **kwargs)
        # enable_webtransport makes aioquic send SETTINGS_H3_DATAGRAM (and its own setting, ignored).
        self._http = H3Connection(self._quic, enable_webtransport=datagrams)
        self._streams = {}

    def quic_event_received(self, event):
        if isinstance(event, StreamReset):
            stream = self._streams.get(event.stream_id)
            if stream is not None:
                stream.data.put_nowait(None)
            return
        for h3_event in self._http.handle_event(event):
            stream = self._streams.get(getattr(h3_event, "stream_id", None))
            if stream is None:
                continue
            if isinstance(h3_event, HeadersReceived) and not stream.headers.done():
                stream.headers.set_result(h3_event.headers)
            elif isinstance(h3_event, DataReceived) and h3_event.data:
                stream.data.put_nowait(h3_event.data)
            elif isinstance(h3_event, DatagramReceived):
                stream.datagrams.put_nowait(h3_event.data)
            if getattr(h3_event, "stream_ended", False):
                stream.data.put_nowait(None)

    async def open(self, headers):
        sid = self._quic.get_next_available_stream_id()
        stream = Stream()
        self._streams[sid] = stream
        self._http.send_headers(stream_id=sid, headers=headers, end_stream=False)
        self.transmit()
        response = await asyncio.wait_for(stream.headers, 20)
        return sid, stream, int(dict(response)[b":status"])

    def send(self, sid, data, end=False):
        self._http.send_data(stream_id=sid, data=data, end_stream=end)
        self.transmit()

    def send_datagram(self, sid, content):
        self._http.send_datagram(stream_id=sid, data=content)
        self.transmit()

    async def read(self, stream, n):
        """Reads n bytes of the stream's DATA, or fewer if it ends."""
        while len(stream.buffer) < n and not stream.ended:
            chunk = await asyncio.wait_for(stream.data.get(), 20)
            if chunk is None:
                stream.ended = True
            else:
                stream.buffer += chunk
        out, stream.buffer = stream.buffer[:n], stream.buffer[n:]
        return out

    async def read_all(self, stream):
        while not stream.ended:
            chunk = await asyncio.wait_for(stream.data.get(), 20)
            if chunk is None:
                stream.ended = True
            else:
                stream.buffer += chunk
        out, stream.buffer = stream.buffer, b""
        return out


def ws_frame(text):
    """A masked WebSocket text frame, as a client sends it."""
    payload = text.encode()
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes([0x81, 0x80 | len(payload)]) + mask + masked


async def read_ws_frame(client, stream):
    head = await client.read(stream, 2)
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", await client.read(stream, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await client.read(stream, 8))[0]
    return head[0], (await client.read(stream, length)).decode()


def capsule(capsule_type, value):
    return encode_uint_var(capsule_type) + encode_uint_var(len(value)) + value


async def read_varint(client, stream):
    first = await client.read(stream, 1)
    if not first:
        raise EOFError("the stream ended")
    length = 1 << (first[0] >> 6)
    rest = await client.read(stream, length - 1)
    return Buffer(data=first + rest).pull_uint_var()


async def read_capsule(client, stream):
    """Reads one capsule from the stream: (type, value)."""
    capsule_type = await read_varint(client, stream)
    length = await read_varint(client, stream)
    return capsule_type, await client.read(stream, length)


async def scenarios(client, args, authority):
    results = {}
    if args.tcp_target:
        sid, stream, status = await client.open([(b":method", b"CONNECT"), (b":authority", args.tcp_target.encode())])
        results["connect_status"] = status
        if status == 200:
            client.send(sid, b"hello over aioquic", end=True)
            results["connect_echo"] = (await client.read_all(stream)).decode()
    if args.ws_target:
        host, port = args.ws_target.rsplit(":", 1)
        sid, stream, status = await client.open([
            (b":method", b"CONNECT"), (b":protocol", b"websocket"), (b":scheme", b"http"),
            (b":authority", args.ws_target.encode()), (b":path", b"/chat"),
            (b"sec-websocket-version", b"13")])
        results["ws_status"] = status
        if status == 200:
            client.send(sid, ws_frame("ping over aioquic"))
            opcode, text = await read_ws_frame(client, stream)
            results["ws_echo"] = text
            client.send(sid, b"", end=True)
    if args.udp_target:
        host, port = args.udp_target.rsplit(":", 1)
        path = "/.well-known/masque/udp/%s/%s/" % (host, port)
        sid, stream, status = await client.open([
            (b":method", b"CONNECT"), (b":protocol", b"connect-udp"), (b":scheme", b"https"),
            (b":authority", authority.encode()), (b":path", path.encode()), (b"capsule-protocol", b"?1")])
        results["udp_status"] = status
        if status == 200:
            echoes = []
            for i in range(3):
                client.send_datagram(sid, b"\x00" + ("datagram %d" % i).encode())
                content = await asyncio.wait_for(stream.datagrams.get(), 20)
                echoes.append(content[1:].decode() if content[:1] == b"\x00" else None)
            results["udp_datagram_echoes"] = echoes
            # DATAGRAM capsules on the stream, after one of a type the proxy does not know.
            client.send(sid, capsule(0x2A, b"ignored") + capsule(0x00, b"\x00" + b"by capsule"))
            content = await asyncio.wait_for(stream.datagrams.get(), 20)
            results["udp_capsule_echo"] = content[1:].decode()
            client.send(sid, b"", end=True)
            await client.read_all(stream)
            results["udp_ended"] = True
    return results


async def capsules_only(client, args, authority):
    """CONNECT-UDP on a connection without HTTP/3 datagrams: capsules both ways."""
    host, port = args.udp_target.rsplit(":", 1)
    path = "/.well-known/masque/udp/%s/%s/" % (host, port)
    sid, stream, status = await client.open([
        (b":method", b"CONNECT"), (b":protocol", b"connect-udp"), (b":scheme", b"https"),
        (b":authority", authority.encode()), (b":path", path.encode()), (b"capsule-protocol", b"?1")])
    results = {"udp_capsules_status": status}
    if status == 200:
        echoes = []
        for i in range(3):
            client.send(sid, capsule(0x00, b"\x00" + ("capsule %d" % i).encode()))
            while True:
                capsule_type, value = await read_capsule(client, stream)
                if capsule_type == 0x00:
                    break
            echoes.append(value[1:].decode())
        results["udp_capsule_echoes"] = echoes
        client.send(sid, b"", end=True)
        await client.read_all(stream)
    return results


@contextlib.asynccontextmanager
async def connect(host, port, configuration, datagrams=True):
    """aioquic's connect() on an IPv4 socket: its own binds a dual-stack IPv6 one."""
    loop = asyncio.get_running_loop()
    connection = QuicConnection(configuration=configuration)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MasqueClient(connection, datagrams=datagrams), sock=sock)
    try:
        protocol.connect((host, port))
        await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()


def configuration(args, datagrams):
    config = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True, server_name=args.server_name,
                               max_datagram_frame_size=65536 if datagrams else None)
    config.load_verify_locations(cafile=args.ca)
    config.verify_mode = ssl.CERT_REQUIRED
    return config


async def main(args):
    authority = "%s:%d" % (args.server_name, args.port)
    try:
        async with connect(args.host, args.port, configuration(args, True)) as client:
            results = await scenarios(client, args, authority)
        if args.udp_target:
            async with connect(args.host, args.port, configuration(args, False), datagrams=False) as client:
                results.update(await capsules_only(client, args, authority))
        print("RESULT " + json.dumps({"ok": True, "results": results}), flush=True)
    except Exception as e:  # reported to the test
        print("RESULT " + json.dumps({"ok": False, "error": repr(e)}), flush=True)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic client of MicroProxy's MASQUE tests")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--tcp-target")
    parser.add_argument("--ws-target")
    parser.add_argument("--udp-target")
    raise SystemExit(asyncio.run(main(parser.parse_args())))
