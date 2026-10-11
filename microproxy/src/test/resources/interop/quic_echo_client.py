"""An aioquic client of raw QUIC streams for an ALPN of the test's choosing, the peer of
MicroProxy's QUIC stream hook tests, against quic_echo_server.py (or a server that behaves the
same) through the proxy.

Its QUIC runs over a UDP socket to HOST:PORT, or, with --masque-target, inside a CONNECT-UDP flow
(RFC 9298) to that target, opened on an HTTP/3 connection to the forward proxy at HOST:PORT: the
inner connection's datagrams travel as HTTP Datagrams with context ID 0, in QUIC DATAGRAM frames
when they are small and in DATAGRAM capsules on the request stream otherwise (RFC 9297).

On the inner connection it echoes text on bidirectional streams, a megabyte on another (checked
with SHA-256), sends a unidirectional stream and reads the server's answer on one of its own,
sends a datagram until its echo arrives, resets a stream with code 42 and closes with code 7. It
prints one "RESULT <json>" line.
"""

import argparse
import asyncio
import hashlib
import json
import random
import socket
import ssl

from aioquic.buffer import Buffer, encode_uint_var
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DatagramReceived, DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    ConnectionTerminated,
    DatagramFrameReceived,
    HandshakeCompleted,
    StreamDataReceived,
    StreamReset,
)

PEER = ("127.0.0.1", 443)
# Inner datagrams up to this size go in QUIC DATAGRAM frames, larger ones in capsules.
MAX_DATAGRAM = 1000


class Inner:
    """A QUIC connection driven by hand over any datagram transport (send)."""

    def __init__(self, quic, send):
        self.loop = asyncio.get_running_loop()
        self.quic = quic
        self.send = send
        self.connected = self.loop.create_future()
        self.terminated = self.loop.create_future()
        self.changed = asyncio.Event()
        self.data = {}
        self.ended = set()
        self.uni = asyncio.Queue()
        self.datagrams = asyncio.Queue()
        self._timer = None
        self._timer_at = None

    def connect(self):
        self.quic.connect(PEER, now=self.loop.time())
        self.transmit()

    def receive(self, datagram):
        self.quic.receive_datagram(datagram, PEER, now=self.loop.time())
        self.process()

    def process(self):
        event = self.quic.next_event()
        while event is not None:
            if isinstance(event, HandshakeCompleted) and not self.connected.done():
                self.connected.set_result(event.alpn_protocol)
            elif isinstance(event, StreamDataReceived):
                self.data[event.stream_id] = self.data.get(event.stream_id, b"") + event.data
                if event.end_stream:
                    self.ended.add(event.stream_id)
                    if event.stream_id & 2:
                        self.uni.put_nowait(self.data.pop(event.stream_id))
            elif isinstance(event, DatagramFrameReceived):
                self.datagrams.put_nowait(event.data)
            elif isinstance(event, ConnectionTerminated):
                if not self.connected.done():
                    self.connected.set_exception(ConnectionError(event.reason_phrase))
                if not self.terminated.done():
                    self.terminated.set_result((event.error_code, event.reason_phrase))
            event = self.quic.next_event()
        self.changed.set()
        self.transmit()

    def transmit(self):
        for data, _ in self.quic.datagrams_to_send(now=self.loop.time()):
            self.send(data)
        timer_at = self.quic.get_timer()
        if self._timer is not None and self._timer_at != timer_at:
            self._timer.cancel()
            self._timer = None
        if self._timer is None and timer_at is not None:
            self._timer = self.loop.call_at(timer_at, self._on_timer)
        self._timer_at = timer_at

    def _on_timer(self):
        self._timer = None
        self.quic.handle_timer(now=max(self._timer_at, self.loop.time()))
        self.process()

    async def read_all(self, sid):
        while sid not in self.ended:
            self.changed.clear()
            await asyncio.wait_for(self.changed.wait(), 20)
        return self.data.pop(sid, b"")


async def scenarios(inner):
    results = {"alpn": await asyncio.wait_for(inner.connected, 20)}
    quic = inner.quic
    echoes = []
    for i in range(3):
        sid = quic.get_next_available_stream_id()
        quic.send_stream_data(sid, ("hello %d" % i).encode(), end_stream=True)
        inner.transmit()
        echoes.append((await inner.read_all(sid)).decode())
    results["echoes"] = echoes

    big = random.Random(5).randbytes(1_000_000)
    sid = quic.get_next_available_stream_id()
    for off in range(0, len(big), 65536):
        quic.send_stream_data(sid, big[off : off + 65536], end_stream=off + 65536 >= len(big))
        inner.transmit()
        await asyncio.sleep(0)
    received = await inner.read_all(sid)
    results["big_ok"] = hashlib.sha256(received).digest() == hashlib.sha256(big).digest()
    results["big_length"] = len(received)

    sid = quic.get_next_available_stream_id(is_unidirectional=True)
    quic.send_stream_data(sid, b"uni hello", end_stream=True)
    inner.transmit()
    results["uni_reply"] = (await asyncio.wait_for(inner.uni.get(), 20)).decode()

    for _ in range(10):
        quic.send_datagram_frame(b"ping")
        inner.transmit()
        try:
            results["datagram"] = (await asyncio.wait_for(inner.datagrams.get(), 1)).decode()
            break
        except asyncio.TimeoutError:
            continue

    sid = quic.get_next_available_stream_id()
    quic.send_stream_data(sid, b"partial", end_stream=False)
    inner.transmit()
    await asyncio.sleep(0.3)
    quic.reset_stream(sid, 42)
    inner.transmit()
    results["reset_stream"] = sid
    await asyncio.sleep(0.3)

    quic.close(error_code=7, reason_phrase="done")
    inner.transmit()
    await asyncio.sleep(0.3)
    return results


def inner_configuration(args):
    config = QuicConfiguration(alpn_protocols=[args.alpn], is_client=True, server_name=args.server_name,
                               max_datagram_frame_size=65536, max_data=64 * 1024 * 1024,
                               max_stream_data=16 * 1024 * 1024, idle_timeout=30.0)
    config.load_verify_locations(cafile=args.ca)
    config.verify_mode = ssl.CERT_REQUIRED
    return config


class Socket(asyncio.DatagramProtocol):
    def __init__(self):
        self.inner = None

    def datagram_received(self, data, addr):
        if self.inner is not None:
            self.inner.receive(data)


async def direct(args):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(Socket, sock=sock)
    try:
        inner = Inner(QuicConnection(configuration=inner_configuration(args)),
                      lambda data: transport.sendto(data, (args.host, args.port)))
        protocol.inner = inner
        inner.connect()
        return await scenarios(inner)
    finally:
        transport.close()


def capsule(capsule_type, value):
    return encode_uint_var(capsule_type) + encode_uint_var(len(value)) + value


class Outer(asyncio.DatagramProtocol):
    """The HTTP/3 connection to the proxy, carrying one CONNECT-UDP flow for the inner connection."""

    def __init__(self, quic, address):
        self.loop = asyncio.get_running_loop()
        self.quic = quic
        self.address = address
        self.http = H3Connection(quic, enable_webtransport=True)  # sends SETTINGS_H3_DATAGRAM
        self.transport = None
        self.connected = self.loop.create_future()
        self.response = self.loop.create_future()
        self.sid = None
        self.inner = None
        self.capsules = b""
        self._timer = None
        self._timer_at = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.quic.receive_datagram(data, addr, now=self.loop.time())
        self.process()

    def process(self):
        event = self.quic.next_event()
        while event is not None:
            if isinstance(event, HandshakeCompleted) and not self.connected.done():
                self.connected.set_result(True)
            elif isinstance(event, ConnectionTerminated) and not self.connected.done():
                self.connected.set_exception(ConnectionError(event.reason_phrase))
            for h3 in self.http.handle_event(event):
                if getattr(h3, "stream_id", None) != self.sid:
                    continue
                if isinstance(h3, HeadersReceived) and not self.response.done():
                    self.response.set_result(int(dict(h3.headers)[b":status"]))
                elif isinstance(h3, DatagramReceived) and h3.data[:1] == b"\x00" and self.inner is not None:
                    self.inner.receive(h3.data[1:])
                elif isinstance(h3, DataReceived) and h3.data:
                    self.read_capsules(h3.data)
            event = self.quic.next_event()
        self.transmit()

    def read_capsules(self, data):
        self.capsules += data
        while True:
            buf = Buffer(data=self.capsules)
            try:
                capsule_type = buf.pull_uint_var()
                length = buf.pull_uint_var()
                value = buf.pull_bytes(length)
            except Exception:
                return  # incomplete
            self.capsules = self.capsules[buf.tell():]
            if capsule_type == 0 and value[:1] == b"\x00" and self.inner is not None:
                self.inner.receive(value[1:])

    def send_inner(self, data):
        if len(data) <= MAX_DATAGRAM:
            self.http.send_datagram(stream_id=self.sid, data=b"\x00" + data)
        else:
            self.http.send_data(stream_id=self.sid, data=capsule(0, b"\x00" + data), end_stream=False)
        self.transmit()

    def transmit(self):
        for data, addr in self.quic.datagrams_to_send(now=self.loop.time()):
            self.transport.sendto(data, addr)
        timer_at = self.quic.get_timer()
        if self._timer is not None and self._timer_at != timer_at:
            self._timer.cancel()
            self._timer = None
        if self._timer is None and timer_at is not None:
            self._timer = self.loop.call_at(timer_at, self._on_timer)
        self._timer_at = timer_at

    def _on_timer(self):
        self._timer = None
        self.quic.handle_timer(now=max(self._timer_at, self.loop.time()))
        self.process()


async def masque(args):
    loop = asyncio.get_running_loop()
    config = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True, server_name=args.proxy_name,
                               max_datagram_frame_size=65536, idle_timeout=30.0)
    config.load_verify_locations(cafile=args.proxy_ca)
    config.verify_mode = ssl.CERT_REQUIRED
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    address = (args.host, args.port)
    quic = QuicConnection(configuration=config)
    transport, outer = await loop.create_datagram_endpoint(lambda: Outer(quic, address), sock=sock)
    try:
        quic.connect(address, now=loop.time())
        outer.transmit()
        await asyncio.wait_for(outer.connected, 20)
        host, port = args.masque_target.rsplit(":", 1)
        outer.sid = quic.get_next_available_stream_id()
        path = "/.well-known/masque/udp/%s/%s/" % (host, port)
        outer.http.send_headers(stream_id=outer.sid, headers=[
            (b":method", b"CONNECT"), (b":protocol", b"connect-udp"), (b":scheme", b"https"),
            (b":authority", ("%s:%d" % (args.proxy_name, args.port)).encode()), (b":path", path.encode()),
            (b"capsule-protocol", b"?1")], end_stream=False)
        outer.transmit()
        status = await asyncio.wait_for(outer.response, 20)
        if status != 200:
            return {"masque_status": status}
        inner = Inner(QuicConnection(configuration=inner_configuration(args)), outer.send_inner)
        outer.inner = inner
        inner.connect()
        results = await scenarios(inner)
        results["masque_status"] = status
        return results
    finally:
        quic.close()
        outer.transmit()
        transport.close()


async def main(args):
    try:
        results = await (masque(args) if args.masque_target else direct(args))
        print("RESULT " + json.dumps({"ok": True, "results": results}), flush=True)
    except Exception as e:  # reported to the test
        print("RESULT " + json.dumps({"ok": False, "error": repr(e)}), flush=True)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic raw QUIC client of MicroProxy's QUIC hook tests")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--ca", required=True, help="the CA the inner connection's server is checked with")
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--alpn", required=True)
    parser.add_argument("--masque-target", help="host:port of a CONNECT-UDP flow to run the QUIC in")
    parser.add_argument("--proxy-ca", help="the CA the proxy's HTTP/3 listener is checked with")
    parser.add_argument("--proxy-name", default="localhost")
    raise SystemExit(asyncio.run(main(parser.parse_args())))
