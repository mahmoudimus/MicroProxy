"""An aioquic echo client, the peer of MicroProxy's QUIC interoperability tests.

It connects with the ALPN "microproxy-test", sends seeded random data on bidirectional streams
and checks the echo, optionally sends a unidirectional stream and checks the SHA-256 digest the
server returns on a unidirectional stream of its own, sends datagrams, starts key updates, and
closes with a chosen code. It prints one "RESULT <json>" line and exits with status 0 if every
check passed.
"""

import argparse
import asyncio
import contextlib
import hashlib
import json
import random
import socket
import ssl
import sys
import time

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, DatagramFrameReceived, StreamDataReceived
from aioquic.quic.packet import QuicProtocolVersion
from aioquic.tls import CipherSuite

ALPN = "microproxy-test"


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datagrams = asyncio.Queue()
        self.terminated = asyncio.get_running_loop().create_future()
        self.uni_replies = asyncio.Queue()
        self._uni = {}

    def quic_event_received(self, event):
        if isinstance(event, DatagramFrameReceived):
            self.datagrams.put_nowait(event.data)
        elif isinstance(event, ConnectionTerminated):
            if not self.terminated.done():
                self.terminated.set_result((event.error_code, event.reason_phrase))
        elif isinstance(event, StreamDataReceived) and event.stream_id & 3 == 3:
            data = self._uni.get(event.stream_id, b"") + event.data
            if event.end_stream:
                self._uni.pop(event.stream_id, None)
                self.uni_replies.put_nowait(data)
            else:
                self._uni[event.stream_id] = data
            return
        super().quic_event_received(event)


@contextlib.asynccontextmanager
async def connect(host, port, configuration, create_protocol):
    """aioquic's connect() on an IPv4 socket: its own binds a dual-stack IPv6 one, which not every
    test machine has."""
    loop = asyncio.get_running_loop()
    connection = QuicConnection(configuration=configuration)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(lambda: create_protocol(connection), sock=sock)
    try:
        protocol.connect((host, port))
        await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()


async def echo_stream(protocol, seed, size):
    data = random.Random(seed).randbytes(size)
    reader, writer = await protocol.create_stream()
    for off in range(0, size, 65536):
        writer.write(data[off : off + 65536])
    writer.write_eof()
    received = await reader.read()
    if hashlib.sha256(received).digest() != hashlib.sha256(data).digest():
        raise AssertionError("stream %d: echo of %d bytes differs (%d received)" % (seed, size, len(received)))
    return len(received)


async def main(args):
    configuration = QuicConfiguration(
        alpn_protocols=[ALPN],
        is_client=True,
        server_name=args.server_name,
        max_datagram_frame_size=65536,
        max_data=64 * 1024 * 1024,
        max_stream_data=16 * 1024 * 1024,
        idle_timeout=30.0,
    )
    configuration.load_verify_locations(cafile=args.ca)
    configuration.verify_mode = ssl.CERT_REQUIRED
    if args.cipher_suite:
        configuration.cipher_suites = [CipherSuite[name] for name in args.cipher_suite]
    if args.version == 2:
        configuration.original_version = QuicProtocolVersion.VERSION_2
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")

    result = {"ok": False}
    start = time.monotonic()
    async with connect(args.host, args.port, configuration, ClientProtocol) as protocol:
        quic = protocol._quic
        result["cipher_suite"] = CipherSuite(quic.tls.key_schedule.cipher_suite).name
        result["version"] = quic._version
        if args.expect_server_close:
            # Ask the server to close, then report what it sent
            reader, writer = await protocol.create_stream()
            writer.write(args.expect_server_close.encode())
            writer.write_eof()
            code, reason = await asyncio.wait_for(protocol.terminated, 10)
            result.update(ok=True, close_code=code, close_reason=reason)
            print("RESULT " + json.dumps(result), flush=True)
            return 0

        tasks = [asyncio.ensure_future(echo_stream(protocol, i, args.size)) for i in range(args.streams)]
        for _ in range(args.key_updates):
            await asyncio.sleep(0.05)
            protocol.request_key_update()
            protocol.transmit()
        total = sum(await asyncio.gather(*tasks))

        if args.uni_size:
            data = random.Random(1000).randbytes(args.uni_size)
            sid = quic.get_next_available_stream_id(is_unidirectional=True)
            quic.send_stream_data(sid, data, end_stream=True)
            protocol.transmit()
            digest = await asyncio.wait_for(protocol.uni_replies.get(), 30)
            if digest != hashlib.sha256(data).digest():
                raise AssertionError("unidirectional digest differs")
            total += len(data)

        echoed = 0
        for i in range(args.datagrams):
            quic.send_datagram_frame(b"datagram %d" % i)
            protocol.transmit()
            try:
                reply = await asyncio.wait_for(protocol.datagrams.get(), 0.5)
                if reply.startswith(b"datagram "):
                    echoed += 1
            except asyncio.TimeoutError:
                pass
        if args.datagrams and echoed == 0:
            raise AssertionError("no datagram came back")

        seconds = time.monotonic() - start
        result.update(ok=True, bytes=total, datagrams_echoed=echoed, seconds=round(seconds, 3))
        protocol.close(error_code=args.close_code, reason_phrase=args.close_reason)
        await protocol.wait_closed()
    print("RESULT " + json.dumps(result, default=str), flush=True)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic echo client for interop tests")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--streams", type=int, default=1)
    parser.add_argument("--size", type=int, default=1000)
    parser.add_argument("--uni-size", type=int, default=0)
    parser.add_argument("--datagrams", type=int, default=0)
    parser.add_argument("--key-updates", type=int, default=0)
    parser.add_argument("--cipher-suite", action="append")
    parser.add_argument("--version", type=int, default=1)
    parser.add_argument("--close-code", type=int, default=0)
    parser.add_argument("--close-reason", default="")
    parser.add_argument("--expect-server-close", help="data to send on a stream before waiting for the close")
    parser.add_argument("--secrets-log")
    try:
        sys.exit(asyncio.run(main(parser.parse_args())))
    except Exception as e:  # report every failure the same way
        print("RESULT " + json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}), flush=True)
        sys.exit(1)
