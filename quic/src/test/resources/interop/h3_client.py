"""An HTTP/3 client on aioquic's H3Connection, the peer of MicroProxy's HTTP/3 interop test.

It sends, concurrently: GET /hello, POST /echo with a seeded random body, and GET /bytes/<n>,
checks each response, and prints one "RESULT <json>" line; it exits with status 0 if every check
passed.
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

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection


class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._responses = {}

    def quic_event_received(self, event):
        for h3_event in self._http.handle_event(event):
            response = self._responses.get(getattr(h3_event, "stream_id", None))
            if response is None:
                continue
            if isinstance(h3_event, HeadersReceived):
                response["headers"] = dict(h3_event.headers)
            elif isinstance(h3_event, DataReceived):
                response["body"] += h3_event.data
            if getattr(h3_event, "stream_ended", False) and not response["done"].done():
                response["done"].set_result(None)

    async def request(self, method, authority, path, body=b""):
        sid = self._quic.get_next_available_stream_id()
        response = {"headers": None, "body": b"", "done": asyncio.get_running_loop().create_future()}
        self._responses[sid] = response
        self._http.send_headers(
            stream_id=sid,
            headers=[
                (b":method", method.encode()),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b"user-agent", b"aioquic-interop"),
            ],
            end_stream=not body,
        )
        if body:
            self._http.send_data(stream_id=sid, data=body, end_stream=True)
        self.transmit()
        await asyncio.wait_for(response["done"], 60)
        return response


@contextlib.asynccontextmanager
async def connect(host, port, configuration):
    """aioquic's connect() on an IPv4 socket: its own binds a dual-stack IPv6 one."""
    loop = asyncio.get_running_loop()
    connection = QuicConnection(configuration=configuration)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(lambda: H3ClientProtocol(connection), sock=sock)
    try:
        protocol.connect((host, port))
        await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()


def check(condition, message):
    if not condition:
        raise AssertionError(message)


async def main(args):
    configuration = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True, server_name="localhost",
                                      max_data=64 * 1024 * 1024, max_stream_data=16 * 1024 * 1024)
    configuration.load_verify_locations(cafile=args.ca)
    configuration.verify_mode = ssl.CERT_REQUIRED
    authority = "localhost:%d" % args.port
    upload = random.Random(5).randbytes(args.upload)
    async with connect(args.host, args.port, configuration) as client:
        hello, echo, download = await asyncio.gather(
            client.request("GET", authority, "/hello"),
            client.request("POST", authority, "/echo", upload),
            client.request("GET", authority, "/bytes/%d" % args.download),
        )
        check(hello["headers"][b":status"] == b"200", "GET /hello status %r" % hello["headers"])
        check(hello["body"] == b"hello from MicroProxy QUIC", "GET /hello body %r" % hello["body"][:100])
        check(echo["headers"][b":status"] == b"200", "POST /echo status")
        check(hashlib.sha256(echo["body"]).digest() == hashlib.sha256(upload).digest(), "POST /echo body differs")
        check(len(download["body"]) == args.download, "GET /bytes length %d" % len(download["body"]))
        check(download["headers"].get(b"content-length") == str(args.download).encode(), "content-length")
        # Sequential requests on the same connection
        for i in range(args.repeat):
            r = await client.request("GET", authority, "/hello")
            check(r["body"] == b"hello from MicroProxy QUIC", "repeat %d" % i)
    result = {"ok": True, "echoed": len(echo["body"]), "downloaded": len(download["body"]),
              "server": download["headers"].get(b"server", b"").decode()}
    print("RESULT " + json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic HTTP/3 client for interop tests")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--upload", type=int, default=1_000_000)
    parser.add_argument("--download", type=int, default=2_000_000)
    parser.add_argument("--repeat", type=int, default=5)
    try:
        sys.exit(asyncio.run(main(parser.parse_args())))
    except Exception as e:  # report every failure the same way
        print("RESULT " + json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}), flush=True)
        sys.exit(1)
