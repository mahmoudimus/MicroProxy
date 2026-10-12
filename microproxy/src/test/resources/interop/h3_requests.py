"""An HTTP/3 client on aioquic's H3Connection, the peer of MicroProxy's HTTP/3 proxy tests.

It reads a JSON list of requests from the file named by --requests, sends them on one connection
(all at once with --concurrent, else one after another), and prints one "RESULT <json>" line with
each response: status, headers, body length and SHA-256, the body itself when it is text and
short, and trailers. A request is {"method", "path", "headers": [[name, value], ...], "body":
text, or "body_size" and "seed" for random bytes, "trailers": [[name, value], ...]}; a body's
SHA-256 is reported as "sent_sha256" so the test can compare an echo. It exits with status 0 once
every response has arrived.
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
from aioquic.quic.events import StreamReset


class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._responses = {}

    def quic_event_received(self, event):
        if isinstance(event, StreamReset):
            response = self._responses.get(event.stream_id)
            if response is not None and not response["done"].done():
                response["reset"] = event.error_code
                response["done"].set_result(None)
            return
        for h3_event in self._http.handle_event(event):
            response = self._responses.get(getattr(h3_event, "stream_id", None))
            if response is None:
                continue
            if isinstance(h3_event, HeadersReceived):
                headers = [[k.decode(), v.decode()] for k, v in h3_event.headers]
                status = dict(h3_event.headers).get(b":status", b"")
                if response["headers"] is None:
                    if not status.startswith(b"1"):
                        response["headers"] = headers
                else:
                    response["trailers"] = headers
            elif isinstance(h3_event, DataReceived):
                response["body"] += h3_event.data
            if getattr(h3_event, "stream_ended", False) and not response["done"].done():
                response["done"].set_result(None)

    async def request(self, authority, spec):
        sid = self._quic.get_next_available_stream_id()
        response = {"headers": None, "trailers": [], "body": b"", "reset": None,
                    "done": asyncio.get_running_loop().create_future()}
        self._responses[sid] = response
        if "body_size" in spec:
            body = random.Random(spec.get("seed", 1)).randbytes(spec["body_size"])
        else:
            body = spec.get("body", "").encode()
        trailers = [(k.encode(), v.encode()) for k, v in spec.get("trailers", [])]
        headers = [
            (b":method", spec.get("method", "GET").encode()),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", spec.get("path", "/").encode()),
            (b"user-agent", b"aioquic-proxy-test"),
        ] + [(k.encode(), v.encode()) for k, v in spec.get("headers", [])]
        self._http.send_headers(stream_id=sid, headers=headers, end_stream=not body and not trailers)
        if body:
            for off in range(0, len(body), 65536):
                last = off + 65536 >= len(body)
                self._http.send_data(stream_id=sid, data=body[off:off + 65536], end_stream=last and not trailers)
                self.transmit()
                await asyncio.sleep(0)
        if trailers:
            self._http.send_headers(stream_id=sid, headers=trailers, end_stream=True)
        self.transmit()
        await asyncio.wait_for(response["done"], 120)
        data = response["body"]
        result = {
            "status": None,
            "headers": [],
            "trailers": response["trailers"],
            "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sent_sha256": hashlib.sha256(body).hexdigest(),
            "reset": response["reset"],
        }
        if response["headers"] is not None:
            result["headers"] = [h for h in response["headers"] if not h[0].startswith(":")]
            result["status"] = int(dict(response["headers"])[":status"])
        if len(data) <= 65536:
            try:
                result["text"] = data.decode()
            except UnicodeDecodeError:
                pass
        return result


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


async def main(args):
    with open(args.requests) as f:
        requests = json.load(f)
    configuration = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True, server_name=args.server_name,
                                      max_data=64 * 1024 * 1024, max_stream_data=16 * 1024 * 1024)
    configuration.load_verify_locations(cafile=args.ca)
    configuration.verify_mode = ssl.CERT_REQUIRED
    authority = "%s:%d" % (args.server_name, args.port)
    async with connect(args.host, args.port, configuration) as client:
        if args.concurrent:
            results = await asyncio.gather(*[client.request(authority, r) for r in requests])
        else:
            results = [await client.request(authority, r) for r in requests]
    print("RESULT " + json.dumps({"ok": True, "responses": list(results)}), flush=True)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic HTTP/3 client for MicroProxy's HTTP/3 proxy tests")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--requests", required=True)
    parser.add_argument("--concurrent", action="store_true")
    try:
        sys.exit(asyncio.run(main(parser.parse_args())))
    except Exception as e:  # report every failure the same way
        print("RESULT " + json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}), flush=True)
        sys.exit(1)
