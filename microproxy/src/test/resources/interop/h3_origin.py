"""An HTTP/3 origin server on aioquic's H3Connection, for MicroProxy's HTTP/3 upstream tests.

Resources:

* GET /hello: "hello from aioquic";
* /echo: the request as text (method, path, one "h:name: value" line per field, a blank line,
  then the body), with the request's trailers sent back as trailers;
* GET /bytes/<n>: n bytes (i mod 256);
* GET /trailers: a body and the trailer "x-checksum: 42".

Every response has "x-origin-protocol: h3" and "server: aioquic-origin". It prints
"LISTENING <port>" once bound, and "REQUEST <method> <path>" for each request; it runs until stdin
closes.
"""

import argparse
import asyncio
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


def emit(line):
    print(line, flush=True)


class OriginProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._requests = {}

    def quic_event_received(self, event):
        if self._http is None:
            self._http = H3Connection(self._quic)
        for h3_event in self._http.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                request = self._requests.get(h3_event.stream_id)
                if request is None:
                    self._requests[h3_event.stream_id] = request = {
                        "headers": h3_event.headers, "body": b"", "trailers": []}
                else:
                    request["trailers"] = h3_event.headers
                if h3_event.stream_ended:
                    self._respond(h3_event.stream_id)
            elif isinstance(h3_event, DataReceived):
                request = self._requests.get(h3_event.stream_id)
                if request is not None:
                    request["body"] += h3_event.data
                    if h3_event.stream_ended:
                        self._respond(h3_event.stream_id)

    def _respond(self, sid):
        request = self._requests.pop(sid)
        fields = dict(request["headers"])
        method = fields.get(b":method", b"").decode()
        path = fields.get(b":path", b"").decode()
        emit("REQUEST %s %s" % (method, path))
        trailers = []
        if path == "/hello":
            body = b"hello from aioquic"
        elif path.startswith("/echo"):
            lines = ["method: " + method, "uri: " + path]
            for name, value in sorted((k.decode(), v.decode()) for k, v in request["headers"]):
                if not name.startswith(":"):
                    lines.append("h:%s: %s" % (name, value))
            body = ("\n".join(lines) + "\n\n").encode() + request["body"]
            trailers = request["trailers"]
        elif path.startswith("/bytes/"):
            body = bytes(i % 256 for i in range(int(path[len("/bytes/"):])))
        elif path == "/trailers":
            body = b"with trailers"
            trailers = [(b"x-checksum", b"42")]
        else:
            body = b""
        headers = [(b":status", b"200" if body or path == "/echo" else b"404"),
                   (b"x-origin-protocol", b"h3"), (b"server", b"aioquic-origin")]
        if not trailers:
            headers.append((b"content-length", str(len(body)).encode()))
        self._http.send_headers(stream_id=sid, headers=headers, end_stream=False)
        self._http.send_data(stream_id=sid, data=body, end_stream=not trailers)
        if trailers:
            self._http.send_headers(stream_id=sid, headers=trailers, end_stream=True)
        self.transmit()


async def main(args):
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_data=64 * 1024 * 1024,
        max_stream_data=16 * 1024 * 1024,
        idle_timeout=30.0,
    )
    configuration.load_cert_chain(args.certificate, args.private_key)
    server = await serve(args.host, args.port, configuration=configuration, create_protocol=OriginProtocol)
    port = server._transport.get_extra_info("sockname")[1]
    emit("LISTENING %d" % port)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, sys.stdin.read)
    server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic HTTP/3 origin for MicroProxy's HTTP/3 upstream tests")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    asyncio.run(main(parser.parse_args()))
