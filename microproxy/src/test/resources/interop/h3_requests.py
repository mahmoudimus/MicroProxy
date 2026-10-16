"""An HTTP/3 client on aioquic's H3Connection, the peer of MicroProxy's HTTP/3 proxy tests.

It reads a JSON list of requests from the file named by --requests, sends them on one connection
(all at once with --concurrent, else one after another), and prints one "RESULT <json>" line with
each response: status, headers, body length and SHA-256, the body itself when it is text and
short, and trailers. A request is {"method", "path", "headers": [[name, value], ...], "body":
text, or "body_size" and "seed" for random bytes, "trailers": [[name, value], ...], "end_delay":
seconds to wait before ending the stream}; a body's
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
from aioquic.quic.events import ConnectionTerminated, StreamReset
from aioquic.quic.logger import QuicLogger

# A request fails once nothing has come from the server for this long, or after the longest wait.
QUIET_LIMIT = 30
LONGEST_WAIT = 120
# The client's last QUIC events shown when a request fails.
EVENTS_SHOWN = 80


class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._responses = {}
        self._last_received = self._loop.time()
        self._terminated = None

    def datagram_received(self, data, addr):
        self._last_received = self._loop.time()
        super().datagram_received(data, addr)

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self._terminated = "error %d (frame type %s): %s" % (event.error_code, event.frame_type, event.reason_phrase)
            return
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

    def stalled(self):
        """Where each unfinished response, its stream and the connection had got to, and the
        connection's last events, for a request that failed waiting."""
        quic = self._quic
        lines = ["%.1f s since the last datagram from the server" % (self._loop.time() - self._last_received),
                 "connection: sent %d of max_data %d, received %d of max_data %d" % (
                     quic._remote_max_data_used, quic._remote_max_data, quic._local_max_data.used,
                     quic._local_max_data.value)]
        for sid, response in sorted(self._responses.items()):
            if response["finished"]:
                continue
            state = "stream %d (%s): headers %s, %d body bytes" % (
                sid, response["path"], "received" if response["headers"] is not None else "not received",
                len(response["body"]))
            stream = quic._streams.get(sid)
            if stream is not None:
                state += "; sent to %d (fin %s, acked to %d) of max_stream_data %d; received to %d (fin %s)" % (
                    stream.sender.highest_offset, stream.sender._pending_eof or stream.sender.is_finished,
                    stream.sender._buffer_start, stream.max_stream_data_remote, stream.receiver.highest_offset,
                    stream.receiver.is_finished)
            lines.append(state)
        trace = quic._quic_logger
        if trace is not None:
            events = list(trace._events)
            start = events[0]["time"] if events else 0
            lines.append("last %d of the client's %d QUIC events (ms since the first):" % (
                min(len(events), EVENTS_SHOWN), len(events)))
            lines.extend(describe(e, start) for e in events[-EVENTS_SHOWN:])
        return "\n".join(lines)

    async def wait(self, done):
        """Waits for the future done; fails, saying where everything had got to, if the connection
        ends, nothing comes from the server for QUIET_LIMIT seconds, or LONGEST_WAIT passes."""
        started = self._loop.time()
        while not done.done():
            await asyncio.wait([done], timeout=1)
            if done.done():
                break
            if self._terminated is not None:
                raise ConnectionError("the connection closed: %s\n%s" % (self._terminated, self.stalled()))
            now = self._loop.time()
            if now - self._last_received > QUIET_LIMIT or now - started > LONGEST_WAIT:
                raise TimeoutError("\n" + self.stalled())

    async def request(self, authority, spec):
        sid = self._quic.get_next_available_stream_id()
        response = {"path": spec.get("path", "/"), "finished": False, "headers": None, "trailers": [], "body": b"",
                    "reset": None,
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
        end_delay = spec.get("end_delay", 0)
        self._http.send_headers(stream_id=sid, headers=headers, end_stream=not body and not trailers and not end_delay)
        if body:
            for off in range(0, len(body), 65536):
                last = off + 65536 >= len(body)
                self._http.send_data(stream_id=sid, data=body[off:off + 65536], end_stream=last and not trailers and not end_delay)
                self.transmit()
                await asyncio.sleep(0)
        if trailers:
            self._http.send_headers(stream_id=sid, headers=trailers, end_stream=True)
        if end_delay:
            # The stream's end alone, in a packet of its own, end_delay seconds after the rest
            self.transmit()
            await asyncio.sleep(end_delay)
            self._quic.send_stream_data(sid, b"", end_stream=True)
        self.transmit()
        await self.wait(response["done"])
        response["finished"] = True
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


def describe(event, start):
    """One line for a qlog event of aioquic's: its time since start, name, packet and frames."""
    data = event.get("data", {})
    parts = ["%9.1f %s" % (event.get("time", 0) - start, event.get("name", "?"))]
    header = data.get("header", {})
    if "packet_number" in header:
        parts.append("pn=%s" % header["packet_number"])
    for frame in data.get("frames", []):
        kind = frame.get("frame_type")
        if kind == "stream":
            parts.append("stream %s @%s+%s%s" % (frame["stream_id"], frame["offset"], frame["length"],
                                                 " fin" if frame.get("fin") else ""))
        elif kind == "ack":
            parts.append("ack %s" % frame["acked_ranges"])
        elif kind in ("padding", "ping"):
            parts.append(kind)
        else:
            parts.append(json.dumps(frame, sort_keys=True))
    for key in ("cwnd", "bytes_in_flight", "packet_numbers", "trigger", "state", "new"):
        if key in data:
            parts.append("%s=%s" % (key, data[key]))
    return " ".join(parts)


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
    except BaseException:
        # Left without a CONNECTION_CLOSE: the server keeps its side of a connection that failed
        # until its idle timeout, so the test can see where the server's side had got to.
        transport.close()
        raise
    protocol.close()
    await protocol.wait_closed()
    transport.close()


async def main(args):
    with open(args.requests) as f:
        requests = json.load(f)
    configuration = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True, server_name=args.server_name,
                                      max_data=64 * 1024 * 1024, max_stream_data=16 * 1024 * 1024)
    configuration.quic_logger = QuicLogger()
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
