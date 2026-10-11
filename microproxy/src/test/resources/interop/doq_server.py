"""An aioquic DNS over QUIC server (RFC 9250), the peer of MicroProxy's QUIC message framing
tests, answering from a zone of IPv4 addresses given on the command line.

Each stream the client opens carries one query, with a two-byte length prefix, and ends; the
server answers on the same stream (A records for the zone's names, NXDOMAIN for others) and
finishes it. A stream that ends with anything but one whole framed message is reset with
DOQ_PROTOCOL_ERROR (0x2).

It prints "LISTENING <port>" once bound, then "QUERY <name> <type>" for each query, "RESET
<stream id> <code>" for each stream the client resets, and "BAD <stream id>" for a malformed one.
It runs until stdin closes. DNS messages are built and read here by hand, with no DNS library.
"""

import argparse
import asyncio
import struct
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, StreamReset

DOQ_PROTOCOL_ERROR = 0x2
ZONE = {}


def emit(line):
    print(line, flush=True)


def read_name(message, offset):
    """Reads an uncompressed name (queries are not compressed), returning it and the offset after it."""
    labels = []
    while True:
        length = message[offset]
        offset += 1
        if length == 0:
            return ".".join(labels), offset
        if length & 0xC0:
            raise ValueError("a compressed name in a query")
        labels.append(message[offset : offset + length].decode("ascii"))
        offset += length


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def answer(query):
    query_id, flags, qdcount = struct.unpack("!HHH", query[:6])
    if qdcount != 1:
        raise ValueError("%d questions" % qdcount)
    name, end = read_name(query, 12)
    qtype, qclass = struct.unpack("!HH", query[end : end + 4])
    emit("QUERY %s %d" % (name, qtype))
    address = ZONE.get(name.lower())
    records = b""
    count = 0
    if address is not None and qtype == 1:
        # The owner name points back to the question's (offset 12).
        records = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + bytes(int(x) for x in address.split("."))
        count = 1
    rcode = 0 if address is not None else 3
    reply_flags = 0x8000 | (flags & 0x7900) | 0x0080 | rcode
    header = struct.pack("!HHHHHH", query_id, reply_flags, 1, count, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, qclass) + records


class DoqServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._streams = {}

    def quic_event_received(self, event):
        quic = self._quic
        if isinstance(event, StreamDataReceived):
            data = self._streams.get(event.stream_id, b"") + event.data
            if not event.end_stream:
                self._streams[event.stream_id] = data
                return
            self._streams.pop(event.stream_id, None)
            try:
                if len(data) < 2 or struct.unpack("!H", data[:2])[0] != len(data) - 2:
                    raise ValueError("not one framed message")
                reply = answer(data[2:])
            except (ValueError, IndexError, struct.error, UnicodeDecodeError):
                emit("BAD %d" % event.stream_id)
                quic.reset_stream(event.stream_id, DOQ_PROTOCOL_ERROR)
                return
            quic.send_stream_data(event.stream_id, struct.pack("!H", len(reply)) + reply, end_stream=True)
            self.transmit()
        elif isinstance(event, StreamReset):
            emit("RESET %d %d" % (event.stream_id, event.error_code))
            self._streams.pop(event.stream_id, None)


async def main(args):
    for entry in filter(None, args.zone.split(",")):
        name, address = entry.split("=")
        ZONE[name.lower()] = address
    configuration = QuicConfiguration(alpn_protocols=["doq"], is_client=False, idle_timeout=30.0)
    configuration.load_cert_chain(args.certificate, args.private_key)
    server = await serve(args.host, args.port, configuration=configuration, create_protocol=DoqServerProtocol)
    port = server._transport.get_extra_info("sockname")[1]
    emit("LISTENING %d" % port)
    # Run until the test closes stdin
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, sys.stdin.read)
    server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic DNS over QUIC server for MicroProxy's framing tests")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--zone", default="", help="name=IPv4 pairs, comma-separated")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    asyncio.run(main(parser.parse_args()))
