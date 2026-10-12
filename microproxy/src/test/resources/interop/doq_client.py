"""An aioquic DNS over QUIC client (RFC 9250), the peer of MicroProxy's QUIC message framing tests.

It connects to HOST:PORT with the ALPN doq, asking for --server-name and trusting --ca, and asks
for the A records of each name of --names, each on a stream of its own (message ID 0, a two-byte
length prefix, then the stream's end), all at once. With --split, each query is written in pieces,
its length prefix cut in two, so that the proxy reads it in parts.

It prints one "RESULT <json>" line: for each name, its RCODE and the addresses of its answer.
DNS messages are built and read here by hand, with no DNS library.
"""

import argparse
import asyncio
import json
import ssl
import struct

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def skip_name(message, offset):
    while True:
        length = message[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def parse_answer(message):
    _, flags, qdcount, ancount = struct.unpack("!HHHH", message[:8])
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(message, offset) + 4
    addresses = []
    for _ in range(ancount):
        offset = skip_name(message, offset)
        rtype, _, _, rdlength = struct.unpack("!HHIH", message[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:
            addresses.append(".".join(str(b) for b in message[offset : offset + 4]))
        offset += rdlength
    return {"rcode": flags & 0xF, "addresses": addresses}


async def ask(client, name, split):
    query = struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", 1, 1)
    framed = struct.pack("!H", len(query)) + query
    reader, writer = await client.create_stream()
    if split:
        for piece in (framed[:1], framed[1:5], framed[5:]):
            writer.write(piece)
            await asyncio.sleep(0.05)
    else:
        writer.write(framed)
    writer.write_eof()
    data = await reader.read()
    length = struct.unpack("!H", data[:2])[0]
    if length != len(data) - 2:
        raise ValueError("an answer of %d bytes framed as %d" % (len(data) - 2, length))
    return parse_answer(data[2:])


async def main(args):
    config = QuicConfiguration(alpn_protocols=["doq"], is_client=True, server_name=args.server_name)
    config.verify_mode = ssl.CERT_REQUIRED
    config.load_verify_locations(cafile=args.ca)
    try:
        # An IPv4 socket of its own: aioquic's connect() binds a dual-stack IPv6 one.
        loop = asyncio.get_running_loop()
        quic = QuicConnection(configuration=config)
        transport, client = await loop.create_datagram_endpoint(
            lambda: QuicConnectionProtocol(quic), local_addr=("127.0.0.1", 0))
        try:
            client.connect((args.host, args.port))
            await asyncio.wait_for(client.wait_connected(), 10)
            names = args.names.split(",")
            answers = await asyncio.wait_for(asyncio.gather(*(ask(client, n, args.split) for n in names)), 30)
            results = {"alpn": quic.tls.alpn_negotiated, "answers": dict(zip(names, answers))}
            client.close()
            await client.wait_closed()
        finally:
            transport.close()
        print("RESULT " + json.dumps({"ok": True, "results": results}), flush=True)
    except Exception as e:  # report every failure as a result
        print("RESULT " + json.dumps({"ok": False, "error": repr(e)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic DNS over QUIC client for MicroProxy's framing tests")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--names", required=True, help="comma-separated names to ask for")
    parser.add_argument("--split", action="store_true", help="write each query in pieces")
    asyncio.run(main(parser.parse_args()))
