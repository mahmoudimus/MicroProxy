"""An aioquic client that resumes a session with 0-RTT, a peer of MicroProxy's QUIC interop tests.

It connects with the ALPN "microproxy-test", sends b"hello" on a bidirectional stream, keeps the
session tickets the server sends, and closes. It then connects again with the newest ticket and,
in the same event-loop turn as the connection attempt, before any reply can arrive, sends b"GET /"
on a stream, which aioquic puts in 0-RTT packets when the ticket allows early data. It prints one
"RESULT <json>" line with both replies, whether the second session was resumed and whether the
server accepted the early data.
"""

import argparse
import asyncio
import json
import socket
import ssl
import sys

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived

ALPN = "microproxy-test"


class Protocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.replies = {}
        self.done = {}
        self.handshake = asyncio.get_running_loop().create_future()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted) and not self.handshake.done():
            self.handshake.set_result((event.session_resumed, event.early_data_accepted))
        elif isinstance(event, StreamDataReceived):
            self.replies[event.stream_id] = self.replies.get(event.stream_id, b"") + event.data
            if event.end_stream:
                future = self.done.get(event.stream_id)
                if future is not None and not future.done():
                    future.set_result(self.replies[event.stream_id])
        super().quic_event_received(event)

    def send(self, data):
        """Sends data with a FIN on a new stream, now; returns a future of the reply."""
        sid = self._quic.get_next_available_stream_id()
        self.done[sid] = asyncio.get_running_loop().create_future()
        self._quic.send_stream_data(sid, data, end_stream=True)
        self.transmit()
        return self.done[sid]


async def session(args, ticket, tickets, request):
    configuration = QuicConfiguration(alpn_protocols=[ALPN], is_client=True, server_name="localhost",
                                      idle_timeout=30.0)
    configuration.load_verify_locations(cafile=args.ca)
    configuration.verify_mode = ssl.CERT_REQUIRED
    configuration.session_ticket = ticket
    loop = asyncio.get_running_loop()
    connection = QuicConnection(configuration=configuration, session_ticket_handler=tickets.append)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(lambda: Protocol(connection), sock=sock)
    try:
        protocol.connect((args.host, args.port))
        reply = protocol.send(request)  # in the same turn: 0-RTT data if the ticket allows it
        resumed, early = await asyncio.wait_for(protocol.handshake, 10)
        data = await asyncio.wait_for(reply, 10)
        # Wait a moment for the session tickets, which follow the handshake
        for _ in range(50):
            if tickets:
                break
            await asyncio.sleep(0.02)
        return data, resumed, early
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()


async def main(args):
    tickets = []
    first, first_resumed, _ = await session(args, None, tickets, b"hello")
    if not tickets:
        raise AssertionError("no session ticket")
    ticket = tickets[-1]
    second, resumed, early = await session(args, ticket, [], b"GET /")
    result = {
        "ok": True,
        "first": first.decode(),
        "first_resumed": first_resumed,
        "second": second.decode(),
        "resumed": resumed,
        "early_data_accepted": early,
        "ticket_allows_early_data": ticket.max_early_data_size is not None,
    }
    print("RESULT " + json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic 0-RTT resumption client for interop tests")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--ca", required=True)
    try:
        sys.exit(asyncio.run(main(parser.parse_args())))
    except Exception as e:  # report every failure the same way
        print("RESULT " + json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}), flush=True)
        sys.exit(1)
