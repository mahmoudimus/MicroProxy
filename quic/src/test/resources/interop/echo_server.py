"""An aioquic echo server, the peer of MicroProxy's QUIC interoperability tests.

Raw QUIC streams with the ALPN "microproxy-test":

* a bidirectional stream is echoed back, and finished when the client finishes it; one whose
  data is exactly b"close-me" makes the server close the connection with code 42, reason "bye";
  one whose data is exactly b"key-update" makes the server start a key update and reply b"ok";
* a unidirectional stream is hashed with SHA-256 and the digest is sent back on a new
  server-initiated unidirectional stream;
* datagrams are echoed.

It prints "LISTENING <port>" once bound, then one line per event the tests check:
"CONNECTED <cipher suite>", "RESUMED <session resumed> <early data accepted>" and
"TERMINATED <error code> <reason>". With --tickets it issues session tickets, keeps them in
memory and accepts 0-RTT data with them. It runs until stdin closes.
"""

import argparse
import asyncio
import hashlib
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    DatagramFrameReceived,
    HandshakeCompleted,
    StreamDataReceived,
    StreamReset,
)
from aioquic.tls import CipherSuite

ALPN = "microproxy-test"


def emit(line):
    print(line, flush=True)


class EchoServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._buffers = {}
        self._hashes = {}

    def quic_event_received(self, event):
        quic = self._quic
        if isinstance(event, HandshakeCompleted):
            suite = quic.tls.key_schedule.cipher_suite
            emit("CONNECTED %s" % CipherSuite(suite).name)
            emit("RESUMED %s %s" % (event.session_resumed, event.early_data_accepted))
        elif isinstance(event, StreamDataReceived):
            sid = event.stream_id
            if sid & 2:  # unidirectional
                h = self._hashes.setdefault(sid, hashlib.sha256())
                h.update(event.data)
                if event.end_stream:
                    reply = quic.get_next_available_stream_id(is_unidirectional=True)
                    quic.send_stream_data(reply, h.digest(), end_stream=True)
                    del self._hashes[sid]
            else:
                # The first 16 bytes of a stream are held back: a short stream may be a command
                state = self._buffers.get(sid, b"")
                if state is True:
                    quic.send_stream_data(sid, event.data, end_stream=event.end_stream)
                    if event.end_stream:
                        del self._buffers[sid]
                    return
                buffered = state + event.data
                if len(buffered) > 16:
                    quic.send_stream_data(sid, buffered, end_stream=event.end_stream)
                    if event.end_stream:
                        self._buffers.pop(sid, None)
                    else:
                        self._buffers[sid] = True
                elif event.end_stream:
                    self._buffers.pop(sid, None)
                    if buffered == b"close-me":
                        quic.close(error_code=42, reason_phrase="bye")
                    elif buffered == b"key-update":
                        quic.request_key_update()
                        quic.send_stream_data(sid, b"ok", end_stream=True)
                    else:
                        quic.send_stream_data(sid, buffered, end_stream=True)
                else:
                    self._buffers[sid] = buffered
        elif isinstance(event, StreamReset):
            self._buffers.pop(event.stream_id, None)
            self._hashes.pop(event.stream_id, None)
        elif isinstance(event, DatagramFrameReceived):
            quic.send_datagram_frame(event.data)
        elif isinstance(event, ConnectionTerminated):
            emit("TERMINATED %d %s" % (event.error_code, event.reason_phrase))


async def main(args):
    configuration = QuicConfiguration(
        alpn_protocols=[ALPN],
        is_client=False,
        max_datagram_frame_size=65536,
        max_data=64 * 1024 * 1024,
        max_stream_data=16 * 1024 * 1024,
        idle_timeout=30.0,
    )
    if args.cipher_suite:
        configuration.cipher_suites = [CipherSuite[name] for name in args.cipher_suite]
    configuration.load_cert_chain(args.certificate, args.private_key)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    tickets = {}
    server = await serve(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=EchoServerProtocol,
        retry=args.retry,
        session_ticket_fetcher=(lambda key: tickets.pop(key, None)) if args.tickets else None,
        session_ticket_handler=(lambda t: tickets.__setitem__(t.ticket, t)) if args.tickets else None,
    )
    port = server._transport.get_extra_info("sockname")[1]
    emit("LISTENING %d" % port)
    # Run until the test closes stdin
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, sys.stdin.read)
    server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic echo server for interop tests")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--cipher-suite", action="append", help="e.g. AES_128_GCM_SHA256")
    parser.add_argument("--retry", action="store_true")
    parser.add_argument("--tickets", action="store_true", help="issue session tickets and accept 0-RTT")
    parser.add_argument("--secrets-log")
    asyncio.run(main(parser.parse_args()))
