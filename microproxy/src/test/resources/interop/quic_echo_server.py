"""An aioquic echo server for an ALPN of the test's choosing, the peer of MicroProxy's QUIC
stream hook tests.

Raw QUIC streams:

* a bidirectional stream is echoed back, and finished when the client finishes it;
* a unidirectional stream is answered, once it ends, on a new server-initiated unidirectional
  stream with b"uni-echo:" and its data;
* datagrams are echoed.

It prints "LISTENING <port>" once bound, then one line per event the tests check:
"CONNECTED <alpn>", "RESET <stream id> <error code>" and "TERMINATED <error code> <reason>". It
runs until stdin closes.
"""

import argparse
import asyncio
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


def emit(line):
    print(line, flush=True)


class EchoServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._uni = {}

    def quic_event_received(self, event):
        quic = self._quic
        if isinstance(event, HandshakeCompleted):
            emit("CONNECTED %s" % event.alpn_protocol)
        elif isinstance(event, StreamDataReceived):
            sid = event.stream_id
            if sid & 2:  # unidirectional
                data = self._uni.get(sid, b"") + event.data
                if event.end_stream:
                    self._uni.pop(sid, None)
                    reply = quic.get_next_available_stream_id(is_unidirectional=True)
                    quic.send_stream_data(reply, b"uni-echo:" + data, end_stream=True)
                else:
                    self._uni[sid] = data
            else:
                quic.send_stream_data(sid, event.data, end_stream=event.end_stream)
        elif isinstance(event, StreamReset):
            emit("RESET %d %d" % (event.stream_id, event.error_code))
            self._uni.pop(event.stream_id, None)
        elif isinstance(event, DatagramFrameReceived):
            quic.send_datagram_frame(event.data)
        elif isinstance(event, ConnectionTerminated):
            emit("TERMINATED %d %s" % (event.error_code, event.reason_phrase))


async def main(args):
    configuration = QuicConfiguration(
        alpn_protocols=[args.alpn],
        is_client=False,
        max_datagram_frame_size=65536,
        max_data=64 * 1024 * 1024,
        max_stream_data=16 * 1024 * 1024,
        idle_timeout=30.0,
    )
    configuration.load_cert_chain(args.certificate, args.private_key)
    server = await serve(args.host, args.port, configuration=configuration, create_protocol=EchoServerProtocol)
    port = server._transport.get_extra_info("sockname")[1]
    emit("LISTENING %d" % port)
    # Run until the test closes stdin
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, sys.stdin.read)
    server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aioquic echo server for MicroProxy's QUIC hook tests")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--alpn", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    asyncio.run(main(parser.parse_args()))
