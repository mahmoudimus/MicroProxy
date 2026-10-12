"""A gRPC server on grpcio, for MicroProxy's gRPC interop tests.

The service interop.Interop, with generic handlers on raw bytes, so no generated code:

* Echo (unary): the request back; the initial metadata carries the request's "via" and
  "x-client-bin" back, the trailing metadata "x-length";
* Split (server streaming): the request is "count,size"; count messages of size bytes, the i-th
  filled with i mod 256;
* Collect (client streaming): "<messages> <bytes> <sha256>" of everything received;
* Chat (bidirectional): each message back, uppercased, as soon as it arrives;
* Fail (unary): INVALID_ARGUMENT with a message, a google.rpc.Status in grpc-status-details-bin
  (hand-encoded, carrying a google.rpc.ErrorInfo), and "x-failure: yes";
* Wait (unary): blocks until the call ends, as its deadline does;
* Hold (server streaming): sends "started", then blocks until the call ends, as the client's
  cancellation does.

Stdout gets "LISTENING <port>" once bound, then one line per event: "CALL <method> ...",
"WAIT remaining=<seconds|none>", "WAIT_ENDED active=<bool>", "HOLD remaining=<seconds|none>" and
"HOLD_ENDED active=<bool>". It runs until stdin closes.
"""

import argparse
import hashlib
import sys
import threading
from concurrent import futures

import grpc

MAX_MESSAGE = 64 * 1024 * 1024
ENDED_WAIT = 60

_out = threading.Lock()


def emit(line):
    with _out:
        print(line, flush=True)


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def field(number, value):
    """A protobuf field: an int as a varint, bytes or str length-delimited."""
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode()
    return varint(number << 3 | 2) + varint(len(value)) + value


def status_details(code, message):
    """google.rpc.Status{code, message, details: [Any(google.rpc.ErrorInfo)]}."""
    error_info = field(1, "BAD_INPUT") + field(2, "interop.test")
    any_ = field(1, "type.googleapis.com/google.rpc.ErrorInfo") + field(2, error_info)
    return field(1, code) + field(2, message) + field(3, any_)


class _Status(grpc.Status):
    def __init__(self, code, details, trailing_metadata):
        self.code = code
        self.details = details
        self.trailing_metadata = trailing_metadata


def remaining(context):
    """The seconds left before the call's deadline, or "none" (grpcio says None or "forever")."""
    r = context.time_remaining()
    return "none" if r is None or r > 1e9 else "%.3f" % r


def await_end(context):
    """Blocks until the call ends (deadline or cancellation), at most ENDED_WAIT seconds."""
    ended = threading.Event()
    if not context.add_callback(ended.set):
        ended.set()
    ended.wait(ENDED_WAIT)
    return context.is_active()


def echo(request, context):
    metadata = dict(context.invocation_metadata())
    initial = [("x-echo-via", metadata.get("via", "none"))]
    if "x-client-bin" in metadata:
        initial.append(("x-client-bin", metadata["x-client-bin"]))
    context.send_initial_metadata(initial)
    context.set_trailing_metadata([("x-length", str(len(request)))])
    emit("CALL Echo %d" % len(request))
    return request


def split(request, context):
    count, size = (int(x) for x in request.decode().split(","))
    emit("CALL Split %d %d" % (count, size))
    for i in range(count):
        yield bytes([i % 256]) * size


def collect(request_iterator, context):
    n, total, digest = 0, 0, hashlib.sha256()
    for m in request_iterator:
        n += 1
        total += len(m)
        digest.update(m)
    emit("CALL Collect %d %d" % (n, total))
    return ("%d %d %s" % (n, total, digest.hexdigest())).encode()


def chat(request_iterator, context):
    n = 0
    for m in request_iterator:
        n += 1
        yield m.upper()
    emit("CALL Chat %d" % n)


def fail(request, context):
    message = "invalid: " + request.decode()
    code = grpc.StatusCode.INVALID_ARGUMENT
    emit("CALL Fail")
    context.abort_with_status(_Status(code, message, (
        ("grpc-status-details-bin", status_details(code.value[0], message)),
        ("x-failure", "yes"))))


def wait(request, context):
    emit("WAIT remaining=" + remaining(context))
    emit("WAIT_ENDED active=%s" % await_end(context))
    return b""


def hold(request, context):
    emit("HOLD remaining=" + remaining(context))
    yield b"started"
    emit("HOLD_ENDED active=%s" % await_end(context))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    args = parser.parse_args()

    handlers = {
        "Echo": grpc.unary_unary_rpc_method_handler(echo),
        "Split": grpc.unary_stream_rpc_method_handler(split),
        "Collect": grpc.stream_unary_rpc_method_handler(collect),
        "Chat": grpc.stream_stream_rpc_method_handler(chat),
        "Fail": grpc.unary_unary_rpc_method_handler(fail),
        "Wait": grpc.unary_unary_rpc_method_handler(wait),
        "Hold": grpc.unary_stream_rpc_method_handler(hold),
    }
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16), options=[
        ("grpc.max_send_message_length", MAX_MESSAGE),
        ("grpc.max_receive_message_length", MAX_MESSAGE)])
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler("interop.Interop", handlers),))
    with open(args.private_key, "rb") as k, open(args.certificate, "rb") as c:
        credentials = grpc.ssl_server_credentials([(k.read(), c.read())])
    port = server.add_secure_port("127.0.0.1:0", credentials)
    server.start()
    emit("LISTENING %d" % port)
    sys.stdin.read()
    server.stop(grace=None)


if __name__ == "__main__":
    main()
