"""A gRPC client on grpcio, for MicroProxy's gRPC interop tests.

Calls grpc_server.py's interop.Interop at --target over TLS, trusting --ca, through the forward
proxy at --proxy (grpcio's "grpc.http_proxy": a CONNECT to the target, then TLS and HTTP/2 inside
the tunnel). The cases run in order on one channel:

* unary: Echo with text and binary metadata;
* server_streaming: Split into five messages;
* client_streaming: Collect of three messages;
* bidi: Chat, each message sent only once the previous answer has arrived;
* error: Fail, its status, message and trailing metadata;
* deadline: Wait with a deadline of DEADLINE seconds;
* cancel: Hold, cancelled once its first message has arrived;
* large: Echo of 8 MiB, Split into 4 messages of 2 MiB, Collect of 6 MiB and 1 MiB.

It prints one line, "RESULT <json>": {"ok": true, "results": {case: what it saw}}, or {"ok":
false, "error": ...}.
"""

import argparse
import base64
import hashlib
import json
import os
import queue
import sys
import time
import traceback

import grpc

MAX_MESSAGE = 64 * 1024 * 1024
TIMEOUT = 60
DEADLINE = 2.0
MIB = 1024 * 1024

identity = None  # raw bytes both ways: no (de)serializers


def method(channel, kind, name):
    return getattr(channel, kind)("/interop.Interop/" + name, request_serializer=identity,
                                  response_deserializer=identity)


def metadata_dict(metadata):
    out = {}
    for key, value in metadata or ():
        out[key] = base64.b64encode(value).decode() if key.endswith("-bin") else value
    return out


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def unary(channel):
    call = method(channel, "unary_unary", "Echo")
    response, info = call.with_call(b"hello grpc", timeout=TIMEOUT, metadata=(
        ("x-client", "interop"), ("x-client-bin", b"\x00\x01\xfe\xff")))
    return {"response": response.decode(), "code": info.code().name,
            "initial": metadata_dict(info.initial_metadata()),
            "trailing": metadata_dict(info.trailing_metadata())}


def server_streaming(channel):
    call = method(channel, "unary_stream", "Split")(b"5,1000", timeout=TIMEOUT)
    messages = list(call)
    return {"count": len(messages), "sizes": [len(m) for m in messages],
            "fills": [m[0] for m in messages], "code": call.code().name}


def client_streaming(channel):
    parts = [b"alpha", b"beta", b"gamma" * 1000]
    response, info = method(channel, "stream_unary", "Collect").with_call(iter(parts), timeout=TIMEOUT)
    return {"response": response.decode(), "expected": "%d %d %s" % (
        len(parts), sum(len(p) for p in parts), sha256(b"".join(parts))), "code": info.code().name}


def bidi(channel):
    outgoing = queue.Queue()

    def requests():
        while True:
            m = outgoing.get()
            if m is None:
                return
            yield m

    call = method(channel, "stream_stream", "Chat")(requests(), timeout=TIMEOUT)
    answers = []
    for word in (b"one", b"two", b"three"):
        outgoing.put(word)
        # The request stream stays open while this answer comes back.
        answers.append(next(call).decode())
    outgoing.put(None)
    rest = list(call)
    return {"answers": answers, "rest": len(rest), "code": call.code().name}


def error(channel):
    try:
        method(channel, "unary_unary", "Fail")(b"bad-input", timeout=TIMEOUT)
        return {"code": "OK"}
    except grpc.RpcError as e:
        return {"code": e.code().name, "details": e.details(), "trailing": metadata_dict(e.trailing_metadata())}


def deadline(channel):
    start = time.monotonic()
    try:
        method(channel, "unary_unary", "Wait")(b"", timeout=DEADLINE)
        code = "OK"
    except grpc.RpcError as e:
        code = e.code().name
    return {"code": code, "deadline": DEADLINE, "elapsed": time.monotonic() - start}


def cancel(channel):
    call = method(channel, "unary_stream", "Hold")(b"", timeout=None)
    first = next(call).decode()
    call.cancel()
    try:
        rest = list(call)
        code = "OK after %d" % len(rest)
    except grpc.RpcError as e:
        code = e.code().name
    return {"first": first, "code": code}


def large(channel):
    big = os.urandom(8 * MIB)
    response, info = method(channel, "unary_unary", "Echo").with_call(big, timeout=TIMEOUT)
    stream = method(channel, "unary_stream", "Split")(b"4,%d" % (2 * MIB), timeout=TIMEOUT)
    pieces = list(stream)
    parts = [os.urandom(6 * MIB), os.urandom(MIB)]
    collected, _ = method(channel, "stream_unary", "Collect").with_call(iter(parts), timeout=TIMEOUT)
    return {"echo_length": len(response), "echo_intact": response == big, "echo_code": info.code().name,
            "split_sizes": [len(p) for p in pieces],
            "split_intact": all(p == bytes([i]) * (2 * MIB) for i, p in enumerate(pieces)),
            "collected": collected.decode(),
            "collect_expected": "%d %d %s" % (len(parts), sum(len(p) for p in parts), sha256(b"".join(parts)))}


CASES = {"unary": unary, "server_streaming": server_streaming, "client_streaming": client_streaming,
         "bidi": bidi, "error": error, "deadline": deadline, "cancel": cancel, "large": large}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", required=True, help="host:port of the forward proxy")
    parser.add_argument("--target", required=True, help="host:port of the server, as the proxy is asked for it")
    parser.add_argument("--ca", required=True, help="PEM certificates to trust: the proxy's MITM CA")
    parser.add_argument("--cases", default=",".join(CASES))
    args = parser.parse_args()
    try:
        with open(args.ca, "rb") as f:
            credentials = grpc.ssl_channel_credentials(root_certificates=f.read())
        options = [("grpc.http_proxy", "http://" + args.proxy),
                   ("grpc.max_send_message_length", MAX_MESSAGE),
                   ("grpc.max_receive_message_length", MAX_MESSAGE)]
        results = {}
        with grpc.secure_channel(args.target, credentials, options=options) as channel:
            grpc.channel_ready_future(channel).result(timeout=TIMEOUT)
            for name in args.cases.split(","):
                results[name] = CASES[name](channel)
        print("RESULT " + json.dumps({"ok": True, "results": results}), flush=True)
    except Exception as e:  # reported to the test, with the trace on stderr
        traceback.print_exc()
        print("RESULT " + json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
