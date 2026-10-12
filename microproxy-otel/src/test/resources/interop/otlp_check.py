"""Checks MicroProxy's OTLP payloads with opentelemetry-proto's generated Python classes.

Each argument is SIGNAL:ENCODING:FILE, with SIGNAL traces, metrics or logs and ENCODING proto or
json. A proto file is parsed as the signal's Export*ServiceRequest; it must hold no field the
schema does not know, or knows with another wire type (a message rebuilt from what protobuf
understood must have the same size). A json file is OTLP/JSON: its hex trace and span ids are
turned into protobuf's base64 before protobuf's JSON parser reads it, strictly (an unknown field
name fails). When a signal has both encodings, they must decode to equal messages.

It prints one "RESULT <json>" line: per signal, the message as protobuf's JSON printer writes it
(ids base64, 64-bit numbers as strings), for the test to check values; it exits with status 0
when every check passed.
"""

import base64
import json
import sys

from google.protobuf import json_format
from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
from opentelemetry.proto.collector.metrics.v1 import metrics_service_pb2
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2

REQUESTS = {
    "traces": trace_service_pb2.ExportTraceServiceRequest,
    "metrics": metrics_service_pb2.ExportMetricsServiceRequest,
    "logs": logs_service_pb2.ExportLogsServiceRequest,
}

ID_FIELDS = {"traceId", "spanId", "parentSpanId"}


def hex_ids_to_base64(value):
    """OTLP/JSON's ids are hex; protobuf's JSON mapping wants base64 for bytes."""
    if isinstance(value, dict):
        out = {}
        for key, v in value.items():
            if key in ID_FIELDS and isinstance(v, str):
                out[key] = base64.b64encode(bytes.fromhex(v)).decode("ascii")
            else:
                out[key] = hex_ids_to_base64(v)
        return out
    if isinstance(value, list):
        return [hex_ids_to_base64(v) for v in value]
    return value


def main():
    parsed = {}
    for arg in sys.argv[1:]:
        signal, encoding, path = arg.split(":", 2)
        cls = REQUESTS[signal]
        with open(path, "rb") as f:
            data = f.read()
        if encoding == "proto":
            message = cls.FromString(data)
            rebuilt = cls()
            json_format.ParseDict(json_format.MessageToDict(message), rebuilt)
            if rebuilt.ByteSize() != len(data):
                raise SystemExit("%s: %d bytes, of which protobuf understands %d: unknown fields or wire types"
                                 % (path, len(data), rebuilt.ByteSize()))
        else:
            message = cls()
            json_format.ParseDict(hex_ids_to_base64(json.loads(data)), message, ignore_unknown_fields=False)
        if message.ByteSize() == 0:
            raise SystemExit("%s: an empty message" % path)
        other = parsed.get(signal)
        if other is not None and other != message:
            raise SystemExit("%s: the protobuf and JSON encodings differ:\n%s\n---\n%s" % (signal, other, message))
        parsed[signal] = message
    result = {signal: json_format.MessageToDict(m) for signal, m in parsed.items()}
    print("RESULT " + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
