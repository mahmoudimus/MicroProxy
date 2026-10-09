#!/usr/bin/env bash
# Runs h2spec (HTTP/2 conformance tests) against the proxy's h2c listener.
#
# Needs the microproxy and http2-codec classes built first, test classes included:
#   mvn -B -q -DskipTests test-compile -pl microproxy -am
#
# The target is org.microproxy.H2specTarget (microproxy test sources): the proxy with h2c on the
# plain listener and a filter that answers every request with 200. Set H2SPEC to use an h2spec
# binary already present; H2SPEC_PORT to choose the port; extra arguments go to h2spec (such as
# section numbers to run only those, or --strict).
set -euo pipefail

VERSION=2.6.0
SHA256=157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318
PORT=${H2SPEC_PORT:-18080}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'kill "${TARGET_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

if [[ -z "${H2SPEC:-}" ]]; then
  curl -sSfL -o "$WORK/h2spec.tar.gz" \
    "https://github.com/summerwind/h2spec/releases/download/v${VERSION}/h2spec_linux_amd64.tar.gz"
  echo "${SHA256}  $WORK/h2spec.tar.gz" | sha256sum -c -
  mkdir "$WORK/bin"
  tar -xzf "$WORK/h2spec.tar.gz" -C "$WORK/bin" h2spec
  H2SPEC="$WORK/bin/h2spec"
fi

CLASSPATH="$ROOT/microproxy/target/classes:$ROOT/microproxy/target/test-classes:$ROOT/http2-codec/target/classes"
java -cp "$CLASSPATH" org.microproxy.H2specTarget "$PORT" > "$WORK/target.log" 2>&1 &
TARGET_PID=$!
for _ in $(seq 1 100); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then break; fi
  if ! kill -0 "$TARGET_PID" 2>/dev/null; then cat "$WORK/target.log"; exit 1; fi
  sleep 0.1
done

"$H2SPEC" -h 127.0.0.1 -p "$PORT" -o 5 -j "${H2SPEC_REPORT:-$ROOT/h2spec-report.xml}" "$@"
