#!/usr/bin/env bash
# Explicitly opt in: local synthetic observations, with no statistical pass/fail threshold.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ ${1:-} != --run ]]; then
    echo "Usage: $0 --run [output-directory] [samples-per-class] [kem-samples-per-class] [seed]" >&2
    exit 2
fi
output=${2:-/tmp/microproxy-local-timing}
samples=${3:-20000}
kem_samples=${4:-2000}
seed=${5:-20261028}
mkdir -p "$output"
output=$(cd "$output" && pwd)
if ! mvn -B -pl microproxy -am -DskipTests test-compile > "$output/build.log" 2>&1; then
    cat "$output/build.log" >&2
    exit 1
fi
java_cmd=java
if [[ -n ${JAVA_HOME:-} ]]; then java_cmd="$JAVA_HOME/bin/java"; fi
classpath=quic/target/test-classes:quic/target/classes:microproxy/target/classes:http2-codec/target/classes:http3-codec/target/classes:zstd-decoder/target/classes
"$java_cmd" -Xms512m -Xmx512m -cp "$classpath" \
    io.github.mahmoudimus.quic.tls.LocalTimingAssessment "$samples" "$kem_samples" "$seed" "$output/samples.csv" \
    | tee "$output/summary.txt"
