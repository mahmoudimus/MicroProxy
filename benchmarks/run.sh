#!/usr/bin/env bash
# Runs the MicroProxy vs LittleProxy JMH benchmarks and prints the Markdown comparison.
#
#   benchmarks/run.sh [smoke|quick|full] [JMH options and benchmark regexps...]
#
# Presets (JMH options given after the preset override its own):
#   smoke  every benchmark once, small parameters: a correctness check, not a measurement (CI)
#   quick  1 fork, 3 short warm-up and measured iterations, every parameter
#   full   the annotations' settings: 2 forks, 5 x 2 s warm-up, 5 x 3 s measured (the default)
#
# Examples:
#   benchmarks/run.sh quick SmallGet Concurrency
#   benchmarks/run.sh full -prof gc
#   benchmarks/run.sh full -p connections=4096 Concurrency
#
# Writes benchmarks/target/results/<preset>-<time>.json (JMH's JSON) and .md (compare.py's table).
# Builds benchmarks/target/benchmarks.jar first when it is missing, or always with BUILD=1.
# JAVA selects the java binary; RESULTS_DIR the output directory.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
jar="$here/target/benchmarks.jar"
java="${JAVA:-java}"

preset="full"
if [[ $# -gt 0 && "$1" =~ ^(smoke|quick|full)$ ]]; then
    preset="$1"
    shift
fi

case "$preset" in
    smoke) preset_args=(-f 1 -wi 0 -i 1 -r 1s -p connections=16 -p bodyBytes=1048576 -p responseBytes=1024) ;;
    quick) preset_args=(-f 1 -wi 3 -w 2s -i 3 -r 2s) ;;
    full)  preset_args=() ;;
esac

if [[ "${BUILD:-0}" == "1" || ! -f "$jar" ]]; then
    (cd "$root" && mvn --batch-mode -q -Pbench -DskipTests package -pl benchmarks -am)
fi

# With 4096 connections the concurrency benchmark holds 16,384 sockets in one JVM (the client's,
# both sides of the proxy, the origin's): raise the soft limit on open files as far as allowed.
if [[ "$(ulimit -n)" != "unlimited" && "$(ulimit -n)" -lt 32768 ]]; then
    ulimit -n 32768 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
    if [[ "$(ulimit -n)" != "unlimited" && "$(ulimit -n)" -lt 17000 ]]; then
        echo "warning: only $(ulimit -n) open files allowed; ConcurrencyBenchmark with 4096 connections may fail" >&2
    fi
fi

results="${RESULTS_DIR:-$here/target/results}"
mkdir -p "$results"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
json="$results/$preset-$stamp.json"
md="$results/$preset-$stamp.md"

# -foe: a benchmark that fails (a response that does not check out) fails the run.
"$java" -jar "$jar" -foe true "${preset_args[@]}" "$@" -rf json -rff "$json"

python3 "$here/compare.py" "$json" --output "$md"
echo
echo "JMH results: $json"
echo "Comparison:  $md"
