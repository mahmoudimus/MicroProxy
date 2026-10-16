#!/usr/bin/env bash
# Runs the cross-proxy comparison published on docs/project/performance.md: the load-testing
# harness against MicroProxy, LittleProxy and the external proxies of proxies.json, REPS times, each
# repetition a separate harness run with the proxies in a rotated order, then aggregates the runs
# into docs/assets/perf/ (the page's data, charts and tables). While it runs, hostmon.py logs what
# else uses the machine; aggregate.py publishes only runs that pass that contamination guard.
#
#   loadtest/competitors/setup.sh            # once: the external proxies, into .tools/
#   loadtest/competitors/run-all.sh          # about five hours on a 4-vCPU machine (five repetitions)
#
# Environment overrides: REPS (5), PROXIES, SCENARIOS, OUT (loadtest/results/perf-<UTC time>),
# CPUS_PROXY (0), CPUS_ORIGIN (1), CPUS_CLIENT (2-3), NICE (-20; empty for none), PUBLISH (1: write
# docs/assets/perf/; 0: aggregate into $OUT only). Extra arguments go to every harness run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

REPS=${REPS:-5}
PROXIES=${PROXIES:-microproxy,littleproxy,envoy,goproxy,g3proxy,squid}
SCENARIOS=${SCENARIOS:-sweep,ramp,memory,faults,soak}
OUT=${OUT:-loadtest/results/perf-$(date -u +%Y%m%d-%H%M%S)}
CPUS_PROXY=${CPUS_PROXY:-0}
CPUS_ORIGIN=${CPUS_ORIGIN:-1}
CPUS_CLIENT=${CPUS_CLIENT:-2-3}
NICE=${NICE--20}
PUBLISH=${PUBLISH:-1}

[ "$(nproc)" -ge 4 ] || { echo "needs at least 4 CPUs (proxy, origin, two for the load generator)" >&2; exit 1; }
JAR=loadtest/target/microproxy-loadtest.jar
if [ ! -f "$JAR" ]; then
    mvn --batch-mode -q -Pbench -DskipTests package -pl loadtest -am
fi
for bin in envoy goproxy-proxy g3proxy; do
    case ",$PROXIES," in *",${bin%-proxy},"*) [ -x "$HERE/.tools/bin/$bin" ] || { echo "missing $bin: run $HERE/setup.sh" >&2; exit 1; } ;; esac
done

# The settings of every run (the preset is "standard"; these override it). See the page's
# Methodology section for why each is what it is.
SETTINGS=(
    --preset standard --gate none --external off
    --external-proxies "$HERE/proxies.json"
    --cpus-proxy "$CPUS_PROXY" --cpus-origin "$CPUS_ORIGIN" --cpus-client "$CPUS_CLIENT"
    # Rate sweep: 128 keep-alive connections, 128-byte responses, x1.25 steps of 8 s from 2,000 req/s
    # after a 15 s warm-up (JIT compilation for the JVMs). The knee is the first of two unsustainable
    # steps in a row (p99 over 50 ms, errors, or under 95% of the offered rate), so that one noisy
    # step on a shared machine does not end a sweep; the sweep stops one step past it.
    --sweep-start-rate 2000 --sweep-factor 1.25 --sweep-step-seconds 8 --sweep-warmup-seconds 15
    --sweep-max-steps 24 --sweep-connections 128 --sweep-knee-confirm 2 --sweep-steps-after-knee 1
    --slo-p99-ms 50
    # Knee refinement: the x1.25 steps only bracket the maximum to within 25%, so up to 4 more 8 s
    # steps bisect between the last sustained step and the knee (to within 2%: 1.25^(1/16) is 1.4%),
    # each after 2 s at the bracket's lower rate; an unsustained probe is repeated once, like the knee.
    --sweep-refine-steps 4 --sweep-refine-precision 0.02 --sweep-refine-settle-seconds 2
    # Connection ramp: the container's open-file limit (20,000 per process) bounds the largest step.
    --ramp-steps 1000,2000,4000,6000,8000
    # Memory under adversarial clients: every proxy in a 512 MB memory cgroup (the JVMs also keep the
    # standard preset's 256 MB heap and 128 MB direct-memory caps inside it). Rapid reset needs h2c,
    # which only MicroProxy is set up for, so it is left out of the comparison.
    --attacks slowloris,slowread,updown --attack-seconds 40 --attack-cgroup-limit 512m
    # Soak: 100 s at 2,000 req/s; memory sampled every 10 s after a 30 s warm-up.
    --soak-seconds 100 --soak-rate 2000 --soak-sample-seconds 10
)
[ -n "$NICE" ] && SETTINGS+=(--nice "$NICE")

IFS=, read -r -a list <<< "$PROXIES"
mkdir -p "$OUT"
# What was run, from which commit; aggregate.py copies it into the page's data.
dirty=$(git status --porcelain -- loadtest | grep -c . || true)
cat > "$OUT/run-info.json" <<JSON
{
 "commit": "$(git rev-parse HEAD)",
 "uncommittedLoadtestChanges": $dirty,
 "command": "REPS=$REPS PROXIES=$PROXIES SCENARIOS=$SCENARIOS loadtest/competitors/run-all.sh $*",
 "started": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
 "wsl": $(grep -qi microsoft /proc/version && echo true || echo false)
}
JSON
# The contamination guard's log: load average and foreign CPU every 5 s, until this script exits.
python3 -I "$HERE/hostmon.py" $$ "$OUT/hostmon.jsonl" 5 &
# On WSL2, also what the Windows host runs: it shares the cores but is invisible to hostmon.py.
# Without it every run is rejected (aggregate.py), so refuse to start rather than run for hours.
if grep -qi microsoft /proc/version; then
    command -v powershell.exe >/dev/null || { echo "WSL2 without powershell.exe: the Windows host cannot be monitored" >&2; exit 1; }
    python3 -I "$HERE/winmon.py" $$ "$OUT/winmon.jsonl" 5 &
    sleep 15
    [ -s "$OUT/winmon.jsonl" ] || { echo "the Windows host monitor wrote nothing in 15 s (see winmon.py)" >&2; exit 1; }
fi
for ((rep = 1; rep <= REPS; rep++)); do
    # Rotate the order, so no proxy always runs first (or last) in a repetition.
    shift_by=$(( (rep - 1) % ${#list[@]} ))
    order=("${list[@]:shift_by}" "${list[@]:0:shift_by}")
    order_csv=$(IFS=,; echo "${order[*]}")
    echo "=== repetition $rep/$REPS: $order_csv ===" >&2
    java -jar "$JAR" run "${SETTINGS[@]}" --proxies "$order_csv" --scenarios "$SCENARIOS" \
        --out "$OUT/rep$rep" "$@" 2>&1 | tee "$OUT/rep$rep.log" | grep -E '^\[loadtest\] (===|.*sweep [0-9]|.*ramp [0-9]|.*memory/|.*fault |.*soak )' || true
done

ARGS=("$OUT")
[ "$PUBLISH" = 1 ] && ARGS+=(--publish "$ROOT/docs")
python3 -I "$HERE/aggregate.py" "${ARGS[@]}"
