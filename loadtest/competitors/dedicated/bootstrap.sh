#!/usr/bin/env bash
# Prepares a dedicated Linux machine (Ubuntu/Debian, root, at least 8 physical cores, nothing else
# running) for the cross-proxy comparison of docs/project/performance.md, then optionally runs it.
#
#   sudo loadtest/competitors/dedicated/bootstrap.sh            # prepare only
#   sudo RUN=1 loadtest/competitors/dedicated/bootstrap.sh      # prepare, then run the campaign
#
# It installs the build and proxy dependencies, two pinned JDKs (Temurin 21 and 25, checked against
# their SHA-256), the external proxies (setup.sh), applies the kernel and CPU settings the runs
# assume, prints a machine report, and with RUN=1 runs run-all.sh with a CPU split for this machine.
# Environment overrides: JDK (21 or 25; the JDK the proxies and harness run on, default 25),
# REPS (5), OUT, and any run-all.sh variable (CPUS_PROXY, CPUS_ORIGIN, CPUS_CLIENT, PROXIES, ...).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
TOOLS="$HERE/../.tools"
log() { printf '[bootstrap] %s\n' "$*" >&2; }

[ "$(id -u)" = 0 ] || { log "run as root (sysctl, CPU governor, apt)"; exit 1; }
CPUS=$(nproc)
VIRT=$(systemd-detect-virt 2>/dev/null || echo unknown)
if grep -qi microsoft /proc/version; then
    log "WSL2: the Windows host shares these cores; run-all.sh also logs its load (winmon.py) and the guard"
    log "      rejects runs it disturbed. Keep the Windows side idle, on a High/Ultimate performance power plan."
    command -v powershell.exe >/dev/null || { log "powershell.exe is not on the PATH (WSL interop off?): the Windows side cannot be monitored"; exit 1; }
elif [ "$VIRT" != none ] && [ "$VIRT" != unknown ]; then
    log "WARNING: running under $VIRT: use a dedicated-core instance, and check the guard's foreign-CPU record"
fi

# The CPUs to measure on: one hardware thread per physical core (the first of its siblings, so no two
# pinned processes share a core), and on hybrid processors (Intel's performance + efficiency cores)
# only the performance cores, which /sys/devices/cpu_core/cpus lists.
expand() { local r out=(); for r in ${1//,/ }; do if [[ $r == *-* ]]; then out+=($(seq "${r%-*}" "${r#*-}")); else out+=("$r"); fi; done; echo "${out[@]}"; }
pool=$(expand "$(cat /sys/devices/system/cpu/online)")
[ -r /sys/devices/cpu_core/cpus ] && pool=$(expand "$(cat /sys/devices/cpu_core/cpus)") && log "hybrid processor: using only performance cores ($(cat /sys/devices/cpu_core/cpus))"
CORE_CPUS=()
for c in $pool; do
    sib=$(cut -d, -f1 "/sys/devices/system/cpu/cpu$c/topology/thread_siblings_list" | cut -d- -f1)
    [ "$sib" = "$c" ] && CORE_CPUS+=("$c")
done
CORES=${#CORE_CPUS[@]}
# The first core is left for interrupts and housekeeping; then the proxy, the origin, and at least two
# cores for the load generator.
[ "$CORES" -ge 5 ] || { log "need at least 5 usable physical cores (housekeeping, proxy, origin, 2 for the load generator); found $CORES: ${CORE_CPUS[*]}"; exit 1; }
[ "$CORES" -ge 8 ] || log "WARNING: $CORES usable physical cores; 8 or more give the load generator room"
[ "$CPUS" -eq "$(lscpu -p=CORE | grep -v '^#' | sort -u | wc -l)" ] || log "note: SMT is on; only one thread per core is used, and the idle siblings can still disturb it: turning SMT off is better"

# Packages: build tools, Maven, Python, the g3proxy build's needs, Squid.
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends ca-certificates curl git maven python3 build-essential \
    pkg-config capnproto libssl-dev squid util-linux procps linux-tools-common >/dev/null || \
    apt-get install -y -q --no-install-recommends ca-certificates curl git maven python3 build-essential \
    pkg-config capnproto libssl-dev squid util-linux procps
systemctl disable --now squid >/dev/null 2>&1 || true   # the harness starts its own Squid

# Two pinned JDKs: the published runs use JDK 25 (the default here), and JDK 21 for comparison.
mkdir -p "$TOOLS/dl"
jdk() {  # jdk NAME URL SHA256
    local dir="$TOOLS/$1" f="$TOOLS/dl/$1.tar.gz"
    [ -x "$dir/bin/java" ] && return
    curl -fsSL --retry 3 -o "$f" "$2"
    echo "$3  $f" | sha256sum -c --status || { log "$1: checksum mismatch"; exit 1; }
    mkdir -p "$dir" && tar -C "$dir" --strip-components=1 -xzf "$f"
}
jdk temurin-21 https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz \
    ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94
jdk temurin-25 https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jdk_x64_linux_hotspot_25.0.4.1_1.tar.gz \
    dbb698396d478e7fa2b1e50f4103324b2a99b90569ee27c33f2261f9215cf41e
export JAVA_HOME="$TOOLS/temurin-${JDK:-25}"
export PATH="$JAVA_HOME/bin:$PATH"

# Kernel settings the connection ramp and slow-reader scenarios need, restored when this script
# exits. The largest ramp step (8,000 connections) needs 16,000 local ports (client to proxy, proxy to
# origin), which the default range (32768-60999, 28,232 ports) already has, and TIME_WAIT reuse keeps
# them free between scenarios; the range is widened only where nothing else shares it: under WSL2 the
# Linux and Windows port spaces interact, and a range down to 1024 broke the host's own downloads.
KEYS=(net.ipv4.ip_local_port_range net.core.somaxconn net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_tw_reuse fs.file-max fs.nr_open)
declare -A ORIG
for k in "${KEYS[@]}"; do ORIG[$k]=$(sysctl -n "$k" | tr '\t' ' '); done
restore() { for k in "${KEYS[@]}"; do sysctl -q -w "$k=${ORIG[$k]}" || true; done; log "kernel settings restored"; }
trap restore EXIT
sysctl -q -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535 net.ipv4.tcp_tw_reuse=1 \
    fs.file-max=2097152 fs.nr_open=2097152
if ! grep -qi microsoft /proc/version && [ -z "${KEEP_PORT_RANGE:-}" ]; then
    sysctl -q -w net.ipv4.ip_local_port_range="15000 64999"
fi
read -r lo hi <<< "$(sysctl -n net.ipv4.ip_local_port_range)"
[ $((hi - lo + 1)) -ge 20000 ] || { log "only $((hi - lo + 1)) local ports ($lo-$hi); the 8,000-connection ramp needs about 16,000"; exit 1; }
ulimit -n 1048576 || ulimit -n "$(ulimit -Hn)"

# Steady CPU clocks: performance governor, and no turbo where the driver exposes it.
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ -w "$g" ] && echo performance > "$g"; done
[ -w /sys/devices/system/cpu/intel_pstate/no_turbo ] && echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo || true
[ -w /sys/devices/system/cpu/cpufreq/boost ] && echo 0 > /sys/devices/system/cpu/cpufreq/boost || true

# The external proxies (Envoy, goproxy, g3proxy; Squid from apt above) and the harness.
"$HERE/../setup.sh"
(cd "$ROOT" && mvn --batch-mode -q -Pbench -DskipTests package -pl loadtest -am)

# The split over the usable cores: the first left for housekeeping, then the proxy, the origin, and up
# to six for the load generator.
client=$(IFS=,; echo "${CORE_CPUS[*]:3:6}")
export CPUS_PROXY=${CPUS_PROXY:-${CORE_CPUS[1]}} CPUS_ORIGIN=${CPUS_ORIGIN:-${CORE_CPUS[2]}} CPUS_CLIENT=${CPUS_CLIENT:-$client}

log "machine: $(lscpu | sed -n 's/^Model name: *//p'), $CORES usable cores, $CPUS CPUs, virtualization $VIRT, $(free -g | awk '/Mem/{print $2}') GB, kernel $(uname -r)"
log "java: $(java -version 2>&1 | head -1); governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
log "split: proxy $CPUS_PROXY, origin $CPUS_ORIGIN, load generator $CPUS_CLIENT"
log "load now: $(cat /proc/loadavg) (should be near 0: stop everything else on the machine)"
log "local ports: $(sysctl -n net.ipv4.ip_local_port_range | tr '\t' ' '); prepare-only runs restore the kernel settings on exit"

if [ "${RUN:-0}" = 1 ]; then
    cd "$ROOT"
    export OUT=${OUT:-loadtest/results/dedicated-$(date -u +%Y%m%d-%H%M%S)} PUBLISH=0
    "$HERE/../run-all.sh"
    log "done: results in $OUT; aggregate with python3 -I loadtest/competitors/aggregate.py $OUT --publish docs"
fi
