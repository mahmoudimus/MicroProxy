#!/usr/bin/env python3
"""On WSL2, logs what the Windows side of the machine runs while the comparison runs, for the
contamination guard. hostmon.py sees only the Linux VM; work on the Windows host competes for the
same physical cores without showing up there.

    python3 -I loadtest/competitors/winmon.py <benchmark pid> <output .jsonl> [interval seconds]

Every interval (5 s by default) it appends one JSON line: the time, the Windows host's foreign CPU
(the sum of every Windows process's CPU, in percent of one logical processor, leaving out the idle
process and the WSL virtual machine's own processes, whose time is the benchmark's and hostmon.py's
to account for) and the five busiest of those processes. It reads Windows' performance counters
through powershell.exe (WSL interop) and stops when the benchmark process exits. aggregate.py adds
it to hostmon.py's foreign CPU when it judges each run.
"""
import json
import os
import subprocess
import sys
import time

# The WSL VM's own processes on the Windows side (its vCPUs' time shows under vmmem/VmmemWSL).
VM = {"idle", "_total", "vmmem", "vmmemwsl", "vmwp", "vmcompute"}

SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
while ($true) {
  $s = (Get-Counter '\Process(*)\% Processor Time' -SampleInterval INTERVAL -MaxSamples 1).CounterSamples
  $rows = $s | ForEach-Object { '{0}={1}' -f $_.InstanceName, [math]::Round($_.CookedValue, 1) }
  [Console]::Out.WriteLine(($rows -join ';'))
  [Console]::Out.Flush()
}
"""


def main():
    pid, out = int(sys.argv[1]), sys.argv[2]
    interval = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    ps = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", SCRIPT.replace("INTERVAL", str(interval))],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        with open(out, "a", encoding="utf-8") as f:
            for line in ps.stdout:
                if not os.path.exists(f"/proc/{pid}"):
                    break
                procs = {}
                for item in line.strip().split(";"):
                    name, _, value = item.rpartition("=")
                    base = name.split("#")[0].lower()
                    if not name or base in VM:
                        continue
                    try:
                        procs[base] = procs.get(base, 0.0) + float(value)
                    except ValueError:
                        pass
                top = sorted(procs.items(), key=lambda kv: -kv[1])[:5]
                f.write(json.dumps({"t": time.time(), "windowsForeignCpuPct": round(sum(procs.values()), 1),
                                    "topWindows": [{"program": n, "cpuPct": v} for n, v in top]}) + "\n")
                f.flush()
    finally:
        ps.kill()


if __name__ == "__main__":
    main()
