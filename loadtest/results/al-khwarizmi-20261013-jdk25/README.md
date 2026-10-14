# al-khwarizmi WSL2 run data — JDK 25

Measured source: `bfe751dcc0e4ec03b669031c7e9c782607906270`.
Five repetitions cover MicroProxy, LittleProxy, Envoy, GoProxy, g3proxy, and
Squid. The raw JSON retains its numeric measurements. Repository-local absolute
paths have been made relative; Windows monitor records contain timestamp and
total foreign CPU only, with desktop process names omitted. Linux monitor
records retain program names but omit process command lines.

The files use the raw input format consumed by `loadtest/competitors/aggregate.py`.
