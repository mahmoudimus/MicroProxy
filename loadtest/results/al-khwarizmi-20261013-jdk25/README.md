# al-khwarizmi WSL2 run data — JDK 25

Measured source: `bfe751dcc0e4ec03b669031c7e9c782607906270`.
Five repetitions were collected across MicroProxy, LittleProxy, Envoy, GoProxy,
g3proxy, and Squid. Rep1 is retained as raw evidence but excluded from aggregate
figures because Linux host monitoring had one 10.4-second interval
(2026-10-13T22:05:09Z to 22:05:19Z), exceeding twice the nominal 5-second
cadence. The host CPU guard alone accepted it; the stricter coverage rule rejects
it. Aggregate figures therefore use four accepted repetitions. The raw JSON
retains its numeric measurements. Repository-local absolute paths have been made
relative; Windows monitor records contain timestamp and total foreign CPU only,
with desktop process names omitted. Linux monitor records retain program names
but omit process command lines.

The files use the raw input format consumed by `loadtest/competitors/aggregate.py`.
