# A module-level struct whose __len__ reports the thread it runs in (StdlibLoaderTest).
load("@stdlib//larky", "larky")
load("@stdlib//probe", "probe")

S = larky.struct(__len__ = lambda: probe.thread_id())
LOADED_IN = probe.thread_id()
