# A test module whose top level fails (StdlibLoaderTest).
load("@stdlib//larky", "larky")
fail("broken on purpose")
