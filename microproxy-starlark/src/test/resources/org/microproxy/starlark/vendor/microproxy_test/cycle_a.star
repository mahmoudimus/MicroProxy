# A test module that loads itself through cycle_b (StdlibLoaderTest).
load("@vendor//microproxy_test/cycle_b", "b")
a = 1
