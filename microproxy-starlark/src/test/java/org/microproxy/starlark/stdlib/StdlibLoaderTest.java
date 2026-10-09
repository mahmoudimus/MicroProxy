package org.microproxy.starlark.stdlib;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.microproxy.thirdparty.larky.modules.ZLibModule;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Module;

class StdlibLoaderTest {

    @Test
    void labelForms() throws EvalException {
        assertEquals(new Stdlib.Label("stdlib", "urllib/parse"), Stdlib.parse("@stdlib//urllib/parse", false));
        assertEquals(new Stdlib.Label("stdlib", "larky"), Stdlib.parse("@stdlib/larky", false));
        assertEquals(new Stdlib.Label("vendor", "option/result"), Stdlib.parse("@vendor//option/result.star", false));
        assertEquals(new Stdlib.Label("stdlib", "types"), Stdlib.parse("types", true));
        assertThrows(EvalException.class, () -> Stdlib.parse("types", false));
        assertThrows(EvalException.class, () -> Stdlib.parse("@stdlib//a/../b", false));
        assertThrows(EvalException.class, () -> Stdlib.parse("@stdlib//", false));
        assertThrows(EvalException.class, () -> Stdlib.parse("@other//x", false));
    }

    @Test
    void everyListedModuleLoads() throws EvalException {
        for (String name : Stdlib.Modules.STDLIB) {
            Module m = Stdlib.loadAll(List.of("@stdlib//" + name)).get("@stdlib//" + name);
            assertTrue(!m.getGlobals().isEmpty(), name);
        }
        for (String name : Stdlib.Modules.VENDOR) {
            Stdlib.loadAll(List.of("@vendor//" + name));
        }
    }

    @Test
    void nativeModulesAndPackages() throws EvalException {
        Map<String, Module> m = Stdlib.loadAll(List.of("@stdlib//jzlib", "@stdlib//io"));
        assertSame(ZLibModule.INSTANCE, m.get("@stdlib//jzlib").getGlobal("jzlib"));
        // @stdlib//io is io/__init__.star
        assertTrue(m.get("@stdlib//io").getGlobal("io") != null);
    }

    @Test
    void cyclesAreReported() {
        String error = assertThrows(EvalException.class,
                () -> Stdlib.loadAll(List.of("@vendor//microproxy_test/cycle_a"))).getMessage();
        assertTrue(error.contains("cycle in loads: @vendor//microproxy_test/cycle_a -> @vendor//microproxy_test/cycle_b"
                + " -> @vendor//microproxy_test/cycle_a"), error);
    }

    @Test
    void failingModulesAreReportedEachTime() {
        for (int i = 0; i < 2; i++) {
            String error = assertThrows(EvalException.class,
                    () -> Stdlib.loadAll(List.of("@vendor//microproxy_test/broken"))).getMessage();
            assertTrue(error.contains("cannot load '@vendor//microproxy_test/broken'"), error);
            assertTrue(error.contains("broken on purpose"), error);
        }
    }

    /** {@code @stdlib//probe} for {@link #sharedValuesRunInTheCallersThread}. */
    @org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin(name = "probe", doc = "test")
    public static final class Probe implements org.microproxy.thirdparty.starlark.eval.StarlarkValue {
        @org.microproxy.thirdparty.starlark.annot.StarlarkMethod(name = "thread_id", doc = "", useStarlarkThread = true)
        public int threadId(org.microproxy.thirdparty.starlark.eval.StarlarkThread thread) {
            return System.identityHashCode(thread);
        }
    }

    @Test
    void sharedValuesRunInTheCallersThread() throws Exception {
        Stdlib.Loader loader = new Stdlib.Loader(com.google.common.collect.ImmutableMap.<String, Object>builder()
                .putAll(Stdlib.NATIVES).put("probe", new Probe()).buildOrThrow());
        Module shared = loader.loadAll(List.of("@vendor//microproxy_test/caller_thread")).values().iterator().next();
        try (org.microproxy.thirdparty.starlark.eval.Mutability mu =
                org.microproxy.thirdparty.starlark.eval.Mutability.create("caller")) {
            org.microproxy.thirdparty.starlark.eval.StarlarkThread caller =
                    org.microproxy.thirdparty.starlark.eval.StarlarkThread.createTransient(mu, Stdlib.MODULE_SEMANTICS);
            Object len = org.microproxy.thirdparty.starlark.eval.Starlark.call(caller,
                    Stdlib.ENVIRONMENT.get("len"), List.of(shared.getGlobal("S")), Map.of());
            assertEquals(org.microproxy.thirdparty.starlark.eval.StarlarkInt.of(System.identityHashCode(caller)), len);
            assertTrue(!len.equals(shared.getGlobal("LOADED_IN")));
        }
    }

    @Test
    void moduleInitializationIsBounded() {
        Stdlib.Loader loader = new Stdlib.Loader(Stdlib.NATIVES, new Stdlib.Limits(100_000, Duration.ofSeconds(10)));
        String error = assertThrows(EvalException.class,
                () -> loader.loadAll(List.of("@vendor//microproxy_test/endless"))).getMessage();
        assertTrue(error.contains("cannot load '@vendor//microproxy_test/endless'"), error);
        assertTrue(error.contains("steps"), error);
    }
}
