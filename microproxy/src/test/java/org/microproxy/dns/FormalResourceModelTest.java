package org.microproxy.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** Observations of production transitions, checked against Lean by the opt-in formal runner. */
class FormalResourceModelTest {
    @Test
    void observesBudgetBoundariesWithoutUnderflowOrIncreasingAllowance() throws Exception {
        List<String> observations = new ArrayList<>();
        Field remaining = DnssecValidator.WorkBudget.class.getDeclaredField("remaining");
        remaining.setAccessible(true);
        for (int limit : new int[] {1, 8, 128, 8192, Integer.MAX_VALUE}) {
            for (int cost : new int[] {0, 1, 8, 128, 151, 8192, Integer.MAX_VALUE}) {
                var budget = new DnssecValidator.WorkBudget(limit);
                boolean accepted = true;
                try { budget.consume(cost); }
                catch (DnssecValidationException exhausted) { accepted = false; }
                int after = remaining.getInt(budget);
                assertTrue(after >= 0 && after <= limit);
                assertEquals(cost <= limit, accepted);
                assertEquals(accepted ? limit - cost : 0, after);
                observations.add("{\"kind\":\"budget\",\"before\":" + limit + ",\"cost\":" + cost
                        + ",\"accepted\":" + accepted + ",\"after\":" + after + "}");
            }
        }
        export("resources-budget.jsonl", observations);
    }

    @Test
    void observesCacheReplacementEvictionAndExpiryWithAFixedClock() throws Exception {
        List<String> observations = new ArrayList<>();
        for (int capacity : new int[] {0, 1, 2, 4}) {
            long now = 1000;
            var clock = new DnssecResourceLimitsTest.MutableClock(now);
            var cache = new BoundedExpiringCache<Integer, Integer>(capacity,
                    clock);
            Random inputs = new Random(20261028);
            for (int i = 0; i < 64; i++) {
                if (i % 7 == 0) now += 2;
                clock.millis = now; // Fixed for both reads within this operation.
                int key = inputs.nextInt(6);
                long expires = now + new int[] {-1, 0, 1, 10}[inputs.nextInt(4)];
                String before = snapshot(cache);
                cache.put(key, i, expires);
                String after = snapshot(cache);
                assertTrue(size(cache) <= capacity);
                observations.add("{\"kind\":\"cache\",\"capacity\":" + capacity + ",\"now\":" + now
                        + ",\"key\":" + key + ",\"value\":" + i + ",\"expires\":" + expires
                        + ",\"before\":" + before + ",\"after\":" + after + "}");
            }
        }
        export("resources-cache.jsonl", observations);
    }

    private static Map<?, ?> entries(Object cache) throws Exception {
        Field field = cache.getClass().getDeclaredField("entries");
        field.setAccessible(true);
        return (Map<?, ?>) field.get(cache);
    }

    private static int size(Object cache) throws Exception { return entries(cache).size(); }

    private static String snapshot(Object cache) throws Exception {
        List<String> rows = new ArrayList<>();
        for (var entry : entries(cache).entrySet()) {
            Object item = entry.getValue();
            var value = item.getClass().getDeclaredMethod("value");
            var expires = item.getClass().getDeclaredMethod("expiresAtMillis");
            value.setAccessible(true);
            expires.setAccessible(true);
            rows.add("[" + entry.getKey() + "," + value.invoke(item) + "," + expires.invoke(item) + "]");
        }
        Collections.reverse(rows);
        return "[" + String.join(",", rows) + "]";
    }

    private static void export(String filename, List<String> observations) throws Exception {
        String directory = System.getProperty("microproxy.formal.output");
        if (directory != null) {
            Path destination = Path.of(directory).resolve(filename);
            Files.createDirectories(destination.getParent());
            Files.write(destination, observations);
        }
    }
}
