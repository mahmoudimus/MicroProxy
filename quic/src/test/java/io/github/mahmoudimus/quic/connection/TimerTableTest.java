package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class TimerTableTest {

    @Test
    void earliestDeadlineAndExpiry() {
        TimerTable timers = new TimerTable();
        assertEquals(NanoClock.NONE, timers.nextTimeout());
        assertNull(timers.pollExpired(Long.MAX_VALUE));

        timers.set(Timer.IDLE, 300);
        timers.set(Timer.LOSS_DETECTION, 200);
        timers.set(Timer.MAX_ACK_DELAY, 100);
        assertEquals(100, timers.nextTimeout());
        assertTrue(timers.isExpired(Timer.MAX_ACK_DELAY, 100));
        assertFalse(timers.isExpired(Timer.LOSS_DETECTION, 199));

        timers.stop(Timer.MAX_ACK_DELAY);
        assertFalse(timers.isSet(Timer.MAX_ACK_DELAY));
        assertEquals(200, timers.nextTimeout());

        // Drive the table as the connection will: handle every timer due by `now`
        List<Timer> fired = new ArrayList<>();
        Timer t;
        while ((t = timers.pollExpired(350)) != null) {
            fired.add(t);
        }
        assertEquals(List.of(Timer.LOSS_DETECTION, Timer.IDLE), fired);
        assertEquals(NanoClock.NONE, timers.nextTimeout());
    }

    @Test
    void stopAllClearsEverything() {
        TimerTable timers = new TimerTable();
        for (Timer t : Timer.values()) {
            timers.set(t, 10);
        }
        assertEquals(10, timers.get(Timer.CLOSE));
        timers.stopAll();
        for (Timer t : Timer.values()) {
            assertFalse(timers.isSet(t));
        }
    }

    @Test
    void negativeClockValuesWork() {
        TimerTable timers = new TimerTable();
        timers.set(Timer.PACING, -5_000);
        timers.set(Timer.KEEP_ALIVE, -10_000);
        assertEquals(-10_000, timers.nextTimeout());
        assertEquals(Timer.KEEP_ALIVE, timers.pollExpired(-7_000));
    }
}
