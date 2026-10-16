package org.microproxy.dns;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class DnsTransportFailoverTest {

    private static final byte[] QUERY = {1, 2, 3};
    private static final byte[] ANSWER = {4, 5, 6};

    @Test
    void aFailingResolverHandsTheQueryToTheNext() throws IOException {
        List<String> asked = new ArrayList<>();
        DnsTransport transport = DnsTransport.failover(List.of(
                query -> {
                    asked.add("first");
                    throw new IOException("unreachable");
                },
                query -> {
                    asked.add("second");
                    return ANSWER;
                },
                query -> {
                    asked.add("third");
                    return new byte[0];
                }));
        assertArrayEquals(ANSWER, transport.exchange(QUERY));
        assertEquals(List.of("first", "second"), asked);
    }

    @Test
    void laterQueriesStartAtTheResolverThatAnsweredLast() throws IOException {
        List<String> asked = new ArrayList<>();
        boolean[] secondDown = {false};
        DnsTransport transport = DnsTransport.failover(List.of(
                query -> {
                    asked.add("first");
                    throw new IOException("down");
                },
                query -> {
                    asked.add("second");
                    if (secondDown[0]) throw new IOException("down too");
                    return ANSWER;
                },
                query -> {
                    asked.add("third");
                    return ANSWER;
                }));
        transport.exchange(QUERY);
        transport.exchange(QUERY);
        assertEquals(List.of("first", "second", "second"), asked);
        // The one that answered goes down: the next is tried, then the rest wrap around.
        secondDown[0] = true;
        asked.clear();
        transport.exchange(QUERY);
        transport.exchange(QUERY);
        assertEquals(List.of("second", "third", "third"), asked);
    }

    @Test
    void whenEveryResolverFailsTheLastFailureCarriesTheOthers() {
        IOException first = new IOException("first");
        IOException second = new IOException("second");
        DnsTransport transport = DnsTransport.failover(List.of(query -> {
            throw first;
        }, query -> {
            throw second;
        }));
        IOException e = assertThrows(IOException.class, () -> transport.exchange(QUERY));
        assertSame(second, e);
        assertEquals(List.of(first), List.of(e.getSuppressed()));
    }

    @Test
    void anInterruptionIsNotFailedOver() {
        List<String> asked = new ArrayList<>();
        DnsTransport transport = DnsTransport.failover(List.of(query -> {
            asked.add("first");
            throw new InterruptedIOException("interrupted");
        }, query -> {
            asked.add("second");
            return ANSWER;
        }));
        assertThrows(InterruptedIOException.class, () -> transport.exchange(QUERY));
        assertEquals(List.of("first"), asked);
    }

    @Test
    void oneTransportIsUsedAsItIs() {
        DnsTransport only = query -> ANSWER;
        assertSame(only, DnsTransport.failover(List.of(only)));
        assertThrows(IllegalArgumentException.class, () -> DnsTransport.failover(List.of()));
    }
}
