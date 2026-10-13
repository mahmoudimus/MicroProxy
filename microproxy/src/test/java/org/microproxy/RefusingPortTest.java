package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import org.junit.jupiter.api.Test;

/** The {@link TestSupport#refusingPort()} fixture that the connect-failure tests rely on. */
class RefusingPortTest {

    @Test
    void aConnectionToTheReservedPortIsRefusedAtOnce() throws Exception {
        try (Socket refusing = TestSupport.refusingPort()) {
            assertTrue(refusing.getLocalPort() > 0);
            long start = System.nanoTime();
            try (Socket s = new Socket()) {
                // A refusal, not a timeout: the tests that use the port expect an immediate failure.
                assertThrows(ConnectException.class, () -> s.connect(
                        new InetSocketAddress(TestSupport.LOOPBACK, refusing.getLocalPort()), 5_000));
            }
            assertTrue(System.nanoTime() - start < 2_000_000_000L, "the refusal took over 2 s");
            assertTrue(((InetSocketAddress) refusing.getLocalSocketAddress()).getPort() == refusing.getLocalPort());
        }
    }
}
