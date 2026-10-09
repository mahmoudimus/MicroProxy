package io.github.mahmoudimus.http2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class FlowControlTest {

    @Test
    void windowUpdateOverflowOnTheConnectionIsAConnectionError() throws Http2Exception {
        FlowControlWindow w = new FlowControlWindow(0, 65_535);
        w.increment(Integer.MAX_VALUE - 65_535); // exactly 2^31-1
        assertEquals(Integer.MAX_VALUE, w.size());
        Http2Exception e = assertThrows(Http2Exception.class, () -> w.increment(1));
        assertEquals(ErrorCode.FLOW_CONTROL_ERROR, e.errorCode());
        assertTrue(e.isConnectionError());
        assertEquals(Integer.MAX_VALUE, w.size(), "unchanged");
    }

    @Test
    void windowUpdateOverflowOnAStreamIsAStreamError() {
        FlowControlWindow w = new FlowControlWindow(5, 65_535);
        Http2Exception e = assertThrows(Http2Exception.class, () -> w.increment(Integer.MAX_VALUE));
        assertEquals(ErrorCode.FLOW_CONTROL_ERROR, e.errorCode());
        assertFalse(e.isConnectionError());
        assertEquals(5, e.streamId());
    }

    @Test
    void receivingMoreThanTheWindow() throws Http2Exception {
        FlowControlWindow w = new FlowControlWindow(3, 100);
        w.receive(60);
        w.receive(40);
        assertEquals(0, w.size());
        Http2Exception e = assertThrows(Http2Exception.class, () -> w.receive(1));
        assertEquals(ErrorCode.FLOW_CONTROL_ERROR, e.errorCode());
        assertEquals(3, e.streamId());
        assertThrows(IllegalStateException.class, () -> w.send(1));
        assertThrows(IllegalArgumentException.class, () -> w.increment(0));
    }

    @Test
    void controllerTracksConnectionAndStreams() throws Http2Exception {
        FlowController fc = new FlowController();
        fc.addStream(1);
        fc.addStream(3);
        assertEquals(65_535, fc.sendable(1));

        fc.onDataSent(1, 60_000);
        assertEquals(5_535, fc.sendable(3), "the connection window is shared");
        assertThrows(IllegalStateException.class, () -> fc.onDataSent(3, 5_536));
        fc.onWindowUpdateReceived(0, 100_000);
        assertEquals(65_535, fc.sendable(3));
        assertEquals(5_535, fc.sendable(1));
        fc.onWindowUpdateReceived(1, 10);
        assertEquals(5_545, fc.sendable(1));

        fc.onDataReceived(1, 65_535);
        Http2Exception e = assertThrows(Http2Exception.class, () -> fc.onDataReceived(3, 1));
        assertTrue(e.isConnectionError(), "the connection window is exhausted first");
        fc.onWindowUpdateSent(0, 65_535);
        fc.onDataReceived(3, 1);
        e = assertThrows(Http2Exception.class, () -> fc.onDataReceived(1, 1));
        assertFalse(e.isConnectionError());
        assertEquals(1, e.streamId());

        // Closed streams still count against the connection; their updates are ignored.
        fc.removeStream(3);
        assertFalse(fc.hasStream(3));
        assertNull(fc.streamSendWindow(3));
        fc.onWindowUpdateReceived(3, 1);
        fc.onDataReceived(3, 10);
        assertEquals(0, fc.sendable(3));
    }

    @Test
    void initialWindowSizeChangesShiftStreamWindows() throws Http2Exception {
        FlowController fc = new FlowController();
        fc.addStream(1);
        fc.onDataSent(1, 60_000);
        fc.onPeerInitialWindowSize(16_384);
        assertEquals(5_535 - (65_535 - 16_384), fc.streamSendWindow(1).size(), "may go negative");
        assertEquals(0, fc.sendable(1));
        assertEquals(5_535, fc.connectionSendWindow().size(), "connection window unaffected");
        fc.addStream(3);
        assertEquals(16_384, fc.streamSendWindow(3).size());

        fc.onWindowUpdateReceived(1, Integer.MAX_VALUE - 16_384);
        Http2Exception e = assertThrows(Http2Exception.class, () -> fc.onPeerInitialWindowSize(Integer.MAX_VALUE));
        assertEquals(ErrorCode.FLOW_CONTROL_ERROR, e.errorCode());
        assertTrue(e.isConnectionError(), "§6.9.2: a connection error");

        FlowController local = new FlowController(1_000, 65_535);
        local.addStream(1);
        local.onDataReceived(1, 1_000);
        local.onLocalInitialWindowSize(5_000);
        assertEquals(4_000, local.streamReceiveWindow(1).size());
    }
}
