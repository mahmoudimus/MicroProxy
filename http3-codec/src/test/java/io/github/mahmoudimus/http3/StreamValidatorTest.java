package io.github.mahmoudimus.http3;

import static io.github.mahmoudimus.http3.TestBytes.assertConnectionError;
import static io.github.mahmoudimus.http3.TestBytes.assertStreamError;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.http3.Http3StreamValidator.Role;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Which frames may appear on which stream, and in what order (RFC 9114 §4.1, §6.2, §7.2). */
class StreamValidatorTest {

    private static final Http3ErrorCode UNEXPECTED = Http3ErrorCode.H3_FRAME_UNEXPECTED;

    private static final Http3Frame SETTINGS = new Http3Frame.Settings(Map.of());
    private static final Http3Frame DATA = new Http3Frame.Data(new byte[1]);
    private static final Http3Frame HEADERS = new Http3Frame.Headers(new byte[2]);
    private static final Http3Frame PUSH_PROMISE = new Http3Frame.PushPromise(0, new byte[2]);
    private static final Http3Frame GREASE = new Http3Frame.Unknown(0x21, new byte[0]);

    private static Http3StreamValidator control(Role local) throws Http3Exception {
        Http3StreamValidator v = Http3StreamValidator.forControlStream(local);
        v.onFrame(SETTINGS);
        return v;
    }

    // --- control stream ------------------------------------------------------------------------

    @Test
    void controlStreamMustStartWithSettings() throws Http3Exception {
        for (Http3Frame first : new Http3Frame[] {DATA, HEADERS, GREASE, new Http3Frame.GoAway(0), new Http3Frame.MaxPushId(1)}) {
            Http3StreamValidator v = Http3StreamValidator.forControlStream(Role.SERVER);
            assertConnectionError(Http3ErrorCode.H3_MISSING_SETTINGS, () -> v.onFrame(first));
        }
        Http3StreamValidator v = Http3StreamValidator.forControlStream(Role.SERVER);
        assertFalse(v.settingsReceived());
        v.onFrame(SETTINGS);
        assertTrue(v.settingsReceived());
        v.onFrame(GREASE);
        assertConnectionError(UNEXPECTED, () -> v.onFrame(SETTINGS));
    }

    @Test
    void controlStreamRejectsMessageFrames() throws Http3Exception {
        for (Role role : Role.values()) {
            Http3StreamValidator v = control(role);
            assertConnectionError(UNEXPECTED, () -> v.onFrame(DATA));
            assertConnectionError(UNEXPECTED, () -> control(role).onFrame(HEADERS));
            assertConnectionError(UNEXPECTED, () -> control(role).onFrame(PUSH_PROMISE));
        }
    }

    @Test
    void maxPushIdOnlyFromClientsAndNeverDecreasing() throws Http3Exception {
        assertConnectionError(UNEXPECTED, () -> control(Role.CLIENT).onFrame(new Http3Frame.MaxPushId(3)));
        Http3StreamValidator server = control(Role.SERVER);
        server.onFrame(new Http3Frame.MaxPushId(3));
        server.onFrame(new Http3Frame.MaxPushId(3));
        server.onFrame(new Http3Frame.MaxPushId(10));
        assertConnectionError(Http3ErrorCode.H3_ID_ERROR, () -> server.onFrame(new Http3Frame.MaxPushId(9)));
    }

    @Test
    void cancelPushToAServerMustBeWithinMaxPushId() throws Http3Exception {
        Http3StreamValidator server = control(Role.SERVER);
        assertConnectionError(Http3ErrorCode.H3_ID_ERROR, () -> server.onFrame(new Http3Frame.CancelPush(0)));
        Http3StreamValidator server2 = control(Role.SERVER);
        server2.onFrame(new Http3Frame.MaxPushId(5));
        server2.onFrame(new Http3Frame.CancelPush(5));
        assertConnectionError(Http3ErrorCode.H3_ID_ERROR, () -> server2.onFrame(new Http3Frame.CancelPush(6)));
        control(Role.CLIENT).onFrame(new Http3Frame.CancelPush(100));
    }

    @Test
    void goAwayIdentifiers() throws Http3Exception {
        // From a server: a client-initiated bidirectional stream, never increasing.
        Http3StreamValidator client = control(Role.CLIENT);
        assertConnectionError(Http3ErrorCode.H3_ID_ERROR, () -> client.onFrame(new Http3Frame.GoAway(2)));
        Http3StreamValidator client2 = control(Role.CLIENT);
        client2.onFrame(new Http3Frame.GoAway(8));
        client2.onFrame(new Http3Frame.GoAway(8));
        client2.onFrame(new Http3Frame.GoAway(4));
        assertConnectionError(Http3ErrorCode.H3_ID_ERROR, () -> client2.onFrame(new Http3Frame.GoAway(12)));
        // From a client: a push ID, any value, never increasing.
        Http3StreamValidator server = control(Role.SERVER);
        server.onFrame(new Http3Frame.GoAway(7));
        assertConnectionError(Http3ErrorCode.H3_ID_ERROR, () -> server.onFrame(new Http3Frame.GoAway(9)));
    }

    @Test
    void closingTheControlStreamIsAConnectionError() throws Http3Exception {
        assertConnectionError(Http3ErrorCode.H3_CLOSED_CRITICAL_STREAM, () -> control(Role.CLIENT).onEndOfStream());
    }

    // --- request streams -----------------------------------------------------------------------

    @Test
    void requestIsHeadersDataThenOptionalTrailers() throws Http3Exception {
        Http3StreamValidator v = Http3StreamValidator.forRequestStream(0, Role.SERVER);
        v.onFrame(GREASE);
        v.onFrame(HEADERS);
        assertTrue(v.headersReceived());
        v.onFrame(DATA);
        v.onFrame(GREASE);
        v.onFrame(DATA);
        v.onFrame(HEADERS);
        assertTrue(v.trailersReceived());
        v.onFrame(GREASE);
        assertConnectionError(UNEXPECTED, () -> v.onFrame(DATA));
        Http3StreamValidator v2 = Http3StreamValidator.forRequestStream(0, Role.SERVER);
        v2.onFrame(HEADERS);
        v2.onFrame(HEADERS);
        assertConnectionError(UNEXPECTED, () -> v2.onFrame(HEADERS));
        v2.onEndOfStream();
    }

    @Test
    void dataBeforeHeadersIsUnexpected() {
        assertConnectionError(UNEXPECTED, () -> Http3StreamValidator.forRequestStream(4, Role.SERVER).onFrame(DATA));
        assertConnectionError(UNEXPECTED, () -> Http3StreamValidator.forRequestStream(4, Role.CLIENT).onFrame(DATA));
    }

    @Test
    void controlFramesAreUnexpectedOnRequestStreams() {
        for (Http3Frame f : new Http3Frame[] {SETTINGS, new Http3Frame.GoAway(0), new Http3Frame.MaxPushId(0), new Http3Frame.CancelPush(0)}) {
            for (Role role : Role.values()) {
                assertConnectionError(UNEXPECTED, () -> Http3StreamValidator.forRequestStream(0, role).onFrame(f));
            }
            assertConnectionError(UNEXPECTED, () -> Http3StreamValidator.forPushStream(3, Role.CLIENT).onFrame(f));
        }
    }

    @Test
    void pushPromiseOnlyFromAServerOnARequestStream() throws Http3Exception {
        assertConnectionError(UNEXPECTED, () -> Http3StreamValidator.forRequestStream(0, Role.SERVER).onFrame(PUSH_PROMISE));
        Http3StreamValidator client = Http3StreamValidator.forRequestStream(0, Role.CLIENT);
        client.onFrame(PUSH_PROMISE); // before,
        client.onFrame(HEADERS);
        client.onFrame(PUSH_PROMISE); // interleaved with,
        client.onFrame(DATA);
        client.onFrame(HEADERS);
        client.onFrame(PUSH_PROMISE); // and after the response
        Http3StreamValidator push = Http3StreamValidator.forPushStream(3, Role.CLIENT);
        push.onFrame(HEADERS);
        assertConnectionError(UNEXPECTED, () -> push.onFrame(PUSH_PROMISE));
        assertThrows(IllegalArgumentException.class, () -> Http3StreamValidator.forPushStream(3, Role.SERVER));
    }

    @Test
    void interimResponsesAllowAnotherHeaderSection() throws Http3Exception {
        Http3StreamValidator v = Http3StreamValidator.forRequestStream(0, Role.CLIENT);
        v.onFrame(HEADERS); // 103
        v.interimResponse();
        assertFalse(v.headersReceived());
        v.onFrame(HEADERS); // 100
        v.interimResponse();
        v.onFrame(HEADERS); // 200
        v.onFrame(DATA);
        assertThrows(IllegalStateException.class, v::interimResponse);
        assertThrows(IllegalStateException.class, () -> Http3StreamValidator.forRequestStream(0, Role.SERVER).interimResponse());
        Http3StreamValidator fresh = Http3StreamValidator.forRequestStream(0, Role.CLIENT);
        assertThrows(IllegalStateException.class, fresh::interimResponse);
    }

    @Test
    void streamsEndingWithoutAHeaderSection() throws Http3Exception {
        assertStreamError(8, Http3ErrorCode.H3_REQUEST_INCOMPLETE,
                () -> Http3StreamValidator.forRequestStream(8, Role.SERVER).onEndOfStream());
        assertStreamError(8, Http3ErrorCode.H3_MESSAGE_ERROR,
                () -> Http3StreamValidator.forRequestStream(8, Role.CLIENT).onEndOfStream());
        Http3StreamValidator interimOnly = Http3StreamValidator.forRequestStream(8, Role.CLIENT);
        interimOnly.onFrame(HEADERS);
        interimOnly.interimResponse();
        assertStreamError(8, Http3ErrorCode.H3_MESSAGE_ERROR, interimOnly::onEndOfStream);
        Http3StreamValidator complete = Http3StreamValidator.forRequestStream(8, Role.SERVER);
        complete.onFrame(HEADERS);
        assertDoesNotThrow(complete::onEndOfStream);
    }

    // --- unidirectional streams ----------------------------------------------------------------

    @Test
    void criticalStreamsAreUnique() throws Http3Exception {
        for (long type : new long[] {Http3StreamType.CONTROL, Http3StreamType.QPACK_ENCODER, Http3StreamType.QPACK_DECODER}) {
            Http3StreamValidator.UnidirectionalStreams streams = new Http3StreamValidator.UnidirectionalStreams(Role.SERVER);
            assertTrue(streams.onStream(type));
            assertConnectionError(Http3ErrorCode.H3_STREAM_CREATION_ERROR, () -> streams.onStream(type));
            assertConnectionError(Http3ErrorCode.H3_CLOSED_CRITICAL_STREAM, () -> streams.onStreamClosed(type));
        }
    }

    @Test
    void pushStreamsOnlyFromServersAndUnknownStreamsAreIgnored() throws Http3Exception {
        Http3StreamValidator.UnidirectionalStreams atClient = new Http3StreamValidator.UnidirectionalStreams(Role.CLIENT);
        assertTrue(atClient.onStream(Http3StreamType.PUSH));
        assertTrue(atClient.onStream(Http3StreamType.PUSH));
        atClient.onStreamClosed(Http3StreamType.PUSH);
        assertFalse(atClient.onStream(0x21));
        assertFalse(atClient.onStream(0x54));
        atClient.onStreamClosed(0x21);
        Http3StreamValidator.UnidirectionalStreams atServer = new Http3StreamValidator.UnidirectionalStreams(Role.SERVER);
        assertConnectionError(Http3ErrorCode.H3_STREAM_CREATION_ERROR, () -> atServer.onStream(Http3StreamType.PUSH));
    }
}
