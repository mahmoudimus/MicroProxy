package io.github.mahmoudimus.quic.params;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.VarInt;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

class TransportParameterProfileTest {

    /** The parameters of a connection configured as Chrome 156's. */
    private static TransportParameters chromeConfigured() {
        return TransportParameters.builder()
                .initialSourceConnectionId(ConnectionId.EMPTY)
                .maxIdleTimeout(30_000)
                .maxUdpPayloadSize(1472)
                .initialMaxData(15_728_640)
                .initialMaxStreamDataBidiLocal(6_291_456)
                .initialMaxStreamDataBidiRemote(6_291_456)
                .initialMaxStreamDataUni(6_291_456)
                .initialMaxStreamsBidi(100)
                .initialMaxStreamsUni(103)
                .maxDatagramFrameSize(65_535)
                .build();
    }

    private static Map<Long, byte[]> split(byte[] encoded) {
        Map<Long, byte[]> out = new LinkedHashMap<>();
        ByteBuffer b = ByteBuffer.wrap(encoded);
        while (b.hasRemaining()) {
            long id = VarInt.read(b);
            byte[] v = new byte[(int) VarInt.read(b)];
            b.get(v);
            out.put(id, v);
        }
        return out;
    }

    /** Chrome's transport parameters from a captured hello. */
    private static Map<Long, byte[]> chromes(String fixture) throws IOException {
        byte[] hello;
        try (InputStream in = TransportParameterProfileTest.class.getResourceAsStream("/fingerprints/chrome-156-quic/" + fixture)) {
            hello = in.readAllBytes();
        }
        ByteBuffer b = ByteBuffer.wrap(hello);
        b.position(4 + 2 + 32);
        b.position(b.position() + 1 + (b.get(b.position()) & 0xff));
        b.position(b.position() + 2 + (b.getShort(b.position()) & 0xffff));
        b.position(b.position() + 1 + (b.get(b.position()) & 0xff));
        int end = b.position() + 2 + (b.getShort() & 0xffff);
        while (b.position() < end) {
            int type = b.getShort() & 0xffff;
            byte[] data = new byte[b.getShort() & 0xffff];
            b.get(data);
            if (type == 0x39) return split(data);
        }
        throw new AssertionError("no quic_transport_parameters");
    }

    private static boolean isGreaseId(long id) {
        return id >= 27 && (id - 27) % 31 == 0;
    }

    @Test
    void chromesParametersAndValuesExceptGrease() throws IOException {
        Map<Long, byte[]> ours = split(TransportParameterProfile.chrome156().encode(chromeConfigured(), 1, new SplittableRandom(1)));
        Map<Long, byte[]> chrome = chromes("quic-clienthello-0.bin");
        Set<Long> oursIds = new HashSet<>(ours.keySet());
        Set<Long> chromeIds = new HashSet<>(chrome.keySet());
        oursIds.removeIf(TransportParameterProfileTest::isGreaseId);
        chromeIds.removeIf(TransportParameterProfileTest::isGreaseId);
        assertEquals(chromeIds, oursIds);
        for (long id : chromeIds) {
            if (id == TransportParameterProfile.VERSION_INFORMATION) continue;
            assertArrayEquals(chrome.get(id), ours.get(id), "parameter 0x" + Long.toHexString(id));
        }
        assertEquals(1, ours.keySet().stream().filter(TransportParameterProfileTest::isGreaseId).count());
    }

    @Test
    void versionInformationHasTheVersionAndAGreaseOne() {
        Set<Boolean> greaseFirst = new HashSet<>();
        for (long seed = 0; seed < 50; seed++) {
            byte[] v = split(TransportParameterProfile.chrome156().encode(chromeConfigured(), 1, new SplittableRandom(seed)))
                    .get(TransportParameterProfile.VERSION_INFORMATION);
            ByteBuffer b = ByteBuffer.wrap(v);
            assertEquals(1, b.getInt());
            int a = b.getInt();
            int c = b.getInt();
            int grease = a == 1 ? c : a;
            assertTrue((grease & 0x0f0f0f0f) == 0x0a0a0a0a, Integer.toHexString(grease));
            greaseFirst.add(a != 1);
        }
        assertEquals(Set.of(true, false), greaseFirst);
    }

    @Test
    void theOrderChangesFromConnectionToConnection() {
        Set<List<Long>> orders = new HashSet<>();
        for (long seed = 0; seed < 20; seed++) {
            List<Long> ids = new ArrayList<>(split(TransportParameterProfile.chrome156()
                    .encode(chromeConfigured(), 1, new SplittableRandom(seed))).keySet());
            ids.replaceAll(id -> isGreaseId(id) ? -1L : id);
            orders.add(ids);
        }
        assertTrue(orders.size() > 15, "orders seen: " + orders.size());
    }
}
