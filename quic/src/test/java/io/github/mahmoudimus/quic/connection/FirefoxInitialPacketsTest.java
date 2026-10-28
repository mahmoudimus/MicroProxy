package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicClientProfile;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.crypto.DirectionalKeys;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.frame.FrameDecoder;
import io.github.mahmoudimus.quic.packet.Packet;
import io.github.mahmoudimus.quic.packet.PacketHeader;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import io.github.mahmoudimus.quic.tls.CertificateDecompressor;
import io.github.mahmoudimus.quic.tls.TestCerts;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * A client connection with Firefox 159's QUIC profile sends its first Initial datagrams as the
 * captured Firefox did (quic/src/test/resources/fingerprints/firefox-159-quic): 1252 bytes, zero
 * padding after the packet, the ClientHello sliced at its server name, a random first packet
 * number, 8- and 3-byte connection IDs, and Firefox's transport parameters.
 */
class FirefoxInitialPacketsTest {

    /** What a server reads from one Initial datagram. */
    record Seen(int length, int packetEnd, long packetNumber, PacketHeader.Initial header, List<Frame.Crypto> crypto) {}

    static byte[] fixture(String name) {
        try (InputStream in = FirefoxInitialPacketsTest.class.getResourceAsStream("/fingerprints/firefox-159-quic/" + name)) {
            if (in == null) throw new IllegalStateException("missing " + name);
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Connection connect(long seed) {
        QuicClientProfile firefox = QuicClientProfile.firefox159();
        TlsConfig.Builder tls = TlsConfig.builder().serverName("quic.test").alpnProtocols("h3")
                .trustManager(TestCerts.CA.trustManager());
        firefox.applyTo(tls, CertificateDecompressor.ZLIB);
        TransportConfig transport = firefox.applyTo(TransportConfig.builder()).build();
        ClientConfig config = firefox.applyTo(ClientConfig.builder(tls.build()).transport(transport)).build();
        Endpoint endpoint = new Endpoint(firefox.endpointConfig(), null, true);
        return endpoint.connect(seed, config, new InetSocketAddress(InetAddress.getLoopbackAddress(), 443), "quic.test");
    }

    private static List<Seen> read(List<ByteBuffer> datagrams, DirectionalKeys keys) throws Exception {
        List<Seen> out = new ArrayList<>();
        for (ByteBuffer d : datagrams) {
            ByteBuffer copy = ByteBuffer.wrap(bytes(d));
            List<ProtectedPacket> packets = ProtectedPacket.splitDatagram(copy.duplicate(), 0, false);
            ProtectedPacket first = packets.get(0);
            Packet packet = first.unprotect(keys, -1);
            List<Frame.Crypto> crypto = new ArrayList<>();
            for (Frame f : FrameDecoder.decodeAll(packet.payload(), PacketType.INITIAL)) {
                if (f instanceof Frame.Crypto c) crypto.add(c);
            }
            int packetEnd = first.bytes().remaining();
            out.add(new Seen(copy.remaining(), packetEnd, packet.header().packetNumber(),
                    (PacketHeader.Initial) packet.header(), crypto));
        }
        return out;
    }

    private static byte[] bytes(ByteBuffer b) {
        ByteBuffer d = b.duplicate();
        byte[] out = new byte[d.remaining()];
        d.get(out);
        return out;
    }

    /** The captured Firefox's first two datagrams of connection {@code n}, as a server reads them. */
    private static List<Seen> captured(int n) throws Exception {
        byte[] d0 = fixture("initial-datagram-" + n + "-0.bin");
        byte[] d1 = fixture("initial-datagram-" + n + "-1.bin");
        ProtectedPacket p = ProtectedPacket.splitDatagram(ByteBuffer.wrap(d0.clone()), 0, false).get(0);
        DirectionalKeys keys = Keys.initial(QuicVersion.V1, p.destinationId(), true).remote();
        return read(List.of(ByteBuffer.wrap(d0), ByteBuffer.wrap(d1)), keys);
    }

    private static byte[] hello(List<Seen> seen) {
        int length = 0;
        for (Seen s : seen) for (Frame.Crypto c : s.crypto()) length = Math.max(length, (int) c.offset() + c.data().remaining());
        byte[] out = new byte[length];
        for (Seen s : seen) {
            for (Frame.Crypto c : s.crypto()) c.data().duplicate().get(out, (int) c.offset(), c.data().remaining());
        }
        return out;
    }

    /** The transport parameters of a ClientHello, by id in their order. */
    static Map<Long, byte[]> transportParameters(byte[] hello) {
        int p = 4 + 2 + 32;
        p += 1 + (hello[p] & 0xff);
        p += 2 + (((hello[p] & 0xff) << 8) | (hello[p + 1] & 0xff));
        p += 1 + (hello[p] & 0xff);
        int end = p + 2 + (((hello[p] & 0xff) << 8) | (hello[p + 1] & 0xff));
        p += 2;
        while (p < end) {
            int type = ((hello[p] & 0xff) << 8) | (hello[p + 1] & 0xff);
            int length = ((hello[p + 2] & 0xff) << 8) | (hello[p + 3] & 0xff);
            if (type == 57) {
                Map<Long, byte[]> out = new LinkedHashMap<>();
                ByteBuffer b = ByteBuffer.wrap(hello, p + 4, length);
                while (b.hasRemaining()) {
                    long id = io.github.mahmoudimus.quic.VarInt.read(b);
                    byte[] value = new byte[(int) io.github.mahmoudimus.quic.VarInt.read(b)];
                    b.get(value);
                    out.put(id, value);
                }
                return out;
            }
            p += 4 + length;
        }
        return null;
    }

    @Test
    void theFirstDatagramsAreFirefoxs() throws Exception {
        List<Seen> firefox = captured(0);
        for (long seed = 1; seed <= 20; seed++) {
            Connection c = connect(seed);
            List<ByteBuffer> sent = new ArrayList<>();
            for (Transmit t : c.pollTransmit(seed, 10)) sent.add(t.datagram());
            assertEquals(2, sent.size(), "two Initial datagrams");
            List<Seen> ours = read(sent, Keys.initial(QuicVersion.V1, c.initialDcid(), true).remote());
            for (int i = 0; i < 2; i++) {
                assertEquals(firefox.get(i).length(), ours.get(i).length(), "datagram size");
                byte[] d = bytes(sent.get(i));
                for (int k = ours.get(i).packetEnd(); k < d.length; k++) assertEquals(0, d[k], "padding after the packet");
                assertEquals(8, ours.get(i).header().destinationId().length());
                assertEquals(3, ours.get(i).header().sourceId().length());
                assertEquals(0, ours.get(i).header().token().length);
            }
            long first = ours.get(0).packetNumber();
            assertTrue(first >= 1 && first <= 32 + (31L << 5), "first packet number " + first);
            assertEquals(first + 1, ours.get(1).packetNumber());
            // the hello cut at the middle of its server name: its end and its start, then its middle
            byte[] hello = hello(ours);
            List<Frame.Crypto> expected = Connection.sniSlices(hello, 1252 - 16);
            assertEquals(List.of(expected.get(0).offset(), expected.get(1).offset()),
                    ours.get(0).crypto().stream().map(Frame.Crypto::offset).toList());
            assertEquals(List.of(expected.get(2).offset()), ours.get(1).crypto().stream().map(Frame.Crypto::offset).toList());
            // its transport parameters: Firefox's, in its order, but for the connection ID and the GREASE version
            Map<Long, byte[]> theirs = transportParameters(hello(firefox));
            Map<Long, byte[]> mine = transportParameters(hello);
            assertNotNull(mine);
            assertEquals(List.copyOf(theirs.keySet()), List.copyOf(mine.keySet()));
            for (var e : theirs.entrySet()) {
                if (e.getKey() == 0xf) {
                    assertEquals(3, mine.get(0xfL).length);
                } else if (e.getKey() == 0x11) {
                    byte[] v = mine.get(0x11L);
                    assertEquals(16, v.length);
                    assertTrue(Arrays.equals(Arrays.copyOfRange(e.getValue(), 8, 16), Arrays.copyOfRange(v, 8, 16)));
                    assertEquals(0x0a, v[7] & 0x0f, "a GREASE version");
                } else {
                    assertTrue(Arrays.equals(e.getValue(), mine.get(e.getKey())), "transport parameter 0x" + Long.toHexString(e.getKey()));
                }
            }
        }
    }

    @Test
    void sniSlicingCutsEachCapturedHelloAsFirefoxDid() throws Exception {
        for (int n = 0; n < 4; n++) {
            List<Seen> firefox = captured(n);
            List<Frame.Crypto> slices = Connection.sniSlices(hello(firefox), 1252 - 16);
            List<String> theirs = new ArrayList<>();
            List<String> mine = new ArrayList<>();
            for (Seen s : firefox) for (Frame.Crypto c : s.crypto()) theirs.add(c.offset() + "+" + c.data().remaining());
            for (Frame.Crypto c : slices) mine.add(c.offset() + "+" + c.data().remaining());
            assertEquals(theirs, mine, "connection " + n);
        }
    }

    @Test
    void theFirstPacketNumberIsUsuallySmall() {
        // neqo's: 1 to 32, and one time in eight up to 31 * 32 more
        java.util.Random random = new java.util.Random(7);
        int small = 0;
        for (int i = 0; i < 8000; i++) {
            long pn = InitialPacketShape.FIREFOX.firstPacketNumber(random);
            assertTrue(pn >= 1 && pn <= 32 + 31 * 32, "pn " + pn);
            if (pn <= 32) small++;
        }
        // 225/256 of them, about 7031
        assertTrue(small > 6800 && small < 7250, small + " of 8000");
    }
}
