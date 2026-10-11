package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.Hkdf;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.Extensions.PskOffer;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.EncryptedExtensions;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Finished;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.NewSessionTicket;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ServerHello;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The resumed 0-RTT handshake of RFC 8448 section 4, from the ticket of section 3: the resumption
 * PSK, the early secret, the PSK binder over the truncated ClientHello, the client early traffic
 * secret, and the handshake, application and resumption secrets of the resumed session, byte for
 * byte.
 */
class Rfc8448ResumptionTest {

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replace(" ", ""));
    }

    private static HandshakeMessage decode(byte[] raw) throws QuicException {
        return HandshakeMessage.decode(raw[0] & 0xff, Arrays.copyOfRange(raw, 4, raw.length));
    }

    private static final CipherSuite SUITE = CipherSuite.TLS_AES_128_GCM_SHA256;

    /** The resumption master secret of section 3's session. */
    private static final byte[] RESUMPTION_MASTER = hex("7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c");
    private static final byte[] PSK = hex("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
    private static final byte[] EARLY_SECRET = hex("9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");
    private static final byte[] CLIENT_PRIVATE = hex("bff91188283846dd6a2134ef7180ca2b0b14fb10dce707b5098c0dddc813b2df");
    private static final byte[] CLIENT_PUBLIC = hex("e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b");
    private static final byte[] SERVER_PRIVATE = hex("de5b4476e7b490b2652d338acbf2948066f255f9440e23b98fc69835298dc107");
    private static final byte[] SERVER_PUBLIC = hex("121761ee42c333e1b9e77b60dd57c2053cd94512ab47f115e86eff50942cea31");
    private static final byte[] END_OF_EARLY_DATA = hex("05000000");

    private static final byte[] CLIENT_HELLO = hex("010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d9500000613011303130201"
            + "0001cd0000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400"
            + "3300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b00"
            + "03020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c"
            + "000240010015005700000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "2900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c936"
            + "7c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3"
            + "664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf2"
            + "97b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb002120"
            + "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d");
    private static final byte[] SERVER_HELLO = hex("0200005c03033ccfd2dec890222763472ae8136777c9d7358777bb66e91ea5122495f559ea2d00130100003400290002"
            + "000000330024001d0020121761ee42c333e1b9e77b60dd57c2053cd94512ab47f115e86eff50942cea31002b00020304");
    private static final byte[] ENCRYPTED_EXTENSIONS = hex("080000280026000a00140012001d00170018001901000101010201030104001c0002400100000000002a0000");
    private static final byte[] SERVER_FINISHED = hex("1400002048d3e0e1b3d907c6acff145e16090388c77b05c050b634ab1a88bbd0dd1a34b2");
    private static final byte[] CLIENT_FINISHED = hex("140000207230a9c952c25cd6138fc5e6628308c41c5335dd81b9f96bcea50fd32bda416d");
    /** Section 3's NewSessionTicket, which this handshake resumes. */
    private static final byte[] NEW_SESSION_TICKET = hex("040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf"
            + "1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827"
            + "db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228"
            + "bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934a"
            + "e4d3570008002a000400000400");

    @Test
    void resumptionPskFromTheTicket() throws Exception {
        NewSessionTicket nst = assertInstanceOf(NewSessionTicket.class, decode(NEW_SESSION_TICKET));
        assertArrayEquals(NEW_SESSION_TICKET, nst.encode());
        assertEquals(30, nst.lifetime());
        assertEquals(0xfad6aac5L, nst.ageAdd());
        assertArrayEquals(new byte[] {0, 0}, nst.nonce());
        assertEquals(0x400, Extensions.decodeMaxEarlyDataSize(Extension.find(nst.extensions(), ExtensionType.EARLY_DATA)));
        assertArrayEquals(PSK, KeySchedule.resumptionPsk(SUITE, RESUMPTION_MASTER, nst.nonce()));
        assertArrayEquals(EARLY_SECRET, new KeySchedule(SUITE, PSK).secret(), "early secret");
    }

    @Test
    void clientHelloOffersTheTicketLast() throws Exception {
        ClientHello hello = assertInstanceOf(ClientHello.class, decode(CLIENT_HELLO));
        assertArrayEquals(CLIENT_HELLO, hello.encode());
        List<Extension> extensions = hello.extensions();
        assertEquals(ExtensionType.PRE_SHARED_KEY, extensions.get(extensions.size() - 1).type());
        Extensions.expectEmpty(Extension.find(extensions, ExtensionType.EARLY_DATA), ExtensionType.EARLY_DATA);
        assertArrayEquals(new byte[] {Extensions.PSK_DHE_KE}, Extensions.decodePskKeyExchangeModes(
                Extension.find(extensions, ExtensionType.PSK_KEY_EXCHANGE_MODES)));
        assertArrayEquals(CLIENT_PUBLIC, Extensions.decodeKeyShareClient(
                Extension.find(extensions, ExtensionType.KEY_SHARE)).get(0).keyExchange());

        PskOffer offer = Extensions.decodePskOffer(Extension.find(extensions, ExtensionType.PRE_SHARED_KEY));
        NewSessionTicket nst = (NewSessionTicket) decode(NEW_SESSION_TICKET);
        assertEquals(1, offer.identities().size());
        assertArrayEquals(nst.ticket(), offer.identities().get(0).identity());
        assertEquals(0xfad6aacbL, offer.identities().get(0).obfuscatedTicketAge());
        assertEquals(6, (offer.identities().get(0).obfuscatedTicketAge() - nst.ageAdd()) & 0xffffffffL,
                "the ticket was 6 ms old");
        assertEquals(35, offer.bindersLength());
        assertArrayEquals(Extensions.encodePskOffer(offer.identities(), offer.binders()),
                Extension.find(extensions, ExtensionType.PRE_SHARED_KEY));
    }

    @Test
    void pskBinder() throws Exception {
        PskOffer offer = Extensions.decodePskOffer(
                Extension.find(((ClientHello) decode(CLIENT_HELLO)).extensions(), ExtensionType.PRE_SHARED_KEY));
        byte[] prefix = Arrays.copyOf(CLIENT_HELLO, CLIENT_HELLO.length - offer.bindersLength());
        assertEquals(477, prefix.length);
        byte[] hash = Transcript.newDigest(SUITE).digest(prefix);
        assertArrayEquals(hex("63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14"), hash, "binder hash");

        KeySchedule early = new KeySchedule(SUITE, PSK);
        byte[] binderKey = early.deriveSecret(KeySchedule.RESUMPTION_PSK_BINDER, Transcript.newDigest(SUITE).digest());
        assertArrayEquals(hex("69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256"), binderKey, "binder key");
        assertArrayEquals(hex("5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa"),
                SUITE.hkdf().expandLabel(binderKey, "finished", new byte[0], 32), "binder finished key");
        byte[] binder = hex("3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d");
        assertArrayEquals(binder, early.binder(hash));
        assertArrayEquals(binder, offer.binders().get(0));

        // The server's way: a running transcript, the binder over what it would be with the prefix
        Transcript transcript = new Transcript();
        transcript.start(SUITE);
        assertArrayEquals(binder, new KeySchedule(SUITE, PSK).binder(transcript.hashWith(prefix)));
    }

    @Test
    void clientEarlyTrafficSecret() {
        byte[] hash = Transcript.newDigest(SUITE).digest(CLIENT_HELLO);
        assertArrayEquals(hex("08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913"), hash);
        KeySchedule early = new KeySchedule(SUITE, PSK);
        byte[] clientEarly = early.deriveSecret(KeySchedule.CLIENT_EARLY_TRAFFIC, hash);
        assertArrayEquals(hex("3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62"), clientEarly);
        assertArrayEquals(hex("b2026866610937d7423e5be90862ccf24c0e6091186d34f812089ff5be2ef7df"),
                early.deriveSecret(KeySchedule.EARLY_EXPORTER_MASTER, hash));
        // The record-layer keys TLS derives for early data (QUIC uses "quic key" instead)
        Hkdf hkdf = SUITE.hkdf();
        assertArrayEquals(hex("920205a5b7bf2115e6fc5c2942834f54"), hkdf.expandLabel(clientEarly, "key", new byte[0], 16));
        assertArrayEquals(hex("6d475f0993c8e564610db2b9"), hkdf.expandLabel(clientEarly, "iv", new byte[0], 12));
    }

    @Test
    void resumedHandshakeSecrets() throws Exception {
        ServerHello serverHello = assertInstanceOf(ServerHello.class, decode(SERVER_HELLO));
        assertArrayEquals(SERVER_HELLO, serverHello.encode());
        assertEquals(0, Extensions.decodePskSelected(Extension.find(serverHello.extensions(), ExtensionType.PRE_SHARED_KEY)));
        assertArrayEquals(SERVER_PUBLIC, Extensions.decodeKeyShareServer(
                Extension.find(serverHello.extensions(), ExtensionType.KEY_SHARE)).keyExchange());
        EncryptedExtensions ee = assertInstanceOf(EncryptedExtensions.class, decode(ENCRYPTED_EXTENSIONS));
        Extensions.expectEmpty(Extension.find(ee.extensions(), ExtensionType.EARLY_DATA), ExtensionType.EARLY_DATA);

        byte[] shared = KeyExchange.x25519(CLIENT_PRIVATE).agree(SERVER_PUBLIC);
        assertArrayEquals(shared, KeyExchange.x25519(SERVER_PRIVATE).agree(CLIENT_PUBLIC));
        assertArrayEquals(hex("f44194756ff9ec9d25180635d66ea6824c6ab3bf179977be37f723570e7ccb2e"), shared);

        KeySchedule ks = new KeySchedule(SUITE, PSK);
        Transcript transcript = new Transcript();
        transcript.add(CLIENT_HELLO);
        transcript.start(SUITE);
        transcript.add(SERVER_HELLO);
        byte[] helloHash = transcript.hash();
        assertArrayEquals(hex("f736cb34fe25e701551bee6fd24c1cc7102a7daf9405cb15d97aafe16f757d03"), helloHash);

        ks.inputSharedSecret(shared);
        assertArrayEquals(hex("005cb112fd8eb4ccc623bb88a07c64b3ede1605363fc7d0df8c7ce4ff0fb4ae6"), ks.secret(),
                "handshake secret");
        byte[] clientHs = ks.deriveSecret(KeySchedule.CLIENT_HANDSHAKE_TRAFFIC, helloHash);
        byte[] serverHs = ks.deriveSecret(KeySchedule.SERVER_HANDSHAKE_TRAFFIC, helloHash);
        assertArrayEquals(hex("2faac08f851d35fea3604fcb4de82dc62c9b164a70974d0462e27f1ab278700f"), clientHs);
        assertArrayEquals(hex("fe927ae271312e8bf0275b581c54eef020450dc4ecffaa05a1a35d27518e7803"), serverHs);
        ks.inputEmpty();
        assertArrayEquals(hex("e2d32d4ed66dd37897a0e80c84107503ce58bf8aad4cb55a5002d77ecb890ece"), ks.secret(),
                "master secret");

        // A resumed server sends no Certificate or CertificateVerify
        transcript.add(ENCRYPTED_EXTENSIONS);
        byte[] serverFinished = ks.finishedVerifyData(serverHs, transcript.hash());
        assertArrayEquals(SERVER_FINISHED, new Finished(serverFinished).encode());
        transcript.add(SERVER_FINISHED);
        byte[] finishedHash = transcript.hash();
        assertArrayEquals(hex("b0aeffc46a2cfe33114e6fd7d51f9f04b1ca3c497dab08934a774a9d9ad7dbf3"), finishedHash);
        assertArrayEquals(hex("2abbf2b8e381d23dbebe1dd2a7d16a8bf484cb4950d23fb7fb7fa8547062d9a1"),
                ks.deriveSecret(KeySchedule.CLIENT_APPLICATION_TRAFFIC, finishedHash));
        assertArrayEquals(hex("cc21f1bf8feb7dd5fa505bd9c4b468a9984d554a993dc49e6d285598fb672691"),
                ks.deriveSecret(KeySchedule.SERVER_APPLICATION_TRAFFIC, finishedHash));
        assertArrayEquals(hex("3fd93d4ffddc98e64b14dd107aedf8ee4add23f4510f58a4592d0b201bee56b4"),
                ks.deriveSecret(KeySchedule.EXPORTER_MASTER, finishedHash));

        // TLS over TCP sends EndOfEarlyData here; QUIC does not (RFC 9001 section 8.3)
        transcript.add(END_OF_EARLY_DATA);
        byte[] clientFinished = ks.finishedVerifyData(clientHs, transcript.hash());
        assertArrayEquals(CLIENT_FINISHED, new Finished(clientFinished).encode());
        transcript.add(CLIENT_FINISHED);
        byte[] resumptionHash = transcript.hash();
        assertArrayEquals(hex("c3c122e0bd907a4a3ff6112d8fd53dbf89c773d9552e8b6b9d56d361b3a97bf6"), resumptionHash);
        byte[] resumptionMaster = ks.deriveSecret(KeySchedule.RESUMPTION_MASTER, resumptionHash);
        assertArrayEquals(hex("5e95bdf1f89005ea2e9aa0ba85e728e3c19c5fe0c699e3f5bee59faebd0b5406"), resumptionMaster);
        assertNotNull(KeySchedule.resumptionPsk(SUITE, resumptionMaster, new byte[] {0}));
    }
}
