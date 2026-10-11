package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.Hkdf;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateMessage;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateVerify;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.EncryptedExtensions;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Finished;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ServerHello;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECPrivateKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The TLS 1.3 traces of RFC 8448: section 3 (a simple 1-RTT handshake) and section 5 (HelloRetryRequest). */
class Rfc8448Test {

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replace(" ", ""));
    }

    private static HandshakeMessage decode(byte[] raw) throws QuicException {
        return HandshakeMessage.decode(raw[0] & 0xff, Arrays.copyOfRange(raw, 4, raw.length));
    }

    private static final CipherSuite SUITE = CipherSuite.TLS_AES_128_GCM_SHA256;

    // --- section 3 ---

    private static final byte[] CLIENT_PRIVATE = hex("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");
    private static final byte[] CLIENT_PUBLIC = hex("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");
    private static final byte[] SERVER_PRIVATE = hex("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");
    private static final byte[] SERVER_PUBLIC = hex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f");

    private static final byte[] CLIENT_HELLO = hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece700000613011303130201"
            + "0000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400"
            + "230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b00"
            + "03020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c"
            + "00024001");
    private static final byte[] SERVER_HELLO = hex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024"
            + "001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
    private static final byte[] ENCRYPTED_EXTENSIONS = hex("080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000");
    private static final byte[] CERTIFICATE = hex("0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a"
            + "06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a"
            + "0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d98"
            + "0836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced4312"
            + "0998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d0"
            + "3e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b060355"
            + "1d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f"
            + "8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102"
            + "702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8"
            + "f8961229ac9187b42b4de10000");
    private static final byte[] CERTIFICATE_VERIFY = hex("0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d3"
            + "3a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c"
            + "9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3");
    private static final byte[] SERVER_FINISHED = hex(
            "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718");
    private static final byte[] CLIENT_FINISHED = hex(
            "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61");

    @Test
    void x25519KeyExchange() throws Exception {
        KeyExchange client = KeyExchange.x25519(CLIENT_PRIVATE);
        KeyExchange server = KeyExchange.x25519(SERVER_PRIVATE);
        assertArrayEquals(CLIENT_PUBLIC, client.publicKey());
        assertArrayEquals(SERVER_PUBLIC, server.publicKey());
        byte[] shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        assertArrayEquals(shared, client.agree(SERVER_PUBLIC));
        assertArrayEquals(shared, server.agree(CLIENT_PUBLIC));
    }

    @Test
    void keyScheduleAndFinished() throws Exception {
        byte[] shared = KeyExchange.x25519(CLIENT_PRIVATE).agree(SERVER_PUBLIC);
        KeySchedule ks = new KeySchedule(SUITE);
        assertArrayEquals(hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"), ks.secret(),
                "early secret");

        Transcript transcript = new Transcript();
        transcript.add(CLIENT_HELLO);
        transcript.start(SUITE);
        transcript.add(SERVER_HELLO);
        byte[] helloHash = transcript.hash();
        assertArrayEquals(hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"), helloHash);

        ks.inputSharedSecret(shared);
        assertArrayEquals(hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), ks.secret(),
                "handshake secret");
        byte[] clientHs = ks.deriveSecret(KeySchedule.CLIENT_HANDSHAKE_TRAFFIC, helloHash);
        byte[] serverHs = ks.deriveSecret(KeySchedule.SERVER_HANDSHAKE_TRAFFIC, helloHash);
        assertArrayEquals(hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), clientHs);
        assertArrayEquals(hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), serverHs);
        // The record-layer keys TLS would derive from them (QUIC uses "quic key" instead).
        Hkdf hkdf = SUITE.hkdf();
        assertArrayEquals(hex("3fce516009c21727d0f2e4e86ee403bc"), hkdf.expandLabel(serverHs, "key", new byte[0], 16));
        assertArrayEquals(hex("5d313eb2671276ee13000b30"), hkdf.expandLabel(serverHs, "iv", new byte[0], 12));

        ks.inputEmpty();
        assertArrayEquals(hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), ks.secret(),
                "master secret");

        transcript.add(ENCRYPTED_EXTENSIONS);
        transcript.add(CERTIFICATE);
        transcript.add(CERTIFICATE_VERIFY);
        byte[] serverFinished = ks.finishedVerifyData(serverHs, transcript.hash());
        assertArrayEquals(hex("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"), serverFinished);
        assertArrayEquals(SERVER_FINISHED, new Finished(serverFinished).encode());

        transcript.add(SERVER_FINISHED);
        byte[] serverFinishedHash = transcript.hash();
        assertArrayEquals(hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"), serverFinishedHash);
        assertArrayEquals(hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"),
                ks.deriveSecret(KeySchedule.CLIENT_APPLICATION_TRAFFIC, serverFinishedHash));
        assertArrayEquals(hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"),
                ks.deriveSecret(KeySchedule.SERVER_APPLICATION_TRAFFIC, serverFinishedHash));
        assertArrayEquals(hex("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50"),
                ks.deriveSecret(KeySchedule.EXPORTER_MASTER, serverFinishedHash));

        byte[] clientFinished = ks.finishedVerifyData(clientHs, serverFinishedHash);
        assertArrayEquals(hex("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"), clientFinished);
        assertArrayEquals(CLIENT_FINISHED, new Finished(clientFinished).encode());

        transcript.add(CLIENT_FINISHED);
        byte[] clientFinishedHash = transcript.hash();
        assertArrayEquals(hex("209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d"), clientFinishedHash);
        assertArrayEquals(hex("7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"),
                ks.deriveSecret(KeySchedule.RESUMPTION_MASTER, clientFinishedHash));
    }

    @Test
    void messagesDecodeAndReencode() throws Exception {
        for (byte[] raw : List.of(CLIENT_HELLO, SERVER_HELLO, ENCRYPTED_EXTENSIONS, CERTIFICATE, CERTIFICATE_VERIFY,
                SERVER_FINISHED, CLIENT_FINISHED)) {
            HandshakeMessage message = decode(raw);
            assertArrayEquals(raw, message.encode(), HandshakeType.name(message.type()));
        }
        ClientHello hello = assertInstanceOf(ClientHello.class, decode(CLIENT_HELLO));
        assertEquals("server", Extensions.decodeServerName(Extension.find(hello.extensions(), ExtensionType.SERVER_NAME)));
        assertArrayEquals(new int[] {0x1301, 0x1303, 0x1302}, hello.cipherSuites());
        assertArrayEquals(new int[] {0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104},
                Extensions.decodeU16List(Extension.find(hello.extensions(), ExtensionType.SUPPORTED_GROUPS), "groups"));
        List<Extensions.KeyShare> shares =
                Extensions.decodeKeyShareClient(Extension.find(hello.extensions(), ExtensionType.KEY_SHARE));
        assertEquals(1, shares.size());
        assertArrayEquals(CLIENT_PUBLIC, shares.get(0).keyExchange());
        assertArrayEquals(new int[] {HandshakeMessage.TLS13}, Extensions.decodeSupportedVersionsClient(
                Extension.find(hello.extensions(), ExtensionType.SUPPORTED_VERSIONS)));
        assertArrayEquals(new byte[] {1}, Extensions.decodePskKeyExchangeModes(
                Extension.find(hello.extensions(), ExtensionType.PSK_KEY_EXCHANGE_MODES)));

        ServerHello serverHello = assertInstanceOf(ServerHello.class, decode(SERVER_HELLO));
        assertFalse(serverHello.isHelloRetryRequest());
        assertEquals(0x1301, serverHello.cipherSuite());
        assertArrayEquals(SERVER_PUBLIC, Extensions.decodeKeyShareServer(
                Extension.find(serverHello.extensions(), ExtensionType.KEY_SHARE)).keyExchange());

        EncryptedExtensions ee = assertInstanceOf(EncryptedExtensions.class, decode(ENCRYPTED_EXTENSIONS));
        Extensions.expectEmpty(Extension.find(ee.extensions(), ExtensionType.SERVER_NAME), ExtensionType.SERVER_NAME);
    }

    @Test
    void certificateVerifySignature() throws Exception {
        CertificateMessage certificate = assertInstanceOf(CertificateMessage.class, decode(CERTIFICATE));
        X509Certificate cert = CertificateChecks.parse(certificate.entries()).get(0);
        CertificateVerify verify = assertInstanceOf(CertificateVerify.class, decode(CERTIFICATE_VERIFY));
        assertEquals(SignatureScheme.RSA_PSS_RSAE_SHA256, SignatureScheme.forCode(verify.scheme()));
        assertTrue(SignatureScheme.RSA_PSS_RSAE_SHA256.compatibleWith(cert.getPublicKey()));

        Transcript transcript = new Transcript();
        transcript.start(SUITE);
        transcript.add(CLIENT_HELLO);
        transcript.add(SERVER_HELLO);
        transcript.add(ENCRYPTED_EXTENSIONS);
        transcript.add(CERTIFICATE);
        byte[] content = Signatures.content(true, transcript.hash());
        assertTrue(Signatures.verify(SignatureScheme.RSA_PSS_RSAE_SHA256, cert.getPublicKey(), content,
                verify.signature()));
        assertFalse(Signatures.verify(SignatureScheme.RSA_PSS_RSAE_SHA256, cert.getPublicKey(),
                Signatures.content(false, transcript.hash()), verify.signature()), "client context must not verify");
        byte[] corrupted = verify.signature().clone();
        corrupted[10] ^= 1;
        assertFalse(Signatures.verify(SignatureScheme.RSA_PSS_RSAE_SHA256, cert.getPublicKey(), content, corrupted));
    }

    // --- section 5 ---

    private static final byte[] RETRY_CLIENT_HELLO_1 = hex("010000b00303b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee9258a346677b6f00000613011303130201"
            + "0000810000000b0009000006736572766572ff01000100000a00080006001d00170018003300260024001d0020e8e8e3"
            + "f3b93a25ed97a14a7dcacb8a272c6288e585c6484d05262fcad062ad1f002b0003020304000d0020001e040305030603"
            + "020308040805080604010501060102010402050206020202002d00020101001c00024001");
    private static final String COOKIE = "71dcd04bb88bc3189119398a00000000eefafc76c146b823b096f8aacad365dd0030953f"
            + "4edf625636e5f21bb2e23fcc654b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d6e50781b5eda4aa15b0c8be7"
            + "78257d16aa3030e9e7841dd9e4c0342267e8ca0caf571fb2b7cff0f934b0";
    private static final byte[] RETRY_REQUEST = hex("020000ac0303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c00130100008400330002"
            + "0017002c0074007271dcd04bb88bc3189119398a00000000eefafc76c146b823b096f8aacad365dd0030953f4edf6256"
            + "36e5f21bb2e23fcc654b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d6e50781b5eda4aa15b0c8be778257d16"
            + "aa3030e9e7841dd9e4c0342267e8ca0caf571fb2b7cff0f934b0002b00020304");
    private static final byte[] RETRY_CLIENT_PRIVATE = hex(
            "ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39");
    private static final byte[] RETRY_CLIENT_PUBLIC = hex("04a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830e"
            + "ac8f0151812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780");
    private static final byte[] RETRY_CLIENT_HELLO_2 = hex("010001fc0303b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee9258a346677b6f00000613011303130201"
            + "0001cd0000000b0009000006736572766572ff01000100000a00080006001d001700180033004700450017004104a6da"
            + "7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151812677c4d6d2237e85cf01d6910cfb83954e"
            + "76ba7352830534159897e8065780002b0003020304000d0020001e040305030603020308040805080604010501060102"
            + "010402050206020202002c0074007271dcd04bb88bc3189119398a00000000eefafc76c146b823b096f8aacad365dd00"
            + "30953f4edf625636e5f21bb2e23fcc654b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d6e50781b5eda4aa15b"
            + "0c8be778257d16aa3030e9e7841dd9e4c0342267e8ca0caf571fb2b7cff0f934b0002d00020101001c00024001001500"
            + "af0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] RETRY_SERVER_PUBLIC = hex("04583e054b7a66672ae020ad9d2686fcc85b5ad41a134a0f03ee72b893"
            + "052bd85b4c8de6776f5b04ac07d83540eab3e3d9c547bc6528c4317d294686093a6cad7d");
    private static final byte[] RETRY_SERVER_HELLO = hex("020000770303bb341d847fd789c47c387172dc0c9bf147fccacb5043d86ca4c598d3ff571b9800130100004f00330045"
            + "0017004104583e054b7a66672ae020ad9d2686fcc85b5ad41a134a0f03ee72b893052bd85b4c8de6776f5b04ac07d835"
            + "40eab3e3d9c547bc6528c4317d294686093a6cad7d002b00020304");

    @Test
    void helloRetryRequestTranscript() throws Exception {
        ServerHello retry = assertInstanceOf(ServerHello.class, decode(RETRY_REQUEST));
        assertTrue(retry.isHelloRetryRequest());
        assertEquals(NamedGroup.SECP256R1.code(),
                Extensions.decodeKeyShareRetry(Extension.find(retry.extensions(), ExtensionType.KEY_SHARE)));
        assertArrayEquals(hex(COOKIE), Extensions.decodeCookie(Extension.find(retry.extensions(), ExtensionType.COOKIE)));
        for (byte[] raw : List.of(RETRY_CLIENT_HELLO_1, RETRY_REQUEST, RETRY_CLIENT_HELLO_2, RETRY_SERVER_HELLO)) {
            assertArrayEquals(raw, decode(raw).encode());
        }

        PrivateKey p256 = KeyFactory.getInstance("EC").generatePrivate(
                new ECPrivateKeySpec(new BigInteger(1, RETRY_CLIENT_PRIVATE), EcCurves.P256));
        KeyExchange client = KeyExchange.of(NamedGroup.SECP256R1, p256, RETRY_CLIENT_PUBLIC);
        byte[] shared = client.agree(RETRY_SERVER_PUBLIC);
        assertArrayEquals(hex("c142ce13ca11b5c2233652e63ad3d97844f1621fbfb9de69d547dc8fedeabeb4"), shared);

        // The first ClientHello becomes message_hash(Hash(ClientHello1)).
        Transcript transcript = new Transcript();
        transcript.add(RETRY_CLIENT_HELLO_1);
        transcript.start(SUITE);
        transcript.rollupForRetry();
        transcript.add(RETRY_REQUEST);
        transcript.add(RETRY_CLIENT_HELLO_2);
        transcript.add(RETRY_SERVER_HELLO);
        byte[] hash = transcript.hash();
        assertArrayEquals(hex("8aa8e828ec2f8a884fec95a3139de01c15a3daa7ff5bfc3f4bfcc21b438d7bf8"), hash);

        KeySchedule ks = new KeySchedule(SUITE);
        ks.inputSharedSecret(shared);
        assertArrayEquals(hex("ce022e5e6e81e50736d773f2d3adfce8220d049bf510f0dbfac927ef4243b148"), ks.secret());
        assertArrayEquals(hex("158aa7ab8855073582b41d674b4055cabcc534728f659314861b4e08e2011566"),
                ks.deriveSecret(KeySchedule.CLIENT_HANDSHAKE_TRAFFIC, hash));
        assertArrayEquals(hex("3403e781e2af7b6508da28574f6e95a1abf162de83a97927c37672a4a0cef8a1"),
                ks.deriveSecret(KeySchedule.SERVER_HANDSHAKE_TRAFFIC, hash));
        ks.inputEmpty();
        assertArrayEquals(hex("1131545d0baf79ddce9b87f06945781a57dd18ef378dcd2060f8f9a569027ed8"), ks.secret());
    }

    @Test
    void quicKeyUpdateLabel() {
        // RFC 9001 section 6.1: the next secret is HKDF-Expand-Label(secret, "quic ku", "", Hash.length).
        byte[] secret = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        KeySchedule ks = new KeySchedule(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        // RFC 9001 appendix A.5 gives this secret's "quic ku" successor.
        assertArrayEquals(hex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"),
                ks.nextApplicationSecret(secret));
    }
}
