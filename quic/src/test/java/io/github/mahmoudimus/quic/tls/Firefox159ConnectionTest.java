package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.InstantSource;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The Firefox 159 profile's TLS client against the JDK's TLS server: what its hello asks of a
 * server (three key shares, P-521, SHA-1 for TLS 1.2, resumption without session_ticket) works.
 */
class Firefox159ConnectionTest {

    private static final String HOST = "tls.test";

    private ServerSocket server;
    /** The ClientHello of each connection the server accepted. */
    private final List<ClientHello> hellos = new CopyOnWriteArrayList<>();

    @AfterEach
    void close() throws IOException {
        if (server != null) server.close();
    }

    /** A JDK server for {@link #HOST} that answers each line with "echo: line", keeping each connection's hello. */
    private void serve(CertifiedKey key, String protocol, Consumer<SSLParameters> params) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("k", key.privateKey(), new char[0], key.chain().toArray(X509Certificate[]::new));
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(ks, new char[0]);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
        server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            while (!server.isClosed()) {
                try {
                    Socket plain = server.accept();
                    Thread.ofVirtual().start(() -> echo(plain, ctx, protocol, params));
                } catch (IOException e) {
                    return;
                }
            }
        });
    }

    private void echo(Socket plain, SSLContext ctx, String protocol, Consumer<SSLParameters> params) {
        try (plain) {
            DataInputStream in = new DataInputStream(plain.getInputStream());
            ByteArrayOutputStream raw = new ByteArrayOutputStream();
            ByteArrayOutputStream message = new ByteArrayOutputStream();
            int need = -1;
            while (need < 0 || message.size() < need) {
                byte[] header = new byte[5];
                in.readFully(header);
                byte[] fragment = new byte[((header[3] & 0xff) << 8) | (header[4] & 0xff)];
                in.readFully(fragment);
                raw.write(header);
                raw.write(fragment);
                message.write(fragment);
                byte[] m = message.toByteArray();
                if (need < 0 && m.length >= 4) need = 4 + (((m[1] & 0xff) << 16) | ((m[2] & 0xff) << 8) | (m[3] & 0xff));
            }
            byte[] m = message.toByteArray();
            hellos.add(ClientHello.decode(new Reader(Arrays.copyOfRange(m, 4, m.length))));
            SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(plain, new ByteArrayInputStream(raw.toByteArray()), true);
            s.setUseClientMode(false);
            SSLParameters p = s.getSSLParameters();
            p.setProtocols(new String[] {protocol});
            params.accept(p);
            s.setSSLParameters(p);
            s.startHandshake();
            InputStream sin = s.getInputStream();
            OutputStream out = s.getOutputStream();
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            for (int b; (b = sin.read()) >= 0; ) {
                if (b == '\n') {
                    out.write(("echo: " + line.toString(StandardCharsets.UTF_8) + "\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    line.reset();
                } else {
                    line.write(b);
                }
            }
        } catch (Exception e) {
            // the client's assertions report what went wrong
        }
    }

    private static TlsClientConnection.Config config(ClientSessionStore sessions) {
        return new TlsClientConnection.Config(BrowserProfiles.firefox159(), TestCerts.CA.trustManager(), null, sessions,
                Map.of(), CertificateDecompressor.ZLIB, new SecureRandom(), InstantSource.system(), 64 * 1024);
    }

    private TlsClientConnection connect(TlsClientConnection.Config config) throws IOException {
        Socket plain = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
        plain.setSoTimeout(10_000);
        return new TlsClientConnection(config, plain.getInputStream(), plain.getOutputStream(), HOST, HOST,
                List.of("h2", "http/1.1"), HOST + ":443");
    }

    private static String roundTrip(TlsClientConnection c, String text) throws IOException {
        byte[] data = (text + "\n").getBytes(StandardCharsets.UTF_8);
        c.write(data, 0, data.length);
        ByteArrayOutputStream got = new ByteArrayOutputStream();
        while (!got.toString(StandardCharsets.UTF_8).endsWith("\n")) {
            byte[] chunk = c.read();
            if (chunk == null) break;
            got.write(chunk);
        }
        return got.toString(StandardCharsets.UTF_8);
    }

    @Test
    void aTls13HandshakeAndAResumptionWithoutSessionTicket() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, HOST), "TLSv1.3", p -> {});
        ClientSessionMemoryCache sessions = new ClientSessionMemoryCache();
        TlsClientConnection first = connect(config(sessions));
        first.handshake();
        assertEquals("TLSv1.3", first.protocol());
        // the JDK's NewSessionTicket comes after the handshake; reading data takes it in
        assertEquals("echo: one\n", roundTrip(first, "one"));
        TlsClientConnection second = connect(config(sessions));
        second.handshake();
        assertTrue(second.resumed());
        assertEquals("echo: two\n", roundTrip(second, "two"));

        ClientHello fresh = hellos.get(0);
        ClientHello resumed = hellos.get(1);
        assertNotNull(Extension.find(fresh.extensions(), 35));
        assertNull(Extension.find(fresh.extensions(), ExtensionType.PRE_SHARED_KEY));
        assertNull(Extension.find(resumed.extensions(), 35), "a resuming hello has no session_ticket");
        byte[] psk = Extension.find(resumed.extensions(), ExtensionType.PRE_SHARED_KEY);
        assertNotNull(psk);
        assertEquals(ExtensionType.PRE_SHARED_KEY, resumed.extensions().getLast().type());
        // NSS sizes the GREASE ECH of a resuming hello with its PSK
        int freshPayload = echPayload(fresh);
        int resumedPayload = echPayload(resumed);
        assertTrue(resumedPayload >= freshPayload + psk.length + 4 - 31, freshPayload + " then " + resumedPayload);
        assertEquals(0, (resumedPayload - 16) % 32);
    }

    @Test
    void aHelloRetryRequestForP521IsAnsweredWithTheSameGreaseEch() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P256, HOST), "TLSv1.3", p -> p.setNamedGroups(new String[] {"secp521r1"}));
        TlsClientConnection c = connect(config(ClientSessionStore.NONE));
        c.handshake();
        assertEquals(NamedGroup.SECP521R1, c.negotiatedGroup());
        assertEquals("echo: retried\n", roundTrip(c, "retried"));
    }

    @Test
    void aP521CertificatesCertificateVerify() throws Exception {
        serve(TestCerts.CA.issue(KeyType.P521, HOST), "TLSv1.3", p -> {});
        TlsClientConnection c = connect(config(ClientSessionStore.NONE));
        c.handshake();
        assertEquals(SignatureScheme.ECDSA_SECP521R1_SHA512, c.peerSignatureScheme());
        assertEquals("echo: p521\n", roundTrip(c, "p521"));
    }

    @Test
    void tls12WithEcdheOnP521() throws Exception {
        // an RSA certificate: the JDK's server wants an ECDSA certificate's curve among the groups too
        serve(TestCerts.CA.issue(KeyType.RSA, HOST), "TLSv1.2", p -> p.setNamedGroups(new String[] {"secp521r1"}));
        TlsClientConnection c = connect(config(ClientSessionStore.NONE));
        c.handshake();
        assertEquals("TLSv1.2", c.protocol());
        assertEquals("echo: twelve\n", roundTrip(c, "twelve"));
    }

    private static int echPayload(ClientHello hello) throws Exception {
        Reader r = new Reader(Extension.find(hello.extensions(), ProfileExtensions.ENCRYPTED_CLIENT_HELLO));
        r.u8("type");
        r.u16("kdf");
        r.u16("aead");
        r.u8("config id");
        r.vector16(0, "enc");
        return r.vector16(1, "payload").length;
    }
}
