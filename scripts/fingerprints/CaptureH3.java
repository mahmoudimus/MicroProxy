package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.http3.QpackDecoder;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

/**
 * Completes an HTTP/3 connection with a browser and logs its unidirectional streams, its control
 * stream's frames and its first request's fields.
 *
 * <pre>
 * java -cp quic/target/classes:http3-codec/target/classes scripts/fingerprints/CaptureH3.java &lt;out-dir&gt; &lt;udp-port&gt;
 * </pre>
 * It serves {@code q.crt.der} and {@code q.key.der} (PKCS#8) from the working directory: a
 * certificate for {@code quic.test} the browser trusts. Chrome takes one it does not with {@code
 * --ignore-certificate-errors-spki-list=<sha256 of its key>}; Firefox needs the issuing CA in its
 * profile and {@code network.http.http3.disable_when_third_party_roots_found=false}, or it closes
 * HTTP/3 connections to servers whose certificates chain to a root it does not ship. The rest of
 * the setup is {@link CaptureQuic}'s.
 */
public class CaptureH3 {
  static long varint(InputStream in) throws IOException {
    int b = in.read(); if (b < 0) throw new EOFException();
    int len = 1 << (b >> 6); long v = b & 0x3f;
    for (int i = 1; i < len; i++) v = (v << 8) | in.read();
    return v;
  }
  static final StringBuilder LOG = new StringBuilder();
  static synchronized void log(String s) { LOG.append(s).append('\n'); System.out.println(s); }
  public static void main(String[] a) throws Exception {
    Path out = Path.of(a[0]);
    java.security.PrivateKey key = java.security.KeyFactory.getInstance("EC").generatePrivate(
        new java.security.spec.PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("q.key.der"))));
    java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory
        .getInstance("X.509").generateCertificate(new ByteArrayInputStream(Files.readAllBytes(Path.of("q.crt.der"))));
    TlsConfig tls = TlsConfig.builder().certificate(io.github.mahmoudimus.quic.tls.CertifiedKey.of(key, cert)).alpnProtocols("h3").build();
    QuicServer server = QuicServer.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), Integer.parseInt(a[1])),
        ServerConfig.builder(tls).build(), EndpointConfig.defaults(), (from, d) -> { log("datagram from " + from + " bytes=" + d.remaining()); return false; });
    QuicConnection c = server.accept(java.time.Duration.ofSeconds(30));
    log("connection accepted");
    QuicStream control = c.openUnidirectionalStream();
    // control stream type 0x00, empty SETTINGS (0x04, length 0)
    control.getOutputStream().write(new byte[] {0x00, 0x04, 0x00}); control.getOutputStream().flush();
    long deadline = System.currentTimeMillis() + 8000;
    QpackDecoder qpack = new QpackDecoder(0, 100);
    while (System.currentTimeMillis() < deadline) {
      QuicStream s;
      try { s = c.acceptStream(); } catch (IOException e) { break; }
      long id = s.id();
      boolean uni = (id & 0x2) != 0;
      Thread.ofVirtual().start(() -> {
        try {
          InputStream in = s.getInputStream();
          if (uni) {
            long type = varint(in);
            log("uni stream " + id + " type=0x" + Long.toHexString(type));
            if (type == 0) {
              while (true) {
                long ft = varint(in); long fl = varint(in); byte[] p = in.readNBytes((int) fl);
                StringBuilder sb = new StringBuilder("  control frame type=0x" + Long.toHexString(ft) + " len=" + fl);
                if (ft != 4) sb.append(" payload=").append(HexFormat.of().formatHex(p));
                if (ft == 4) { ByteArrayInputStream b = new ByteArrayInputStream(p); while (b.available() > 0) sb.append(String.format(" [0x%x=%d]", varint(b), varint(b))); }
                log(sb.toString());
              }
            } else {
              byte[] rest = in.readNBytes(64);
              log("  bytes " + HexFormat.of().formatHex(rest));
            }
          } else {
            while (true) {
              long ft = varint(in); long fl = varint(in); byte[] p = in.readNBytes((int) fl);
              log("bidi " + id + " frame type=0x" + Long.toHexString(ft) + " len=" + fl);
              if (ft == 1) {
                synchronized (qpack) { qpack.decode(id, p).forEach(h -> log("  " + h.name() + ": " + (h.value().length() > 70 ? h.value().substring(0, 70) + "..." : h.value()))); }
                Files.writeString(out.resolve("h3-log.txt"), LOG);
                break;
              }
            }
          }
        } catch (Exception e) { log("stream " + id + " ended: " + e); }
      });
    }
    Files.writeString(out.resolve("h3-log.txt"), LOG);
    System.exit(0);
  }
}
