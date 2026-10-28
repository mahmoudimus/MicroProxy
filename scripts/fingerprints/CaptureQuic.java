package org.microproxy.impl;

import io.github.mahmoudimus.quic.crypto.DirectionalKeys;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.frame.FrameDecoder;
import io.github.mahmoudimus.quic.packet.Packet;
import io.github.mahmoudimus.quic.packet.PacketType;
import io.github.mahmoudimus.quic.packet.ProtectedPacket;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.util.*;
import org.microproxy.ClientHello;

/**
 * Records a browser's first QUIC Initial datagrams: their sizes, their packets' frames, and the
 * ClientHello they carry, reassembled. It answers nothing, so the browser's retransmissions show
 * the same hello again.
 *
 * <p>In package {@code org.microproxy.impl} for its ClientHello parser, so it is compiled rather
 * than run as a source file:
 * <pre>
 * javac -d out -cp quic/target/classes:microproxy/target/classes:http2-codec/target/classes:http3-codec/target/classes \
 *     scripts/fingerprints/CaptureQuic.java
 * java -cp out:... org.microproxy.impl.CaptureQuic &lt;out-dir&gt; &lt;udp-port&gt;
 * </pre>
 * Point the browser at {@code https://quic.test:<port>/} over HTTP/3: Chrome with {@code
 * --origin-to-force-quic-on=quic.test:<port> --host-resolver-rules="MAP quic.test 127.0.0.1"};
 * Firefox with the preferences {@code network.dns.localDomains=quic.test} and {@code
 * network.http.http3.alt-svc-mapping-for-testing=quic.test;h3=:<port>}.
 */
public class CaptureQuic {
  public static void main(String[] a) throws Exception {
    Path out = Path.of(a[0]); int port = Integer.parseInt(a[1]);
    try (DatagramSocket s = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), port))) {
      s.setSoTimeout(30000);
      QuicClientHello parser = null; ClientHello hello = null; DirectionalKeys keys = null;
      StringBuilder log = new StringBuilder(); int n = 0;
      while (hello == null && n < 16) {
        byte[] buf = new byte[65535]; DatagramPacket p = new DatagramPacket(buf, buf.length); s.receive(p);
        byte[] d = Arrays.copyOf(buf, p.getLength()); Files.write(out.resolve("initial-datagram-" + n + ".bin"), d);
        ByteBuffer bb = ByteBuffer.wrap(d);
        if (parser == null) { parser = QuicClientHello.start(bb.duplicate()); keys = Keys.initial(parser.version(), parser.destinationId(), true).remote(); }
        log.append("datagram ").append(n).append(" bytes=").append(d.length).append('\n');
        ByteBuffer copy = ByteBuffer.wrap(d.clone());
        for (ProtectedPacket pp : ProtectedPacket.splitDatagram(copy, 0, false)) {
          log.append("  packet ").append(pp.type());
          if (pp.type() == PacketType.INITIAL) {
            Packet pk = pp.unprotect(keys, -1);
            log.append(" pn=").append(pk.header().packetNumber()).append(" frames:");
            for (Frame f : FrameDecoder.decodeAll(pk.payload(), PacketType.INITIAL)) {
              if (f instanceof Frame.Crypto c) log.append(" CRYPTO(").append(c.offset()).append('+').append(c.data().remaining()).append(')');
              else if (f instanceof Frame.Padding pad) log.append(" PADDING(").append(pad.length()).append(')');
              else log.append(' ').append(f.getClass().getSimpleName().toUpperCase());
            }
          }
          log.append('\n');
        }
        hello = parser.offer(bb.duplicate()); n++;
      }
      Files.write(out.resolve("quic-clienthello.bin"), hello.raw());
      Files.writeString(out.resolve("quic-initial-layout.txt"), log);
      System.out.print(log);
      System.out.println("ja4 " + org.microproxy.extras.TlsFingerprints.ja4(hello, true) + " alpn=" + hello.alpnProtocols() + " exts=" + hello.extensionTypes());
    }
  }
}
