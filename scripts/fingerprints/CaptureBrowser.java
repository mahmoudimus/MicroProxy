

import io.github.mahmoudimus.http2.HpackDecoder;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.KeyStore;
import java.util.*;
import javax.net.ssl.*;

/**
 * Records a browser's raw ClientHello and its HTTP/2 connection preface frames, then answers 200.
 *
 * <p>Usage: {@code CaptureBrowser <out-dir> <port> <keystore.p12> [page]}. With {@code page}, {@code /}
 * is an HTML page loading a stylesheet, scripts, an image and a fetch, every request on the
 * connection is answered and recorded (with any PRIORITY frames), and the connection is kept until
 * the browser has been quiet for five seconds: what a browser's per-request HEADERS priorities are.
 */
public class CaptureBrowser {
  public static void main(String[] a) throws Exception {
    Path out = Path.of(a[0]); int port = Integer.parseInt(a[1]); boolean page = a.length > 3 && a[3].equals("page");
    KeyStore ks = KeyStore.getInstance("PKCS12"); ks.load(new FileInputStream(a[2]), "changeit".toCharArray());
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509"); kmf.init(ks, "changeit".toCharArray());
    SSLContext ctx = SSLContext.getInstance("TLS"); ctx.init(kmf.getKeyManagers(), null, null);
    try (ServerSocket ss = new ServerSocket(port, 50, InetAddress.getLoopbackAddress())) {
      ss.setSoTimeout(60000);
      for (int conn = 0; conn < 4; conn++) {
        Socket plain = ss.accept();
        DataInputStream in = new DataInputStream(plain.getInputStream());
        ByteArrayOutputStream raw = new ByteArrayOutputStream(), hs = new ByteArrayOutputStream();
        int need = -1;
        while (need < 0 || hs.size() < need) {
          byte[] h = new byte[5]; in.readFully(h); raw.write(h);
          byte[] rec = new byte[((h[3] & 0xff) << 8) | (h[4] & 0xff)]; in.readFully(rec); raw.write(rec); hs.write(rec);
          byte[] b = hs.toByteArray();
          if (need < 0 && b.length >= 4) need = 4 + (((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff));
        }
        Files.write(out.resolve("clienthello-" + conn + ".bin"), hs.toByteArray());
        SSLSocket tls = (SSLSocket) ctx.getSocketFactory().createSocket(plain, new ByteArrayInputStream(raw.toByteArray()), true);
        tls.setUseClientMode(false);
        tls.setHandshakeApplicationProtocolSelector((s, offered) -> offered.contains("h2") ? "h2" : offered.isEmpty() ? null : offered.get(0));
        try { tls.startHandshake(); } catch (IOException e) { System.out.println("conn " + conn + " handshake: " + e); plain.close(); continue; }
        System.out.println("conn " + conn + " " + tls.getSession().getProtocol() + " alpn=" + tls.getApplicationProtocol());
        if (!"h2".equals(tls.getApplicationProtocol())) { tls.close(); continue; }
        DataInputStream h2 = new DataInputStream(tls.getInputStream());
        byte[] preface = new byte[24]; h2.readFully(preface);
        OutputStream os = tls.getOutputStream();
        os.write(new byte[] {0, 0, 0, 4, 0, 0, 0, 0, 0}); os.write(new byte[] {0, 0, 0, 4, 1, 0, 0, 0, 0}); os.flush();
        ByteArrayOutputStream frames = new ByteArrayOutputStream();
        StringBuilder report = new StringBuilder();
        HpackDecoder dec = new HpackDecoder();
        while (true) {
          byte[] fh = new byte[9];
          try { h2.readFully(fh); } catch (SocketTimeoutException | EOFException quiet) { break; }
          int len = ((fh[0] & 0xff) << 16) | ((fh[1] & 0xff) << 8) | (fh[2] & 0xff), type = fh[3] & 0xff, flags = fh[4] & 0xff;
          int sid = ((fh[5] & 0x7f) << 24) | ((fh[6] & 0xff) << 16) | ((fh[7] & 0xff) << 8) | (fh[8] & 0xff);
          byte[] p = new byte[len]; h2.readFully(p); frames.write(fh); frames.write(p);
          report.append("frame type=").append(type).append(" flags=").append(flags).append(" stream=").append(sid).append(" len=").append(len);
          if (type == 4 && (flags & 1) == 0) for (int i = 0; i < len; i += 6)
            report.append(String.format(" [%d=%d]", ((p[i] & 0xff) << 8) | (p[i + 1] & 0xff), ((long) (p[i + 2] & 0xff) << 24) | ((p[i + 3] & 0xff) << 16) | ((p[i + 4] & 0xff) << 8) | (p[i + 5] & 0xff)));
          if (type == 8) report.append(" increment=").append(((long) (p[0] & 0x7f) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff));
          report.append('\n');
          if (type == 1) {
            int off = 0, end = len;
            if ((flags & 0x8) != 0) { end -= p[0] & 0xff; off = 1; }
            if ((flags & 0x20) != 0) { report.append("  priority excl=").append((p[off] & 0x80) != 0).append(" dep=").append(((p[off] & 0x7f) << 24) | ((p[off+1] & 0xff) << 16) | ((p[off+2] & 0xff) << 8) | (p[off+3] & 0xff)).append(" weight=").append((p[off + 4] & 0xff) + 1).append('\n'); off += 5; }
            dec.decode(sid, Arrays.copyOfRange(p, off, end)).forEach(f -> report.append("  ").append(f.name()).append(": ").append(f.value().length() > 60 ? f.value().substring(0, 60) + "..." : f.value()).append('\n'));
            if (!page) {
              os.write(new byte[] {0, 0, 1, 1, 5, 0, 0, 0, (byte) sid, (byte) 0x88}); os.flush();
              break;
            }
            respond(os, sid, report.substring(report.lastIndexOf(":path: ") + 7, report.indexOf("\n", report.lastIndexOf(":path: "))));
            tls.setSoTimeout(5000);
          }
          if (type == 2) {
            report.append("  priority frame excl=").append((p[0] & 0x80) != 0).append(" dep=").append(((p[0] & 0x7f) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)).append(" weight=").append((p[4] & 0xff) + 1).append('\n');
          }
        }
        Files.write(out.resolve("h2-preface-" + conn + ".bin"), frames.toByteArray());
        Files.writeString(out.resolve("h2-" + conn + ".txt"), report);
        System.out.print(report);
        tls.close();
      }
    } catch (SocketTimeoutException e) { System.out.println("done (timeout)"); }
  }

  static final String HTML = "<!doctype html><html><head><link rel=stylesheet href=/style.css>"
      + "<script src=/script.js></script><script async src=/async.js></script></head><body>"
      + "<img src=/image.png><script>fetch('/data.json')</script></body></html>";

  /** Answers a request on {@code sid}: the page for {@code /}, an empty 200 otherwise. */
  static void respond(OutputStream os, int sid, String path) throws IOException {
    byte[] body = path.equals("/") ? HTML.getBytes("UTF-8") : new byte[0];
    // :status 200, then content-type (static index 31) as a literal without indexing
    String type = path.equals("/") ? "text/html" : path.endsWith(".css") ? "text/css"
        : path.endsWith(".js") ? "text/javascript" : path.endsWith(".png") ? "image/png" : "application/json";
    ByteArrayOutputStream block = new ByteArrayOutputStream();
    block.write(0x88); block.write(0x0f); block.write(0x10); block.write(type.length()); block.write(type.getBytes("US-ASCII"));
    byte[] h = block.toByteArray();
    os.write(new byte[] {0, 0, (byte) h.length, 1, 4, (byte) (sid >>> 24), (byte) (sid >>> 16), (byte) (sid >>> 8), (byte) sid});
    os.write(h);
    os.write(new byte[] {0, (byte) (body.length >>> 8), (byte) body.length, 0, 1, (byte) (sid >>> 24), (byte) (sid >>> 16), (byte) (sid >>> 8), (byte) sid});
    os.write(body);
    os.flush();
  }
}
