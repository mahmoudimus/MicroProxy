// Ported from rustls src/msgs/persist.rs (ServerSessionValue, CommonServerSessionValue and
// Tls13ServerSessionValue: the session state a stateless ticket carries, and its codec), with the
// QUIC transport parameters a server needs to decide on 0-RTT (RFC 9000 section 7.4.1) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * What a server seals into a session ticket, so that it can resume the session statelessly: the
 * resumption PSK and its suite, the age obfuscation, issue time and lifetime, whether and how much
 * early data the ticket allows, the server name and ALPN protocol of the session, the server's
 * QUIC transport parameters at the time, and a random identifier for single-use checks.
 */
record ServerTicket(CipherSuite suite, byte[] psk, long ageAdd, Instant issued, long lifetimeSeconds,
        long maxEarlyDataSize, String serverName, String alpn, byte[] transportParameters, byte[] id) {

    private static final int VERSION = 1;
    static final int ID_LENGTH = 16;

    byte[] encode() {
        Writer w = new Writer();
        w.u8(VERSION).u16(suite.code()).vector8(psk).u32(ageAdd);
        long millis = issued.toEpochMilli();
        w.u32(millis >>> 32).u32(millis & 0xffffffffL);
        w.u32(lifetimeSeconds).u32(maxEarlyDataSize);
        if (serverName != null) {
            w.u8(1).vector8(serverName.getBytes(StandardCharsets.US_ASCII));
        } else {
            w.u8(0);
        }
        w.vector8(alpn.getBytes(StandardCharsets.ISO_8859_1));
        w.vector16(transportParameters);
        w.bytes(id);
        return w.toByteArray();
    }

    /** Decodes the state a ticket opened to; null if it is not in this format. */
    static ServerTicket decode(byte[] data) {
        try {
            Reader r = new Reader(data);
            if (r.u8("version") != VERSION) {
                return null;
            }
            CipherSuite suite = CipherSuite.forCode(r.u16("suite"));
            byte[] psk = r.vector8(1, "psk");
            long ageAdd = r.u32("age_add");
            long millis = (r.u32("issued") << 32) | r.u32("issued");
            long lifetime = r.u32("lifetime");
            long maxEarlyData = r.u32("max_early_data_size");
            String serverName = r.u8("sni") == 1 ? new String(r.vector8(1, "sni"), StandardCharsets.US_ASCII) : null;
            String alpn = new String(r.vector8(1, "alpn"), StandardCharsets.ISO_8859_1);
            byte[] parameters = r.vector16(0, "transport parameters");
            byte[] id = r.bytes(ID_LENGTH, "id");
            r.expectEnd("ticket");
            if (suite == null) {
                return null;
            }
            return new ServerTicket(suite, psk, ageAdd, Instant.ofEpochMilli(millis), lifetime, maxEarlyData,
                    serverName, alpn, parameters, id);
        } catch (QuicException e) {
            return null;
        }
    }
}
