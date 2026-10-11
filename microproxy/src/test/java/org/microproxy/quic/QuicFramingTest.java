package org.microproxy.quic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.microproxy.dns.DnsMessage;

/** {@link QuicFraming}'s rules and {@link QuicMessage}'s decoders. */
class QuicFramingTest {

    @Test
    void defaultsFrameDnsOverQuic() {
        QuicFraming d = QuicFraming.defaults();
        assertSame(MessageFramer.u16(), d.framerFor("doq", "dns.example", "dns.example"));
        assertNull(d.framerFor("other", "dns.example", null));
        assertNull(d.framerFor(null, null, null));
        assertNull(QuicFraming.none().framerFor("doq", null, null));
        assertEquals(1 << 20, d.maxMessageSize());
        assertEquals(2, d.errorCode());
    }

    @Test
    void rulesByAlpnHostAndAny() {
        QuicFraming f = QuicFraming.parse("myproto=varint, *.example.com=lf ,chat.test=crlf,*=u32");
        assertEquals(Map.of("doq", "u16", "myproto", "varint", "*.example.com", "lf", "chat.test", "crlf", "*", "u32"),
                f.rules());
        assertSame(MessageFramer.varint(), f.framerFor("myproto", "other.test", null));
        // A host rule wins over the ALPN's, by host or SNI, ignoring case; *.x matches x and below.
        assertSame(MessageFramer.lines(), f.framerFor("myproto", "a.b.EXAMPLE.com", null));
        assertSame(MessageFramer.lines(), f.framerFor("doq", "example.com", null));
        assertSame(MessageFramer.crlfLines(), f.framerFor("doq", "192.0.2.1", "chat.test."));
        assertSame(MessageFramer.u32(), f.framerFor("unknown", "else.test", null));
        assertNull(f.withRules("doq=none").framerFor("doq", "x", null), "none turns the default off");
        assertNull(f.withRule("*", "none").framerFor("unknown", "else.test", null));
        assertThrows(IllegalArgumentException.class, () -> QuicFraming.parse("doq"));
        assertThrows(IllegalArgumentException.class, () -> QuicFraming.parse("doq="));
    }

    @Test
    void customFramersByName() {
        MessageFramer nul = (data, offset, length) -> {
            for (int i = 0; i < length; i++) if (data[offset + i] == 0) return i + 1;
            return MessageFramer.NEED_MORE;
        };
        QuicFraming f = QuicFraming.parse("mine=script");
        assertThrows(IllegalArgumentException.class, f::validate);
        assertThrows(IllegalStateException.class, () -> f.framerFor("mine", null, null));
        QuicFraming named = f.withFramer("Script", nul);
        named.validate();
        assertSame(nul, named.framerFor("mine", null, null));
        assertSame(nul, QuicFraming.none().withRule("direct", nul).framerFor("direct", null, null));
        assertThrows(IllegalArgumentException.class, () -> f.withFramer("u16", nul));
        assertThrows(IllegalArgumentException.class, () -> f.withFramer("none", nul));
        assertEquals(64, f.withMaxMessageSize(64).maxMessageSize());
        assertEquals(0x10, f.withErrorCode(0x10).errorCode());
        assertThrows(IllegalArgumentException.class, () -> f.withMaxMessageSize(0));
        assertThrows(IllegalArgumentException.class, () -> f.withErrorCode(1L << 62));
        assertThrows(IllegalArgumentException.class, () -> MessageFramer.named("u8"));
    }

    @Test
    void messagesDecodeDnsAndRender() throws Exception {
        byte[] query = DnsMessage.query(9, "blocked.test", DnsMessage.A).encode();
        QuicMessage m = new QuicMessage(query, true, 4, "doq", Instant.EPOCH);
        assertEquals("blocked.test", m.dns().questions().getFirst().name());
        assertEquals("dns", m.render().orElseThrow().view());
        assertTrue(m.render().orElseThrow().text().contains("blocked.test. IN A"));
        QuicMessage answer = m.withDns(m.dns().reply(List.of(DnsMessage.ResourceRecord.of("blocked.test", DnsMessage.A,
                60, DnsMessage.Address.of("0.0.0.0"))))).withFromClient(false);
        assertEquals(false, answer.fromClient());
        assertEquals(4, answer.streamId());
        assertEquals("0.0.0.0", answer.dns().answers().getFirst().data().text());
        QuicMessage proto = new QuicMessage(new byte[] {0x08, (byte) 0x96, 0x01}, false, 0, "x", Instant.EPOCH);
        assertEquals(150L, ((Number) proto.protobuf().toPlain().get(1)).longValue());
        assertEquals("hi", m.withText("hi").text());
        assertEquals(2, m.withData("hi".getBytes(StandardCharsets.UTF_8)).length());
    }
}
