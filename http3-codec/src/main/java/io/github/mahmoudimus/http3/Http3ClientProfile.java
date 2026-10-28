package io.github.mahmoudimus.http3;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.random.RandomGenerator;

/**
 * What a client's HTTP/3 connections look like to a server: the SETTINGS on its control stream,
 * in order, with a GREASE setting (RFC 9114 section 7.2.4.1); a GREASE frame after them (section
 * 7.2.8); a PRIORITY_UPDATE frame (RFC 9218) for each request that has a {@code priority}; the
 * order of the request pseudo-headers; and whether the QPACK encoder and decoder streams are
 * opened only when there is something to send on them.
 *
 * @param name the profile's name
 * @param settings the settings, in order
 * @param greaseSetting whether a GREASE setting (random id and value) follows them
 * @param greaseFrame whether a GREASE frame (random type, 1 to 3 random bytes) follows SETTINGS
 * @param priorityUpdates whether a request's {@code priority} is also sent as a PRIORITY_UPDATE
 * @param pseudoHeaderOrder the request pseudo-headers in the order they are sent
 * @param lazyQpackStreams whether the QPACK streams wait for their first instruction
 */
public record Http3ClientProfile(String name, Map<Long, Long> settings, boolean greaseSetting, boolean greaseFrame,
        boolean priorityUpdates, List<String> pseudoHeaderOrder, boolean lazyQpackStreams) {

    /** PRIORITY_UPDATE for a request stream (RFC 9218 section 7.2). */
    public static final long PRIORITY_UPDATE_REQUEST = 0xf0700;

    public Http3ClientProfile {
        Objects.requireNonNull(name, "name");
        settings = Collections.unmodifiableMap(new LinkedHashMap<>(settings));
        pseudoHeaderOrder = List.copyOf(pseudoHeaderOrder);
    }

    /**
     * Chrome 156's, as captured over HTTP/3: QPACK_MAX_TABLE_CAPACITY 65536,
     * MAX_FIELD_SECTION_SIZE 262144, QPACK_BLOCKED_STREAMS 100, H3_DATAGRAM 1 and a GREASE
     * setting; a GREASE frame; PRIORITY_UPDATE for requests; pseudo-headers {@code :method
     * :authority :scheme :path}; QPACK streams opened when first needed.
     *
     * @return the profile
     */
    public static Http3ClientProfile chrome156() {
        Map<Long, Long> settings = new LinkedHashMap<>();
        settings.put(0x1L, 65_536L);
        settings.put(0x6L, 262_144L);
        settings.put(0x7L, 100L);
        settings.put(0x33L, 1L);
        return new Http3ClientProfile("chrome-156", settings, true, true, true,
                List.of(":method", ":authority", ":scheme", ":path"), true);
    }

    /** {@return the QPACK_MAX_TABLE_CAPACITY advertised, 0 when not} */
    public long qpackMaxTableCapacity() {
        return settings.getOrDefault(0x1L, 0L);
    }

    /** {@return the QPACK_BLOCKED_STREAMS advertised, 0 when not} */
    public long qpackBlockedStreams() {
        return settings.getOrDefault(0x7L, 0L);
    }

    /** {@return the MAX_FIELD_SECTION_SIZE advertised, 0 when not (unlimited)} */
    public long maxFieldSectionSize() {
        return settings.getOrDefault(0x6L, 0L);
    }

    /** A reserved identifier, {@code 0x1f * N + 0x21} (RFC 9114 sections 7.2.4.1, 7.2.8). */
    private static long reserved(RandomGenerator random) {
        return 0x1fL * random.nextLong(1L << 35) + 0x21;
    }

    /**
     * The SETTINGS for one connection: the profile's, then a GREASE setting with a random value.
     *
     * @param random the source of the GREASE setting
     * @return the settings, in order
     */
    public Map<Long, Long> settings(RandomGenerator random) {
        Map<Long, Long> out = new LinkedHashMap<>(settings);
        if (greaseSetting) out.put(reserved(random), random.nextLong(1L << 32));
        return out;
    }

    /**
     * The GREASE frame for one connection, or null when the profile sends none.
     *
     * @param random the source of its type and payload
     * @return the frame
     */
    public Http3Frame greaseFrame(RandomGenerator random) {
        if (!greaseFrame) return null;
        byte[] payload = new byte[1 + random.nextInt(3)];
        random.nextBytes(payload);
        return new Http3Frame.Unknown(reserved(random), payload);
    }

    /**
     * The PRIORITY_UPDATE for a request stream with a {@code priority} field value.
     *
     * @param streamId the request stream
     * @param priority the priority field value, such as {@code u=0, i}
     * @return the frame
     */
    public Http3Frame priorityUpdate(long streamId, String priority) {
        byte[] value = priority.getBytes(StandardCharsets.US_ASCII);
        byte[] id = QuicVarInt.encode(streamId);
        byte[] payload = new byte[id.length + value.length];
        System.arraycopy(id, 0, payload, 0, id.length);
        System.arraycopy(value, 0, payload, id.length, value.length);
        return new Http3Frame.Unknown(PRIORITY_UPDATE_REQUEST, payload);
    }

    /**
     * {@code fields} with its request pseudo-headers in the profile's order, the rest after them as
     * they were.
     *
     * @param fields a request's fields, pseudo-headers first
     * @return the reordered fields
     */
    public List<HeaderField> order(List<HeaderField> fields) {
        List<HeaderField> out = new ArrayList<>(fields.size());
        for (String name : pseudoHeaderOrder) {
            for (HeaderField f : fields) {
                if (f.name().equals(name)) out.add(f);
            }
        }
        for (HeaderField f : fields) {
            if (!pseudoHeaderOrder.contains(f.name())) out.add(f);
        }
        return out;
    }
}
