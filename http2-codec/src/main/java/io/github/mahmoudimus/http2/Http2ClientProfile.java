package io.github.mahmoudimus.http2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * What a client's HTTP/2 connections look like to a server, the parts of it that HTTP/2
 * fingerprints (Akamai's among them) record:
 * <ul>
 *   <li>the SETTINGS it opens with, in order;</li>
 *   <li>the WINDOW_UPDATE that grows the connection window;</li>
 *   <li>the priority its request HEADERS carry;</li>
 *   <li>the order of the request pseudo-headers.</li>
 * </ul>
 *
 * @param name the profile's name, such as {@code chrome-156}
 * @param settings the SETTINGS identifiers and values, in the order they are sent
 * @param connectionWindowIncrement the connection WINDOW_UPDATE increment sent after SETTINGS, 0 for none
 * @param headersPriority the RFC 7540 priority on every request's HEADERS, or null for none
 * @param pseudoHeaderOrder the request pseudo-headers in the order they are sent
 */
public record Http2ClientProfile(String name, Map<Integer, Long> settings, int connectionWindowIncrement,
        Frame.PrioritySpec headersPriority, List<String> pseudoHeaderOrder) {

    private static final List<String> REQUEST_PSEUDO_HEADERS = List.of(":method", ":scheme", ":authority", ":path");

    public Http2ClientProfile {
        Objects.requireNonNull(name, "name");
        settings = Collections.unmodifiableMap(new LinkedHashMap<>(settings));
        if (connectionWindowIncrement < 0) throw new IllegalArgumentException("negative window increment");
        pseudoHeaderOrder = List.copyOf(pseudoHeaderOrder);
        if (pseudoHeaderOrder.size() != 4 || !pseudoHeaderOrder.containsAll(REQUEST_PSEUDO_HEADERS)) {
            throw new IllegalArgumentException("pseudo-header order must name each of " + REQUEST_PSEUDO_HEADERS);
        }
    }

    /**
     * Chrome 156, as captured from 156.0.8078.48 (macOS): SETTINGS {@code HEADER_TABLE_SIZE 65536},
     * {@code ENABLE_PUSH 0}, {@code INITIAL_WINDOW_SIZE 6291456}, {@code MAX_HEADER_LIST_SIZE
     * 262144}; a connection WINDOW_UPDATE of 15663105; HEADERS with an exclusive dependency on the
     * root and weight 256; pseudo-headers {@code :method :authority :scheme :path}. Its Akamai
     * fingerprint is {@code 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p}.
     *
     * @return the profile
     */
    public static Http2ClientProfile chrome156() {
        Map<Integer, Long> settings = new LinkedHashMap<>();
        settings.put(Http2Settings.HEADER_TABLE_SIZE, 65_536L);
        settings.put(Http2Settings.ENABLE_PUSH, 0L);
        settings.put(Http2Settings.INITIAL_WINDOW_SIZE, 6_291_456L);
        settings.put(Http2Settings.MAX_HEADER_LIST_SIZE, 262_144L);
        return new Http2ClientProfile("chrome-156", settings, 15_663_105, new Frame.PrioritySpec(0, true, 256),
                List.of(":method", ":authority", ":scheme", ":path"));
    }

    /**
     * The local settings the profile advertises, applied to the protocol's defaults: the values a
     * connection must then hold itself to (its decoder's table size, its stream windows).
     *
     * @return the settings
     * @throws IllegalArgumentException if a value is not a valid setting
     */
    public Http2Settings localSettings() {
        try {
            return Http2Settings.DEFAULT.apply(new Frame.Settings(false, settings));
        } catch (Http2Exception e) {
            throw new IllegalArgumentException("invalid setting in " + name + ": " + e.getMessage(), e);
        }
    }

    /**
     * {@code fields} with its request pseudo-headers in the profile's order, and the rest after them
     * as they were.
     *
     * @param fields a request's header list, pseudo-headers first
     * @return the reordered list
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

    /**
     * The Akamai HTTP/2 fingerprint of this profile's connections:
     * {@code SETTINGS|WINDOW_UPDATE|PRIORITY frames|pseudo-header order}, with no PRIORITY frames.
     *
     * @return the fingerprint, such as {@code 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p}
     */
    public String akamai() {
        StringBuilder sb = new StringBuilder();
        settings.forEach((id, value) -> sb.append(sb.isEmpty() ? "" : ";").append(id).append(':').append(value));
        sb.append('|').append(connectionWindowIncrement == 0 ? "00" : Integer.toString(connectionWindowIncrement));
        sb.append("|0|");
        for (int i = 0; i < pseudoHeaderOrder.size(); i++) {
            sb.append(i == 0 ? "" : ",").append(pseudoHeaderOrder.get(i).charAt(1));
        }
        return sb.toString();
    }
}
