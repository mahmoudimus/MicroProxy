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
 *   <li>the priority its request HEADERS carry, which may depend on the request;</li>
 *   <li>the order of the request pseudo-headers;</li>
 *   <li>the id of its first stream.</li>
 * </ul>
 *
 * @param name the profile's name, such as {@code chrome-156}
 * @param settings the SETTINGS identifiers and values, in the order they are sent
 * @param connectionWindowIncrement the connection WINDOW_UPDATE increment sent after SETTINGS, 0 for none
 * @param headersPriority the RFC 7540 priority on a request's HEADERS, or null for none
 * @param pseudoHeaderOrder the request pseudo-headers in the order they are sent
 * @param firstStreamId the id of the first stream a connection opens: 1, or 3 for a client that
 *     keeps 1 for an HTTP/1.1 upgrade (Firefox)
 * @param teTrailers whether every request carries {@code te: trailers}, as Firefox's do; otherwise
 *     only those whose client accepted trailers
 */
public record Http2ClientProfile(String name, Map<Integer, Long> settings, int connectionWindowIncrement,
        RequestPriority headersPriority, List<String> pseudoHeaderOrder, int firstStreamId, boolean teTrailers) {

    /** The priority a request's HEADERS carry, from the request's header list. */
    @FunctionalInterface
    public interface RequestPriority {

        /**
         * The priority for a request.
         *
         * @param request the request's header list, pseudo-headers first
         * @return the priority, or null for none
         */
        Frame.PrioritySpec of(List<HeaderField> request);
    }

    private static final List<String> REQUEST_PSEUDO_HEADERS = List.of(":method", ":scheme", ":authority", ":path");

    public Http2ClientProfile {
        Objects.requireNonNull(name, "name");
        settings = Collections.unmodifiableMap(new LinkedHashMap<>(settings));
        if (connectionWindowIncrement < 0) throw new IllegalArgumentException("negative window increment");
        pseudoHeaderOrder = List.copyOf(pseudoHeaderOrder);
        if (pseudoHeaderOrder.size() != 4 || !pseudoHeaderOrder.containsAll(REQUEST_PSEUDO_HEADERS)) {
            throw new IllegalArgumentException("pseudo-header order must name each of " + REQUEST_PSEUDO_HEADERS);
        }
        if (firstStreamId < 1 || (firstStreamId & 1) == 0) throw new IllegalArgumentException("first stream id " + firstStreamId);
        if (headersPriority == null) headersPriority = request -> null;
    }

    /** A profile whose every request carries {@code headersPriority}, its first stream 1. */
    public Http2ClientProfile(String name, Map<Integer, Long> settings, int connectionWindowIncrement,
            Frame.PrioritySpec headersPriority, List<String> pseudoHeaderOrder) {
        this(name, settings, connectionWindowIncrement, request -> headersPriority, pseudoHeaderOrder, 1, false);
    }

    /**
     * The priority on a request's HEADERS.
     *
     * @param request the request's header list
     * @return the priority, or null for none
     */
    public Frame.PrioritySpec priority(List<HeaderField> request) {
        return headersPriority.of(request);
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
     * Firefox 159, as captured from 159.0 (macOS): SETTINGS {@code HEADER_TABLE_SIZE 65536},
     * {@code ENABLE_PUSH 0}, {@code INITIAL_WINDOW_SIZE 131072}, {@code MAX_FRAME_SIZE 16384}; a
     * connection WINDOW_UPDATE of 12517377; pseudo-headers {@code :method :path :authority :scheme};
     * streams from 3; {@code te: trailers} on every request; and HEADERS that depend on the root,
     * not exclusively, with a weight that follows the request ({@link #firefoxPriority}). Its Akamai
     * fingerprint is
     * {@code 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s}.
     *
     * @return the profile
     */
    public static Http2ClientProfile firefox159() {
        Map<Integer, Long> settings = new LinkedHashMap<>();
        settings.put(Http2Settings.HEADER_TABLE_SIZE, 65_536L);
        settings.put(Http2Settings.ENABLE_PUSH, 0L);
        settings.put(Http2Settings.INITIAL_WINDOW_SIZE, 131_072L);
        settings.put(Http2Settings.MAX_FRAME_SIZE, 16_384L);
        return new Http2ClientProfile("firefox-159", settings, 12_517_377, Http2ClientProfile::firefoxPriority,
                List.of(":method", ":path", ":authority", ":scheme"), 3, true);
    }

    /**
     * Firefox's HEADERS priority for a request: no dependency (stream 0, not exclusive) and the
     * weight Firefox gives that kind of request, 22 less its internal priority. Measured from
     * Firefox 159 loading a page ({@code fingerprints/firefox-159/h2-page.txt}): 42 for a document
     * ({@code sec-fetch-dest: document}); for an image, 14 at urgency 4 ({@code priority: u=4, i})
     * and 12 at urgency 5; and 22 for the rest (stylesheets, scripts, fetches, and the favicon, an
     * image at urgency 6).
     *
     * @param request the request's header list
     * @return the priority
     */
    public static Frame.PrioritySpec firefoxPriority(List<HeaderField> request) {
        String dest = value(request, "sec-fetch-dest");
        int weight;
        if ("document".equals(dest)) {
            weight = 42;
        } else if ("image".equals(dest) && urgency(value(request, "priority")) == 4) {
            weight = 14;
        } else if ("image".equals(dest) && urgency(value(request, "priority")) == 5) {
            weight = 12;
        } else {
            weight = 22;
        }
        return new Frame.PrioritySpec(0, false, weight);
    }

    /** The urgency of a {@code priority} field (RFC 9218), -1 if it names none. */
    private static int urgency(String priority) {
        if (priority == null) return -1;
        for (String part : priority.split(",")) {
            String p = part.strip();
            if (p.length() == 3 && p.startsWith("u=") && Character.isDigit(p.charAt(2))) return p.charAt(2) - '0';
        }
        return -1;
    }

    private static String value(List<HeaderField> fields, String name) {
        for (HeaderField f : fields) {
            if (f.name().equals(name)) return f.value();
        }
        return null;
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
