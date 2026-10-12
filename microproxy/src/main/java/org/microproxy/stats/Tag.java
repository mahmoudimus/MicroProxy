package org.microproxy.stats;

import java.util.Objects;

/**
 * A value taken out of a metric's flat name, which Prometheus shows as a label.
 *
 * @param name the tag's name, such as {@code envoy_cluster_name}
 * @param value the tag's value, such as {@code direct}
 */
public record Tag(String name, String value) {

    /**
     * Checks both parts.
     *
     * @param name the tag's name
     * @param value the tag's value
     */
    public Tag {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(value, "value");
    }
}
