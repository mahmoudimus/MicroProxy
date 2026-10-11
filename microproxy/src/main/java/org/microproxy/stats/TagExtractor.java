package org.microproxy.stats;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Takes tag values out of flat stat names, once, when a metric is registered, as Envoy's tag
 * extraction does: {@code cluster.direct.upstream_rq_2xx} becomes {@code cluster.upstream_rq_xx}
 * with the tags {@code envoy_cluster_name="direct"} and {@code envoy_response_code_class="2"}.
 *
 * <p>Each rule is a tag name and a regular expression with two groups: the first is the part
 * removed from the name, the second (inside it, or equal to it) the tag's value. The rules run in
 * order, each on what the earlier ones left of the name; a rule that does not match adds nothing.
 * The {@linkplain #envoyDefaults() defaults} give the tags Envoy gives the stats MicroProxy has:
 *
 * <ul>
 *   <li>{@code envoy_http_conn_manager_prefix}: {@code http.<prefix>.}
 *   <li>{@code envoy_cluster_name}: {@code cluster.<name>.}
 *   <li>{@code envoy_listener_address}: {@code listener.<address>.} (an address such as {@code
 *       0.0.0.0_8080} or {@code [__1]_8080})
 *   <li>{@code envoy_response_code_class}: the digit of a name ending in {@code _rq_<digit>xx}
 *   <li>{@code microproxy_response_flag}: the flag at the end of {@code
 *       downstream_rq_response_flag.<flag>}, a MicroProxy stat
 * </ul>
 *
 * <p>and these for MicroProxy's per-protocol stats:
 *
 * <ul>
 *   <li>{@code microproxy_direction}: {@code downstream} or {@code upstream} in {@code
 *       http2.<direction>.} and {@code http3.<direction>.}
 *   <li>{@code microproxy_quic_scope}: {@code downstream}, {@code upstream}, {@code transparent}
 *       or {@code masque} in {@code quic.<scope>.}
 *   <li>{@code microproxy_quic_error}: the error at the end of {@code handshake_failures.<error>}
 *   <li>{@code microproxy_congestion_controller}: the controller at the end of {@code
 *       congestion_controller.<name>}
 *   <li>{@code microproxy_drop_reason}: the reason at the end of {@code dropped_initials.<reason>}
 *   <li>{@code microproxy_socks_version}: {@code v4} or {@code v5} in {@code socks.<version>.}
 *   <li>{@code microproxy_socks_reply}: the reply at the end of {@code replies.<reply>}
 *   <li>{@code microproxy_reject_reason}: the reason at the end of {@code flow_rejected.<reason>}
 *   <li>{@code microproxy_tunnel_kind}: the kind in {@code tunnel.<kind>.}
 *   <li>{@code microproxy_close_code}: the code at the end of {@code close_codes.<code>}
 *   <li>{@code microproxy_hook}: the hook family in {@code hooks.<family>.}
 * </ul>
 *
 * <p>Values in flat names cannot contain dots (except listener addresses): the proxy writes the
 * cluster and prefix names it makes up with underscores instead ({@link #sanitize}).
 */
public final class TagExtractor {

    /**
     * One rule.
     *
     * @param tagName the name of the tag the rule finds
     * @param pattern the expression: group 1 is removed from the name, group 2 is the value
     */
    public record Rule(String tagName, Pattern pattern) {

        /**
         * Checks the rule.
         *
         * @param tagName the name of the tag the rule finds
         * @param pattern the expression, with at least two groups
         * @throws IllegalArgumentException if the expression has fewer than two groups
         */
        public Rule {
            Objects.requireNonNull(tagName, "tagName");
            if (pattern.matcher("").groupCount() < 2) {
                throw new IllegalArgumentException("a tag rule needs two groups (removed, value): " + pattern);
            }
        }
    }

    /**
     * A name with its tags taken out.
     *
     * @param tagExtractedName what is left of the name
     * @param tags the tags found, in the order of the rules
     */
    public record Result(String tagExtractedName, List<Tag> tags) {

        /**
         * Copies the tags.
         *
         * @param tagExtractedName what is left of the name
         * @param tags the tags found
         */
        public Result {
            Objects.requireNonNull(tagExtractedName, "tagExtractedName");
            tags = List.copyOf(tags);
        }
    }

    private static final TagExtractor DEFAULTS = new TagExtractor(List.of(
            rule("envoy_http_conn_manager_prefix", "^http\\.(([^.]+)\\.)"),
            rule("envoy_cluster_name", "^cluster\\.(([^.]+)\\.)"),
            rule("envoy_listener_address", "^listener\\.(([0-9._]+_[0-9]+|\\[[0-9a-fA-F_]*\\]_[0-9]+|[^.]+)\\.)"),
            rule("envoy_response_code_class", "_rq_(([1-5]))xx$"),
            rule("microproxy_response_flag", "\\.downstream_rq_response_flag(\\.([A-Za-z]+))$"),
            rule("microproxy_direction", "^http[23]\\.((downstream|upstream)\\.)"),
            rule("microproxy_quic_scope", "^quic\\.((downstream|upstream|transparent|masque)\\.)"),
            rule("microproxy_quic_error", "\\.handshake_failures(\\.([a-z0-9_]+))$"),
            rule("microproxy_congestion_controller", "\\.congestion_controller(\\.([a-z0-9_]+))$"),
            rule("microproxy_drop_reason", "\\.dropped_initials(\\.([a-z_]+))$"),
            rule("microproxy_socks_version", "^socks\\.((v4|v5)\\.)"),
            rule("microproxy_socks_reply", "\\.replies(\\.([a-z_]+))$"),
            rule("microproxy_reject_reason", "\\.flow_rejected(\\.([a-z_]+))$"),
            rule("microproxy_tunnel_kind", "^tunnel\\.((h1_connect|h2_connect|h3_connect|socks|forwarded|raw)\\.)"),
            rule("microproxy_close_code", "\\.close_codes(\\.([0-9a-z_]+))$"),
            rule("microproxy_hook", "^hooks\\.(([a-z0-9_]+)\\.)")));

    private static final TagExtractor NONE = new TagExtractor(List.of());

    private final List<Rule> rules;

    private TagExtractor(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    private static Rule rule(String tagName, String regex) {
        return new Rule(tagName, Pattern.compile(regex));
    }

    /** {@return the rules for the tags Envoy gives MicroProxy's stats (see the class documentation)} */
    public static TagExtractor envoyDefaults() {
        return DEFAULTS;
    }

    /** {@return an extractor with no rules, which leaves every name whole} */
    public static TagExtractor none() {
        return NONE;
    }

    /**
     * This extractor with one more rule, which runs after the others.
     *
     * @param tagName the name of the tag the rule finds
     * @param regex the expression: group 1 is removed from the name, group 2 is the value
     * @return a new extractor
     * @throws IllegalArgumentException if the expression has fewer than two groups
     * @throws java.util.regex.PatternSyntaxException if it is not a valid expression
     */
    public TagExtractor with(String tagName, String regex) {
        List<Rule> more = new ArrayList<>(rules);
        more.add(rule(tagName, regex));
        return new TagExtractor(more);
    }

    /** {@return the rules, in the order they run} */
    public List<Rule> rules() {
        return rules;
    }

    /**
     * Takes the tags out of {@code name}.
     *
     * @param name a flat stat name
     * @return the tag-extracted name and the tags
     */
    public Result extract(String name) {
        String rest = name;
        List<Tag> tags = new ArrayList<>(2);
        for (Rule rule : rules) {
            Matcher m = rule.pattern().matcher(rest);
            if (!m.find() || m.group(1) == null || m.group(2) == null) continue;
            tags.add(new Tag(rule.tagName(), m.group(2)));
            rest = rest.substring(0, m.start(1)) + rest.substring(m.end(1));
        }
        return new Result(rest, tags);
    }

    /**
     * {@code value} made fit to be one element of a flat name: every character other than a
     * letter, digit, {@code _} or {@code -} becomes {@code _}, so that it has no dots.
     *
     * @param value a cluster name, host name or similar
     * @return the value with only letters, digits, {@code _} and {@code -}
     */
    public static String sanitize(String value) {
        StringBuilder sb = null;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
            if (!ok && sb == null) {
                sb = new StringBuilder(value.length());
                sb.append(value, 0, i);
            }
            if (sb != null) sb.append(ok ? c : '_');
        }
        String result = sb == null ? value : sb.toString();
        return result.isEmpty() ? "_" : result;
    }
}
