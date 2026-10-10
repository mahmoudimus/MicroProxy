/*
 * Choosing a view by priority, with "auto" for the best one, is ported from mitmproxy
 * (https://github.com/mitmproxy/mitmproxy), mitmproxy/contentviews/_registry.py. Copyright (c)
 * 2013, Aldo Cortesi. Licensed under the MIT License; see META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.contentviews;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeSet;

/**
 * A set of {@link ContentView}s, and the choice among them. In {@code auto} mode the view with the
 * highest {@link ContentView#priority} renders a body; if it cannot, the next one tries, and when
 * none can, there is no rendering (callers show the body as they would without views).
 *
 * <pre>{@code
 * ContentViews views = ContentViews.defaults().withSchema(ProtoSchema.load(Path.of("api.desc")));
 * views.render(body, ContentView.Metadata.forResponse(request, response))
 *         .ifPresent(r -> System.out.println(r.view() + ":\n" + r.text()));
 * }</pre>
 *
 * <p>The default views: {@code protobuf}, {@code grpc}, {@code json}, {@code graphql}, {@code
 * msgpack}, {@code urlencoded}, {@code multipart}, {@code query}, {@code socketio}, and {@code
 * hex} (only when named). Instances are immutable and safe to share; {@link #with} and {@link
 * #withSchema} return new ones.
 */
public final class ContentViews {

    /** The name that picks the best view for each body. */
    public static final String AUTO = "auto";

    private static final System.Logger LOG = System.getLogger(ContentViews.class.getName());
    private static final ContentViews DEFAULTS = new ContentViews(standard(ProtoSchema.empty()), ProtoSchema.empty());

    /**
     * A body rendered by a view.
     *
     * @param view the name of the view that rendered it
     * @param text the text
     */
    public record Rendered(String view, String text) {}

    private final List<ContentView> views;
    private final ProtoSchema schema;

    private ContentViews(List<ContentView> views, ProtoSchema schema) {
        this.views = List.copyOf(views);
        this.schema = schema;
    }

    private static List<ContentView> standard(ProtoSchema schema) {
        return List.of(new ProtobufView(schema), new GrpcView(schema), new JsonView(), new GraphQlView(),
                new MsgPackView(), new FormViews.UrlEncoded(), new FormViews.Multipart(), new FormViews.Query(),
                new SocketIoView(), new HexView());
    }

    /** {@return the default views, decoding protobuf without a schema} */
    public static ContentViews defaults() {
        return DEFAULTS;
    }

    /**
     * These views with {@code view} added, replacing a view of the same name.
     *
     * @param view the view
     * @return the new set
     */
    public ContentViews with(ContentView view) {
        Objects.requireNonNull(view, "view");
        List<ContentView> all = new ArrayList<>(views);
        all.removeIf(existing -> existing.name().equals(view.name()));
        all.add(view);
        return new ContentViews(all, schema);
    }

    /**
     * These views with the protobuf and gRPC views decoding with {@code schema}.
     *
     * @param schema the schema
     * @return the new set
     */
    public ContentViews withSchema(ProtoSchema schema) {
        Objects.requireNonNull(schema, "schema");
        List<ContentView> all = new ArrayList<>(views.size());
        for (ContentView v : views) {
            if (v instanceof ProtobufView) all.add(new ProtobufView(schema));
            else if (v instanceof GrpcView) all.add(new GrpcView(schema));
            else all.add(v);
        }
        return new ContentViews(all, schema);
    }

    /** {@return the schema the protobuf and gRPC views decode with} */
    public ProtoSchema schema() {
        return schema;
    }

    /** {@return {@value #AUTO} and the views' names, sorted} */
    public List<String> names() {
        List<String> names = new ArrayList<>();
        names.add(AUTO);
        names.addAll(new TreeSet<>(views.stream().map(ContentView::name).toList()));
        return names;
    }

    /**
     * The view named {@code name}.
     *
     * @param name a view's name (any case)
     * @return the view, or empty if there is none
     */
    public Optional<ContentView> get(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        return views.stream().filter(v -> v.name().equals(n)).findFirst();
    }

    /**
     * The view {@code auto} mode would try first.
     *
     * @param data the body, decoded
     * @param metadata what is known about the message
     * @return the view with the highest positive priority, or empty if none applies
     */
    public Optional<ContentView> select(byte[] data, ContentView.Metadata metadata) {
        List<ContentView> candidates = candidates(data, metadata);
        return candidates.isEmpty() ? Optional.empty() : Optional.of(candidates.getFirst());
    }

    /**
     * Renders a body with the best view that can.
     *
     * @param data the body, decoded
     * @param metadata what is known about the message
     * @return the rendering, or empty if no view applies or none could render the body
     */
    public Optional<Rendered> render(byte[] data, ContentView.Metadata metadata) {
        for (ContentView v : candidates(data, metadata)) {
            Optional<Rendered> r = tryRender(v, data, metadata);
            if (r.isPresent()) return r;
        }
        return Optional.empty();
    }

    /**
     * Renders a body with the view named {@code view}, or the best one for {@value #AUTO}.
     *
     * @param view a view's name, or {@value #AUTO}
     * @param data the body, decoded
     * @param metadata what is known about the message
     * @return the rendering, or empty if the view could not render the body
     * @throws IllegalArgumentException if there is no view named {@code view}
     */
    public Optional<Rendered> render(String view, byte[] data, ContentView.Metadata metadata) {
        if (view.equalsIgnoreCase(AUTO)) return render(data, metadata);
        ContentView v = get(view).orElseThrow(() -> new IllegalArgumentException(
                "no content view " + view + "; there are " + String.join(", ", names())));
        return tryRender(v, data, metadata);
    }

    /**
     * What a header or trailer field means, for the fields gRPC defines: the name of a {@code
     * grpc-status} code, the text of a percent-encoded {@code grpc-message}, and the message in a
     * binary ({@code -bin}) field, {@code grpc-status-details-bin} as a {@code google.rpc.Status}.
     *
     * @param name the field's name
     * @param value the field's value
     * @return a line (or YAML lines) explaining the value, or {@code null} for other fields
     */
    public String describeHeader(String name, String value) {
        try {
            Yaml.Node node = GrpcView.describe(name, value, schema);
            if (node == null) return null;
            if (node instanceof Yaml.Scalar s) return s.comment() != null && s.comment().equals("percent-decoded")
                    ? Grpc.message(value) : s.comment();
            return Yaml.emit(node).stripTrailing();
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.DEBUG, "describing " + name + " failed", e);
            return null;
        }
    }

    private List<ContentView> candidates(byte[] data, ContentView.Metadata metadata) {
        List<ContentView> out = new ArrayList<>();
        List<Double> priorities = new ArrayList<>();
        for (ContentView v : views) {
            double p;
            try {
                p = v.priority(data, metadata);
            } catch (RuntimeException e) {
                LOG.log(System.Logger.Level.DEBUG, "content view " + v.name() + " failed to rate a body", e);
                continue;
            }
            if (p > 0) {
                out.add(v);
                priorities.add(p);
            }
        }
        List<Integer> order = new ArrayList<>();
        for (int i = 0; i < out.size(); i++) order.add(i);
        // Stable: among equal priorities, the earlier view first.
        order.sort(Comparator.comparingDouble((Integer i) -> -priorities.get(i)));
        return order.stream().map(out::get).toList();
    }

    private static Optional<Rendered> tryRender(ContentView v, byte[] data, ContentView.Metadata metadata) {
        try {
            String text = v.render(data, metadata);
            return text == null ? Optional.empty() : Optional.of(new Rendered(v.name(), text));
        } catch (DecodeException e) {
            return Optional.empty();
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.DEBUG, "content view " + v.name() + " failed", e);
            return Optional.empty();
        }
    }

    @Override
    public String toString() {
        return "ContentViews" + names();
    }
}
