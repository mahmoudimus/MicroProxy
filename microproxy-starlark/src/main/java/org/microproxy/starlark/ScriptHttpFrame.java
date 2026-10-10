package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.microproxy.frames.Field;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.Http2Frame;
import org.microproxy.frames.Http3Frame;
import org.microproxy.frames.HttpFrame;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * An HTTP/2 or HTTP/3 frame as {@code on_frame} sees it, or as {@code h2.data(...)} and the like
 * make it. Like {@link ScriptFrame}, it is edited in place: assign {@code payload}, {@code text},
 * {@code error_code} or {@code debug_data}, or change {@code headers} and {@code settings}, which
 * are live. Fields a frame type does not have are {@code None}.
 */
@StarlarkBuiltin(name = "frame", doc = "An HTTP/2 or HTTP/3 frame.")
public final class ScriptHttpFrame implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("protocol", "type", "type_code", "stream_id",
            "end_stream", "direction", "ack", "payload", "text", "headers", "settings", "error_code", "error", "debug_data",
            "last_stream_id");

    private final FrameDirection direction;
    /** For HTTP/3, the stream the frame was read from (-1 for one a script made). */
    private final long streamId;
    private final Mutability mu;
    /** The frame, with the assigned fields applied. */
    private HttpFrame frame;
    /** Live views, made when first read. */
    private FrameFields fields;
    private ScriptHeaders headers;
    private Dict<Object, Object> settings;

    ScriptHttpFrame(HttpFrame frame, FrameDirection direction, long streamId, Mutability mu) {
        this.frame = frame;
        this.direction = direction;
        this.streamId = streamId;
        this.mu = mu;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a frame value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.HTTP_FRAME_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.HTTP_FRAME;
    }

    /** The frame to use: the original if nothing changed, else one with the changes. */
    HttpFrame toFrame() throws EvalException {
        HttpFrame out = frame;
        try {
            if (fields != null) {
                List<Field> edited = fields.fields();
                out = switch (out) {
                    case Http2Frame.Headers h when !edited.equals(h.fields()) -> h.withFields(edited);
                    case Http2Frame.PushPromise p when !edited.equals(p.fields()) ->
                            new Http2Frame.PushPromise(p.streamId(), p.promisedStreamId(), edited);
                    case Http3Frame.Headers h when !edited.equals(h.fields()) -> h.withFields(edited);
                    case Http3Frame.PushPromise p when !edited.equals(p.fields()) -> new Http3Frame.PushPromise(p.pushId(), edited);
                    default -> out;
                };
            }
            if (settings != null) {
                if (out instanceof Http2Frame.Settings s && !s.ack()) {
                    Map<Integer, Long> values = new LinkedHashMap<>();
                    for (Map.Entry<Object, Object> e : settings.entrySet()) {
                        int id = e.getKey() instanceof String name ? Http2Frame.settingId(name) : setting(e.getKey(), Integer.MAX_VALUE).intValue();
                        values.put(id, setting(e.getValue(), Long.MAX_VALUE));
                    }
                    if (!values.equals(s.values())) out = s.withValues(values);
                } else if (out instanceof Http3Frame.Settings s) {
                    Map<Long, Long> values = new LinkedHashMap<>();
                    for (Map.Entry<Object, Object> e : settings.entrySet()) {
                        long id = e.getKey() instanceof String name ? Http3Frame.settingId(name) : setting(e.getKey(), Long.MAX_VALUE);
                        values.put(id, setting(e.getValue(), Long.MAX_VALUE));
                    }
                    if (!values.equals(s.values())) out = s.withValues(values);
                }
            }
        } catch (IllegalArgumentException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
        return out;
    }

    private static Long setting(Object value, long max) throws EvalException {
        if (!(value instanceof StarlarkInt i)) {
            throw Starlark.errorf("settings are ints keyed by name or number, not %s", Starlark.type(value));
        }
        long v = i.toLong("setting");
        if (v < 0 || v > max) throw Starlark.errorf("setting out of range: %d", v);
        return v;
    }

    @Override
    public Object getValue(String name) throws EvalException {
        return switch (name) {
            case "protocol" -> frame.protocol().alpn();
            case "type" -> frame.typeName();
            case "type_code" -> StarlarkInt.of(frame.typeCode());
            case "stream_id" -> StarlarkInt.of(frame instanceof Http2Frame h2 ? h2.streamId() : streamId);
            case "end_stream" -> frame instanceof Http2Frame.Data d && d.endStream()
                    || frame instanceof Http2Frame.Headers h && h.endStream();
            case "direction" -> direction == null ? Starlark.NONE : direction.name().toLowerCase(Locale.ROOT);
            case "ack" -> frame instanceof Http2Frame.Settings s && s.ack() || frame instanceof Http2Frame.Ping p && p.ack();
            case "payload" -> {
                byte[] p = payload();
                yield p == null ? Starlark.NONE : StarlarkBytes.of(null, p);
            }
            case "text" -> text();
            case "headers" -> headers();
            case "settings" -> settings();
            case "error_code" -> switch (frame) {
                case Http2Frame.RstStream r -> StarlarkInt.of(r.errorCode());
                case Http2Frame.GoAway g -> StarlarkInt.of(g.errorCode());
                default -> Starlark.NONE;
            };
            case "error" -> switch (frame) {
                case Http2Frame.RstStream r -> r.errorName();
                case Http2Frame.GoAway g -> g.errorName();
                default -> Starlark.NONE;
            };
            case "debug_data" -> frame instanceof Http2Frame.GoAway g ? StarlarkBytes.of(null, g.debugData()) : Starlark.NONE;
            case "last_stream_id" -> switch (frame) {
                case Http2Frame.GoAway g -> StarlarkInt.of(g.lastStreamId());
                case Http3Frame.GoAway g -> StarlarkInt.of(g.id());
                default -> Starlark.NONE;
            };
            default -> null;
        };
    }

    private byte[] payload() {
        return switch (frame) {
            case Http2Frame.Data d -> d.data();
            case Http2Frame.Unknown u -> u.payload();
            case Http3Frame.Data d -> d.data();
            case Http3Frame.Unknown u -> u.payload();
            default -> null;
        };
    }

    private Object text() {
        byte[] payload = payload();
        if (payload == null) return Starlark.NONE;
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(payload)).toString();
        } catch (CharacterCodingException e) {
            return Starlark.NONE;
        }
    }

    private Object headers() {
        if (headers == null) {
            List<Field> list = switch (frame) {
                case Http2Frame.Headers h -> h.fields();
                case Http2Frame.PushPromise p -> p.fields();
                case Http3Frame.Headers h -> h.fields();
                case Http3Frame.PushPromise p -> p.fields();
                default -> null;
            };
            if (list == null) return Starlark.NONE;
            fields = new FrameFields(list);
            headers = new ScriptHeaders(fields, false);
        }
        return headers;
    }

    private Object settings() throws EvalException {
        if (settings == null) {
            settings = Dict.of(mu);
            if (frame instanceof Http2Frame.Settings s && !s.ack()) {
                for (Map.Entry<Integer, Long> e : s.values().entrySet()) {
                    settings.putEntry(Http2Frame.settingName(e.getKey()), StarlarkInt.of(e.getValue()));
                }
            } else if (frame instanceof Http3Frame.Settings s) {
                for (Map.Entry<Long, Long> e : s.values().entrySet()) {
                    settings.putEntry(Http3Frame.settingName(e.getKey()), StarlarkInt.of(e.getValue()));
                }
            } else {
                settings = null;
                return Starlark.NONE;
            }
        }
        return settings;
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public void setField(String field, Object value) throws EvalException {
        try {
            switch (field) {
                case "payload", "text" -> {
                    byte[] bytes = field.equals("text") ? text(value) : Builtins.bytes(value, field);
                    frame = switch (frame) {
                        case Http2Frame.Data d -> d.withData(bytes);
                        case Http2Frame.Unknown u -> u.withPayload(bytes);
                        case Http3Frame.Data d -> d.withData(bytes);
                        case Http3Frame.Unknown u -> u.withPayload(bytes);
                        default -> throw readOnly(field);
                    };
                }
                case "error_code" -> {
                    if (!(value instanceof StarlarkInt code)) {
                        throw Starlark.errorf("error_code must be an int, not %s", Starlark.type(value));
                    }
                    frame = switch (frame) {
                        case Http2Frame.RstStream r -> r.withErrorCode(code.toLong("error_code"));
                        case Http2Frame.GoAway g -> g.withErrorCode(code.toLong("error_code"));
                        default -> throw readOnly(field);
                    };
                }
                case "debug_data" -> {
                    if (!(frame instanceof Http2Frame.GoAway g)) throw readOnly(field);
                    frame = g.withDebugData(Builtins.bytes(value, field));
                }
                default -> throw Starlark.errorf(FIELDS.contains(field)
                        ? "frame." + field + " is read-only" : getErrorMessageForUnknownField(field));
            }
        } catch (IllegalArgumentException e) {
            throw Starlark.errorf("%s", e.getMessage());
        }
    }

    private static byte[] text(Object value) throws EvalException {
        if (!(value instanceof String s)) throw Starlark.errorf("text must be a string, not %s", Starlark.type(value));
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private EvalException readOnly(String field) {
        return Starlark.errorf("a %s frame has no %s to assign", frame.typeName(), field);
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "frame has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<").append(frame.protocol().alpn()).append(' ').append(frame.typeName());
        if (frame instanceof Http2Frame h2) printer.append(" stream ").append(h2.streamId());
        if (direction != null) printer.append(' ').append(direction.name().toLowerCase(Locale.ROOT));
        printer.append('>');
    }
}
