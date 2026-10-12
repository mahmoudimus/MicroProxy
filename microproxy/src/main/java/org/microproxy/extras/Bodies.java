package org.microproxy.extras;

import java.io.IOException;
import java.util.Arrays;
import java.util.function.UnaryOperator;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpMessage;

/**
 * Editing buffered bodies, shared by {@link RewriteRules} (text) and {@link ModifyBody} (bytes):
 * decode the content codings, edit, and re-encode only when something changed.
 */
final class Bodies {

    private Bodies() {}

    /**
     * Whether a message's body is worth buffering for editing: its codings can be decoded, and it
     * is not an event stream, which never ends and so could never be buffered whole.
     */
    static boolean editable(HttpMessage message) {
        return HttpBodies.canDecode(message) && !HttpBodies.mediaType(message).equals("text/event-stream");
    }

    /**
     * Applies {@code edit} to the decoded body and stores the result (re-encoded) if it differs.
     *
     * @return whether the body changed
     */
    static boolean edit(FullHttpMessage message, UnaryOperator<byte[]> edit) throws IOException {
        byte[] original = HttpBodies.decoded(message);
        byte[] edited = edit.apply(original);
        if (Arrays.equals(original, edited)) return false;
        HttpBodies.setDecoded(message, edited);
        return true;
    }

    /**
     * Applies {@code edit} to the body as text, in the charset of its {@code Content-Type}.
     *
     * @return whether the body changed
     */
    static boolean editText(FullHttpMessage message, UnaryOperator<String> edit) throws IOException {
        String original = HttpBodies.text(message);
        String edited = edit.apply(original);
        if (edited.equals(original)) return false;
        HttpBodies.setText(message, edited);
        return true;
    }
}
