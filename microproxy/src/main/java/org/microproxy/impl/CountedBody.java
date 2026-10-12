package org.microproxy.impl;

import java.io.IOException;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaders;

/**
 * A request body that counts the bytes read from it into its exchange's {@link ClientFlowContext},
 * for the access log ({@code %BYTES_RECEIVED%}). Used only when there are trackers to tell.
 */
final class CountedBody implements MessageBody {

    private final MessageBody body;
    private final ClientFlowContext flow;

    CountedBody(MessageBody body, ClientFlowContext flow) {
        this.body = body;
        this.flow = flow;
    }

    @Override
    public boolean hasBody() {
        return body.hasBody();
    }

    @Override
    public long declaredLength() {
        return body.declaredLength();
    }

    @Override
    public boolean isDone() {
        return body.isDone();
    }

    @Override
    public HttpContent next() throws IOException {
        HttpContent content = body.next();
        if (content != null) flow.addBytesReceived(content.contentLength());
        return content;
    }

    @Override
    public int read(byte[] dst, int off, int len) throws IOException {
        int n = body.read(dst, off, len);
        if (n > 0) flow.addBytesReceived(n);
        return n;
    }

    @Override
    public HttpHeaders trailers() {
        return body.trailers();
    }

    @Override
    public boolean hasBufferedInput() {
        return body.hasBufferedInput();
    }
}
