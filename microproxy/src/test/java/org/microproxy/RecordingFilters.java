package org.microproxy;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpMessage;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.LastHttpContent;

/**
 * An {@link HttpFilters} that records the name of every callback it receives, in order, so tests
 * can assert which hooks ran and in which sequence. Message hooks are recorded with the kind of
 * object they saw, e.g. {@code clientToProxyRequest:head} or {@code serverToProxyResponse:last}.
 * Subclasses can override a hook (calling {@code super}) to also change what it returns.
 */
public class RecordingFilters implements HttpFilters {

    /** Every callback received, in order. Shared by all exchanges this instance is used for. */
    public final List<String> events;

    public RecordingFilters() {
        this(new CopyOnWriteArrayList<>());
    }

    /** Records into {@code events}, e.g. a list shared by the filters of several requests. */
    public RecordingFilters(List<String> events) {
        this.events = events;
    }

    /** {@code head}, {@code full}, {@code last} or {@code content}. */
    public static String kind(HttpObject o) {
        if (o instanceof FullHttpMessage) return "full";
        if (o instanceof HttpMessage) return "head";
        if (o instanceof LastHttpContent) return "last";
        if (o instanceof HttpContent) return "content";
        return String.valueOf(o);
    }

    /** A {@link HttpFiltersSource} that hands out {@code filters} for every request. */
    public static HttpFiltersSource sourceOf(HttpFilters filters) {
        return new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return filters;
            }
        };
    }

    /** Whether {@code event} was recorded. */
    public boolean saw(String event) {
        return events.contains(event);
    }

    /** Waits up to {@code millis} for {@code event} to be recorded; returns whether it was. */
    public boolean await(String event, long millis) throws InterruptedException {
        long deadline = System.nanoTime() + millis * 1_000_000;
        while (!events.contains(event)) {
            if (System.nanoTime() > deadline) return false;
            Thread.sleep(5);
        }
        return true;
    }

    /** Asserts-friendly view: the position of {@code event}, or -1. */
    public int indexOf(String event) {
        return events.indexOf(event);
    }

    @Override
    public HttpResponse clientToProxyRequest(HttpObject httpObject) {
        events.add("clientToProxyRequest:" + kind(httpObject));
        return null;
    }

    @Override
    public HttpResponse proxyToServerRequest(HttpObject httpObject) {
        events.add("proxyToServerRequest:" + kind(httpObject));
        return null;
    }

    @Override
    public void proxyToServerRequestSending() {
        events.add("proxyToServerRequestSending");
    }

    @Override
    public void proxyToServerRequestSent() {
        events.add("proxyToServerRequestSent");
    }

    @Override
    public HttpObject serverToProxyResponse(HttpObject httpObject) {
        events.add("serverToProxyResponse:" + kind(httpObject));
        return httpObject;
    }

    @Override
    public void serverToProxyResponseTimedOut() {
        events.add("serverToProxyResponseTimedOut");
    }

    @Override
    public void serverToProxyResponseReceiving() {
        events.add("serverToProxyResponseReceiving");
    }

    @Override
    public void serverToProxyResponseReceived() {
        events.add("serverToProxyResponseReceived");
    }

    @Override
    public HttpObject proxyToClientResponse(HttpObject httpObject) {
        events.add("proxyToClientResponse:" + kind(httpObject));
        return httpObject;
    }

    @Override
    public InetSocketAddress proxyToServerResolutionStarted(String resolvingServerHostAndPort) {
        events.add("proxyToServerResolutionStarted");
        return null;
    }

    @Override
    public void proxyToServerResolutionFailed(String hostAndPort) {
        events.add("proxyToServerResolutionFailed");
    }

    @Override
    public void proxyToServerResolutionSucceeded(String serverHostAndPort, InetSocketAddress resolvedRemoteAddress) {
        events.add("proxyToServerResolutionSucceeded");
    }

    @Override
    public void proxyToServerConnectionStarted() {
        events.add("proxyToServerConnectionStarted");
    }

    @Override
    public void proxyToServerConnectionSSLHandshakeStarted() {
        events.add("proxyToServerConnectionSSLHandshakeStarted");
    }

    @Override
    public void proxyToServerConnectionFailed() {
        events.add("proxyToServerConnectionFailed");
    }

    @Override
    public void proxyToServerConnectionSucceeded(FullFlowContext serverContext) {
        events.add("proxyToServerConnectionSucceeded");
    }

    @Override
    public boolean proxyToServerAllowMitm() {
        events.add("proxyToServerAllowMitm");
        return true;
    }
}
