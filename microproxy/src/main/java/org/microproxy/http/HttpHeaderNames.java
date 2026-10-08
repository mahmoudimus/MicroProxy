package org.microproxy.http;

/** Common header names. Header lookups in {@link HttpHeaders} are case-insensitive. */
public final class HttpHeaderNames {

    public static final String ACCEPT_ENCODING = "Accept-Encoding";
    public static final String CONNECTION = "Connection";
    public static final String CONTENT_ENCODING = "Content-Encoding";
    public static final String CONTENT_LENGTH = "Content-Length";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String DATE = "Date";
    public static final String EXPECT = "Expect";
    public static final String HOST = "Host";
    public static final String KEEP_ALIVE = "Keep-Alive";
    public static final String LOCATION = "Location";
    public static final String PROXY_AUTHENTICATE = "Proxy-Authenticate";
    public static final String PROXY_AUTHORIZATION = "Proxy-Authorization";
    public static final String PROXY_CONNECTION = "Proxy-Connection";
    public static final String SEC_WEBSOCKET_KEY = "Sec-WebSocket-Key";
    public static final String TE = "TE";
    public static final String TRAILER = "Trailer";
    public static final String TRANSFER_ENCODING = "Transfer-Encoding";
    public static final String UPGRADE = "Upgrade";
    public static final String USER_AGENT = "User-Agent";
    public static final String VIA = "Via";

    private HttpHeaderNames() {}
}
