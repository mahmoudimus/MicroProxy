package org.microproxy;

import java.io.IOException;
import java.nio.file.Path;
import org.microproxy.impl.DefaultHttpProxyServer;

/** Entry point: {@code MicroProxy.bootstrap().withPort(8080).start()}. */
public final class MicroProxy {

    private MicroProxy() {}

    public static HttpProxyServerBootstrap bootstrap() {
        return DefaultHttpProxyServer.bootstrap();
    }

    /** A bootstrap configured from a properties file (see the README for keys). */
    public static HttpProxyServerBootstrap bootstrapFromFile(Path path) throws IOException {
        return DefaultHttpProxyServer.bootstrapFromFile(path);
    }
}
