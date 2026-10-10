package org.microproxy.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;

/**
 * An HTTP/2 {@code CONNECT} stream shown as a connected socket, so that a TLS session can be
 * layered over it ({@link javax.net.ssl.SSLSocketFactory#createSocket(Socket, InputStream,
 * boolean)}) and the decrypted connection served like any other client connection: an intercepted
 * {@code CONNECT} inside an HTTP/2 connection.
 *
 * <p>The streams are the tunnel's bytes in DATA frames, which wait for flow-control window both
 * ways. The read timeout applies to reads as a socket's does; {@link #shutdownOutput} sends
 * END_STREAM; {@link #close} ends the output too and fails reads in progress, as closing a TCP
 * socket does. A reset of the stream fails reads and writes. Socket options have no meaning and
 * are accepted and ignored; nothing here opens a file descriptor.
 */
final class StreamSocket extends Socket {

    private final Http2StreamChannel stream;
    private final InputStream in;
    private final OutputStream out;
    private final InetSocketAddress remote;
    private final InetSocketAddress local;
    private volatile boolean closed;
    private volatile boolean outputShutdown;
    private volatile boolean inputShutdown;

    StreamSocket(Http2StreamChannel stream, InputStream in, OutputStream out, InetSocketAddress remote,
            InetSocketAddress local) {
        this.stream = stream;
        this.in = in;
        this.out = out;
        this.remote = remote;
        this.local = local;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        if (closed) throw new SocketException("Socket is closed");
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        if (closed) throw new SocketException("Socket is closed");
        return out;
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        if (timeout < 0) throw new IllegalArgumentException("timeout < 0");
        stream.setReadTimeout(timeout);
    }

    @Override
    public int getSoTimeout() {
        return stream.readTimeout();
    }

    @Override
    public void shutdownOutput() throws IOException {
        if (closed) throw new SocketException("Socket is closed");
        outputShutdown = true;
        stream.endTunnelOutput();
    }

    @Override
    public void shutdownInput() throws IOException {
        if (closed) throw new SocketException("Socket is closed");
        inputShutdown = true;
    }

    @Override
    public boolean isOutputShutdown() {
        return outputShutdown;
    }

    @Override
    public boolean isInputShutdown() {
        return inputShutdown;
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        stream.closeTunnel();
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public boolean isConnected() {
        return true;
    }

    @Override
    public boolean isBound() {
        return true;
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return remote;
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return local;
    }

    @Override
    public InetAddress getInetAddress() {
        return remote == null ? null : remote.getAddress();
    }

    @Override
    public int getPort() {
        return remote == null ? 0 : remote.getPort();
    }

    @Override
    public InetAddress getLocalAddress() {
        return local == null ? null : local.getAddress();
    }

    @Override
    public int getLocalPort() {
        return local == null ? -1 : local.getPort();
    }

    // Options: meaningless for a stream; accepted and ignored.

    @Override
    public void setTcpNoDelay(boolean on) {}

    @Override
    public boolean getTcpNoDelay() {
        return true;
    }

    @Override
    public void setSoLinger(boolean on, int linger) {}

    @Override
    public int getSoLinger() {
        return -1;
    }

    @Override
    public void setKeepAlive(boolean on) {}

    @Override
    public boolean getKeepAlive() {
        return false;
    }

    @Override
    public void setSendBufferSize(int size) {}

    @Override
    public int getSendBufferSize() {
        return Http2Endpoint.MAX_DATA_FRAME;
    }

    @Override
    public void setReceiveBufferSize(int size) {}

    @Override
    public int getReceiveBufferSize() {
        return Http2Endpoint.MAX_DATA_FRAME;
    }

    @Override
    public void setTrafficClass(int tc) {}

    @Override
    public int getTrafficClass() {
        return 0;
    }

    @Override
    public void setReuseAddress(boolean on) {}

    @Override
    public boolean getReuseAddress() {
        return false;
    }

    @Override
    public void setOOBInline(boolean on) {}

    @Override
    public boolean getOOBInline() {
        return false;
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        throw new SocketException("urgent data is not supported on an HTTP/2 stream");
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        throw new SocketException("already connected");
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        throw new SocketException("already bound");
    }

    @Override
    public String toString() {
        return "StreamSocket[" + stream.logPrefix().strip() + "]";
    }
}
