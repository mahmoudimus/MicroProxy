package org.microproxy.impl;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketOption;
import java.util.Set;
import org.microproxy.ClientHelloNotSentException;

/**
 * The connection to a server that the proxy's TLS handshake with it runs on, as a socket that
 * tells whether the handshake's first write, the ClientHello, reached the connection: when that
 * write fails (the connection was reset before it, by the server or a chained proxy in front of
 * it), it fails with a {@link ClientHelloNotSentException} instead, whose cause is the socket's
 * own exception. Everything else is the underlying socket's.
 *
 * <p>A connection the peer only closed (without a reset) still takes the ClientHello: its end shows
 * when the answer is read, as a close after the ClientHello.
 */
final class ClientHelloSocket extends Socket {

    private final Socket socket;
    private volatile OutputStream out;
    /** Whether a write reached the connection. */
    private volatile boolean written;

    ClientHelloSocket(Socket socket) {
        this.socket = socket;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return socket.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        OutputStream o = out;
        if (o == null) {
            o = new FilterOutputStream(socket.getOutputStream()) {
                @Override
                public void write(int b) throws IOException {
                    try {
                        this.out.write(b);
                    } catch (IOException e) {
                        throw failed(e);
                    }
                    written = true;
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    try {
                        this.out.write(b, off, len);
                    } catch (IOException e) {
                        throw failed(e);
                    }
                    if (len > 0) written = true;
                }

                @Override
                public void flush() throws IOException {
                    try {
                        this.out.flush();
                    } catch (IOException e) {
                        throw failed(e);
                    }
                }
            };
            out = o;
        }
        return o;
    }

    /** {@code e}, or, when nothing was written before it (and it is no timeout), the ClientHello's failure. */
    private IOException failed(IOException e) {
        return written || e instanceof InterruptedIOException ? e : new ClientHelloNotSentException(e);
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        socket.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return socket.getSoTimeout();
    }

    @Override
    public void shutdownOutput() throws IOException {
        socket.shutdownOutput();
    }

    @Override
    public void shutdownInput() throws IOException {
        socket.shutdownInput();
    }

    @Override
    public boolean isOutputShutdown() {
        return socket.isOutputShutdown();
    }

    @Override
    public boolean isInputShutdown() {
        return socket.isInputShutdown();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    @Override
    public boolean isClosed() {
        return socket.isClosed();
    }

    @Override
    public boolean isConnected() {
        return socket.isConnected();
    }

    @Override
    public boolean isBound() {
        return socket.isBound();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return socket.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return socket.getLocalSocketAddress();
    }

    @Override
    public InetAddress getInetAddress() {
        return socket.getInetAddress();
    }

    @Override
    public int getPort() {
        return socket.getPort();
    }

    @Override
    public InetAddress getLocalAddress() {
        return socket.getLocalAddress();
    }

    @Override
    public int getLocalPort() {
        return socket.getLocalPort();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        socket.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return socket.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        socket.setSoLinger(on, linger);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return socket.getSoLinger();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        socket.setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return socket.getKeepAlive();
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException {
        socket.setSendBufferSize(size);
    }

    @Override
    public int getSendBufferSize() throws SocketException {
        return socket.getSendBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        socket.setReceiveBufferSize(size);
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
        return socket.getReceiveBufferSize();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        socket.setTrafficClass(tc);
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return socket.getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        socket.setReuseAddress(on);
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return socket.getReuseAddress();
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        socket.setOOBInline(on);
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return socket.getOOBInline();
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        socket.sendUrgentData(data);
    }

    @Override
    public <T> Socket setOption(SocketOption<T> name, T value) throws IOException {
        socket.setOption(name, value);
        return this;
    }

    @Override
    public <T> T getOption(SocketOption<T> name) throws IOException {
        return socket.getOption(name);
    }

    @Override
    public Set<SocketOption<?>> supportedOptions() {
        return socket.supportedOptions();
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
        return socket.toString();
    }
}
