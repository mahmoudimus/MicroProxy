/**
 * A dependency-free QUIC transport (RFC 9000, 9001, 9002, 9221, 9369). This package holds the
 * shared primitives ({@link io.github.mahmoudimus.quic.VarInt}, {@link
 * io.github.mahmoudimus.quic.ConnectionId}, {@link io.github.mahmoudimus.quic.QuicVersion}, ...) and
 * the blocking API built for virtual threads: {@link io.github.mahmoudimus.quic.QuicServer} and
 * {@link io.github.mahmoudimus.quic.QuicClient} own a UDP socket each, and hand out {@link
 * io.github.mahmoudimus.quic.QuicConnection}s whose {@link io.github.mahmoudimus.quic.QuicStream}s
 * are read and written as {@link java.io.InputStream}s and {@link java.io.OutputStream}s.
 *
 * <p>The protocol itself is sans-I/O, in {@link io.github.mahmoudimus.quic.connection}: the I/O
 * layer here only moves datagrams and wakes connections up.
 */
package io.github.mahmoudimus.quic;
