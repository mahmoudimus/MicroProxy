/**
 * The sans-I/O QUIC connection and endpoint, ported from quinn-proto: the {@link
 * io.github.mahmoudimus.quic.connection.Connection} state machine (handshake, packet assembly and
 * processing, key updates, closing and draining), the {@link
 * io.github.mahmoudimus.quic.connection.Endpoint} that routes datagrams and answers with Version
 * Negotiation, Retry and stateless resets, their configurations ({@link
 * io.github.mahmoudimus.quic.connection.TransportConfig}, {@link
 * io.github.mahmoudimus.quic.connection.ServerConfig}, {@link
 * io.github.mahmoudimus.quic.connection.ClientConfig}, {@link
 * io.github.mahmoudimus.quic.connection.EndpointConfig}), and the building blocks they are made of:
 * range sets ({@link io.github.mahmoudimus.quic.connection.RangeSet}), reassembly of received data
 * ({@link io.github.mahmoudimus.quic.connection.Assembler}), buffering of sent data ({@link
 * io.github.mahmoudimus.quic.connection.SendBuffer}), streams and flow control ({@link
 * io.github.mahmoudimus.quic.connection.StreamsState}), packet number spaces and ACK generation
 * ({@link io.github.mahmoudimus.quic.connection.PacketSpace}), loss detection ({@link
 * io.github.mahmoudimus.quic.connection.Recovery}), pacing ({@link
 * io.github.mahmoudimus.quic.connection.Pacer}), path MTU discovery ({@link
 * io.github.mahmoudimus.quic.connection.MtuDiscovery}) and timers ({@link
 * io.github.mahmoudimus.quic.connection.TimerTable}).
 *
 * <p>Nothing here performs I/O, reads a clock or starts a thread: every method that depends on time
 * takes the current time as a {@code long} in nanoseconds from one monotonic clock (see {@link
 * io.github.mahmoudimus.quic.connection.NanoClock}), so tests drive them with a fake clock.
 *
 * <p><b>Threads.</b> None of these classes is thread-safe and none takes a lock. Each connection is
 * owned by one driver that serializes all access to it, and the endpoint likewise; configurations
 * are immutable.
 */
package io.github.mahmoudimus.quic.connection;
