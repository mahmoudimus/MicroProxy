/**
 * The sans-I/O building blocks of a QUIC connection, ported from quinn-proto's {@code connection}
 * module: range sets ({@link io.github.mahmoudimus.quic.connection.RangeSet}), reassembly of
 * received data ({@link io.github.mahmoudimus.quic.connection.Assembler}), buffering of sent data
 * ({@link io.github.mahmoudimus.quic.connection.SendBuffer}), streams and flow control ({@link
 * io.github.mahmoudimus.quic.connection.StreamsState}) and pacing ({@link
 * io.github.mahmoudimus.quic.connection.Pacer}).
 *
 * <p>Nothing here performs I/O, reads a clock or starts a thread: every method that depends on time
 * takes the current time as a {@code long} in nanoseconds from one monotonic clock (see {@link
 * io.github.mahmoudimus.quic.connection.NanoClock}), so tests drive them with a fake clock.
 *
 * <p><b>Threads.</b> None of these classes is thread-safe and none takes a lock. Each instance is
 * owned by a single connection, and the connection layer serializes all access to it.
 */
package io.github.mahmoudimus.quic.connection;
