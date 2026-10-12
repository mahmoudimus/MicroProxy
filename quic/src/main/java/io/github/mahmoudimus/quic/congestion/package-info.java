/**
 * Congestion control for QUIC (RFC 9002 section 7), ported from quinn-proto's {@code congestion}
 * module: the {@link io.github.mahmoudimus.quic.congestion.Controller} interface, {@link
 * io.github.mahmoudimus.quic.congestion.NewReno} (RFC 9002), {@link
 * io.github.mahmoudimus.quic.congestion.Cubic} (RFC 9438, the default, as in quinn) and the {@link
 * io.github.mahmoudimus.quic.congestion.RttEstimator} they read.
 *
 * <p>All times are nanoseconds from the connection's monotonic clock, passed in by the caller.
 * Controllers are not thread-safe and take no locks: each belongs to one connection, which
 * serializes access; configurations are immutable and shared.
 */
package io.github.mahmoudimus.quic.congestion;
