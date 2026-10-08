package org.microproxy;

/**
 * A snapshot of the shared server connection pool.
 *
 * @param totalConnections pooled connections alive, leased or idle
 * @param activeConnections connections currently leased to a request or session
 * @param idleConnections connections waiting in the pool
 * @param borrowCount leases granted (reused or newly created)
 * @param returnCount connections returned to the pool
 * @param evictionCount idle connections closed for idle timeout or to make room
 * @param validationFailureCount idle connections found closed when about to be reused
 */
// @value-candidate: becomes a value class in the valhalla build profile
public record PoolMetrics(
        int totalConnections,
        int activeConnections,
        int idleConnections,
        long borrowCount,
        long returnCount,
        long evictionCount,
        long validationFailureCount) {}
