package org.microproxy;

/** Implementations of the shared server connection pool. */
public enum ServerConnectionPoolType {
    /** Idle connections kept per host and route, with global and per-host limits. */
    CONCURRENT_MAP
}
