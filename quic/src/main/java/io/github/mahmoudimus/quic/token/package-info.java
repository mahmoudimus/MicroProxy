/**
 * Address validation tokens (RFC 9000 section 8.1), ported from quinn-proto's {@code token.rs} and
 * {@code bloom_token_log.rs}: Retry and NEW_TOKEN tokens sealed with AES-256-GCM under a key the
 * server holds ({@link io.github.mahmoudimus.quic.token.TokenKey}), their validation with expiry
 * and address binding ({@link io.github.mahmoudimus.quic.token.TokenValidator}), and a bounded
 * replay log ({@link io.github.mahmoudimus.quic.token.BloomTokenLog}).
 */
package io.github.mahmoudimus.quic.token;
