/**
 * QUIC packet protection (RFC 9001 section 5): AEAD payload keys, header protection keys, Initial
 * keys per version, key updates and the Retry integrity tag.
 *
 * <p>Key objects hold reusable JDK {@link javax.crypto.Cipher} instances and are confined to one
 * thread at a time; no locking is used.
 */
package io.github.mahmoudimus.quic.crypto;
