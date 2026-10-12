// Ported from rustls src/ticketer.rs (TicketRotator: a current and a previous ticket key, switched
// once per lifetime, with the previous one still decrypting for another lifetime) and
// rustls-ring src/ticketer.rs (AeadTicketer: key_name, nonce, sealed state and tag, the key name
// as additional data, a bound on the ciphertext length) (Apache-2.0), with AES-256-GCM as the AEAD.
package io.github.mahmoudimus.quic.tls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A stateless session ticket encrypter for a server (RFC 8446 section 4.6.1, RFC 5077 section 4):
 * the session state is sealed into the ticket with AES-256-GCM under a server key, so the server
 * keeps nothing per session. The key rotates once per {@linkplain #lifetime() lifetime}; tickets
 * sealed under the previous key are still opened during the following lifetime, so every ticket
 * stays usable for at least one lifetime and at most two.
 *
 * <pre>
 *   key_name (16) | nonce (12) | AES-256-GCM(state) with the key name as additional data | tag (16)
 * </pre>
 *
 * <p>The nonce is random for every ticket (a counter would let observers link tickets). A ticket
 * longer than any this ticketer sealed is rejected before decryption.
 *
 * <p>Servers that must accept each other's tickets need to share a ticketer, which this class does
 * not provide across processes: each instance has its own random keys.
 *
 * <p><b>Threads.</b> Thread-safe without locks: the key state is an immutable value swapped
 * atomically, and every operation uses its own {@link Cipher}.
 */
public final class Ticketer {

    /** The default lifetime of a ticket key, and so of tickets: 6 hours, as rustls uses. */
    public static final Duration DEFAULT_LIFETIME = Duration.ofHours(6);
    /** The longest ticket lifetime TLS 1.3 allows: 7 days (RFC 8446 section 4.6.1). */
    public static final Duration MAX_LIFETIME = Duration.ofDays(7);

    private static final int KEY_NAME_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH = 16;

    /** One key: its name, the AES key, and when it stops sealing new tickets. */
    private record Generation(byte[] keyName, SecretKeySpec key, Instant expires) {}

    private record State(Generation current, Generation previous) {}

    private final Duration lifetime;
    private final InstantSource clock;
    private final SecureRandom random;
    private final AtomicReference<State> state;
    private final AtomicInteger maxCiphertext = new AtomicInteger();

    private Ticketer(Duration lifetime, InstantSource clock, SecureRandom random) {
        if (lifetime.isNegative() || lifetime.isZero() || lifetime.compareTo(MAX_LIFETIME) > 0) {
            throw new IllegalArgumentException("ticket lifetime " + lifetime);
        }
        this.lifetime = lifetime;
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        this.state = new AtomicReference<>(new State(newGeneration(clock.instant()), null));
    }

    /**
     * A ticketer with random keys rotated every {@link #DEFAULT_LIFETIME}.
     *
     * @return the ticketer
     */
    public static Ticketer create() {
        return create(DEFAULT_LIFETIME, InstantSource.system());
    }

    /**
     * A ticketer with random keys.
     *
     * @param lifetime how long a key seals tickets, which is also the lifetime announced in each
     *     ticket; at most 7 days
     * @param clock the wall clock that times rotation
     * @return the ticketer
     * @throws IllegalArgumentException if the lifetime is not positive or exceeds 7 days
     */
    public static Ticketer create(Duration lifetime, InstantSource clock) {
        return new Ticketer(lifetime, clock, new SecureRandom());
    }

    /**
     * The lifetime of a key, announced as the ticket lifetime.
     *
     * @return the lifetime
     */
    public Duration lifetime() {
        return lifetime;
    }

    private Generation newGeneration(Instant now) {
        byte[] key = new byte[32];
        byte[] name = new byte[KEY_NAME_LENGTH];
        random.nextBytes(key);
        random.nextBytes(name);
        Generation g = new Generation(name, new SecretKeySpec(key, "AES"), now.plus(lifetime));
        Arrays.fill(key, (byte) 0);
        return g;
    }

    /** The current state, rotated first if the current key has expired. */
    private State roll(Instant now) {
        while (true) {
            State s = state.get();
            if (!now.isAfter(s.current().expires())) {
                return s;
            }
            State next = new State(newGeneration(now), s.current());
            if (state.compareAndSet(s, next)) {
                return next;
            }
        }
    }

    /**
     * Seals session state into a ticket under the current key.
     *
     * @param plaintext the encoded session state
     * @return the ticket
     */
    public byte[] encrypt(byte[] plaintext) {
        Generation g = roll(clock.instant()).current();
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        byte[] out = new byte[KEY_NAME_LENGTH + NONCE_LENGTH + plaintext.length + TAG_LENGTH];
        System.arraycopy(g.keyName(), 0, out, 0, KEY_NAME_LENGTH);
        System.arraycopy(nonce, 0, out, KEY_NAME_LENGTH, NONCE_LENGTH);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, g.key(), new GCMParameterSpec(TAG_LENGTH * 8, nonce));
            c.updateAAD(g.keyName());
            c.doFinal(plaintext, 0, plaintext.length, out, KEY_NAME_LENGTH + NONCE_LENGTH);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM sealing failed", e);
        }
        maxCiphertext.accumulateAndGet(out.length, Math::max);
        return out;
    }

    /**
     * Opens a ticket sealed by this ticketer under its current key, or its previous key while that
     * is within its grace lifetime.
     *
     * @param ticket the ticket from a client
     * @return the session state, or null if the ticket is not one of ours, has been tampered with,
     *     or its key is gone
     */
    public byte[] decrypt(byte[] ticket) {
        if (ticket.length > maxCiphertext.get() || ticket.length < KEY_NAME_LENGTH + NONCE_LENGTH + TAG_LENGTH) {
            return null;
        }
        Instant now = clock.instant();
        State s = roll(now);
        byte[] plain = open(s.current(), ticket);
        if (plain == null && s.previous() != null && !now.isAfter(s.previous().expires().plus(lifetime))) {
            plain = open(s.previous(), ticket);
        }
        return plain;
    }

    private static byte[] open(Generation g, byte[] ticket) {
        byte[] name = Arrays.copyOfRange(ticket, 0, KEY_NAME_LENGTH);
        if (!MessageDigest.isEqual(name, g.keyName())) {
            return null;
        }
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, g.key(),
                    new GCMParameterSpec(TAG_LENGTH * 8, ticket, KEY_NAME_LENGTH, NONCE_LENGTH));
            c.updateAAD(name);
            int offset = KEY_NAME_LENGTH + NONCE_LENGTH;
            return c.doFinal(ticket, offset, ticket.length - offset);
        } catch (AEADBadTagException e) {
            return null;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM opening failed", e);
        }
    }
}
