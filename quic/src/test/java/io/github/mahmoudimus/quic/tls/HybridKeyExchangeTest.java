package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.mahmoudimus.quic.QuicException;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem): ML-KEM-768 first, then X25519, in shares and secret. */
class HybridKeyExchangeTest {

    private final SecureRandom random = new SecureRandom();

    @Test
    void clientAndServerAgree() throws Exception {
        KeyExchange client = KeyExchange.generate(NamedGroup.X25519_MLKEM768, random);
        byte[] clientShare = client.publicKey();
        assertEquals(1216, clientShare.length);
        KeyExchange.Response server = KeyExchange.respond(NamedGroup.X25519_MLKEM768, clientShare, random);
        assertEquals(1120, server.publicKey().length);
        byte[] secret = client.agree(server.publicKey());
        assertEquals(64, secret.length);
        assertArrayEquals(server.secret(), secret);
    }

    @Test
    void theSecretIsTheMlKemKeyThenTheX25519One() throws Exception {
        KeyExchange client = KeyExchange.generate(NamedGroup.X25519_MLKEM768, random);
        byte[] clientShare = client.publicKey();
        KeyExchange.Response server = KeyExchange.respond(NamedGroup.X25519_MLKEM768, clientShare, random);
        byte[] serverX25519 = Arrays.copyOfRange(server.publicKey(), 1088, 1120);
        // swapping in a different X25519 share changes only the last 32 bytes of the secret
        KeyExchange other = KeyExchange.generate(NamedGroup.X25519, random);
        byte[] swapped = server.publicKey().clone();
        System.arraycopy(other.publicKey(), 0, swapped, 1088, 32);
        byte[] a = client.agree(server.publicKey());
        byte[] b = client.agree(swapped);
        assertArrayEquals(Arrays.copyOf(a, 32), Arrays.copyOf(b, 32));
        assertEquals(false, Arrays.equals(Arrays.copyOfRange(a, 32, 64), Arrays.copyOfRange(b, 32, 64)));
        assertEquals(32, serverX25519.length);
    }

    @Test
    void sharesOfTheWrongLengthAreIllegalParameters() throws Exception {
        KeyExchange client = KeyExchange.generate(NamedGroup.X25519_MLKEM768, random);
        QuicException e = assertThrows(QuicException.class, () -> client.agree(new byte[1121]));
        assertEquals(QuicException.CRYPTO_ERROR + TlsAlert.ILLEGAL_PARAMETER, e.code());
        e = assertThrows(QuicException.class,
                () -> KeyExchange.respond(NamedGroup.X25519_MLKEM768, new byte[1215], random));
        assertEquals(QuicException.CRYPTO_ERROR + TlsAlert.ILLEGAL_PARAMETER, e.code());
    }

    @Test
    void anEncapsulationKeyFailingTheModulusCheckIsAnIllegalParameter() throws Exception {
        byte[] share = KeyExchange.generate(NamedGroup.X25519_MLKEM768, random).publicKey();
        share[0] = (byte) 0xff;
        share[1] = (byte) 0x0f;
        QuicException e = assertThrows(QuicException.class,
                () -> KeyExchange.respond(NamedGroup.X25519_MLKEM768, share, random));
        assertEquals(QuicException.CRYPTO_ERROR + TlsAlert.ILLEGAL_PARAMETER, e.code());
    }

    @Test
    void aTls13HandshakeNegotiatesTheHybridGroup() throws Exception {
        Handshakes h = HandshakeTest.run(HandshakeTest.client().groups(NamedGroup.X25519_MLKEM768),
                HandshakeTest.server().groups(NamedGroup.X25519_MLKEM768, NamedGroup.X25519));
        h.assertAgreement();
        assertEquals(NamedGroup.X25519_MLKEM768, h.client.negotiatedGroup());
    }

    @Test
    void theServerKeepsPreferringX25519() throws Exception {
        // the client's one share is the hybrid; the server's default groups put X25519 first, so it
        // asks for an X25519 share with a HelloRetryRequest
        Handshakes h = HandshakeTest.run(HandshakeTest.client().groups(NamedGroup.X25519_MLKEM768, NamedGroup.X25519),
                HandshakeTest.server());
        h.assertAgreement();
        assertEquals(NamedGroup.X25519, h.client.negotiatedGroup());
    }
}
