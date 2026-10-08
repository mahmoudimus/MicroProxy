package org.microproxy.dns;

import java.net.UnknownHostException;

/**
 * DNS data failed DNSSEC validation ("bogus"): a signature did not verify, a chain of trust was
 * broken, or signed data was missing its signatures or denial proofs. The host is treated as
 * unresolvable.
 */
public class DnssecValidationException extends UnknownHostException {

    public DnssecValidationException(String message) {
        super(message);
    }
}
