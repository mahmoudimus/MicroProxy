package org.microproxy.starlark.stdlib;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.ParamType;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.NoneType;
import org.microproxy.thirdparty.starlark.eval.Sequence;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkFloat;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkList;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;

/**
 * {@code @stdlib//jrandom}: randomness from {@link SecureRandom}, for {@code random.star} and
 * {@code uuid.star} (starlarky's came from BouncyCastle's registrar). There is no seeding: every
 * value is unpredictable, like Python's {@code random.SystemRandom}.
 */
@StarlarkBuiltin(name = "jrandom", doc = "Random numbers from SecureRandom (used by @stdlib//random).")
public final class RandomModule implements StarlarkValue {

    static final RandomModule INSTANCE = new RandomModule();

    /** Largest number of bytes one call produces. */
    private static final int MAX_BYTES = 16 << 20;

    private static final SecureRandom RANDOM = new SecureRandom();

    private RandomModule() {}

    private static int count(StarlarkInt n, String what) throws EvalException {
        int count = n.toInt(what);
        if (count < 0) {
            throw Starlark.errorf("ValueError: negative argument not allowed");
        }
        if (count > MAX_BYTES) {
            throw Starlark.errorf("ValueError: %s is too large (at most %d)", what, MAX_BYTES);
        }
        return count;
    }

    /**
     * Produces cryptographically strong random bytes.
     *
     * @param n the number of bytes, from zero through 16 MiB
     * @return immutable random bytes
     * @throws EvalException if the byte count is negative or exceeds the limit
     */
    @StarlarkMethod(name = "urandom", doc = "n random bytes.", parameters = {@Param(name = "n")})
    public StarlarkBytes urandom(StarlarkInt n) throws EvalException {
        byte[] out = new byte[count(n, "n")];
        RANDOM.nextBytes(out);
        return StarlarkBytes.immutableOf(out);
    }

    /**
     * Produces random bytes using the same generator as {@link #urandom}.
     *
     * @param n the number of bytes, from zero through 16 MiB
     * @return immutable random bytes
     * @throws EvalException if the byte count is negative or exceeds the limit
     */
    @StarlarkMethod(name = "randbytes", doc = "n random bytes.", parameters = {@Param(name = "n")})
    public StarlarkBytes randbytes(StarlarkInt n) throws EvalException {
        return urandom(n);
    }

    /**
     * Produces a non-negative integer with at most the requested number of bits.
     *
     * @param k the number of random bits, from zero through 134,217,728 bits
     * @return an integer sampled uniformly from {@code [0, 2**k)}
     * @throws EvalException if the bit count is negative or exceeds the limit
     */
    @StarlarkMethod(name = "getrandbits", doc = "An int with k random bits.", parameters = {@Param(name = "k")})
    public StarlarkInt getrandbits(StarlarkInt k) throws EvalException {
        int bits = k.toInt("k");
        if (bits < 0) {
            throw Starlark.errorf("ValueError: number of bits must be non-negative");
        }
        if (bits > 8 * MAX_BYTES) {
            throw Starlark.errorf("ValueError: k is too large");
        }
        return StarlarkInt.of(new BigInteger(bits, RANDOM));
    }

    /** A uniform random integer in [0, n), n > 0. */
    private static BigInteger below(BigInteger n) {
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), RANDOM);
        } while (r.compareTo(n) >= 0);
        return r;
    }

    /**
     * Chooses an integer uniformly from a stepped, stop-exclusive range.
     *
     * @param start the first value, or the stop value when {@code stop} is {@code None}
     * @param stop the exclusive endpoint, or {@code None} for a range starting at zero
     * @param step the nonzero difference between successive values
     * @return a randomly selected range member
     * @throws EvalException if the step is zero or the range is empty
     */
    @StarlarkMethod(name = "randrange", doc = "randrange(stop) or randrange(start, stop[, step]).",
            parameters = {
                @Param(name = "start"),
                @Param(name = "stop", defaultValue = "None",
                        allowedTypes = {@ParamType(type = StarlarkInt.class), @ParamType(type = NoneType.class)}),
                @Param(name = "step", defaultValue = "1"),
            })
    public StarlarkInt randrange(StarlarkInt start, Object stop, StarlarkInt step) throws EvalException {
        BigInteger lo = start.toBigInteger();
        BigInteger hi;
        if (stop == Starlark.NONE) {
            hi = lo;
            lo = BigInteger.ZERO;
        } else {
            hi = ((StarlarkInt) stop).toBigInteger();
        }
        BigInteger st = step.toBigInteger();
        if (st.signum() == 0) {
            throw Starlark.errorf("ValueError: zero step for randrange()");
        }
        BigInteger width = hi.subtract(lo);
        // number of values: ceil(width / step)
        BigInteger n = st.signum() > 0
                ? width.add(st).subtract(BigInteger.ONE).divide(st)
                : width.add(st).add(BigInteger.ONE).divide(st);
        if (n.signum() <= 0) {
            throw Starlark.errorf("ValueError: empty range for randrange()");
        }
        return StarlarkInt.of(lo.add(st.multiply(below(n))));
    }

    /**
     * Chooses an integer uniformly between inclusive endpoints.
     *
     * @param a the inclusive lower endpoint
     * @param b the inclusive upper endpoint
     * @return a randomly selected integer from {@code a} through {@code b}
     * @throws EvalException if {@code b} is less than {@code a}
     */
    @StarlarkMethod(name = "randint", doc = "A random int N with a <= N <= b.",
            parameters = {@Param(name = "a"), @Param(name = "b")})
    public StarlarkInt randint(StarlarkInt a, StarlarkInt b) throws EvalException {
        BigInteger n = b.toBigInteger().subtract(a.toBigInteger()).add(BigInteger.ONE);
        if (n.signum() <= 0) {
            throw Starlark.errorf("ValueError: empty range for randrange()");
        }
        return StarlarkInt.of(a.toBigInteger().add(below(n)));
    }

    /**
     * Produces a uniformly distributed random fraction.
     *
     * @return a random float in {@code [0.0, 1.0)}
     */
    @StarlarkMethod(name = "random", doc = "A random float in [0.0, 1.0).")
    public StarlarkFloat random() {
        return StarlarkFloat.of(RANDOM.nextDouble());
    }

    /**
     * Interpolates between two numeric endpoints using a random fraction.
     *
     * @param a the first integer or float endpoint
     * @param b the second integer or float endpoint
     * @return a randomly interpolated float
     * @throws EvalException if an endpoint is not a supported number
     */
    @StarlarkMethod(name = "uniform", doc = "A random float between a and b.",
            parameters = {@Param(name = "a"), @Param(name = "b")})
    public StarlarkFloat uniform(Object a, Object b) throws EvalException {
        double x = toDouble(a);
        double y = toDouble(b);
        return StarlarkFloat.of(x + (y - x) * RANDOM.nextDouble());
    }

    private static double toDouble(Object x) throws EvalException {
        if (x instanceof StarlarkInt i) return i.toDouble();
        if (x instanceof StarlarkFloat f) return f.toDouble();
        throw Starlark.errorf("TypeError: must be real number, not %s", Starlark.type(x));
    }

    /**
     * Selects an element uniformly from a non-empty sequence.
     *
     * @param seq the sequence to choose from
     * @return one of the sequence elements
     * @throws EvalException if the sequence is empty
     */
    @StarlarkMethod(name = "choice", doc = "A random element of a non-empty sequence.",
            parameters = {@Param(name = "seq")})
    public Object choice(Sequence<?> seq) throws EvalException {
        if (seq.isEmpty()) {
            throw Starlark.errorf("IndexError: Cannot choose from an empty sequence");
        }
        return seq.get(RANDOM.nextInt(seq.size()));
    }

    /**
     * Randomly permutes a mutable list in place.
     *
     * @param x the list to reorder
     * @throws EvalException if the list cannot be mutated
     */
    @StarlarkMethod(name = "shuffle", doc = "Shuffles a list in place.", parameters = {@Param(name = "x")})
    public void shuffle(StarlarkList<?> x) throws EvalException {
        List<Object> items = new ArrayList<>(x);
        Collections.shuffle(items, RANDOM);
        @SuppressWarnings("unchecked")
        StarlarkList<Object> list = (StarlarkList<Object>) x;
        for (int i = 0; i < items.size(); i++) {
            list.setElementAt(i, items.get(i));
        }
    }

    /**
     * Samples sequence positions without replacement.
     *
     * @param population the source sequence; repeated values remain distinct positions
     * @param k the number of positions to choose
     * @param thread the calling thread that owns the result list
     * @return a list of the selected elements in sampling order
     * @throws EvalException if {@code k} is negative, too large or not representable as an int
     */
    @StarlarkMethod(name = "sample", doc = "A list of k unique elements chosen from population.",
            parameters = {@Param(name = "population"), @Param(name = "k")},
            useStarlarkThread = true)
    public StarlarkList<?> sample(Sequence<?> population, StarlarkInt k, StarlarkThread thread) throws EvalException {
        int n = k.toInt("k");
        if (n < 0 || n > population.size()) {
            throw Starlark.errorf("ValueError: Sample larger than population or is negative");
        }
        List<Object> items = new ArrayList<>(population);
        for (int i = 0; i < n; i++) {
            Collections.swap(items, i, i + RANDOM.nextInt(items.size() - i));
        }
        return StarlarkList.copyOf(thread.mutability(), items.subList(0, n));
    }
}
