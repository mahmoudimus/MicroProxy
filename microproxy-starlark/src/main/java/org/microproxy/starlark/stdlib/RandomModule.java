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

    @StarlarkMethod(name = "urandom", doc = "n random bytes.", parameters = {@Param(name = "n")})
    public StarlarkBytes urandom(StarlarkInt n) throws EvalException {
        byte[] out = new byte[count(n, "n")];
        RANDOM.nextBytes(out);
        return StarlarkBytes.immutableOf(out);
    }

    @StarlarkMethod(name = "randbytes", doc = "n random bytes.", parameters = {@Param(name = "n")})
    public StarlarkBytes randbytes(StarlarkInt n) throws EvalException {
        return urandom(n);
    }

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

    @StarlarkMethod(name = "randint", doc = "A random int N with a <= N <= b.",
            parameters = {@Param(name = "a"), @Param(name = "b")})
    public StarlarkInt randint(StarlarkInt a, StarlarkInt b) throws EvalException {
        BigInteger n = b.toBigInteger().subtract(a.toBigInteger()).add(BigInteger.ONE);
        if (n.signum() <= 0) {
            throw Starlark.errorf("ValueError: empty range for randrange()");
        }
        return StarlarkInt.of(a.toBigInteger().add(below(n)));
    }

    @StarlarkMethod(name = "random", doc = "A random float in [0.0, 1.0).")
    public StarlarkFloat random() {
        return StarlarkFloat.of(RANDOM.nextDouble());
    }

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

    @StarlarkMethod(name = "choice", doc = "A random element of a non-empty sequence.",
            parameters = {@Param(name = "seq")})
    public Object choice(Sequence<?> seq) throws EvalException {
        if (seq.isEmpty()) {
            throw Starlark.errorf("IndexError: Cannot choose from an empty sequence");
        }
        return seq.get(RANDOM.nextInt(seq.size()));
    }

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
