/** Negative control: overridable virtual method controls a branch. */
public final class VirtualDispatch {
    public static class Base {
        public int tag() {
            return 0;
        }
    }

    public static class Sub extends Base {
        private final byte[] secret;

        Sub(byte[] secret) {
            this.secret = secret;
        }

        @Override
        public int tag() {
            return secret[0];
        }
    }

    public static int run(byte[] ignored, Base value) {
        if (value.tag() != 0) {
            return 1;
        }
        return 0;
    }
}
