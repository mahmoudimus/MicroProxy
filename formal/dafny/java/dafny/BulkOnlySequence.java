package dafny;

import java.util.Arrays;

/**
 * Test-only byte sequence whose element-access path throws, so a caller that boxes through
 * {@code DafnySequence.select} fails while the primitive bulk-copy path succeeds.
 *
 * <p>Pinned DafnyRuntime 4.9.1 declares {@code ArrayDafnySequence} final, so this class cannot
 * subclass it as originally suggested. It instead constructs the real package-private
 * {@code ArrayDafnySequence} with a {@code TypeDescriptor<Byte>} whose {@code cloneArray} returns a
 * primitive {@code byte[]} copy and whose {@code getArrayElement} throws. That is the actual ABI
 * used by the runtime, without changing production code.
 */
@SuppressWarnings("auxiliaryclass")
public final class BulkOnlySequence {
    private BulkOnlySequence() {}

    public static DafnySequence<Byte> of(byte[] bytes) {
        return new ArrayDafnySequence<>(new ThrowingByteType(), bytes);
    }

    private static final class ThrowingByteType extends TypeDescriptor<Byte> {
        ThrowingByteType() {
            super(Byte.TYPE);
        }

        @Override
        public Byte defaultValue() {
            return 0;
        }

        @Override
        public boolean isInstance(Object value) {
            return value instanceof Byte;
        }

        @Override
        public TypeDescriptor<?> arrayType() {
            return BYTE_ARRAY;
        }

        @Override
        public Byte getArrayElement(Object array, int index) {
            throw new AssertionError("payload element access through select is forbidden");
        }

        @Override
        public void setArrayElement(Object array, int index, Byte value) {
            ((byte[]) array)[index] = value;
        }

        @Override
        public Object cloneArray(Object array) {
            return ((byte[]) array).clone();
        }

        @Override
        public void fillArray(Object array, Byte value) {
            Arrays.fill((byte[]) array, value);
        }

        @Override
        public boolean arrayShallowEquals(Object left, Object right) {
            return Arrays.equals((byte[]) left, (byte[]) right);
        }
    }
}
