/**
 * Issue-117 regression fixture: scalar putfield operand binding and the
 * descriptor-based reference-writer gate.
 *
 * JVM putfield stack order is `..., objectref, value`; the value is on top.
 * These public fields have public roles and the secret fields have secret
 * roles, so the tests can distinguish "stored the argument" from "stored the
 * receiver". `refValue` and `refObject` are reference fields and must stay
 * fail-closed, including when their policy rule omits array_role/seq_role.
 */
public final class FieldStoreProbe {
    public int publicValue;
    public long publicLong;
    public int secretValue;
    public long secretLong;
    public int[] refValue;
    public Object refObject;

    public void set(int value) { publicValue = value; }
    public void setLong(long value) { publicLong = value; }
    public void setSecret(int value) { secretValue = value; }
    public void setSecretLong(long value) { secretLong = value; }
    public void setRef(int[] value) { refValue = value; }
    public void setRefObject(Object value) { refObject = value; }

    public int setAndEcho(int secret) { publicValue = secret; return secret; }

    public int get() { return publicValue; }
    public long getLong() { return publicLong; }
    public int getSecret() { return secretValue; }
    public long getSecretLong() { return secretLong; }
}
