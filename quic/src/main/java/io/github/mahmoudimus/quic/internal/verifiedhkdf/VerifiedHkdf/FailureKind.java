// Class FailureKind
// Dafny class FailureKind compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf;


@SuppressWarnings({"unchecked", "deprecation"})
public abstract class FailureKind {
  public FailureKind() {
  }
  private static final dafny.TypeDescriptor<FailureKind> _TYPE = dafny.TypeDescriptor.<FailureKind>referenceWithInitializer(FailureKind.class, () -> FailureKind.Default());
  public static dafny.TypeDescriptor<FailureKind> _typeDescriptor() {
    return (dafny.TypeDescriptor<FailureKind>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final FailureKind theDefault = io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.FailureKind.create_InvalidHash();
  public static FailureKind Default() {
    return theDefault;
  }
  public static FailureKind create_InvalidHash() {
    return new FailureKind_InvalidHash();
  }
  public static FailureKind create_InvalidKey() {
    return new FailureKind_InvalidKey();
  }
  public static FailureKind create_InvalidLength() {
    return new FailureKind_InvalidLength();
  }
  public static FailureKind create_InvalidLabel() {
    return new FailureKind_InvalidLabel();
  }
  public boolean is_InvalidHash() { return this instanceof FailureKind_InvalidHash; }
  public boolean is_InvalidKey() { return this instanceof FailureKind_InvalidKey; }
  public boolean is_InvalidLength() { return this instanceof FailureKind_InvalidLength; }
  public boolean is_InvalidLabel() { return this instanceof FailureKind_InvalidLabel; }
  public static java.util.ArrayList<FailureKind> AllSingletonConstructors() {
    java.util.ArrayList<FailureKind> singleton_iterator = new java.util.ArrayList<>();
    singleton_iterator.add(new FailureKind_InvalidHash());
    singleton_iterator.add(new FailureKind_InvalidKey());
    singleton_iterator.add(new FailureKind_InvalidLength());
    singleton_iterator.add(new FailureKind_InvalidLabel());
    return singleton_iterator;
  }
}
