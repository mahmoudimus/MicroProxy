package org.microproxy.thirdparty.larky.objects.type;

import org.microproxy.thirdparty.larky.parser.StarlarkUtil;
import com.google.common.collect.ImmutableList;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import java.util.Map;

import org.microproxy.thirdparty.larky.modules.types.LarkyCollection;
import org.microproxy.thirdparty.larky.objects.LarkyBindable;
import org.microproxy.thirdparty.larky.objects.LarkyFunction;
import org.microproxy.thirdparty.larky.objects.LarkyPyObject;
import org.microproxy.thirdparty.larky.objects.PyObject;

import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.HasBinary;
import org.microproxy.thirdparty.starlark.eval.StarlarkCallable;
import org.microproxy.thirdparty.starlark.eval.StarlarkFunction;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.Tuple;
import org.microproxy.thirdparty.starlark.syntax.TokenKind;

import javax.annotation.Nullable;

final public class LarkyProvidedTypeClass implements
  ForwardingLarkyType,
    TypeConstructor,
    LarkyCollection,
    HasBinary,
    StarlarkCallable
{

  private final ImmutableSet<SpecialMethod> operations;
  private final StarlarkThread thread;
  private final LarkyTypeObject type;
  public LarkyProvidedTypeClass(StarlarkThread thread, LarkyTypeObject type) {
    this.thread = thread;
    this.type = type;
    this.operations =
      getInternalDictUnsafe()
        .keySet()
        .stream()
        .filter(e -> SpecialMethod.of(e) != SpecialMethod.NOT_SET)
        .map(SpecialMethod::of)
        .collect(Sets.toImmutableEnumSet());
    init(thread);
  }

  private void init(StarlarkThread thread) {
    final Map<String, Object> clsDict = this.getInternalDictUnsafe();
    for (Map.Entry<String, Object> entry : clsDict.entrySet()) {
      Object value = entry.getValue();
      if(value instanceof StarlarkFunction) {
        // We are decorating a StarlarkFunction with a LarkyFunction so
        // that we can enable python descriptor support.
        value = LarkyFunction.create((StarlarkFunction) value, thread);
      }

      if (value instanceof LarkyBindable) {
        ((LarkyBindable) value).bindToOwnerIfNotBound(this);
      }

      clsDict.put(entry.getKey(), value);
    }
  }

  @Override
  public Object call(StarlarkThread thread, Tuple args, Dict<String, Object> kwargs) throws EvalException, InterruptedException {
    /*
      If __new__() is invoked during object construction, and it
      returns an instance of cls, then the new instance’s __init__() method
      will be invoked like __init__(self[, ...]), where self is the new
      instance and the remaining arguments are the same as were passed
      to the object constructor.
     */
    LarkyPyObject newInst = (LarkyPyObject) this.__new__(Tuple.concat(Tuple.of(this), args), kwargs, thread);
    LarkyType instanceCls;
    instanceCls = newInst.typeClass();

    if (this == instanceCls) {
      newInst.__init__(args, kwargs);
      return newInst;
    }
    /*
      If __new__() does not return an instance of cls, then the new
      instance’s __init__() method will not be invoked.
     */
    return newInst;

  }

  @Override
  public PyObject __new__(Tuple args, Dict<String, Object> kwargs, StarlarkThread thread) {
    final LarkyType cls = (LarkyType) args.get(0);
    final LarkyPyObject newInst = new LarkyPyObject(cls, thread);
    return newInst;
  }

  @Override
  public String __repr__() {
    return
      String.format("<class '%s'>",
        __name__()
      )
      ;
  }

  @Override
  public String toString() {
    return __name__();
  }

  @Override
  public String getName() {
    return __repr__();
  }

  @Override
  public LarkyType delegate() {
    return type;
  }

  @Override
  public boolean isDataDescriptor() {
    return this.operations.contains(SpecialMethod.dunder_set)
      || this.operations.contains(SpecialMethod.dunder_delete);
  }

  @Override
  public boolean isNonDataDescriptor() {
    return this.operations.contains(SpecialMethod.dunder_get);
  }

  @Override
  public LarkyType typeClass() {
    return LarkyTypeObject.getInstance();
  }

  @Override
  public LarkyType __class__() {
    return LarkyTypeObject.getInstance();
  }

  @Override
  public StarlarkThread getCurrentThread() {
    return StarlarkUtil.callerOr(thread);
  }

  @Nullable
  @Override
  public Object binaryOp(TokenKind op, Object that, boolean thisLeft) throws EvalException {
    return BinaryOpHelper.operatorDispatch(this, op, that, thisLeft, this.getCurrentThread());
  }

  @Override
  public ImmutableSet<SpecialMethod> getSpecialMethods() {
    return operations;
  }

  /** A class is a type: annotating with it accepts its instances and those of its subclasses. */
  @Override
  public StarlarkType createStarlarkType(ImmutableList<TypeConstructor.Term> args)
      throws TypeConstructor.Failure {
    return LarkyClassType.create(this, args);
  }
}
