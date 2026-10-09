package org.microproxy.thirdparty.larky.modules.types;

import com.google.common.collect.ImmutableList;

import org.microproxy.thirdparty.larky.parser.StarlarkUtil;

import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkCallable;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.StarlarkSetIndexable;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.syntax.TokenKind;


public interface LarkyIndexable extends LarkyObject, StarlarkSetIndexable.Threaded {

  default Object get__setitem__() {
    return getField(PyProtocols.__SETITEM__);
  }

  default Object get__getitem__() {
    return getField(PyProtocols.__GETITEM__);
  }


  default Object get__contains__() {
    return getField(PyProtocols.__CONTAINS__);
  }

  @Override
  default void setIndex(StarlarkThread starlarkThread, StarlarkSemantics semantics, Object key, Object value) throws EvalException {
    final Object __setitem__ = get__setitem__();
    if(__setitem__ != null && StarlarkUtil.isCallable(__setitem__)) {
      Starlark.checkHashable(key);
      this.invoke(starlarkThread, __setitem__, ImmutableList.of(key, value), EMPTY_KWARGS);
      return;
    }
    throw Starlark.errorf("TypeError: '%s' object does not support item assignment", typeName());
  }

  @Override
  default Object getIndex(StarlarkThread starlarkThread, StarlarkSemantics semantics, Object key) throws EvalException {
    // The __getitem__ magic method is usually used for list indexing, dictionary lookup, or
    // accessing ranges of values.
    final StarlarkCallable __getitem__ = (StarlarkCallable) get__getitem__();
    if(__getitem__ != null) {
      return this.invoke(starlarkThread, __getitem__, ImmutableList.of(key), EMPTY_KWARGS);
    }
    throw Starlark.errorf("TypeError: '%s' object is not subscriptable", typeName());
  }

  @Override
  default boolean containsKey(StarlarkThread starlarkThread, StarlarkSemantics semantics, Object key) throws EvalException {
    return __contains__(this, TokenKind.IN, key, false, starlarkThread);
  }

  /**
   * The below does not belong in LarkyObject because LarkyObject does not dictate what operations should exist on an
   * object. That is left to the interface implementer.
   *
   * However, in Larky, we can simply "tack-on" the magic method (i.e. __len__
   * or __contains__, etc.) and we expect various operations to work on that object.
   *
   * This is why we want to make it easy to have Indexable so we can operator overload [], etc.
   */
  default boolean __contains__(LarkyIndexable lhs, TokenKind op, Object rhs, boolean thisLeft, StarlarkThread thread) throws EvalException {
    // is this (thisLeft = true) "is this in that?" or (thisLeft = false) "is that in this?"
    // first, check to see if __contains__ exists?
    final StarlarkCallable __contains__ =
      thisLeft
        ? (StarlarkCallable) ((LarkyIndexable) rhs).get__contains__()
        : (StarlarkCallable) lhs.get__contains__();
    if (__contains__ != null) {
      return thisLeft
               ? (boolean) ((LarkyIndexable) rhs).invoke(thread, __contains__, ImmutableList.of(lhs), EMPTY_KWARGS)
               : (boolean) lhs.invoke(thread, __contains__, ImmutableList.of(rhs), EMPTY_KWARGS);
    }
    throw Starlark.errorf(
      "unsupported binary operation: %s %s %s", Starlark.type(rhs), TokenKind.IN, typeName());
  }

}
