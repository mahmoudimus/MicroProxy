package org.microproxy.thirdparty.larky.objects.type;

import com.google.common.base.Suppliers;
import com.google.common.collect.ImmutableMap;
import java.util.Map;
import java.util.function.Supplier;

import org.microproxy.thirdparty.larky.LarkySemantics;
import org.microproxy.thirdparty.larky.modules.types.LarkyObject;
import org.microproxy.thirdparty.larky.modules.types.PyProtocols;
import org.microproxy.thirdparty.larky.objects.LarkyFunction;
import org.microproxy.thirdparty.larky.objects.PyObject;

import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;

import org.microproxy.thirdparty.larky.modules.utils.Sneaky;

public abstract class TypeClassLookup {

  private TypeClassLookup() {} // do not instantiate

  private static final Map<String, Supplier<Object>> TYPENAMES_TO_CLASS =
    ImmutableMap.of(
      "string", Suppliers.memoize(() -> Starlark.UNIVERSE.get("str")),
      "NoneType", Suppliers.memoize(() ->  Starlark.UNIVERSE.get("None")),
      "function", Suppliers.memoize(() -> LarkyFunction.TYPE)
  );


  private static Object toTypeClass(String typeName) throws EvalException {
    // Is the typename in the fast path?
    Supplier<Object> typeClass = TYPENAMES_TO_CLASS.get(typeName);
    Object out = typeClass.get();
    if(out == null) {
      // It's not, is it in the predeclared universe?
      out = Starlark.UNIVERSE.get(typeName);
      // TODO(mahmoudimus): we should continue caching this to avoid
      //  a second lookup.
      if(out == null) {
        /*
         * It's not, we couldn't find the type class. Abort.
         * It could be that the type name is not mapped 1 <=> 1 in
         * the Starlark.UNIVERSE and might need a special case entry
         * in the TYPENAMES_TO_CLASS field above
        */
        throw Starlark.errorf("Unknown type class for %s.", typeName);
      }
    }
    return out;
  }

  public static Object type(Object x) {
    return type(x,null);
  }

  public static Object type(Object x, StarlarkThread thread) {
    return thread != null && thread.getSemantics().getBool(LarkySemantics.PYCOMPAT_TYPE_BUILTIN_FUNCTION)
             ? pythonLikeBehavior(x, thread)
             : defaultBehavior(x) ;
  }

  public static Object pythonLikeBehavior(Object x, StarlarkThread thread) {
    try {
      Object result;
      if (x instanceof LarkyObject) {
        final LarkyObject larkyObject = (LarkyObject) x;
        if (larkyObject instanceof PyObject) {
          result = ((PyObject) larkyObject).typeClass();
        } else if (larkyObject.hasClassField()) {
          result = larkyObject.getField(PyProtocols.__CLASS__, thread);
        } else if (larkyObject.hasNameField()) {
          result = x;
        } else {
          result = defaultBehavior(x);
        }
      } else {
        result = toTypeClass(defaultBehavior(x));
      }
      return result;
    } catch (Throwable sneaky) {
      throw Sneaky.sneakyThrow(sneaky);
    }
  }


  public static String defaultBehavior(Object obj) {
    String result;
    if (obj instanceof LarkyObject) {
      final LarkyObject larkyObject = (LarkyObject) obj;
      result = larkyObject.typeName();
    } else {
      result = Starlark.type(obj);
    }
    return result;
  }

}
