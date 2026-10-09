package org.microproxy.thirdparty.larky.modules.types.structs;

import com.google.common.collect.ImmutableMap;

import org.microproxy.thirdparty.starlark.eval.StarlarkThread;

class ImmutableStruct extends SimpleStruct {
  ImmutableStruct(ImmutableMap<String, Object> fields, StarlarkThread currentThread) {
    super(fields, currentThread);
  }

  @Override
  public boolean isImmutable() {
    return true;
  }
}
