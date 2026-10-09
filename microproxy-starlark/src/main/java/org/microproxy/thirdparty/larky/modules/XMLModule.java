package org.microproxy.thirdparty.larky.modules;

import org.microproxy.thirdparty.larky.modules.xml.LarkyXMLNamespaceContext;

import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;


@StarlarkBuiltin(
    name = "jxml",
    category = "BUILTIN",
    doc = "java specific xml/xml-security/xmldsig/xml-crypto implementation")
public class XMLModule implements StarlarkValue {
  public static final XMLModule INSTANCE = new XMLModule();

  @StarlarkMethod(name="_namespace_map", useStarlarkThread = true)
  public LarkyXMLNamespaceContext namespaceMap(StarlarkThread thread) {
    return LarkyXMLNamespaceContext.forThread(thread);
  }
}
