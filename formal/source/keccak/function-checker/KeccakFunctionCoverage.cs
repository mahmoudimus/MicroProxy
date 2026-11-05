using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Microsoft.Dafny;
using Microsoft.Dafny.Plugins;

// DEVELOPMENT COMPONENT: checks four pure-function observation bodies ONLY.
// No method/whole-Keccak/noninterference/delivery/timing qualification.
// Trusted structural observer, not a formal semantics of Dafny or of C#.
public sealed class KeccakFunctionCoverageConfiguration : PluginConfiguration {
  public override Rewriter[] GetRewriters(ErrorReporter reporter) =>
    new Rewriter[] { new KeccakFunctionCoverageRewriter(reporter) };
}

public sealed class KeccakFunctionCoverageRewriter : Rewriter {
  readonly ErrorReporter reporter;
  readonly Dictionary<string, Function> markers = new();
  readonly Dictionary<string, DatatypeCtor> constructors = new();
  readonly Dictionary<ITEExpr, BigInteger> sites = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<BigInteger, ITEExpr> siteOwners = new();
  Function encode;
  Function current;
  static readonly string[] names = { "Rotate", "Constant", "Offset", "Source" };
  static readonly string[] markerNames = { "Call", "Branch", "Read", "Write", "LoopBound", "Ops", "Alloc", "LoopCheck" };
  sealed class Guard {
    public ITEExpr Node;
    public bool Outcome;
    public int[] Operations;
  }
  public KeccakFunctionCoverageRewriter(ErrorReporter reporter) : base(reporter) { this.reporter = reporter; }
  void Error(IOrigin origin, string message) => reporter.Error(MessageSource.Rewriter, origin, "KFC: " + message);
  static Expression E(Expression expression) {
    while (true) {
      if (expression is ConcreteSyntaxExpression c && c.ResolvedExpression != null && !ReferenceEquals(c.ResolvedExpression, expression)) { expression = c.ResolvedExpression; continue; }
      if (expression is ParensExpression p) { expression = p.E; continue; }
      return expression;
    }
  }
  static IVariable Variable(Expression expression) => E(expression) is IdentifierExpr id ? id.Var : null;
  static bool Integer(Expression expression, out BigInteger value) {
    expression = E(expression);
    if (expression is LiteralExpr l && l.Value is BigInteger b) { value = b; return true; }
    if (expression is LiteralExpr s && s.Value is int i) { value = i; return true; }
    value = 0; return false;
  }
  static string TypeName(Microsoft.Dafny.Type type) {
    type = type.NormalizeExpand();
    if (type is BitvectorType b) return "bv" + b.Width;
    if (type is IntType) return "int";
    if (type is BoolType) return "bool";
    if (type is SeqType s) return "seq<" + TypeName(s.Arg) + ">";
    if (type is UserDefinedType u) return u.ResolvedClass?.FullName ?? "unsupported-unresolved-type";
    return "unsupported-type";
  }
  static bool Scalar(Microsoft.Dafny.Type type) {
    type = type.NormalizeExpand();
    return type is BitvectorType b && b.Width > 0 && b.Width <= 64 || type is IntType || TypeName(type) == "NativeTypes.I";
  }
  ModuleDefinition Module(Program program, string name) {
    var modules = program.Modules().Where(m => m.Name == name).ToList();
    if (modules.Count != 1 || modules[0].FullName != name) { Error(program.GetStartOfFirstFileToken(), "missing/duplicate/shadow module " + name); return null; }
    return modules[0];
  }
  DefaultClassDecl Default(ModuleDefinition module) {
    if (module == null) return null;
    var classes = module.TopLevelDecls.OfType<DefaultClassDecl>().ToList();
    if (classes.Count != 1) { Error(module.Tok, "missing/duplicate default class"); return null; }
    return classes[0];
  }
  Function Function(DefaultClassDecl owner, string name) {
    if (owner == null) return null;
    var members = owner.Members.Where(m => m.Name == name).ToList();
    if (members.Count != 1 || members[0] is not Function function || function.FullName != owner.EnclosingModuleDefinition.Name + "._default." + name) {
      Error(owner.Tok, "missing/duplicate/invalid exact function " + name); return null;
    }
    return function;
  }
  public override void PostResolve(Program program) {
    var native = Default(Module(program, "NativeKeccak"));
    var trace = Default(Module(program, "SourceTrace"));
    var vocabulary = Module(program, "SourceObservationVocabulary");
    var vocabularyDefault = Default(vocabulary);
    if (reporter.HasErrors) return;
    encode = Function(vocabularyDefault, "Encode");
    var types = vocabulary.TopLevelDecls.OfType<DatatypeDecl>().Where(t => t.Name == "Event" && t.FullName == "SourceObservationVocabulary.Event").ToList();
    if (types.Count != 1) { Error(vocabulary.Tok, "missing exact Event datatype"); return; }
    foreach (var c in types[0].Ctors) if (!constructors.TryAdd(c.Name, c)) Error(c.Tok, "duplicate Event constructor");
    if (encode == null || !encode.IsGhost || encode.HasExternAttribute || encode.ByMethodDecl != null || encode.ByMethodBody != null || TypeName(encode.ResultType) != "seq<int>") {
      Error(vocabulary.Tok, "invalid concrete ghost canonical encoder"); return;
    }
    NativeCanonicalEncoderPolicy.Check(encode, constructors, Error);
    foreach (var name in markerNames) {
      var marker = Function(trace, name);
      if (marker == null) continue;
      markers[name] = marker;
      CheckMarker(name, marker);
    }
    if (reporter.HasErrors) return;
    var actualFunctions = native.Members.OfType<Function>().Where(f => !f.IsGhost).ToList();
    if (actualFunctions.Count != names.Length || actualFunctions.Any(f => !names.Contains(f.Name))) Error(native.Tok, "non-ghost function inventory differs from exact four native functions");
    foreach (var name in names) {
      var function = Function(native, name);
      if (function != null) CheckFunction(function);
    }
    if (!reporter.HasErrors) Console.WriteLine("KECCAK-FUNCTION-OBSERVATIONS OK: exact functions [NativeKeccak.Rotate,NativeKeccak.Constant,NativeKeccak.Offset,NativeKeccak.Source]; FUNCTION-ONLY DEVELOPMENT SCOPE");
  }
  void CheckMarker(string name, Function function) {
    if (!function.IsGhost || function.HasExternAttribute || function.ByMethodDecl != null || function.ByMethodBody != null || TypeName(function.ResultType) != "seq<int>" || function.Body == null) { Error(function.Tok, "invalid exact ghost marker " + name); return; }
    if (E(function.Body) is not FunctionCallExpr call || !ReferenceEquals(call.Function, encode) || call.Args.Count != 1 || E(call.Args[0]) is not DatatypeValue value || !constructors.TryGetValue(name, out var ctor) || !ReferenceEquals(value.Ctor, ctor) || value.Arguments.Count != function.Ins.Count || ctor.Formals.Count != function.Ins.Count) {
      Error(function.Tok, "marker body is not exact canonical Encode(constructor(positional arguments)): " + name); return;
    }
    for (int i = 0; i < function.Ins.Count; i++) if (!ReferenceEquals(Variable(value.Arguments[i]), function.Ins[i])) Error(value.Arguments[i].Tok, "marker changes/reorders formal " + i);
  }
  void CheckFunction(Function function) {
    current = function; sites.Clear(); siteOwners.Clear();
    var inputs = function.Name == "Rotate" ? new[] { "bv64", "NativeTypes.I" } : new[] { "NativeTypes.I" };
    string result = function.Name is "Offset" or "Source" ? "NativeTypes.I" : "bv64";
    if (function.IsGhost || function.HasExternAttribute || function.ByMethodDecl != null || function.ByMethodBody != null || function.ByMethodTok != null || function.ReadsHeap || function.Reads.Children.Any() || function.Body == null || Attributes.Contains(function.Attributes, "opaque")) { Error(function.Tok, "function is not concrete, read-free, executable, non-by-method native code"); return; }
    if (function.Ins.Count != inputs.Length || function.Ins.Where((p,i) => i >= inputs.Length || p.IsGhost || TypeName(p.Type) != inputs[i]).Any()) { Error(function.Tok, "function input signature mismatch"); return; }
    if (function.ResultType.NormalizeExpand() is not UserDefinedType tuple || tuple.ResolvedClass is not TupleTypeDecl declaration || declaration.Dims != 2 || tuple.TypeArgs.Count != 2 || declaration.ArgumentGhostness.Count != 2 || declaration.ArgumentGhostness[0] || !declaration.ArgumentGhostness[1] || TypeName(tuple.TypeArgs[0]) != result || TypeName(tuple.TypeArgs[1]) != "seq<int>") { Error(function.Tok, "result must be exact native value/ghost seq<int> tuple"); return; }
    CheckPath(function.Body, new List<Guard>(), tuple, result);
  }
  void CheckPath(Expression expression, List<Guard> path, UserDefinedType tuple, string result) {
    expression = E(expression);
    if (expression is ITEExpr branch) {
      var operations = new int[7];
      if (TypeName(branch.Test.Type) != "bool" || !Count(branch.Test, operations, true)) { Error(branch.Test.Tok, "unsupported actual branch guard"); return; }
      var yes = new List<Guard>(path) { new Guard { Node=branch, Outcome=true, Operations=operations } };
      var no = new List<Guard>(path) { new Guard { Node=branch, Outcome=false, Operations=operations } };
      CheckPath(branch.Thn, yes, tuple, result); CheckPath(branch.Els, no, tuple, result); return;
    }
    if (expression is not DatatypeValue value || !ReferenceEquals(value.Ctor.EnclosingDatatype, tuple.ResolvedClass) || value.Arguments.Count != 2 || value.Ctor.Formals.Count != 2 || value.Ctor.Formals[0].IsGhost || !value.Ctor.Formals[1].IsGhost || TypeName(value.Arguments[0].Type) != result) { Error(expression.Tok, "native leaf is not the actual value/ghost trace tuple"); return; }
    var ops = new int[7];
    if (!Count(value.Arguments[0], ops, false)) { Error(value.Arguments[0].Tok, "unsupported actual value expression (including calls, arrays or higher-order forms)"); return; }
    var observations = Leaves(value.Arguments[1]).ToList();
    int index = 0;
    foreach (var guard in path) {
      if (guard.Operations.Any(c => c != 0)) RequireOps(observations, ref index, guard.Operations, value.Tok);
      if (index >= observations.Count || E(observations[index]) is not FunctionCallExpr marker || !ReferenceEquals(marker.Function, markers["Branch"]) || marker.Args.Count != 2 || !Integer(marker.Args[0], out var site) || site < 0 || site > int.MaxValue || E(marker.Args[1]) is not LiteralExpr outcome || outcome.Value is not bool flag || flag != guard.Outcome) { Error(value.Tok, "trace omits/changes actual branch prefix or branch outcome"); return; }
      if (sites.TryGetValue(guard.Node, out var prior) && prior != site) Error(marker.Tok, "same actual guard has inconsistent static site labels");
      else sites[guard.Node] = site;
      if (siteOwners.TryGetValue(site, out var owner) && !ReferenceEquals(owner, guard.Node)) Error(marker.Tok, "different actual guards reuse a static site label");
      else siteOwners[site] = guard.Node;
      index++;
    }
    if (ops.Any(c => c != 0)) RequireOps(observations, ref index, ops, value.Tok);
    if (index != observations.Count) Error(observations[index].Tok, "trace has unexpected extra observations");
  }
  static IEnumerable<Expression> Leaves(Expression expression) {
    expression = E(expression);
    if (expression is BinaryExpr b && b.ResolvedOp == BinaryExpr.ResolvedOpcode.Concat) return Leaves(b.E0).Concat(Leaves(b.E1));
    if (expression is SeqDisplayExpr s && s.Elements.Count == 0) return Enumerable.Empty<Expression>();
    return new[] { expression };
  }
  void RequireOps(List<Expression> observations, ref int index, int[] expected, IOrigin origin) {
    if (index >= observations.Count || E(observations[index]) is not FunctionCallExpr marker || !ReferenceEquals(marker.Function, markers["Ops"]) || marker.Args.Count != 7) { Error(origin, "trace omits actual scalar operation family counts"); return; }
    for (int i=0; i<expected.Length; i++) if (!Integer(marker.Args[i], out var actual) || actual != expected[i]) Error(marker.Args[i].Tok, "scalar operation count mismatch at family " + i);
    index++;
  }
  bool Count(Expression expression, int[] operations, bool guard) {
    expression = E(expression);
    if (expression is IdentifierExpr id) return current.Ins.Any(p => ReferenceEquals(p,id.Var)) && !id.Var.IsGhost && Scalar(id.Type);
    if (expression is LiteralExpr literal) return Scalar(literal.Type) || guard && literal.Value is bool;
    if (expression is ConversionExpr conversion) return Scalar(conversion.Type) && Scalar(conversion.E.Type) && Count(conversion.E,operations,false);
    if (expression is not BinaryExpr binary) return false;
    if (binary.Op == BinaryExpr.Opcode.Eq || binary.Op == BinaryExpr.Opcode.Neq)
      return guard && Count(binary.E0,operations,false) && Count(binary.E1,operations,false);
    int family;
    switch (binary.ResolvedOp) {
      case BinaryExpr.ResolvedOpcode.Add: family=0; break;
      case BinaryExpr.ResolvedOpcode.Sub: family=1; break;
      case BinaryExpr.ResolvedOpcode.Mul: family=2; break;
      case BinaryExpr.ResolvedOpcode.Div: family=3; break;
      case BinaryExpr.ResolvedOpcode.Mod: family=4; break;
      case BinaryExpr.ResolvedOpcode.BitwiseAnd:
      case BinaryExpr.ResolvedOpcode.BitwiseOr:
      case BinaryExpr.ResolvedOpcode.BitwiseXor: family=5; break;
      case BinaryExpr.ResolvedOpcode.LeftShift:
      case BinaryExpr.ResolvedOpcode.RightShift: family=6; break;
      default: return false;
    }
    if (!Scalar(binary.Type) || !Scalar(binary.E0.Type) || !Scalar(binary.E1.Type)) return false;
    operations[family]++;
    return Count(binary.E0,operations,false) && Count(binary.E1,operations,false);
  }
}
