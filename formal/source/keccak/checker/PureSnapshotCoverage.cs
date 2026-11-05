using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Microsoft.Dafny;
using Microsoft.Dafny.Plugins;

// Trusted resolved-AST binding checker for the focused pure-snapshot protocol.
//
// This is deliberately a binding-only gate.  It does not prove the checker,
// operation coverage, Keccak, noninterference or the C# rule itself.  It binds
// one explicitly ghost full-tuple witness to the exact actual NativeKeccak.Rotate
// declaration, one inline .0 value call, and exactly one ordered child .1 leaf in
// a pre-statement trace packet.  Every unsupported shape is an error.
public class PureSnapshotCoverageConfiguration : PluginConfiguration {
  public override Rewriter[] GetRewriters(ErrorReporter reporter) =>
    new Rewriter[] { new PureSnapshotCoverageRewriter(reporter) };
}

public class PureSnapshotCoverageRewriter : Rewriter {
  const string RootModule = "SnapshotBindingControls";
  const string NativeModule = "NativeKeccak";
  const string TraceModule = "SourceTrace";
  static readonly string[] RootNames = { "Local", "ArrayRead", "Around" };
  static readonly string[] MarkerNames = { "Call", "Read", "Write", "Ops", "Branch" };
  const int RotateTarget = 20;

  sealed class RootShape {
    public string[] Ins;
    public string[] Outs;
    public bool[] OutGhost;
  }

  static readonly Dictionary<string, RootShape> rootShapes = new() {
    ["Local"] = new RootShape {
      Ins = new[] { "bv64", "NativeTypes.I" },
      Outs = new[] { "bv64", "seq<int>" }, OutGhost = new[] { false, true } },
    ["ArrayRead"] = new RootShape {
      Ins = new[] { "array<bv64>", "array<bv64>", "NativeTypes.I", "NativeTypes.I", "NativeTypes.I" },
      Outs = new[] { "seq<int>" }, OutGhost = new[] { true } },
    ["Around"] = new RootShape {
      Ins = new[] { "array<bv64>", "NativeTypes.I" },
      Outs = new[] { "bv64", "seq<int>" }, OutGhost = new[] { false, true } },
  };

  readonly ErrorReporter reporter;
  Function rotateFunction;
  readonly Dictionary<string, Function> markerFunctions = new();
  Method currentMethod;
  Formal traceFormal;

  sealed class Definition {
    public IVariable Var;
    public Expression Rhs;
    public AssignStatement Assign;
    public IOrigin Tok;
    public bool Ghost;
  }

  sealed class Candidate {
    public LocalVariable Local;
    public VarDeclStmt VarDecl;
    public AssignStatement Assign;
    public Expression Rhs;
    public FunctionCallExpr Call;
  }

  sealed class RuntimeEvent {
    public string Kind;              // Read, Write, Call, Child, Ops
    public int Site = -1;
    public int Role = -1;
    public Expression Address;
    public int Target = -1;
    public int Arity = -1;
    public int[] Ops;
  }

  sealed class EventContext {
    public int Site;
    public bool CallSeen;
  }

  public PureSnapshotCoverageRewriter(ErrorReporter reporter) : base(reporter) {
    this.reporter = reporter;
  }

  void Error(IOrigin tok, string message) {
    reporter.Error(MessageSource.Rewriter, tok, message);
  }

  static string TypeSig(Microsoft.Dafny.Type t) {
    t = t.NormalizeExpand();
    if (t is BitvectorType bv) return "bv" + bv.Width;
    if (t is IntType) return "int";
    if (t is BoolType) return "bool";
    if (t is SeqType st) return "seq<" + TypeSig(st.Arg) + ">";
    if (t is UserDefinedType u) {
      if (u.IsArrayType) {
        if (u.AsArrayType == null || u.AsArrayType.Dims != 1) return "array-rank-" + (u.AsArrayType?.Dims ?? -1);
        if (u.TypeArgs == null || u.TypeArgs.Count != 1) return "array-arity-" + (u.TypeArgs?.Count ?? -1);
        return "array<" + TypeSig(u.TypeArgs[0]) + ">";
      }
      if (u.ResolvedClass != null) return u.ResolvedClass.FullName;
      return u.FullName;
    }
    return t.ToString();
  }

  static bool TypeEq(Microsoft.Dafny.Type a, Microsoft.Dafny.Type b) {
    if (a == null || b == null) return ReferenceEquals(a, b);
    a = a.NormalizeExpand();
    b = b.NormalizeExpand();
    if (a is BitvectorType ba && b is BitvectorType bb) return ba.Width == bb.Width;
    if (a is IntType && b is IntType) return true;
    if (a is BoolType && b is BoolType) return true;
    if (a is SeqType sa && b is SeqType sb) return TypeEq(sa.Arg, sb.Arg);
    if (a is UserDefinedType ua && b is UserDefinedType ub) {
      if (ua.IsArrayType || ub.IsArrayType) {
        if (!ua.IsArrayType || !ub.IsArrayType) return false;
        if ((ua.AsArrayType?.Dims ?? -1) != (ub.AsArrayType?.Dims ?? -1)) return false;
      } else if (ua.ResolvedClass != null || ub.ResolvedClass != null) {
        if (!ReferenceEquals(ua.ResolvedClass, ub.ResolvedClass)) return false;
      } else if (ua.FullName != ub.FullName) {
        return false;
      }
      var at = ua.TypeArgs ?? new List<Microsoft.Dafny.Type>();
      var bt = ub.TypeArgs ?? new List<Microsoft.Dafny.Type>();
      if (at.Count != bt.Count) return false;
      for (int i = 0; i < at.Count; i++) if (!TypeEq(at[i], bt[i])) return false;
      return true;
    }
    return false; // Unknown resolved type kinds are never equal by spelling.
  }

  static bool IsGhostTuple(Microsoft.Dafny.Type t) {
    t = t.NormalizeExpand();
    if (t is not UserDefinedType ud || ud.ResolvedClass is not TupleTypeDecl tt || tt.Dims != 2) return false;
    var g = tt.ArgumentGhostness;
    return g.Count == 2 && !g[0] && g[1] && ud.TypeArgs.Count == 2 &&
           TypeSig(ud.TypeArgs[0]) == "bv64" && TypeSig(ud.TypeArgs[1]) == "seq<int>";
  }

  static Expression Unwrap(Expression e) {
    while (e is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null &&
           !ReferenceEquals(cse.ResolvedExpression, e)) e = cse.ResolvedExpression;
    return e;
  }

  static Expression Strip(Expression e) {
    while (true) {
      e = Unwrap(e);
      if (e is ParensExpression p) { e = p.E; continue; }
      return e;
    }
  }

  static IVariable AsVar(Expression e) {
    e = Strip(e);
    if (e is IdentifierExpr id) return id.Var;
    if (e is AutoGhostIdentifierExpr ag) return ag.Var;
    return null;
  }

  static bool TryInt(Expression e, out BigInteger value) {
    e = Strip(e);
    if (e is LiteralExpr lit && lit.Value is BigInteger big) { value = big; return true; }
    if (e is LiteralExpr lit2 && lit2.Value is int small) { value = small; return true; }
    value = 0;
    return false;
  }

  static bool IsEmptySeq(Expression e) {
    e = Strip(e);
    return e is SeqDisplayExpr display && display.Elements.Count == 0;
  }

  static bool IsTrue(Expression e) {
    e = Strip(e);
    return e is LiteralExpr lit && lit.Value is bool b && b;
  }

  static IEnumerable<Expression> ConcatLeaves(Expression e) {
    e = Unwrap(e);
    if (e is ParensExpression p) return ConcatLeaves(p.E);
    if (e is BinaryExpr b && b.ResolvedOp == BinaryExpr.ResolvedOpcode.Concat)
      return ConcatLeaves(b.E0).Concat(ConcatLeaves(b.E1));
    return new[] { e };
  }

  static FunctionCallExpr DirectCall(Expression e) {
    e = Strip(e);
    if (e is FunctionCallExpr fc) return fc;
    if (e is ApplySuffix ap) {
      if (ap.ResolvedExpression is FunctionCallExpr resolved) return resolved;
      if (Strip(ap.Lhs) is FunctionCallExpr lhs) return lhs;
      foreach (var child in ap.SubExpressions) {
        var direct = DirectCall(child);
        if (direct != null) return direct;
      }
    }
    return null;
  }

  static IEnumerable<FunctionCallExpr> AllCalls(Expression e) {
    var seen = new HashSet<Expression>(ReferenceEqualityComparer.Instance);
    foreach (var x in e.DescendantsAndSelf) {
      if (!seen.Add(x)) continue;
      if (x is FunctionCallExpr fc) yield return fc;
    }
  }

  static bool MentionsTrace(Expression e, Formal trace) {
    foreach (var x in e.DescendantsAndSelf)
      if (x is IdentifierExpr id && ReferenceEquals(id.Var, trace)) return true;
    return false;
  }

  ModuleDefinition ExactModule(Program program, string name) {
    var matches = program.Modules().Where(m => m.Name == name).ToList();
    if (matches.Count != 1 || matches[0].FullName != name) {
      Error(program.GetStartOfFirstFileToken(), "PSB001: missing, duplicate or shadowed exact module " + name);
      return null;
    }
    return matches[0];
  }

  DefaultClassDecl ExactDefault(ModuleDefinition module) {
    if (module == null) return null;
    var defaults = module.TopLevelDecls.OfType<DefaultClassDecl>().ToList();
    if (defaults.Count != 1) {
      Error(module.Tok, "PSB001: missing exact default class in " + module.FullName);
      return null;
    }
    return defaults[0];
  }

  Function FindFunction(DefaultClassDecl decl, string name) {
    if (decl == null) return null;
    var matches = decl.Members.OfType<Function>()
      .Where(f => f.Name == name && f.FullName == decl.EnclosingModuleDefinition.Name + "._default." + name).ToList();
    if (matches.Count != 1) {
      Error(decl.Tok, "PSB001: expected exactly one exact function " + name + " in " + decl.EnclosingModuleDefinition.Name);
      return null;
    }
    return matches[0];
  }

  Method FindMethod(DefaultClassDecl decl, string name) {
    if (decl == null) return null;
    var matches = decl.Members.OfType<Method>()
      .Where(m => m.Name == name && m.FullName == decl.EnclosingModuleDefinition.Name + "._default." + name).ToList();
    if (matches.Count == 0) {
      Error(decl.Tok, "PSB001: missing required root " + decl.EnclosingModuleDefinition.Name + "." + name);
      return null;
    }
    if (matches.Count != 1) {
      Error(decl.Tok, "PSB001: duplicate required root " + decl.EnclosingModuleDefinition.Name + "." + name);
      return null;
    }
    return matches[0];
  }

  public override void PostResolve(Program program) {
    var module = ExactModule(program, RootModule);
    var native = ExactModule(program, NativeModule);
    var trace = ExactModule(program, TraceModule);
    if (module == null || native == null || trace == null) return;

    var rootDefault = ExactDefault(module);
    var nativeDefault = ExactDefault(native);
    var traceDefault = ExactDefault(trace);
    if (rootDefault == null || nativeDefault == null || traceDefault == null) return;

    markerFunctions.Clear();
    foreach (var name in MarkerNames) {
      var fn = FindFunction(traceDefault, name);
      if (fn == null) continue;
      if (!fn.IsGhost || fn.ByMethodDecl != null || fn.ByMethodBody != null || fn.Body == null) {
        Error(fn.Tok, "PSB022: SourceTrace." + name + " is not the exact ghost, concrete marker declaration");
        continue;
      }
      markerFunctions[name] = fn;
    }
    rotateFunction = FindFunction(nativeDefault, "Rotate");
    if (rotateFunction != null) CheckAdmittedFunction(rotateFunction, "NativeKeccak.Rotate");
    if (reporter.HasErrors) return;

    foreach (var name in RootNames) {
      var method = FindMethod(rootDefault, name);
      if (method == null) continue;
      CheckRoot(method);
    }
    if (!reporter.HasErrors) {
      Console.WriteLine("PURE-SNAPSHOT-BINDING OK: exact roots [SnapshotBindingControls.Local,SnapshotBindingControls.ArrayRead,SnapshotBindingControls.Around]");
      foreach (var name in RootNames) Console.WriteLine("PURE-SNAPSHOT-BINDING ROOT OK: SnapshotBindingControls." + name);
    }
  }

  void CheckAdmittedFunction(Function fn, string label) {
    if (fn == null) {
      Error(currentMethod?.Tok, "PSB006: missing admitted pure target for " + label);
      return;
    }
    if (fn.ByMethodDecl != null || fn.ByMethodBody != null || fn.ByMethodTok != null)
      Error(fn.Tok, "PSB007: " + label + " uses function-by-method, which is unsupported");
    if (fn.HasExternAttribute || fn.Body == null)
      Error(fn.Tok, "PSB006: " + label + " has an extern or missing concrete body");
    if (fn.IsGhost)
      Error(fn.Tok, "PSB006: " + label + " must be an executable pure function");
    if (fn.ReadsHeap || (fn.Reads != null && fn.Reads.Children.Any()))
      Error(fn.Tok, "PSB008: " + label + " has heap reads; only a read-free pure target is admitted");
    if (!IsGhostTuple(fn.ResultType))
      Error(fn.Tok, "PSB006: " + label + " does not return the exact (real value, ghost seq<int>) tuple");
    if (fn.Ins.Count != 2 || fn.Ins.Any(f => f.IsGhost) || TypeSig(fn.Ins[0].Type) != "bv64" || TypeSig(fn.Ins[1].Type) != "NativeTypes.I")
      Error(fn.Tok, "PSB006: " + label + " does not have the exact (bv64,NativeTypes.I) formals");
    if (fn.Body != null) {
      CheckPureBody(fn.Body, fn);
      foreach (var call in fn.Body.DescendantsAndSelf.OfType<FunctionCallExpr>()) {
        if (call.Function == null || !call.Function.IsGhost || !markerFunctions.Values.Contains(call.Function))
          Error(call.Tok, "PSB009: admitted pure target contains another function call");
      }
      if (fn.Body.DescendantsAndSelf.OfType<StmtExpr>().Any())
        Error(fn.Tok, "PSB006: admitted pure target contains a statement expression");
      foreach (var ms in fn.Body.DescendantsAndSelf.OfType<MemberSelectExpr>()) {
        if (ms.Member is Field && !(ms.Obj.Type.NormalizeExpand() is UserDefinedType ut && ut.IsArrayType && ms.MemberName == "Length"))
          Error(ms.Tok, "PSB008: admitted pure target reads a mutable/global field");
      }
    }
  }

  // This is only a finite callee/heap closure check. Exact Git-pinned marker
  // definitions and the separate Dafny body proof remain trusted premises.
  void CheckPureBody(Expression expression, Function owner) {
    var e = Strip(expression);
    if (e is LiteralExpr) return;
    if (e is IdentifierExpr id && owner.Ins.Any(f => ReferenceEquals(f, id.Var))) return;
    if (e is BinaryExpr b && (IsSupportedOp(b.ResolvedOp) ||
        b.ResolvedOp == BinaryExpr.ResolvedOpcode.EqCommon || b.ResolvedOp == BinaryExpr.ResolvedOpcode.Concat)) {
      CheckPureBody(b.E0, owner); CheckPureBody(b.E1, owner); return;
    }
    // Dafny inserts this bounded shift-distance cast in the actual Rotate body.
    if (e is ConversionExpr cv && TypeSig(cv.E.Type) == "NativeTypes.I" && TypeSig(cv.Type) == "bv7") {
      CheckPureBody(cv.E, owner); return;
    }
    if (e is ITEExpr ite) {
      CheckPureBody(ite.Test, owner); CheckPureBody(ite.Thn, owner); CheckPureBody(ite.Els, owner); return;
    }
    if (e is DatatypeValue value && IsGhostTuple(value.Type) && value.Arguments.Count == 2) {
      foreach (var arg in value.Arguments) CheckPureBody(arg, owner);
      return;
    }
    if (e is FunctionCallExpr fc && fc.Function != null && fc.Function.IsGhost &&
        markerFunctions.Values.Contains(fc.Function)) {
      foreach (var arg in fc.Args) CheckPureBody(arg, owner);
      return;
    }
    Error(e.Tok, "PSB009: admitted pure target contains an unsupported resolved body expression " + e.GetType().Name);
  }

  void CheckCallTarget(Function fn, IOrigin tok, string what) {
    if (fn == null) {
      Error(tok, "PSB006: " + what + " has no resolved function target");
      return;
    }
    CheckAdmittedFunction(fn, what);
    if (rotateFunction == null || !ReferenceEquals(fn, rotateFunction))
      Error(tok, "PSB006: actual call target is not the exact NativeKeccak.Rotate declaration: " + fn.FullName);
  }

  bool CheckRootSignature(Method m) {
    if (!rootShapes.TryGetValue(m.Name, out var shape)) {
      Error(m.Tok, "PSB002: no exact root shape for " + m.Name);
      return false;
    }
    bool ok = true;
    if (m.IsGhost || m.IsLemmaLike) {
      Error(m.Tok, "PSB002: root must be an executable non-lemma method");
      ok = false;
    }
    if (m.Ins.Count != shape.Ins.Length) {
      Error(m.Tok, "PSB002: " + m.Name + ": expected " + shape.Ins.Length + " input formals, found " + m.Ins.Count);
      ok = false;
    } else {
      for (int i = 0; i < shape.Ins.Length; i++) {
        var actual = TypeSig(m.Ins[i].Type);
        if (actual != shape.Ins[i] || m.Ins[i].IsGhost) {
          Error(m.Ins[i].Tok, "PSB002: " + m.Name + ": input " + i + " expected " + shape.Ins[i] + ", found " + actual);
          ok = false;
        }
      }
    }
    if (m.Outs.Count != shape.Outs.Length) {
      Error(m.Tok, "PSB002: " + m.Name + ": expected " + shape.Outs.Length + " outputs, found " + m.Outs.Count);
      ok = false;
    } else {
      for (int i = 0; i < shape.Outs.Length; i++) {
        var actual = TypeSig(m.Outs[i].Type);
        if (actual != shape.Outs[i] || m.Outs[i].IsGhost != shape.OutGhost[i]) {
          Error(m.Outs[i].Tok, "PSB002: " + m.Name + ": output " + i + " expected " + shape.Outs[i] + (shape.OutGhost[i] ? " ghost" : "") + ", found " + actual);
          ok = false;
        }
      }
    }
    return ok;
  }

  static AssignStatement AsAssign(Statement s) {
    if (s is AssignStatement a) return a;
    if (s is VarDeclStmt vd && vd.Assign is AssignStatement va) return va;
    return null;
  }

  static bool SingleRhs(AssignStatement a, out Expression rhs) {
    rhs = null;
    if (a == null || a.Lhss.Count != 1 || a.Rhss.Count != 1) return false;
    if (a.Rhss[0] is not ExprRhs er) return false;
    rhs = er.Expr;
    return true;
  }

  List<Definition> AllDefinitions(BlockStmt root) {
    var result = new List<Definition>();
    var assignStatements = root.DescendantsAndSelf.OfType<AssignStatement>().ToList();
    var wrapped = new HashSet<SingleAssignStmt>(ReferenceEqualityComparer.Instance);
    foreach (var a in assignStatements)
      foreach (var sa in a.DescendantsAndSelf.OfType<SingleAssignStmt>()) wrapped.Add(sa);
    foreach (var a in assignStatements) {
      for (int i = 0; i < a.Lhss.Count; i++) {
        var v = AsVar(a.Lhss[i]);
        if (v == null) continue;
        Expression rhs = i < a.Rhss.Count && a.Rhss[i] is ExprRhs er ? er.Expr : null;
        result.Add(new Definition { Var = v, Rhs = rhs, Assign = a, Tok = a.Tok, Ghost = a.IsGhost });
      }
    }
    foreach (var sa in root.DescendantsAndSelf.OfType<SingleAssignStmt>()) {
      if (wrapped.Contains(sa)) continue;
      var v = AsVar(sa.Lhs);
      if (v == null) continue;
      Expression rhs = sa.Rhs is ExprRhs er ? er.Expr : null;
      result.Add(new Definition { Var = v, Rhs = rhs, Tok = sa.Tok, Ghost = sa.IsGhost });
    }
    foreach (var cs in root.DescendantsAndSelf.OfType<CallStmt>()) {
      foreach (var lhs in cs.Lhs) {
        var v = AsVar(lhs);
        if (v != null) result.Add(new Definition { Var = v, Rhs = null, Tok = cs.Tok, Ghost = true });
      }
    }
    return result;
  }

  static int Pos(IOrigin tok) => tok?.StartToken?.pos ?? 0;

  void CheckRoot(Method m) {
    currentMethod = m;
    if (!CheckRootSignature(m)) return;
    traceFormal = m.Outs.FirstOrDefault(f => ((IVariable)f).Name == "trace" && ((IVariable)f).IsGhost);
    if (traceFormal == null || TypeSig(traceFormal.Type) != "seq<int>") {
      Error(m.Tok, "PSB002: " + m.Name + ": expected exactly one ghost seq<int> output named trace");
      return;
    }
    if (m.Body is not BlockStmt body) {
      Error(m.Tok, "PSB002: root body is not a block");
      return;
    }

    var definitions = AllDefinitions(body);
    var traceDefs = definitions.Where(d => ReferenceEquals(d.Var, traceFormal))
      .OrderBy(d => Pos(d.Tok)).ToList();
    var candidates = new List<Candidate>();
    foreach (var vd in body.DescendantsAndSelf.OfType<VarDeclStmt>()) {
      if (vd.Assign is not AssignStatement assign) continue;
      for (int i = 0; i < vd.Locals.Count && i < assign.Lhss.Count; i++) {
        var local = vd.Locals[i];
        if (!local.IsGhost || !ReferenceEquals(AsVar(assign.Lhss[i]), local)) continue;
        if (assign.Rhss.Count <= i || assign.Rhss[i] is not ExprRhs er) continue;
        var rhs = er.Expr;
        if (!rhs.DescendantsAndSelf.OfType<FunctionCallExpr>().Any()) continue;
        candidates.Add(new Candidate {
          Local = local, VarDecl = vd, Assign = assign, Rhs = rhs, Call = DirectCall(rhs)
        });
      }
    }
    if (candidates.Count == 0) {
      Error(m.Tok, "PSB003: missing full-tuple ghost witness definition");
      return;
    }
    if (candidates.Count != 1) {
      Error(candidates[1].VarDecl.Tok, "PSB003: expected exactly one full-tuple ghost witness definition, found " + candidates.Count);
      return;
    }
    var candidate = candidates[0];
    var witness = candidate.Local;
    if (candidate.VarDecl.Locals.Count != 1 || !candidate.VarDecl.IsGhost || !candidate.Assign.IsGhost ||
        !SingleRhs(candidate.Assign, out var capturedRhs) || !ReferenceEquals(AsVar(candidate.Assign.Lhss[0]), witness)) {
      Error(candidate.VarDecl.Tok, "PSB005: witness must be one explicitly ghost local with one full-result assignment");
      return;
    }
    var witnessDefs = definitions.Where(d => ReferenceEquals(d.Var, witness)).ToList();
    if (witnessDefs.Count != 1) {
      Error(witnessDefs.Count == 0 ? candidate.VarDecl.Tok : witnessDefs[1].Tok,
            "PSB004: witness " + witness.Name + " must have exactly one definition across the whole method, found " + witnessDefs.Count);
      return;
    }
    if (candidate.Call == null) {
      Error(candidate.Rhs.Tok, "PSB005: witness must capture the full result of the exact pure call directly, not a fabricated tuple or projection");
      return;
    }
    CheckCallTarget(candidate.Call.Function, candidate.Call.Tok, "witness capture");
    if (!IsGhostTuple(witness.Type) || !TypeEq(witness.Type, candidate.Call.Function?.ResultType)) {
      Error(candidate.Rhs.Tok, "PSB005: witness does not have the exact full (real, ghost) tuple type of the pure call");
      return;
    }

    if (body.Body.Count < 3) {
      Error(m.Tok, "PSB012: root does not contain reset/capture/packet/actual statements");
      return;
    }
    var witnessIndex = body.Body.IndexOf(candidate.VarDecl);
    if (witnessIndex != 1) {
      Error(candidate.VarDecl.Tok, "PSB019: witness must immediately follow the sole initial trace reset; no prefix statements are admitted");
      return;
    }
    if (witnessIndex < 0) {
      Error(candidate.VarDecl.Tok, "PSB012: witness capture must be a direct statement of the method body in the same lexical block as the actual call");
      return;
    }
    if (traceDefs.Count == 0) {
      Error(m.Tok, "PSB013: trace must be reset exactly once");
      return;
    }
    if (!SingleRhs(traceDefs[0].Assign, out var resetRhs) || !traceDefs[0].Assign.IsGhost ||
        !ReferenceEquals(AsVar(traceDefs[0].Assign.Lhss[0]), traceFormal)) {
      Error(traceDefs[0].Tok, "PSB013: trace reset must be one ghost assignment to the trace formal");
      return;
    }
    if (!IsEmptySeq(traceDefs[0].Rhs)) {
      Error(traceDefs[0].Tok, "PSB013: trace must be reset exactly once, with an initial empty sequence");
      return;
    }
    if (!ReferenceEquals(AsAssign(body.Body[0]), traceDefs[0].Assign)) {
      Error(traceDefs[0].Tok, "PSB013: the initial trace reset must be the first top-level statement");
      return;
    }
    if (traceDefs.Count != 2) {
      Error(traceDefs.Count > 2 ? traceDefs[2].Tok : traceDefs[0].Tok,
            "PSB013: trace must be reset exactly once and then updated by exactly one packet");
      return;
    }
    var packet = traceDefs[1];
    if (!SingleRhs(packet.Assign, out var packetRhs) || !packet.Assign.IsGhost ||
        !ReferenceEquals(AsVar(packet.Assign.Lhss[0]), traceFormal)) {
      Error(packet.Tok, "PSB013: trace packet must be one ghost assignment to the trace formal");
      return;
    }
    if (witnessIndex + 1 >= body.Body.Count) {
      Error(packet.Tok, "PSB012: missing trace packet immediately after the witness capture");
      return;
    }
    if (!ReferenceEquals(AsAssign(body.Body[witnessIndex + 1]), packet.Assign)) {
      var between = body.Body[witnessIndex + 1];
      if (!between.IsGhost)
        Error(between.Tok, "PSB012: executable effect between witness capture and trace packet");
      else
        Error(between.Tok, "PSB019: unsupported ghost statement between witness capture and trace packet");
      return;
    }
    if (witnessIndex + 2 >= body.Body.Count) {
      Error(m.Tok, "PSB012: missing actual inline .0 call statement immediately after the trace packet");
      return;
    }
    var actualStatement = body.Body[witnessIndex + 2];
    if (actualStatement.IsGhost) {
      Error(actualStatement.Tok, "PSB019: actual call statement must be executable");
      return;
    }
    var actual = AsAssign(actualStatement);
    if (actual == null) {
      Error(actualStatement.Tok, "PSB019: unsupported executable statement " + actualStatement.GetType().Name + " in the fixed pure-snapshot root grammar");
      return;
    }
    if (body.Body.Count != witnessIndex + 3) {
      Error(body.Body[witnessIndex + 3].Tok, "PSB019: unsupported extra executable/ghost statement after the actual call");
      return;
    }
    if (!SingleRhs(actual, out var actualRhs)) {
      Error(actual.Tok, "PSB021: actual statement must be a single-LHS, single-RHS assignment");
      return;
    }
    if (!CheckActualShape(actual, actualRhs)) return;

    var calls = AllCalls(actualRhs).ToList();
    if (calls.Count == 0) {
      Error(actualRhs.Tok, "PSB017: actual statement has no inline pure .0 call");
      return;
    }
    if (calls.Count != 1) {
      Error(calls[1].Tok, "PSB016: exactly one actual non-ghost call is supported per statement; found " + calls.Count);
      return;
    }
    var actualCall = calls[0];
    CheckCallTarget(actualCall.Function, actualCall.Tok, "actual call");
    var projection = FindProjection(actualRhs, actualCall, "0");
    if (projection == null) {
      Error(actualCall.Tok, "PSB017: actual call must be the inline .0 projection of the exact pure call");
      return;
    }
    if (!TypeEq(projection.Type, witness.Type.NormalizeExpand() is UserDefinedType wt && wt.TypeArgs.Count == 2 ? wt.TypeArgs[0] : null))
      Error(projection.Tok, "PSB017: actual .0 projection does not have the witness value type");

    if (!ReferenceEquals(candidate.Call.Function, actualCall.Function)) {
      Error(actualCall.Tok, "PSB011: capture and actual call do not resolve to the same function declaration");
      return;
    }
    if (candidate.Call.Args.Count != actualCall.Args.Count) {
      Error(actualCall.Tok, "PSB011: capture and actual call arities differ");
      return;
    }
    foreach (var arg in candidate.Call.Args) ValidateArgument(arg);
    foreach (var arg in actualCall.Args) ValidateArgument(arg);
    for (int i = 0; i < candidate.Call.Args.Count; i++) {
      if (!TypedEq(candidate.Call.Args[i], actualCall.Args[i])) {
        Error(actualCall.Args[i].Tok, "PSB011: capture and actual call arguments are not typed-identical at argument " + i);
        return;
      }
    }

    var events = new List<RuntimeEvent>();
    var ctx = new EventContext();
    GenerateEvents(actualRhs, events, ctx);
    if (!ctx.CallSeen) {
      Error(actualRhs.Tok, "PSB017: actual expression did not traverse the bound inline call");
      return;
    }
    if (actual.Lhss.Count == 1 && Strip(actual.Lhss[0]) is SeqSelectExpr lhsSelect && lhsSelect.E1 == null) {
      var role = RoleOf(lhsSelect.Seq);
      if (role < 0) {
        Error(lhsSelect.Seq.Tok, "PSB021: array write target is not a non-ghost array formal");
        return;
      }
      ValidateArgument(lhsSelect.E0);
      events.Add(new RuntimeEvent { Kind = "Write", Site = ctx.Site++, Role = role, Address = lhsSelect.E0 });
    }
    MatchPacket(m, packet, witness, events);
  }

  bool CheckActualShape(AssignStatement actual, Expression rhs) {
    if (actual.Lhss.Count != 1) {
      Error(actual.Tok, "PSB021: actual statement must have exactly one LHS");
      return false;
    }
    var lhs = Strip(actual.Lhss[0]);
    if (lhs is IdentifierExpr id) {
      if (id.Var == null || id.Var.IsGhost || ReferenceEquals(id.Var, traceFormal)) {
        Error(lhs.Tok, "PSB021: scalar actual assignment target must be a non-ghost local/output");
        return false;
      }
      return true;
    }
    if (lhs is SeqSelectExpr sel && sel.E1 == null) {
      var index = Strip(sel.E0);
      var indexVar = AsVar(index);
      if (!(index is LiteralExpr) && !(indexVar != null && !indexVar.IsGhost && currentMethod.Ins.Any(f => ReferenceEquals(f, indexVar)))) {
        Error(sel.E0.Tok, "PSB021: array assignment index must be a typed literal or non-ghost formal; complex LHS evaluation is not admitted");
        return false;
      }
      if (RoleOf(sel.Seq) < 0) {
        Error(sel.Seq.Tok, "PSB021: array actual assignment target is not a non-ghost array formal");
        return false;
      }
      return true;
    }
    Error(lhs.Tok, "PSB021: unsupported actual assignment LHS " + lhs.GetType().Name);
    return false;
  }

  int RoleOf(Expression e) {
    var v = AsVar(e);
    if (v == null || v.IsGhost) return -1;
    for (int i = 0; i < currentMethod.Ins.Count; i++)
      if (ReferenceEquals(currentMethod.Ins[i], v) && TypeSig(v.Type).StartsWith("array<")) return i;
    return -1;
  }

  static MemberSelectExpr FindProjection(Expression root, FunctionCallExpr call, string name) {
    foreach (var ms in root.DescendantsAndSelf.OfType<MemberSelectExpr>()) {
      if (ms.MemberName != name) continue;
      if (ReferenceEquals(DirectCall(ms.Obj), call)) return ms;
    }
    return null;
  }

  static bool IsWitnessChild(Expression e, IVariable witness, Microsoft.Dafny.Type witnessType) {
    e = Strip(e);
    if (e is not MemberSelectExpr ms || ms.MemberName != "1") return false;
    if (!ReferenceEquals(AsVar(ms.Obj), witness)) return false;
    if (ms.Member is not DatatypeDestructor dd) return false;
    var wt = witnessType.NormalizeExpand();
    if (wt is not UserDefinedType ud || ud.ResolvedClass is not TupleTypeDecl tt) return false;
    if (!ReferenceEquals(dd.EnclosingClass, tt)) return false;
    return TypeSig(ms.Type) == "seq<int>";
  }

  static bool ReviewedConversion(ConversionExpr cv) {
    var from = TypeSig(cv.E.Type); var to = TypeSig(cv.Type);
    return (from == "bv8" && to == "bv64") || (from == "bv64" && to == "bv8") ||
           (from == "NativeTypes.I" && to == "int") || (from == "int" && to == "NativeTypes.I");
  }

  void ValidateArgument(Expression e) {
    e = Strip(e);
    if (e is IdentifierExpr || e is AutoGhostIdentifierExpr || e is LiteralExpr) return;
    if (e is ConversionExpr cv) {
      if (!ReviewedConversion(cv)) Error(cv.Tok, "PSB010: unreviewed conversion in argument grammar");
      ValidateArgument(cv.E); return;
    }
    if (e is BinaryExpr b) {
      if (b.ResolvedOp == BinaryExpr.ResolvedOpcode.And || b.ResolvedOp == BinaryExpr.ResolvedOpcode.Or ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Imp || b.ResolvedOp == BinaryExpr.ResolvedOpcode.Iff) {
        Error(b.Tok, "PSB010: short-circuit/logical argument expression is unsupported");
        return;
      }
      if (!IsSupportedOp(b.ResolvedOp)) {
        Error(b.Tok, "PSB010: unsupported argument operator " + b.ResolvedOp);
        return;
      }
      ValidateArgument(b.E0);
      ValidateArgument(b.E1);
      return;
    }
    if (e is SeqSelectExpr sel && sel.E1 == null) {
      var v = AsVar(sel.Seq);
      if (v == null || v.IsGhost || !TypeSig(v.Type).StartsWith("array<")) {
        Error(sel.Seq.Tok, "PSB010: array select argument must read a resolved non-ghost rank-one array");
        return;
      }
      ValidateArgument(sel.E0);
      return;
    }
    if (e is MemberSelectExpr ms) {
      if (ms.MemberName == "Length" && ms.Obj.Type.NormalizeExpand() is UserDefinedType ut && ut.IsArrayType) {
        ValidateArgument(ms.Obj);
        return;
      }
      if (ms.Member is DatatypeDestructor && DirectCall(ms.Obj) != null) {
        Error(e.Tok, "PSB010: nested function call in a witness argument is unsupported");
        return;
      }
      Error(e.Tok, "PSB010: unsupported member/field argument expression");
      return;
    }
    if (e is ITEExpr) {
      Error(e.Tok, "PSB010: conditional/ITE argument expression is unsupported");
      return;
    }
    if (e is StmtExpr) {
      Error(e.Tok, "PSB010: statement expression is unsupported");
      return;
    }
    if (e is FunctionCallExpr || e is ApplySuffix) {
      Error(e.Tok, "PSB010: nested function call in a witness argument is unsupported");
      return;
    }
    if (e is LetExpr || e is LetOrFailExpr || e is MatchExpr || e is NestedMatchExpr ||
        e is SeqDisplayExpr || e is SeqUpdateExpr || e is LambdaExpr || e is UnaryOpExpr) {
      Error(e.Tok, "PSB010: unsupported argument expression " + e.GetType().Name);
      return;
    }
    Error(e.Tok, "PSB010: unsupported argument expression " + e.GetType().Name);
  }

  static bool IsSupportedOp(BinaryExpr.ResolvedOpcode op) {
    switch (op) {
      case BinaryExpr.ResolvedOpcode.Add:
      case BinaryExpr.ResolvedOpcode.Sub:
      case BinaryExpr.ResolvedOpcode.Mul:
      case BinaryExpr.ResolvedOpcode.Div:
      case BinaryExpr.ResolvedOpcode.Mod:
      case BinaryExpr.ResolvedOpcode.LeftShift:
      case BinaryExpr.ResolvedOpcode.RightShift:
      case BinaryExpr.ResolvedOpcode.BitwiseAnd:
      case BinaryExpr.ResolvedOpcode.BitwiseOr:
      case BinaryExpr.ResolvedOpcode.BitwiseXor:
        return true;
      default:
        return false;
    }
  }

  static int[] OpCounts(BinaryExpr.ResolvedOpcode op) {
    var counts = new int[7];
    switch (op) {
      case BinaryExpr.ResolvedOpcode.Add: counts[0]++; break;
      case BinaryExpr.ResolvedOpcode.Sub: counts[1]++; break;
      case BinaryExpr.ResolvedOpcode.Mul: counts[2]++; break;
      case BinaryExpr.ResolvedOpcode.Div: counts[3]++; break;
      case BinaryExpr.ResolvedOpcode.Mod: counts[4]++; break;
      case BinaryExpr.ResolvedOpcode.BitwiseAnd:
      case BinaryExpr.ResolvedOpcode.BitwiseOr:
      case BinaryExpr.ResolvedOpcode.BitwiseXor: counts[5]++; break;
      case BinaryExpr.ResolvedOpcode.LeftShift:
      case BinaryExpr.ResolvedOpcode.RightShift: counts[6]++; break;
    }
    return counts;
  }

  void GenerateEvents(Expression e, List<RuntimeEvent> events, EventContext ctx) {
    e = Strip(e);
    if (e is IdentifierExpr || e is AutoGhostIdentifierExpr || e is LiteralExpr) return;
    if (e is ConversionExpr cv) {
      if (!ReviewedConversion(cv)) Error(cv.Tok, "PSB020: unreviewed conversion in executable grammar");
      GenerateEvents(cv.E, events, ctx); return;
    }
    if (e is BinaryExpr b) {
      if (b.ResolvedOp == BinaryExpr.ResolvedOpcode.And || b.ResolvedOp == BinaryExpr.ResolvedOpcode.Or ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Imp || b.ResolvedOp == BinaryExpr.ResolvedOpcode.Iff) {
        Error(b.Tok, "PSB020: short-circuit/logical executable expression is unsupported");
        return;
      }
      if (!IsSupportedOp(b.ResolvedOp)) {
        Error(b.Tok, "PSB020: unsupported executable operator " + b.ResolvedOp);
        return;
      }
      GenerateEvents(b.E0, events, ctx);
      GenerateEvents(b.E1, events, ctx);
      events.Add(new RuntimeEvent { Kind = "Ops", Ops = OpCounts(b.ResolvedOp) });
      return;
    }
    if (e is SeqSelectExpr sel && sel.E1 == null) {
      var v = AsVar(sel.Seq);
      var role = RoleOf(sel.Seq);
      if (v == null || role < 0) {
        Error(sel.Seq.Tok, "PSB020: array read must target a resolved non-ghost rank-one array formal");
        return;
      }
      GenerateEvents(sel.E0, events, ctx);
      events.Add(new RuntimeEvent { Kind = "Read", Site = ctx.Site++, Role = role, Address = sel.E0 });
      return;
    }
    if (e is MemberSelectExpr ms) {
      if (ms.MemberName == "Length" && ms.Obj.Type.NormalizeExpand() is UserDefinedType ut && ut.IsArrayType) {
        GenerateEvents(ms.Obj, events, ctx);
        return;
      }
      if (ms.Member is DatatypeDestructor dd && (ms.MemberName == "0" || ms.MemberName == "1")) {
        GenerateEvents(ms.Obj, events, ctx);
        return;
      }
      Error(e.Tok, "PSB020: unsupported executable member/field expression");
      return;
    }
    if (e is FunctionCallExpr || e is ApplySuffix) {
      var fc = DirectCall(e);
      if (fc == null) {
        Error(e.Tok, "PSB020: unsupported executable call/apply expression");
        return;
      }
      if (ctx.CallSeen) {
        Error(fc.Tok, "PSB016: nested or second executable call in the actual statement is unsupported");
        return;
      }
      ctx.CallSeen = true;
      CheckCallTarget(fc.Function, fc.Tok, "actual inline call");
      foreach (var arg in fc.Args) GenerateEvents(arg, events, ctx);
      events.Add(new RuntimeEvent { Kind = "Call", Site = ctx.Site++, Target = RotateTarget, Arity = fc.Args.Count });
      events.Add(new RuntimeEvent { Kind = "Child" });
      return;
    }
    if (e is ITEExpr) { Error(e.Tok, "PSB020: conditional/ITE executable expression is unsupported"); return; }
    if (e is StmtExpr) { Error(e.Tok, "PSB020: statement expression is unsupported"); return; }
    if (e is LetExpr || e is LetOrFailExpr || e is MatchExpr || e is NestedMatchExpr ||
        e is SeqDisplayExpr || e is SeqUpdateExpr || e is LambdaExpr || e is UnaryOpExpr ||
        e is DatatypeValue) {
      Error(e.Tok, "PSB020: unsupported executable expression " + e.GetType().Name);
      return;
    }
    Error(e.Tok, "PSB020: unsupported executable expression " + e.GetType().Name);
  }

  static bool AddressEq(Expression a, Expression b) {
    if (TypedEq(a, b)) return true;
    // Narrow event-address exception only: NativeTypes.I -> int widening for
    // array indices.  This is not argument normalization.
    if (Strip(b) is ConversionExpr bc && TypeSig(bc.Type) == "int" && TypeSig(bc.E.Type) == "NativeTypes.I" && TypedEq(a, bc.E)) return true;
    if (Strip(a) is ConversionExpr ac && TypeSig(ac.Type) == "int" && TypeSig(ac.E.Type) == "NativeTypes.I" && TypedEq(ac.E, b)) return true;
    return false;
  }

  static bool TypedEq(Expression a, Expression b) {
    if (a == null || b == null) return false;
    a = Unwrap(a);
    b = Unwrap(b);
    if (a is ParensExpression pa) return TypedEq(pa.E, b);
    if (b is ParensExpression pb) return TypedEq(a, pb.E);
    if (!TypeEq(a.Type, b.Type)) return false;
    var va = AsVar(a);
    var vb = AsVar(b);
    if (va != null || vb != null) return va != null && vb != null && ReferenceEquals(va, vb);
    if (a is LiteralExpr la && b is LiteralExpr lb) {
      if (la.Value is BigInteger ia && lb.Value is BigInteger ib) return ia == ib;
      if (la.Value is int sa && lb.Value is int sb) return sa == sb;
      return Equals(la.Value, lb.Value);
    }
    if (a is BinaryExpr ba && b is BinaryExpr bb)
      return ba.ResolvedOp == bb.ResolvedOp && TypedEq(ba.E0, bb.E0) && TypedEq(ba.E1, bb.E1);
    if (a is UnaryOpExpr ua && b is UnaryOpExpr ub)
      return ua.ResolvedOp == ub.ResolvedOp && TypedEq(ua.E, ub.E);
    if (a is ConversionExpr ca && b is ConversionExpr cb)
      return TypeEq(ca.Type, cb.Type) && TypedEq(ca.E, cb.E);
    if (a is MemberSelectExpr ma && b is MemberSelectExpr mb)
      return ReferenceEquals(ma.Member, mb.Member) && TypedEq(ma.Obj, mb.Obj);
    if (a is SeqSelectExpr qa && b is SeqSelectExpr qb)
      return qa.E1 == null && qb.E1 == null &&
             TypedEq(qa.Seq, qb.Seq) && TypedEq(qa.E0, qb.E0);
    return false;
  }

  void MatchPacket(Method m, Definition packet, LocalVariable witness, List<RuntimeEvent> events) {
    var leaves = ConcatLeaves(packet.Rhs).ToList();
    if (leaves.Count == 0 || !ReferenceEquals(AsVar(leaves[0]), traceFormal)) {
      Error(packet.Tok, "PSB013: the sole old trace must be the first flattened packet leaf");
      return;
    }
    for (int i = 1; i < leaves.Count; i++) {
      if (MentionsTrace(leaves[i], traceFormal)) {
        Error(leaves[i].Tok, "PSB013: trace packet may not read/reset the trace except as its first leaf");
        return;
      }
    }
    var packetEvents = new List<Expression>();
    for (int i = 1; i < leaves.Count; i++) packetEvents.Add(leaves[i]);
    int pi = 0;
    foreach (var ev in events) {
      if (pi >= packetEvents.Count) {
        if (ev.Kind == "Child")
          Error(packet.Tok, "PSB015: expected exact witness child immediately after the Call event");
        else
          Error(packet.Tok, "PSB015: missing trace packet event for actual " + ev.Kind + " observation");
        return;
      }
      var leaf = packetEvents[pi];
      if (ev.Kind != "Child" && IsWitnessChild(leaf, witness, witness.Type)) {
        Error(leaf.Tok, "PSB015: trace packet event order does not match actual runtime evaluation order");
        return;
      }
      if (ev.Kind == "Child") {
        if (!IsWitnessChild(leaf, witness, witness.Type)) {
          Error(leaf.Tok, "PSB015: expected exact witness child immediately after the Call event");
          return;
        }
        pi++;
        continue;
      }
      var marker = DirectCall(leaf);
      if (marker == null || marker.Function == null) {
        Error(leaf.Tok, "PSB014: trace packet leaf is not an exact SourceTrace marker");
        return;
      }
      if (!markerFunctions.TryGetValue(ev.Kind, out var expectedMarker) || !ReferenceEquals(marker.Function, expectedMarker)) {
        Error(leaf.Tok, "PSB015: trace packet event order does not match actual runtime evaluation order (expected " + ev.Kind + ")");
        return;
      }
      switch (ev.Kind) {
        case "Call":
          if (marker.Args.Count != 3 || !TryInt(marker.Args[0], out var site) || site != ev.Site ||
              !TryInt(marker.Args[1], out var target) || target != ev.Target ||
              !TryInt(marker.Args[2], out var arity) || arity != ev.Arity) {
            Error(marker.Tok, "PSB015: trace packet Call event is not the exact actual callsite/target/arity");
            return;
          }
          break;
        case "Read":
          if (marker.Args.Count != 3 || !TryInt(marker.Args[0], out var rsite) || rsite != ev.Site ||
              !TryInt(marker.Args[1], out var rrole) || rrole != ev.Role || !AddressEq(marker.Args[2], ev.Address)) {
            Error(marker.Tok, "PSB015: trace packet Read event does not match the actual array read");
            return;
          }
          break;
        case "Write":
          if (marker.Args.Count != 3 || !TryInt(marker.Args[0], out var wsite) || wsite != ev.Site ||
              !TryInt(marker.Args[1], out var wrole) || wrole != ev.Role || !AddressEq(marker.Args[2], ev.Address)) {
            Error(marker.Tok, "PSB015: trace packet Write event does not match the actual array write");
            return;
          }
          break;
        case "Ops":
          if (marker.Args.Count != 7) {
            Error(marker.Tok, "PSB015: trace packet Ops event must have seven counts");
            return;
          }
          for (int i = 0; i < 7; i++) {
            if (!TryInt(marker.Args[i], out var count) || count != ev.Ops[i]) {
              Error(marker.Args[i].Tok, "PSB015: trace packet Ops counts do not match actual executable operations");
              return;
            }
          }
          break;
        default:
          Error(leaf.Tok, "PSB014: unsupported trace packet event kind " + ev.Kind);
          return;
      }
      pi++;
    }
    if (pi != packetEvents.Count) {
      Error(packetEvents[pi].Tok, "PSB015: unexpected extra trace-packet leaf");
      return;
    }
  }
}
