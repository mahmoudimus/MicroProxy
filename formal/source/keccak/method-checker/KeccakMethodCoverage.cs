using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Microsoft.Dafny;
using Microsoft.Dafny.Plugins;

// Defensive resolved-AST coverage checker for the complete NativeKeccak method
// inventory.  This is a trusted structural observer, not a formal semantics of
// Dafny and not a noninterference or delivery proof.  It fails closed on every
// statement/expression shape it does not explicitly model.
public sealed class KeccakMethodCoverageConfiguration : PluginConfiguration {
  public override Rewriter[] GetRewriters(ErrorReporter reporter) =>
    new Rewriter[] { new KeccakMethodCoverageRewriter(reporter) };
}

public sealed class KeccakMethodCoverageRewriter : Rewriter {
  const string NativeModule = "NativeKeccak";
  const string TraceModule = "SourceTrace";
  const string VocabularyModule = "SourceObservationVocabulary";

  static readonly string[] MethodNames = {
    "SetLane", "Iota", "Wipe", "Chi", "Theta", "RhoPi", "Round",
    "PermuteScratch", "Permute", "NewOffsets", "NewSources"
  };
  static readonly string[] FunctionNames = { "Rotate", "Constant", "Offset", "Source" };
  static readonly string[] MarkerNames = { "Call", "Branch", "Read", "Write", "LoopBound", "LoopCheck", "Ops", "Alloc" };

  static readonly Dictionary<string, int> methodTargetsByName = new() {
    ["SetLane"] = 10, ["Iota"] = 11, ["Wipe"] = 12, ["Chi"] = 13, ["Theta"] = 14,
    ["RhoPi"] = 15, ["Round"] = 16, ["PermuteScratch"] = 17, ["Permute"] = 18,
    ["NewOffsets"] = 19, ["NewSources"] = 21
  };
  static readonly Dictionary<string, int> functionTargetsByName = new() {
    ["Rotate"] = 20, ["Constant"] = 22, ["Offset"] = 23, ["Source"] = 24
  };

  sealed class MethodShape {
    public string[] Ins;
    public string[] Outs;
    public bool[] OutGhost;
  }
  static readonly Dictionary<string, MethodShape> methodShapes = new() {
    ["NewOffsets"] = new MethodShape {
      Ins = new string[0], Outs = new[] { "array<NativeTypes.I>", "seq<int>" }, OutGhost = new[] { false, true } },
    ["NewSources"] = new MethodShape {
      Ins = new string[0], Outs = new[] { "array<NativeTypes.I>", "seq<int>" }, OutGhost = new[] { false, true } },
    ["SetLane"] = new MethodShape {
      Ins = new[] { "array<bv64>", "NativeTypes.I", "bv64" }, Outs = new[] { "seq<int>" }, OutGhost = new[] { true } },
    ["Iota"] = new MethodShape {
      Ins = new[] { "array<bv64>", "bv64" }, Outs = new[] { "seq<int>" }, OutGhost = new[] { true } },
    ["Theta"] = new MethodShape {
      Ins = new[] { "array<bv64>", "array<bv64>" }, Outs = new[] { "seq<int>" }, OutGhost = new[] { true } },
    ["RhoPi"] = new MethodShape {
      Ins = new[] { "array<bv64>", "array<bv64>", "array<NativeTypes.I>", "array<NativeTypes.I>" },
      Outs = new[] { "seq<int>" }, OutGhost = new[] { true } },
    ["Chi"] = new MethodShape {
      Ins = new[] { "array<bv64>", "array<bv64>" }, Outs = new[] { "seq<int>" }, OutGhost = new[] { true } },
    ["Round"] = new MethodShape {
      Ins = new[] { "array<bv64>", "array<bv64>", "array<bv64>", "array<NativeTypes.I>", "array<NativeTypes.I>", "bv64" },
      Outs = new[] { "seq<int>" }, OutGhost = new[] { true } },
    ["PermuteScratch"] = new MethodShape {
      Ins = new[] { "array<bv64>", "array<bv64>", "array<bv64>", "array<NativeTypes.I>", "array<NativeTypes.I>" },
      Outs = new[] { "seq<int>" }, OutGhost = new[] { true } },
    ["Permute"] = new MethodShape {
      Ins = new[] { "array<bv64>" }, Outs = new[] { "seq<int>" }, OutGhost = new[] { true } },
    ["Wipe"] = new MethodShape {
      Ins = new[] { "array<bv64>" }, Outs = new[] { "seq<int>" }, OutGhost = new[] { true } }
  };

  readonly ErrorReporter reporter;
  readonly Dictionary<string, Function> markers = new();
  readonly Dictionary<string, DatatypeCtor> eventCtors = new();
  readonly Dictionary<string, Method> methodTargets = new();
  readonly Dictionary<string, Function> functionTargets = new();
  Function canonicalEncode;

  Method currentMethod;
  Formal traceFormal;
  readonly List<IVariable> roleVars = new();
  int nextSite;
  readonly Dictionary<BlockStmt, List<TracePacket>> packetsByBlock = new(ReferenceEqualityComparer.Instance);
  readonly List<TracePacket> allPackets = new();
  readonly Dictionary<IVariable, List<Definition>> definitions = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<IVariable, int> allocSites = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<IVariable, string> factoryResults = new(ReferenceEqualityComparer.Instance);

  sealed class Definition {
    public IVariable Var;
    public Statement Stmt;
    public AssignStatement Assign;
    public Expression Rhs;
  }

  sealed class TracePacket {
    public Statement Stmt;
    public BlockStmt Block;
    public int Index;
    public List<Expression> Leaves;
    public bool Initial;
    public int LeafIndex;
    public bool Consumed => LeafIndex >= Leaves.Count;
  }

  sealed class BlockState {
    public BlockStmt Block;
    public List<TracePacket> Packets;
    public int PacketIndex;
    public TracePacket Current => PacketIndex < Packets.Count ? Packets[PacketIndex] : null;
  }

  sealed class Expected {
    public string Kind;           // Read Write Call Alloc Branch LoopBound LoopCheck Ops Child
    public int Site = -1;
    public int Role = -1;
    public Expression Address;    // Read/Write address, Alloc dimension, LoopBound bound
    public int Target = -1;
    public int Arity = -1;
    public int[] Ops;
    public bool Guard;
    public Expression Iteration;
    public IVariable IterationVar;
    public IVariable Child;
    public bool PureChild;
  }

  sealed class Snapshot {
    public IVariable Witness;
    public Function Function;
    public List<Expression> Args;
    public Statement ActualStmt;
    public BlockStmt Block;
  }

  sealed class EvalContext {
    public BlockStmt Block;
    public Statement Stmt;
    public int PureCalls;
    public readonly List<Snapshot> Snapshots = new();
  }

  public KeccakMethodCoverageRewriter(ErrorReporter reporter) : base(reporter) {
    this.reporter = reporter;
  }

  void Err(string code, IOrigin tok, string message) {
    reporter.Error(MessageSource.Rewriter, tok, code + ": " + message);
  }

  static int Pos(IOrigin tok) => tok?.StartToken?.pos ?? -1;

  static string TypeSig(Microsoft.Dafny.Type t) {
    if (t == null) return "unsupported-null-type";
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
      return "unsupported-unresolved-user-type";
    }
    return "unsupported-type";
  }

  static bool TypeEq(Microsoft.Dafny.Type a, Microsoft.Dafny.Type b) {
    if (a == null || b == null) return false;
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
      } else if (ua.ResolvedClass == null || ub.ResolvedClass == null ||
                 !ReferenceEquals(ua.ResolvedClass, ub.ResolvedClass)) return false;
      var at = ua.TypeArgs ?? new List<Microsoft.Dafny.Type>();
      var bt = ub.TypeArgs ?? new List<Microsoft.Dafny.Type>();
      if (at.Count != bt.Count) return false;
      for (int i = 0; i < at.Count; i++) if (!TypeEq(at[i], bt[i])) return false;
      return true;
    }
    return false; // Unknown resolved type kinds are never equal by spelling.
  }

  static bool IsGhostTuple(Microsoft.Dafny.Type t, out Microsoft.Dafny.Type valueType) {
    valueType = null;
    t = t.NormalizeExpand();
    if (t is not UserDefinedType ud || ud.ResolvedClass is not TupleTypeDecl tt || tt.Dims != 2) return false;
    var g = tt.ArgumentGhostness;
    if (g.Count != 2 || g[0] || !g[1]) return false;
    if (ud.TypeArgs == null || ud.TypeArgs.Count != 2) return false;
    if (TypeSig(ud.TypeArgs[1]) != "seq<int>") return false;
    valueType = ud.TypeArgs[0];
    return true;
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
    }
    return null;
  }

  static IEnumerable<FunctionCallExpr> ResolvedCalls(Expression expression) {
    if (expression == null) yield break;
    var seen = new HashSet<Expression>(ReferenceEqualityComparer.Instance);
    var todo = new Stack<Expression>();
    todo.Push(expression);
    while (todo.Count > 0) {
      var e = Strip(todo.Pop());
      if (!seen.Add(e)) continue;
      if (e is FunctionCallExpr call) yield return call;
      foreach (var child in e.SubExpressions) todo.Push(child);
    }
  }

  static IEnumerable<Expression> ActualExpressions(Statement statement) {
    var assign = statement as AssignStatement;
    if (statement is VarDeclStmt vd) assign = vd.Assign as AssignStatement;
    if (assign != null) {
      foreach (var lhs in assign.Lhss) yield return lhs;
      foreach (var rhs in assign.Rhss.OfType<ExprRhs>()) yield return rhs.Expr;
      foreach (var call in assign.DescendantsAndSelf.OfType<CallStmt>())
        foreach (var arg in call.Args) yield return arg;
    } else if (statement is SingleAssignStmt single) {
      yield return single.Lhs;
      if (single.Rhs is ExprRhs rhs) yield return rhs.Expr;
    } else if (statement is CallStmt call) {
      foreach (var arg in call.Args) yield return arg;
    }
  }

  static bool Mentions(Expression e, IVariable v) {
    if (e == null) return false;
    foreach (var x in e.DescendantsAndSelf)
      if (x is IdentifierExpr id && ReferenceEquals(id.Var, v)) return true;
    return false;
  }

  static bool IsNumericType(Microsoft.Dafny.Type t) {
    t = t.NormalizeExpand();
    if (t is IntType) return true;
    if (t is BitvectorType bv) return bv.Width >= 1 && bv.Width <= 64;
    if (t is UserDefinedType u && u.ResolvedClass != null) return u.ResolvedClass.FullName == "NativeTypes.I";
    return false;
  }

  static bool IsAdmittedConversion(ConversionExpr cv) =>
    IsNumericType(cv.E.Type) && IsNumericType(cv.Type);

  static bool IsComparison(BinaryExpr.ResolvedOpcode op) {
    switch (op) {
      case BinaryExpr.ResolvedOpcode.EqCommon:
      case BinaryExpr.ResolvedOpcode.NeqCommon:
      case BinaryExpr.ResolvedOpcode.Lt:
      case BinaryExpr.ResolvedOpcode.Le:
      case BinaryExpr.ResolvedOpcode.Gt:
      case BinaryExpr.ResolvedOpcode.Ge:
        return true;
      default:
        return false;
    }
  }

  static bool IsArithmetic(BinaryExpr.ResolvedOpcode op) {
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
      return qa.E1 == null && qb.E1 == null && TypedEq(qa.Seq, qb.Seq) && TypedEq(qa.E0, qb.E0);
    if (a is FunctionCallExpr fa && b is FunctionCallExpr fb) {
      if (!ReferenceEquals(fa.Function, fb.Function) || fa.Args.Count != fb.Args.Count) return false;
      for (int i = 0; i < fa.Args.Count; i++) if (!TypedEq(fa.Args[i], fb.Args[i])) return false;
      return true;
    }
    return false;
  }

  // Address/bound equality: full typed equality first, then the single
  // reviewed outer NativeTypes.I -> int widening, then mathematical literal
  // equality.  Inner conversions are never stripped.
  static bool BoundEq(Expression actual, Expression marker) {
    if (TypedEq(actual, marker)) return true;
    var m = Strip(marker);
    if (m is ConversionExpr mc && TypeSig(mc.Type) == "int" && TypeSig(mc.E.Type) == "NativeTypes.I" &&
        TypedEq(actual, mc.E)) return true;
    var a = Strip(actual);
    if (a is ConversionExpr ac && TypeSig(ac.Type) == "int" && TypeSig(ac.E.Type) == "NativeTypes.I" &&
        TypedEq(ac.E, marker)) return true;
    if (TryInt(actual, out var av) && TryInt(marker, out var mv)) return av == mv;
    return false;
  }

  ModuleDefinition ExactModule(Program program, string name) {
    var matches = program.Modules().Where(m => m.Name == name).ToList();
    if (matches.Count != 1 || matches[0].FullName != name) {
      Err("KMC001", program.GetStartOfFirstFileToken(), "missing, duplicate or shadowed exact module " + name);
      return null;
    }
    return matches[0];
  }

  DefaultClassDecl ExactDefault(ModuleDefinition module) {
    if (module == null) return null;
    var defaults = module.TopLevelDecls.OfType<DefaultClassDecl>().ToList();
    if (defaults.Count != 1) {
      Err("KMC001", module.Tok, "missing exact default class in " + module.FullName);
      return null;
    }
    return defaults[0];
  }

  public override void PostResolve(Program program) {
    var native = ExactModule(program, NativeModule);
    var trace = ExactModule(program, TraceModule);
    var vocabulary = ExactModule(program, VocabularyModule);
    if (native == null || trace == null || vocabulary == null) return;
    var nativeDefault = ExactDefault(native);
    var traceDefault = ExactDefault(trace);
    var vocabularyDefault = ExactDefault(vocabulary);
    if (nativeDefault == null || traceDefault == null || vocabularyDefault == null) return;

    CheckVocabulary(vocabulary, vocabularyDefault);
    CheckMarkers(trace, traceDefault);
    CheckInventory(program, native, nativeDefault);
    if (reporter.HasErrors) return;

    foreach (var name in FunctionNames) {
      var fn = functionTargets[name];
      functionTargets[name] = fn;
      CheckFunction(fn, name);
    }
    if (reporter.HasErrors) return;

    foreach (var name in MethodNames) {
      if (!methodTargets.TryGetValue(name, out var m)) {
        Err("KMC001", native.Tok, "missing required method NativeKeccak." + name);
        continue;
      }
      CheckMethod(m);
      if (reporter.HasErrors) return;
    }

    if (!reporter.HasErrors) {
      foreach (var name in MethodNames) Console.WriteLine("KECCAK-METHOD-COVERAGE ROOT OK: NativeKeccak." + name);
      Console.WriteLine("KECCAK-METHOD-COVERAGE OK: exact methods [NativeKeccak.NewOffsets,NativeKeccak.NewSources,NativeKeccak.SetLane,NativeKeccak.Iota,NativeKeccak.Theta,NativeKeccak.RhoPi,NativeKeccak.Chi,NativeKeccak.Round,NativeKeccak.PermuteScratch,NativeKeccak.Permute,NativeKeccak.Wipe]; exact functions [NativeKeccak.Rotate,NativeKeccak.Constant,NativeKeccak.Offset,NativeKeccak.Source]; qualification=false");
    }
  }

  void CheckVocabulary(ModuleDefinition module, DefaultClassDecl def) {
    var encoders = def.Members.OfType<Function>().Where(f => f.Name == "Encode").ToList();
    if (encoders.Count != 1 || !encoders[0].IsGhost || encoders[0].FullName != VocabularyModule + "._default.Encode" ||
        encoders[0].Ins.Count != 1 || encoders[0].Body == null || encoders[0].HasExternAttribute ||
        encoders[0].ByMethodDecl != null || encoders[0].ByMethodBody != null ||
        TypeSig(encoders[0].ResultType) != "seq<int>") {
      Err("KMC009", module.Tok, "missing exact concrete ghost canonical vocabulary Encode");
      return;
    }
    canonicalEncode = encoders[0];
    var events = module.TopLevelDecls.OfType<DatatypeDecl>()
      .Where(d => d.Name == "Event" && d.FullName == VocabularyModule + ".Event").ToList();
    if (events.Count != 1) {
      Err("KMC009", module.Tok, "missing exact canonical Event datatype");
      return;
    }
    foreach (var ctor in events[0].Ctors)
      if (!eventCtors.TryAdd(ctor.Name, ctor)) Err("KMC009", ctor.Tok, "duplicate canonical event constructor " + ctor.Name);
    var schema = new Dictionary<string, string[]> {
      ["Call"] = new[] { "int", "int", "int" },
      ["Branch"] = new[] { "int", "bool" },
      ["Read"] = new[] { "int", "int", "int" },
      ["Write"] = new[] { "int", "int", "int" },
      ["LoopBound"] = new[] { "int", "int" },
      ["LoopCheck"] = new[] { "int", "bool", "int" },
      ["Ops"] = Enumerable.Repeat("int", 7).ToArray(),
      ["Alloc"] = new[] { "int", "int" },
      ["ProviderCall"] = Enumerable.Repeat("int", 7).ToArray()
    };
    if (eventCtors.Count != schema.Count || canonicalEncode.TypeArgs.Count != 0 ||
        canonicalEncode.ReadsHeap || canonicalEncode.Reads.Children.Any() ||
        TypeSig(canonicalEncode.Ins[0].Type) != VocabularyModule + ".Event")
      Err("KMC009", canonicalEncode.Tok, "canonical encoder/schema signature is not the exact read-free Event -> seq<int> contract");
    foreach (var kv in schema) {
      if (!eventCtors.TryGetValue(kv.Key, out var ctor) || ctor.Formals.Count != kv.Value.Length) {
        Err("KMC009", module.Tok, "canonical constructor schema mismatch: " + kv.Key);
        continue;
      }
      for (int i = 0; i < kv.Value.Length; i++)
        if (TypeSig(ctor.Formals[i].Type) != kv.Value[i])
          Err("KMC009", ctor.Tok, "canonical constructor field type mismatch: " + kv.Key + "/" + i);
    }
    NativeCanonicalEncoderPolicy.Check(canonicalEncode, eventCtors, (tok, msg) => Err("KMC009", tok, msg));

    foreach (var td in module.TopLevelDecls.OfType<TopLevelDeclWithMembers>()) {
      if (ReferenceEquals(td, def)) continue;
      foreach (var member in td.Members)
        if (member.Name == "Encode" || member.Name == "Event")
          Err("KMC001", member.Tok, "reserved vocabulary name shadowed outside the exact default declaration: " + member.FullName);
    }
  }

  void CheckMarkers(ModuleDefinition module, DefaultClassDecl def) {
    foreach (var td in module.TopLevelDecls.OfType<TopLevelDeclWithMembers>()) {
      if (ReferenceEquals(td, def)) continue;
      foreach (var member in td.Members)
        if (MarkerNames.Contains(member.Name))
          Err("KMC001", member.Tok, "reserved marker name shadowed outside the exact default declaration: " + member.FullName);
    }
    foreach (var name in MarkerNames) {
      var matches = def.Members.OfType<Function>().Where(f => f.Name == name).ToList();
      if (matches.Count != 1 || matches[0].FullName != TraceModule + "._default." + name) {
        Err("KMC001", module.Tok, "expected exactly one exact SourceTrace." + name);
        continue;
      }
      var fn = matches[0];
      if (!fn.IsGhost || fn.HasExternAttribute || fn.ByMethodDecl != null || fn.ByMethodBody != null ||
          fn.ByMethodTok != null || fn.TypeArgs.Count != 0 ||
          fn.Body == null || fn.ReadsHeap || (fn.Reads != null && fn.Reads.Children.Any()) ||
          TypeSig(fn.ResultType) != "seq<int>") {
        Err("KMC009", fn.Tok, "SourceTrace." + name + " is not the exact ghost, read-free, concrete marker declaration");
        continue;
      }
      markers[name] = fn;
      CheckMarkerBody(name, fn);
    }
  }

  void CheckMarkerBody(string name, Function fn) {
    var body = fn.Body == null ? null : Unwrap(fn.Body);
    if (body is not FunctionCallExpr call || !ReferenceEquals(call.Function, canonicalEncode) || call.Args.Count != 1 ||
        Unwrap(call.Args[0]) is not DatatypeValue value || !eventCtors.TryGetValue(name, out var ctor) ||
        !ReferenceEquals(value.Ctor, ctor) || value.Arguments.Count != fn.Ins.Count ||
        value.Arguments.Count != ctor.Formals.Count) {
      Err("KMC009", fn.Tok, "marker body is not exact canonical Encode(constructor(positional formals)): " + fn.FullName);
      return;
    }
    for (int i = 0; i < fn.Ins.Count; i++) {
      if (!TypeEq(fn.Ins[i].Type, ctor.Formals[i].Type))
        Err("KMC009", fn.Tok, "marker formal type differs from its canonical constructor: " + name + "/" + i);
      if (!ReferenceEquals(AsVar(value.Arguments[i]), fn.Ins[i]))
        Err("KMC009", value.Arguments[i].Tok, "marker helper changes or reorders positional formal " + i + ": " + fn.FullName);
    }
  }

  void CheckInventory(Program program, ModuleDefinition module, DefaultClassDecl def) {
    var importNames = new Dictionary<string, string> {
      ["T"] = "NativeTypes", ["S"] = "KeccakSpec", ["ST"] = "SourceTrace"
    };
    var seenImports = new HashSet<string>();
    foreach (var declaration in module.TopLevelDecls) {
      if (ReferenceEquals(declaration, def)) continue;
      if (declaration is not AliasModuleDecl alias || !importNames.TryGetValue(alias.Name, out var targetName)) {
        Err("KMC001", declaration.Tok, "unsupported NativeKeccak top-level declaration outside exact default class/imports: " + declaration.GetType().Name);
        continue;
      }
      var targets = program.Modules().Where(m => m.FullName == targetName).ToList();
      if (!seenImports.Add(alias.Name) || targets.Count != 1 || alias.Opened || alias.ShadowsLiteralModule ||
          alias.Exports != null && alias.Exports.Count != 0 ||
          alias.TargetQId?.Decl is not LiteralModuleDecl importedModule ||
          !ReferenceEquals(importedModule.ModuleDef, targets.FirstOrDefault()) ||
          !ReferenceEquals(alias.Signature?.ModuleDef, targets.FirstOrDefault()))
        Err("KMC001", alias.Tok, "NativeKeccak import is not the exact resolved admitted module: " + alias.Name);
    }
    if (seenImports.Count != importNames.Count)
      Err("KMC001", module.Tok, "NativeKeccak must retain the exact three resolved admitted imports");
    var reserved = new HashSet<string>(MethodNames.Concat(FunctionNames));
    foreach (var td in module.TopLevelDecls.OfType<TopLevelDeclWithMembers>()) {
      if (ReferenceEquals(td, def)) continue;
      foreach (var member in td.Members)
        if (reserved.Contains(member.Name))
          Err("KMC001", member.Tok, "reserved NativeKeccak name shadowed outside the exact default declaration: " + member.FullName);
    }

    foreach (var td in module.TopLevelDecls.OfType<TopLevelDeclWithMembers>()) {
      foreach (var member in td.Members) {
        if (member is not (Function or Method or Field))
          Err("KMC001", member.Tok, "unsupported member declaration kind in NativeKeccak: " + member.GetType().Name);
        if (member is Field field && !field.IsGhost)
          Err("KMC001", field.Tok, "non-ghost field/constant initialization is outside the exact NativeKeccak executable inventory: " + field.FullName);
        if (member is Method gm && !gm.IsGhost && !gm.IsLemmaLike && (td != def || !MethodNames.Contains(gm.Name)))
          Err("KMC001", gm.Tok, "extra non-ghost method in NativeKeccak: " + gm.FullName);
        if (member is Function gf && !gf.IsGhost && (td != def || !FunctionNames.Contains(gf.Name)))
          Err("KMC001", gf.Tok, "extra non-ghost function in NativeKeccak: " + gf.FullName);
      }
    }

    var nonGhostMethods = def.Members.OfType<Method>().Where(m => !m.IsGhost && !m.IsLemmaLike).ToList();
    if (nonGhostMethods.Count != MethodNames.Length || nonGhostMethods.Any(m => !MethodNames.Contains(m.Name))) {
      Err("KMC001", def.Tok, "non-ghost method inventory differs from the exact eleven NativeKeccak methods");
    }
    foreach (var name in MethodNames) {
      var matches = def.Members.OfType<Method>()
        .Where(m => m.Name == name && m.FullName == NativeModule + "._default." + name).ToList();
      if (matches.Count != 1) {
        Err("KMC001", def.Tok, "expected exactly one exact method NativeKeccak." + name);
        continue;
      }
      if (matches[0].IsGhost || matches[0].IsLemmaLike || matches[0].HasExternAttribute || matches[0].Body == null) {
        Err("KMC002", matches[0].Tok, "NativeKeccak." + name + " must be a concrete executable non-lemma, non-extern method");
        continue;
      }
      methodTargets[name] = matches[0];
    }

    var nonGhostFunctions = def.Members.OfType<Function>().Where(f => !f.IsGhost).ToList();
    if (nonGhostFunctions.Count != FunctionNames.Length || nonGhostFunctions.Any(f => !FunctionNames.Contains(f.Name))) {
      Err("KMC001", def.Tok, "non-ghost function inventory differs from the exact four NativeKeccak functions");
    }
    foreach (var name in FunctionNames) {
      var matches = def.Members.OfType<Function>()
        .Where(f => f.Name == name && f.FullName == NativeModule + "._default." + name).ToList();
      if (matches.Count != 1) {
        Err("KMC001", def.Tok, "expected exactly one exact function NativeKeccak." + name);
        continue;
      }
      functionTargets[name] = matches[0];
    }
  }

  void CheckFunction(Function fn, string name) {
    if (fn.TypeArgs.Count != 0) {
      Err("KMC002", fn.Tok, "generic pure target is outside the exact NativeKeccak signature");
      return;
    }
    if (fn.IsGhost) {
      Err("KMC002", fn.Tok, "NativeKeccak." + name + " must be an executable pure function");
      return;
    }
    if (fn.HasExternAttribute || fn.Body == null) {
      Err("KMC002", fn.Tok, "NativeKeccak." + name + " has an extern or missing concrete body");
      return;
    }
    if (fn.ByMethodDecl != null || fn.ByMethodBody != null || fn.ByMethodTok != null) {
      Err("KMC002", fn.Tok, "NativeKeccak." + name + " uses function-by-method, which is unsupported");
      return;
    }
    if (fn.ReadsHeap || (fn.Reads != null && fn.Reads.Children.Any())) {
      Err("KMC002", fn.Tok, "NativeKeccak." + name + " has heap reads");
      return;
    }
    if (Attributes.Contains(fn.Attributes, "opaque")) {
      Err("KMC002", fn.Tok, "NativeKeccak." + name + " is opaque; its concrete body is not checked");
      return;
    }
    var expectedIns = name == "Rotate" ? new[] { "bv64", "NativeTypes.I" } : new[] { "NativeTypes.I" };
    if (fn.Ins.Count != expectedIns.Length ||
        fn.Ins.Where((f, i) => i >= expectedIns.Length || f.IsGhost || TypeSig(f.Type) != expectedIns[i]).Any()) {
      Err("KMC002", fn.Tok, "NativeKeccak." + name + " input signature mismatch");
      return;
    }
    if (!IsGhostTuple(fn.ResultType, out var valueType)) {
      Err("KMC002", fn.Tok, "NativeKeccak." + name + " must return the exact (value, ghost seq<int>) tuple");
      return;
    }
    var expectedValue = name == "Rotate" || name == "Constant" ? "bv64" : "NativeTypes.I";
    if (TypeSig(valueType) != expectedValue) {
      Err("KMC002", fn.Tok, "NativeKeccak." + name + " value result type mismatch");
    }
  }

  bool CheckMethodSignature(Method m) {
    if (!methodShapes.TryGetValue(m.Name, out var shape)) {
      Err("KMC002", m.Tok, "no exact method shape for " + m.Name);
      return false;
    }
    bool ok = true;
    if (m.TypeArgs.Count != 0 || Attributes.Contains(m.Attributes, "opaque")) {
      Err("KMC002", m.Tok, "generic/opaque method is outside the exact NativeKeccak declaration contract");
      ok = false;
    }
    if (m.Ins.Count != shape.Ins.Length) {
      Err("KMC002", m.Tok, m.Name + ": expected " + shape.Ins.Length + " inputs, found " + m.Ins.Count);
      ok = false;
    } else {
      for (int i = 0; i < shape.Ins.Length; i++) {
        if (TypeSig(m.Ins[i].Type) != shape.Ins[i] || m.Ins[i].IsGhost) {
          Err("KMC002", m.Ins[i].Tok, m.Name + ": input " + i + " expected " + shape.Ins[i] + ", found " + TypeSig(m.Ins[i].Type));
          ok = false;
        }
      }
    }
    if (m.Outs.Count != shape.Outs.Length) {
      Err("KMC002", m.Tok, m.Name + ": expected " + shape.Outs.Length + " outputs, found " + m.Outs.Count);
      ok = false;
    } else {
      for (int i = 0; i < shape.Outs.Length; i++) {
        if (TypeSig(m.Outs[i].Type) != shape.Outs[i] || m.Outs[i].IsGhost != shape.OutGhost[i]) {
          Err("KMC002", m.Outs[i].Tok, m.Name + ": output " + i + " expected " + shape.Outs[i] + (shape.OutGhost[i] ? " ghost" : "") + ", found " + TypeSig(m.Outs[i].Type));
          ok = false;
        }
      }
    }
    var traces = m.Outs.Where(o => o.IsGhost && o.Name == "trace" && TypeSig(o.Type) == "seq<int>").ToList();
    if (traces.Count != 1) {
      Err("KMC002", m.Tok, m.Name + ": expected exactly one ghost seq<int> output named trace");
      ok = false;
    } else {
      traceFormal = traces[0];
    }
    if (m.Body is not BlockStmt) {
      Err("KMC002", m.Tok, m.Name + ": method body is not a block");
      ok = false;
    }
    return ok;
  }

  void BuildRoles(Method m) {
    roleVars.Clear();
    foreach (var f in m.Ins)
      if (!f.IsGhost && TypeSig(f.Type).StartsWith("array<")) roleVars.Add(f);
    if (m.Name == "NewOffsets" || m.Name == "NewSources") {
      foreach (var o in m.Outs)
        if (!o.IsGhost && TypeSig(o.Type) == "array<NativeTypes.I>") roleVars.Add(o);
    }
    if (m.Name == "Permute") {
      var locals = m.Body.DescendantsAndSelf.OfType<VarDeclStmt>()
        .SelectMany(v => v.Locals)
        .Where(l => !l.IsGhost && TypeSig(l.Type).StartsWith("array<"))
        .OrderBy(l => Pos(l.Tok)).ToList();
      foreach (var l in locals) if (!roleVars.Any(r => ReferenceEquals(r, l))) roleVars.Add(l);
    }
  }

  int RoleOf(Expression arrayExpr) {
    var v = AsVar(arrayExpr);
    if (v == null || v.IsGhost) return -1;
    for (int i = 0; i < roleVars.Count; i++)
      if (ReferenceEquals(roleVars[i], v)) return i;
    return -1;
  }

  bool IsTraceAssignment(Statement s, out AssignStatement assign) {
    assign = null;
    if (s is AssignStatement a && a.Lhss.Count == 1 && ReferenceEquals(AsVar(a.Lhss[0]), traceFormal)) {
      assign = a;
      return true;
    }
    if (s is SingleAssignStmt sa && ReferenceEquals(AsVar(sa.Lhs), traceFormal)) return true;
    return false;
  }

  List<TracePacket> PacketsForBlock(BlockStmt block) {
    if (packetsByBlock.TryGetValue(block, out var cached)) return cached;
    var list = new List<TracePacket>();
    for (int i = 0; i < block.Body.Count; i++) {
      var s = block.Body[i];
      if (!IsTraceAssignment(s, out var assign)) continue;
      var packet = new TracePacket { Stmt = s, Block = block, Index = i };
      if (assign != null) {
        if (assign.Rhss.Count != 1 || assign.Rhss[0] is not ExprRhs er) {
          Err("KMC003", s.Tok, "trace packet must have exactly one expression RHS");
          continue;
        }
        packet.Leaves = IsEmptySeq(er.Expr) ? new List<Expression>() : ConcatLeaves(er.Expr).ToList();
      } else {
        var sa = (SingleAssignStmt)s;
        if (sa.Rhs is not ExprRhs er) {
          Err("KMC003", s.Tok, "trace packet must have exactly one expression RHS");
          continue;
        }
        packet.Leaves = IsEmptySeq(er.Expr) ? new List<Expression>() : ConcatLeaves(er.Expr).ToList();
      }
      list.Add(packet);
      allPackets.Add(packet);
    }
    packetsByBlock[block] = list;
    return list;
  }

  void CollectPackets(Method m) {
    packetsByBlock.Clear();
    allPackets.Clear();
    foreach (var block in m.Body.DescendantsAndSelf.OfType<BlockStmt>()) PacketsForBlock(block);
  }

  void ValidatePacketStructure() {
    if (allPackets.Count == 0) {
      Err("KMC003", currentMethod.Tok, currentMethod.Name + ": no trace assignment");
      return;
    }
    allPackets.Sort((a, b) => {
      int pa = Pos(a.Stmt.Tok), pb = Pos(b.Stmt.Tok);
      if (pa != pb) return pa.CompareTo(pb);
      return (a.Stmt.Tok?.StartToken?.col ?? 0).CompareTo(b.Stmt.Tok?.StartToken?.col ?? 0);
    });
    for (int i = 0; i < allPackets.Count; i++) {
      var p = allPackets[i];
      p.Initial = i == 0;
      if (!p.Stmt.IsGhost) Err("KMC003", p.Stmt.Tok, "trace packet must be a ghost assignment");
      if (p.Initial) {
        if (p.Block != currentMethod.Body) {
          Err("KMC003", p.Stmt.Tok, "initial trace packet must be a direct top-level method statement");
        } else {
          for (int j = 0; j < currentMethod.Body.Body.IndexOf(p.Stmt); j++)
            if (!currentMethod.Body.Body[j].IsGhost)
              Err("KMC003", p.Stmt.Tok, "initial trace packet must precede every executable method statement");
        }
        if (p.Leaves.Count == 0) {
          Expression resetExpr = null;
          if (p.Stmt is AssignStatement assign && assign.Rhss.Count == 1 && assign.Rhss[0] is ExprRhs aer) resetExpr = aer.Expr;
          if (p.Stmt is SingleAssignStmt saReset && saReset.Rhs is ExprRhs ser) resetExpr = ser.Expr;
          if (!IsEmptySeq(resetExpr))
            Err("KMC003", p.Stmt.Tok, "initial trace reset must be the actual empty sequence");
        } else {
          foreach (var leaf in p.Leaves)
            if (Mentions(leaf, traceFormal))
              Err("KMC003", leaf.Tok, "initial event packet may not read the trace");
        }
      } else {
        if (p.Leaves.Count == 0 || !ReferenceEquals(AsVar(p.Leaves[0]), traceFormal)) {
          Err("KMC003", p.Stmt.Tok, "later trace update must append to the same trace as its first leaf");
          continue;
        }
        for (int j = 1; j < p.Leaves.Count; j++)
          if (Mentions(p.Leaves[j], traceFormal))
            Err("KMC003", p.Leaves[j].Tok, "trace may appear only once, as the first leaf");
        if (p.Leaves.Count == 1)
          Err("KMC003", p.Stmt.Tok, "later trace packet must contain observations, not an empty reset");
        p.LeafIndex = 1; // skip the immutable trace prefix
      }
    }
  }

  void CollectDefinitions(Method m) {
    definitions.Clear();
    var assigns = m.Body.DescendantsAndSelf.OfType<AssignStatement>().ToList();
    var wrapped = new HashSet<SingleAssignStmt>(ReferenceEqualityComparer.Instance);
    foreach (var a in assigns)
      foreach (var sa in a.DescendantsAndSelf.OfType<SingleAssignStmt>()) wrapped.Add(sa);
    foreach (var a in assigns) {
      for (int i = 0; i < a.Lhss.Count; i++) {
        var v = AsVar(a.Lhss[i]);
        if (v == null) continue;
        Expression rhs = i < a.Rhss.Count && a.Rhss[i] is ExprRhs er ? er.Expr : null;
        AddDefinition(v, a, a, rhs);
      }
    }
    foreach (var sa in m.Body.DescendantsAndSelf.OfType<SingleAssignStmt>()) {
      if (wrapped.Contains(sa)) continue;
      var v = AsVar(sa.Lhs);
      if (v == null) continue;
      Expression rhs = sa.Rhs is ExprRhs er ? er.Expr : null;
      AddDefinition(v, sa, null, rhs);
    }
    // Such-that assignments are definitions even when hidden in ghost control
    // flow. They must invalidate single-definition witnesses and child locals.
    foreach (var ast in m.Body.DescendantsAndSelf.OfType<AssignSuchThatStmt>())
      foreach (var lhs in ast.Lhss) {
        var v = AsVar(lhs);
        if (v != null) AddDefinition(v, ast, null, null);
      }
    var allCalls = m.Body.DescendantsAndSelf.OfType<CallStmt>().ToList();
    var wrappedCalls = new HashSet<CallStmt>(ReferenceEqualityComparer.Instance);
    foreach (var a in assigns)
      foreach (var cs in a.DescendantsAndSelf.OfType<CallStmt>()) wrappedCalls.Add(cs);
    foreach (var sa in m.Body.DescendantsAndSelf.OfType<SingleAssignStmt>())
      foreach (var cs in sa.DescendantsAndSelf.OfType<CallStmt>()) wrappedCalls.Add(cs);
    foreach (var cs in allCalls) {
      if (wrappedCalls.Contains(cs)) continue;
      for (int i = 0; i < cs.Lhs.Count; i++) {
        var v = AsVar(cs.Lhs[i]);
        if (v != null) AddDefinition(v, cs, null, null);
      }
    }
  }

  void AddDefinition(IVariable v, Statement stmt, AssignStatement assign, Expression rhs) {
    if (!definitions.TryGetValue(v, out var list)) definitions[v] = list = new List<Definition>();
    list.Add(new Definition { Var = v, Stmt = stmt, Assign = assign, Rhs = rhs });
  }

  static bool IsWithin(Statement inner, Statement outer) {
    if (ReferenceEquals(inner, outer)) return true;
    foreach (var s in outer.DescendantsAndSelf.OfType<Statement>())
      if (ReferenceEquals(s, inner)) return true;
    return false;
  }

  void CheckHiddenGhostWrites(Method m) {
    foreach (var s in m.Body.DescendantsAndSelf.OfType<Statement>()) {
      if (s is CallStmt cs) {
        if (cs.Lhs.Any(l => ReferenceEquals(AsVar(l), traceFormal)))
          Err("KMC003", cs.Tok, "call output cannot clobber the trace formal");
      }
      if (s is AssignStatement a && a.Lhss.Count > 1 && a.Lhss.Any(l => ReferenceEquals(AsVar(l), traceFormal)))
        Err("KMC003", a.Tok, "trace may not be assigned in a parallel statement");
      if (s is AssignSuchThatStmt ast && ast.Lhss.Any(l => ReferenceEquals(AsVar(l), traceFormal)))
        Err("KMC003", ast.Tok, "trace may not be assigned by a such-that statement");
      if (s is IfStmt || s is WhileStmt || s is ForLoopStmt || s is ForallStmt ||
          s is AlternativeLoopStmt || s is MatchStmt || s is NestedMatchStmt) {
        if (s.IsGhost) {
          foreach (var hidden in s.DescendantsAndSelf.OfType<AssignStatement>())
            if (hidden.Lhss.Any(l => ReferenceEquals(AsVar(l), traceFormal)))
              Err("KMC003", hidden.Tok, "hidden ghost-branch trace assignment is not supported");
          foreach (var x in s.DescendantsAndSelf.OfType<SingleAssignStmt>())
            if (ReferenceEquals(AsVar(x.Lhs), traceFormal))
              Err("KMC003", x.Tok, "hidden ghost-branch trace assignment is not supported");
        }
      }
    }
  }

  void CheckMethod(Method m) {
    currentMethod = m;
    nextSite = 0;
    roleVars.Clear();
    allocSites.Clear();
    factoryResults.Clear();
    if (!CheckMethodSignature(m)) return;
    BuildRoles(m);
    CheckUnboundPureCalls(m);
    if (reporter.HasErrors) return;
    CollectPackets(m);
    ValidatePacketStructure();
    CollectDefinitions(m);
    CheckHiddenGhostWrites(m);
    CheckSnapshotPrestateGaps(m);
    if (reporter.HasErrors) return;

    var state = new BlockState { Block = m.Body, Packets = PacketsForBlock(m.Body) };
    // A pure empty reset is not attached to a runtime statement.
    if (state.Current != null && state.Current.Initial && state.Current.Leaves.Count == 0) {
      state.PacketIndex++;
    }
    ProcessBlock(state);
    if (reporter.HasErrors) return;
    if (state.Current != null) {
      Err("KMC004", state.Current.Stmt.Tok, m.Name + ": extra unobserved trace packet");
      return;
    }
    foreach (var kv in packetsByBlock) {
      if (kv.Key == m.Body) continue;
      if (kv.Value.Any(p => !p.Consumed))
        Err("KMC004", kv.Value.First(p => !p.Consumed).Stmt.Tok, m.Name + ": extra unobserved trace packet in nested block");
    }
    if (reporter.HasErrors) return;

    if (m.Name == "Permute") {
      CheckPermuteRegistry();
    }
    if (m.Name == "NewOffsets" || m.Name == "NewSources") {
      var outFormal = roleVars.FirstOrDefault();
      if (outFormal == null || !allocSites.ContainsKey(outFormal) || allocSites[outFormal] != 0)
        Err("KMC010", m.Tok, m.Name + ": factory output r must be the role0 actual allocation");
    }
  }

  void CheckPermuteRegistry() {
    var names = roleVars.Select(v => v.Name).ToList();
    if (roleVars.Count != 5 || roleVars[0].Name != "a" || roleVars[1].Name != "b" || roleVars[2].Name != "c" ||
        roleVars[3].Name != "offsets" || roleVars[4].Name != "sources") {
      Err("KMC010", currentMethod.Tok, "Permute roles must be actual a0,b1,c2,offsets3,sources4 declarations");
      return;
    }
    foreach (var v in new[] { roleVars[1], roleVars[2] })
      if (!allocSites.ContainsKey(v)) Err("KMC010", v.Tok, "Permute local array role is not an actual allocation: " + v.Name);
    if (!factoryResults.TryGetValue(roleVars[3], out var offsetsTarget) || offsetsTarget != "NewOffsets")
      Err("KMC010", roleVars[3].Tok, "Permute offsets role is not the actual NewOffsets result");
    if (!factoryResults.TryGetValue(roleVars[4], out var sourcesTarget) || sourcesTarget != "NewSources")
      Err("KMC010", roleVars[4].Tok, "Permute sources role is not the actual NewSources result");
  }

  void CheckSnapshotPrestateGaps(Method method) {
    // Diagnose stale snapshots before an interposed effect can consume their
    // PRE packet as if it belonged to that effect. The final binding still
    // checks declaration/argument identity, single definition and LAST assert.
    foreach (var block in method.Body.DescendantsAndSelf.OfType<BlockStmt>()) {
      for (int captureIndex = 0; captureIndex < block.Body.Count; captureIndex++) {
        if (block.Body[captureIndex] is not VarDeclStmt vd || !vd.IsGhost || vd.Locals.Count != 1 ||
            !IsGhostTuple(vd.Locals[0].Type, out _) || vd.Assign is not AssignStatement a ||
            a.Rhss.Count != 1 || a.Rhss[0] is not ExprRhs rhs) continue;
        var captured = DirectCall(rhs.Expr);
        if (captured == null || !IsAdmittedPure(captured.Function)) continue;
        for (int actualIndex = captureIndex + 1; actualIndex < block.Body.Count; actualIndex++) {
          var actual = block.Body[actualIndex];
          if (actual.IsGhost || actual is not (VarDeclStmt or AssignStatement or SingleAssignStmt or CallStmt)) continue;
          bool matches = ActualExpressions(actual).SelectMany(ResolvedCalls).Any(call =>
            ReferenceEquals(call.Function, captured.Function) && call.Args.Count == captured.Args.Count &&
            call.Args.Where((arg, i) => !TypedEq(arg, captured.Args[i])).Count() == 0);
          if (!matches) continue;
          for (int gapIndex = captureIndex + 1; gapIndex < actualIndex; gapIndex++)
            if (!block.Body[gapIndex].IsGhost) {
              Err("KMC006", block.Body[gapIndex].Tok, "executable effect between snapshot capture and actual call");
              break;
            }
          break;
        }
      }
    }
  }

  void CheckUnboundPureCalls(Method method) {
    var checkedCalls = new HashSet<FunctionCallExpr>(ReferenceEqualityComparer.Instance);
    void ExpressionCalls(Expression expression) {
      if (expression == null) return;
      foreach (var call in ResolvedCalls(expression)) {
        if (!checkedCalls.Add(call) || !IsAdmittedPure(call.Function)) continue;
        bool captured = method.Body.DescendantsAndSelf.OfType<VarDeclStmt>().Any(vd => {
          if (!vd.IsGhost || vd.Locals.Count != 1 || !IsGhostTuple(vd.Locals[0].Type, out _) ||
              vd.Assign is not AssignStatement a || a.Rhss.Count != 1 || a.Rhss[0] is not ExprRhs rhs) return false;
          var witnessCall = DirectCall(rhs.Expr);
          return witnessCall != null && ReferenceEquals(witnessCall.Function, call.Function) &&
            witnessCall.Args.Count == call.Args.Count &&
            !call.Args.Where((arg, i) => !TypedEq(arg, witnessCall.Args[i])).Any();
        });
        if (!captured)
          Err("KMC006", call.Tok, "unbound actual pure call has no exact full-tuple ghost witness");
      }
    }
    void AssignmentCalls(AssignStatement assignment) {
      foreach (var lhs in assignment.Lhss) ExpressionCalls(lhs);
      foreach (var rhs in assignment.Rhss)
        if (rhs is ExprRhs er) ExpressionCalls(er.Expr);
      foreach (var call in assignment.DescendantsAndSelf.OfType<CallStmt>())
        foreach (var arg in call.Args) ExpressionCalls(arg);
    }
    void Walk(Statement statement) {
      if (statement.IsGhost) return;
      if (statement is BlockStmt block) { foreach (var child in block.Body) Walk(child); return; }
      if (statement is ForLoopStmt loop) {
        ExpressionCalls(loop.Start); ExpressionCalls(loop.End); Walk(loop.Body); return;
      }
      if (statement is IfStmt branch) {
        ExpressionCalls(branch.Guard); Walk(branch.Thn); if (branch.Els != null) Walk(branch.Els); return;
      }
      if (statement is VarDeclStmt vd && vd.Assign is AssignStatement va) { AssignmentCalls(va); return; }
      if (statement is AssignStatement assignment) { AssignmentCalls(assignment); return; }
      if (statement is SingleAssignStmt single) {
        ExpressionCalls(single.Lhs); if (single.Rhs is ExprRhs rhs) ExpressionCalls(rhs.Expr); return;
      }
      if (statement is CallStmt call) foreach (var arg in call.Args) ExpressionCalls(arg);
    }
    Walk(method.Body);
  }

  void ProcessBlock(BlockState state) {
    for (int i = 0; i < state.Block.Body.Count; i++) {
      var s = state.Block.Body[i];
      if (s.IsGhost) {
        CheckGhostStatement(s, state);
        continue;
      }
      ProcessExecutable(s, state, i);
      if (reporter.HasErrors) return;
    }
  }

  bool IsPacketStatement(BlockState state, Statement s) =>
    state.Packets.Any(p => ReferenceEquals(p.Stmt, s));

  void CheckGhostStatement(Statement s, BlockState state) {
    if (IsPacketStatement(state, s)) return;
    foreach (var cs in s.DescendantsAndSelf.OfType<CallStmt>()) {
      if (cs.Method == null) {
        Err("KMC008", cs.Tok, "unresolved ghost call target");
        continue;
      }
      if (methodTargets.Values.Any(x => ReferenceEquals(x, cs.Method)))
        Err("KMC003", cs.Tok, "ghost statement cannot invoke the executable NativeKeccak method " + cs.Method.Name);
      else if (!cs.Method.IsGhost && !cs.Method.IsLemmaLike)
        Err("KMC004", cs.Tok, "unobserved executable call in a ghost statement: " + cs.Method.FullName);
    }
  }

  void ProcessExecutable(Statement s, BlockState state, int index) {
    if (s is ForLoopStmt fl) { ProcessLoop(fl, state, index); return; }
    if (s is IfStmt iff) { ProcessIf(iff, state, index); return; }
    if (s is VarDeclStmt vd) {
      if (vd.Assign == null) return; // ghost/no initializer; no runtime event
      if (vd.Assign is not AssignStatement asg) { Err("KMC008", vd.Tok, "unsupported variable declaration assignment form"); return; }
      ProcessAssignLike(vd, asg, asg.Lhss, asg.Rhss, state, index);
      return;
    }
    if (s is AssignStatement a) { ProcessAssignLike(s, a, a.Lhss, a.Rhss, state, index); return; }
    if (s is SingleAssignStmt sa) {
      var lhs = new List<Expression> { sa.Lhs };
      var rhs = new List<AssignmentRhs> { sa.Rhs };
      ProcessAssignLike(s, null, lhs, rhs, state, index);
      return;
    }
    if (s is CallStmt bare) {
      ProcessEffectCall(s, bare, state, index);
      return;
    }
    if (s is BlockStmt nested) {
      var child = new BlockState { Block = nested, Packets = PacketsForBlock(nested) };
      ProcessBlock(child);
      if (child.Current != null)
        Err("KMC004", child.Current.Stmt.Tok, "extra unobserved trace packet in nested block");
      return;
    }
    Err("KMC008", s.Tok, "unsupported executable statement " + s.GetType().Name);
  }

  void ProcessAssignLike(Statement top, AssignStatement assign, List<Expression> lhss, List<AssignmentRhs> rhss,
                         BlockState state, int index) {
    var calls = top.DescendantsAndSelf.OfType<CallStmt>().ToList();
    if (calls.Count > 0) {
      if (calls.Count != 1) {
        Err("KMC005", top.Tok, "exactly one effectful call per executable statement is supported");
        return;
      }
      ProcessEffectCall(top, calls[0], state, index);
      return;
    }
    if (lhss.Count != 1 || rhss.Count != 1) {
      Err("KMC004", top.Tok, "ordinary assignment must have exactly one LHS and one RHS");
      return;
    }
    if (rhss[0] is TypeRhs tr) {
      ProcessAlloc(top, lhss[0], tr, state, index);
      return;
    }
    if (rhss[0] is not ExprRhs er) {
      Err("KMC008", top.Tok, "unsupported assignment RHS " + rhss[0].GetType().Name);
      return;
    }
    if (lhss.Any(l => ReferenceEquals(AsVar(l), traceFormal))) {
      Err("KMC003", top.Tok, "trace assignment is not a well-formed packet");
      return;
    }
    var ctx = new EvalContext { Block = state.Block, Stmt = top };
    var events = new List<Expected>();
    EvalExpr(er.Expr, events, ctx, true);
    if (reporter.HasErrors) return;

    var lhs = Strip(lhss[0]);
    if (lhs is IdentifierExpr || lhs is AutoGhostIdentifierExpr) {
      var v = AsVar(lhs);
      if (v == null || v.IsGhost) {
        Err("KMC004", lhs.Tok, "scalar assignment target must be a non-ghost local/formal/output");
        return;
      }
      if (v.Type.NormalizeExpand() is UserDefinedType ut && ut.IsArrayType) {
        Err("KMC010", lhs.Tok, "array alias assignment is unsupported; only fresh allocation or factory results are registered");
        return;
      }
    } else if (lhs is SeqSelectExpr sel && sel.E1 == null) {
      var role = RoleOf(sel.Seq);
      if (role < 0) {
        Err("KMC010", sel.Seq.Tok, "array write target has no registered role identity");
        return;
      }
      var idx = Strip(sel.E0);
      var idxVar = AsVar(idx);
      if (!(idx is LiteralExpr) && !(idxVar != null && !idxVar.IsGhost)) {
        Err("KMC004", sel.E0.Tok, "array write index must be a literal or simple non-ghost variable");
        return;
      }
      if (sel.Seq.Type.NormalizeExpand() is UserDefinedType st && st.IsArrayType && st.AsArrayType != null && st.AsArrayType.Dims != 1) {
        Err("KMC004", sel.Seq.Tok, "only rank-one array writes are supported");
        return;
      }
      events.Add(new Expected { Kind = "Write", Site = nextSite++, Role = role, Address = sel.E0 });
    } else {
      Err("KMC008", lhs.Tok, "unsupported assignment LHS " + lhs.GetType().Name);
      return;
    }

    if (events.Count == 0) {
      // A scalar copy/literal/length is unobserved by this vocabulary.  A pure
      // call always contributes Call, so this is not a hidden snapshot path.
      if (ctx.Snapshots.Count != 0) Err("KMC006", top.Tok, "pure call snapshot without a trace packet");
      return;
    }
    var packet = TakePrePacket(state, index, top, false);
    if (packet == null) return;
    ConsumeEvents(packet, events, "ordinary assignment");
    if (reporter.HasErrors) return;
    if (!packet.Consumed) Err("KMC004", packet.Stmt.Tok, "ordinary assignment packet has extra observations");
    else state.PacketIndex++;
    ValidateSnapshots(ctx);
  }

  TracePacket TakePrePacket(BlockState state, int index, Statement stmt, bool allowLengthGap) {
    var p = state.Current;
    if (p == null || p.Index >= index) {
      Err("KMC004", stmt.Tok, "missing PRE packet before " + stmt.GetType().Name);
      return null;
    }
    for (int i = p.Index + 1; i < index; i++) {
      var between = state.Block.Body[i];
      if (between.IsGhost) continue;
      if (allowLengthGap && IsLengthInit(between)) continue;
      Err("KMC004", between.Tok, "executable statement between PRE packet and its operation");
      return null;
    }
    return p;
  }

  bool IsLengthInit(Statement s) {
    if (s is not VarDeclStmt vd || vd.Assign is not AssignStatement a) return false;
    if (vd.Locals.Count != 1 || a.Lhss.Count != 1 || a.Rhss.Count != 1 || a.Rhss[0] is not ExprRhs er) return false;
    if (vd.Locals[0].IsGhost || TypeSig(vd.Locals[0].Type) != "NativeTypes.I") return false;
    if (!ReferenceEquals(AsVar(a.Lhss[0]), vd.Locals[0])) return false;
    var e = Strip(er.Expr);
    if (e is not ConversionExpr cv || TypeSig(cv.Type) != "NativeTypes.I" || TypeSig(cv.E.Type) != "int") return false;
    return Strip(cv.E) is MemberSelectExpr ms && ms.MemberName == "Length" &&
           ms.Obj.Type.NormalizeExpand() is UserDefinedType ut && ut.IsArrayType;
  }

  void ProcessAlloc(Statement top, Expression lhsExpr, TypeRhs tr, BlockState state, int index) {
    if (currentMethod.Name != "Permute" && currentMethod.Name != "NewOffsets" && currentMethod.Name != "NewSources") {
      Err("KMC010", tr.Tok, currentMethod.Name + ": allocation is not admitted for this method");
      return;
    }
    if (tr.ArrayDimensions == null || tr.ArrayDimensions.Count != 1) {
      Err("KMC010", tr.Tok, "allocation must have exactly one array dimension");
      return;
    }
    if (tr.InitCall != null || tr.InitDisplay != null || tr.ElementInit != null || tr.Bindings != null || tr.Path != null) {
      Err("KMC010", tr.Tok, "allocation may not carry initializers, init calls or nondefault bindings/path");
      return;
    }
    var dim = tr.ArrayDimensions[0];
    var dimStripped = Strip(dim);
    if (!(dimStripped is LiteralExpr) && AsVar(dimStripped) == null) {
      Err("KMC010", dim.Tok, "allocation dimension must be a literal or simple non-ghost variable");
      return;
    }
    var lhsVar = AsVar(lhsExpr);
    if (lhsVar == null || lhsVar.IsGhost) {
      Err("KMC010", lhsExpr.Tok, "allocation result must be bound to a non-ghost variable");
      return;
    }
    if (currentMethod.Name == "NewOffsets" || currentMethod.Name == "NewSources") {
      var outFormal = currentMethod.Outs.FirstOrDefault(o => !o.IsGhost && TypeSig(o.Type) == "array<NativeTypes.I>");
      if (outFormal == null || !ReferenceEquals(lhsVar, outFormal)) {
        Err("KMC010", lhsExpr.Tok, currentMethod.Name + ": only the factory output formal r may be allocated");
        return;
      }
    } else {
      if (lhsVar is not LocalVariable || lhsVar.Type.NormalizeExpand() is not UserDefinedType lut || !lut.IsArrayType) {
        Err("KMC010", lhsExpr.Tok, "Permute allocation result must be a fresh local array");
        return;
      }
      if (allocSites.ContainsKey(lhsVar)) {
        Err("KMC010", lhsExpr.Tok, "array local is allocated more than once");
        return;
      }
    }
    var site = nextSite++;
    var events = new List<Expected> { new Expected { Kind = "Alloc", Site = site, Address = dim } };
    var packet = TakePrePacket(state, index, top, false);
    if (packet == null) return;
    ConsumeEvents(packet, events, "allocation");
    if (reporter.HasErrors) return;
    if (!packet.Consumed) Err("KMC004", packet.Stmt.Tok, "allocation packet has extra observations");
    else state.PacketIndex++;
    allocSites[lhsVar] = site;
  }

  int TargetOf(Method m) {
    var pair = methodTargets.FirstOrDefault(kv => ReferenceEquals(kv.Value, m));
    return pair.Value == null ? -1 : methodTargetsByName[pair.Key];
  }

  int TargetOf(Function f) {
    var pair = functionTargets.FirstOrDefault(kv => ReferenceEquals(kv.Value, f));
    return pair.Value == null ? -1 : functionTargetsByName[pair.Key];
  }

  bool IsAdmittedPure(Function f) => f != null && functionTargets.Values.Any(x => ReferenceEquals(x, f));

  void ProcessEffectCall(Statement top, CallStmt cs, BlockState state, int index) {
    if (cs.Method == null) {
      Err("KMC005", cs.Tok, "effectful call has no resolved method target");
      return;
    }
    if (cs.Receiver != null && cs.Receiver is not StaticReceiverExpr) {
      Err("KMC005", cs.Tok, "instance receiver-style calls are unsupported");
      return;
    }
    var target = TargetOf(cs.Method);
    if (target < 0) {
      Err("KMC005", cs.Tok, "unregistered effectful callee " + cs.Method.FullName);
      return;
    }
    if (cs.Lhs.Count != cs.Method.Outs.Count) {
      Err("KMC005", cs.Tok, "call output count does not match the exact callee signature");
      return;
    }
    IVariable child = null;
    int ghostIndex = -1;
    for (int i = 0; i < cs.Lhs.Count; i++) {
      var v = AsVar(cs.Lhs[i]);
      if (v == null) {
        Err("KMC005", cs.Lhs[i].Tok, "call output binding is not a resolved variable");
        return;
      }
      var formal = cs.Method.Outs[i];
      if (v.IsGhost != formal.IsGhost) {
        Err("KMC005", cs.Lhs[i].Tok, "call output ghostness does not match the exact callee output " + i);
        return;
      }
      if (!TypeEq(v.Type, formal.Type)) {
        Err("KMC005", cs.Lhs[i].Tok, "call output type does not match the exact callee output " + i);
        return;
      }
      if (ReferenceEquals(v, traceFormal)) {
        Err("KMC003", cs.Lhs[i].Tok, "call output cannot clobber the trace formal");
        return;
      }
      if (formal.IsGhost) {
        if (ghostIndex >= 0) {
          Err("KMC005", cs.Tok, "exactly one ghost trace output is supported");
          return;
        }
        ghostIndex = i;
        child = v;
      }
    }
    if (child == null) {
      Err("KMC005", cs.Tok, "effectful call has no ghost child trace output");
      return;
    }
    if (!definitions.TryGetValue(child, out var childDefs) || childDefs.Count != 1 || !IsWithin(childDefs[0].Stmt, top)) {
      Err("KMC005", cs.Tok, "effectful child trace local must have exactly one defining output in this call");
      return;
    }

    if (cs.Method.Name == "NewOffsets" || cs.Method.Name == "NewSources") {
      for (int i = 0; i < cs.Lhs.Count; i++) {
        var formal = cs.Method.Outs[i];
        if (formal.IsGhost) continue;
        var v = AsVar(cs.Lhs[i]);
        if (v is not LocalVariable) {
          Err("KMC010", cs.Lhs[i].Tok, "factory result must bind a fresh local array");
          return;
        }
        factoryResults[v] = cs.Method.Name;
      }
    }

    var ctx = new EvalContext { Block = state.Block, Stmt = top };
    var argEvents = new List<Expected>();
    foreach (var arg in cs.Args) EvalExpr(arg, argEvents, ctx, true);
    if (reporter.HasErrors) return;
    if (ctx.PureCalls > 1) {
      Err("KMC006", cs.Tok, "only one nested pure call is supported in an effectful argument list");
      return;
    }

    var site = nextSite++;
    var callEvent = new Expected { Kind = "Call", Site = site, Target = target, Arity = cs.Args.Count };
    var childEvent = new Expected { Kind = "Child", Child = child, PureChild = false };

    if (argEvents.Count > 0) {
      var pre = TakePrePacket(state, index, top, false);
      if (pre == null) return;
      ConsumeEvents(pre, argEvents, "effectful call arguments");
      if (reporter.HasErrors) return;
      if (!pre.Consumed) Err("KMC006", pre.Stmt.Tok, "effectful argument packet has extra observations");
      else state.PacketIndex++;
      ValidateSnapshots(ctx);
      if (reporter.HasErrors) return;
    } else if (ctx.Snapshots.Count != 0) {
      Err("KMC006", cs.Tok, "pure snapshot without observed call arguments");
      return;
    }

    // IMMEDIATELY next statement must be the exact Call+child POST packet.
    if (index + 1 >= state.Block.Body.Count) {
      Err("KMC005", cs.Tok, "missing immediate POST packet after effectful call");
      return;
    }
    var next = state.Block.Body[index + 1];
    var post = state.Current;
    if (post == null || !ReferenceEquals(post.Stmt, next) || post.Index != index + 1) {
      Err("KMC005", cs.Tok, "effectful call POST packet must be the immediately next statement");
      return;
    }
    ConsumeEvents(post, new List<Expected> { callEvent, childEvent }, "effectful call POST packet");
    if (reporter.HasErrors) return;
    if (!post.Consumed) Err("KMC005", post.Stmt.Tok, "effectful POST packet must contain exactly Call and the actual child local");
    else state.PacketIndex++;
  }

  void ProcessLoop(ForLoopStmt fl, BlockState state, int index) {
    if (!fl.GoingUp) {
      Err("KMC011", fl.Tok, "only finite ascending for loops are supported");
      return;
    }
    if (fl.LoopIndex == null || fl.LoopIndex.IsGhost || TypeSig(fl.LoopIndex.Type) != "NativeTypes.I") {
      Err("KMC011", fl.Tok, "loop iterator must be a non-ghost NativeTypes.I bound variable");
      return;
    }
    var start = fl.Start;
    var end = fl.End;
    if (end == null || fl.Body == null) {
      Err("KMC011", fl.Tok, "unbounded/bodyless for loop is unsupported");
      return;
    }
    // Dafny evaluates a for-loop end once, before entry. Reusing its expression
    // after a body assignment would observe a different value at the exit.
    var endVariables = new HashSet<IVariable>(ReferenceEqualityComparer.Instance);
    foreach (var expression in end.DescendantsAndSelf.OfType<Expression>()) {
      var variable = AsVar(expression);
      if (variable != null) endVariables.Add(variable);
    }
    foreach (var variable in endVariables)
      if (definitions.TryGetValue(variable, out var defs) && defs.Any(d => IsWithin(d.Stmt, fl.Body))) {
        Err("KMC011", fl.Tok, "loop end expression variable is assigned inside the loop body");
        return;
      }
    var startEvents = new List<Expected>();
    var endEvents = new List<Expected>();
    var dummy = new EvalContext { Block = state.Block, Stmt = fl };
    EvalExpr(start, startEvents, dummy, false);
    EvalExpr(end, endEvents, dummy, false);
    if (startEvents.Count != 0 || endEvents.Count != 0) {
      Err("KMC011", fl.Tok, "loop bound expressions with runtime observations are unsupported");
      return;
    }
    int startSite = nextSite++;
    int endSite = nextSite++;
    int checkSite = nextSite++;
    var boundEvents = new List<Expected> {
      new Expected { Kind = "LoopBound", Site = startSite, Address = start },
      new Expected { Kind = "LoopBound", Site = endSite, Address = end }
    };

    // Consume the two bounds from one or two PRE packets, with no executable
    // statement between a packet and its actual loop.
    int consumedBounds = 0;
    while (consumedBounds < 2) {
      var p = state.Current;
      if (p == null || p.Index >= index) {
        Err("KMC011", fl.Tok, "missing LoopBound observation for loop start/end");
        return;
      }
      for (int i = p.Index + 1; i < index; i++) {
        var between = state.Block.Body[i];
        if (between.IsGhost) continue;
        Err("KMC011", between.Tok, "executable statement between LoopBound packet and its loop");
        return;
      }
      while (consumedBounds < 2 && !p.Consumed) {
        var ev = boundEvents[consumedBounds];
        var leaf = p.Leaves[p.LeafIndex];
        if (!IsMarker(leaf, "LoopBound")) {
          Err("KMC011", leaf.Tok, "loop PRE packet must contain only LoopBound(start) then LoopBound(end)");
          return;
        }
        ConsumeOne(p, ev, "loop bound");
        if (reporter.HasErrors) return;
        consumedBounds++;
      }
      if (!p.Consumed) {
        Err("KMC011", p.Stmt.Tok, "loop PRE packet has extra observations");
        return;
      }
      state.PacketIndex++;
      if (consumedBounds < 2) {
        // The next packet may follow the no-event length declaration.
        continue;
      }
    }

    var body = new BlockState { Block = fl.Body, Packets = PacketsForBlock(fl.Body) };
    ConsumeLoopCheck(body, checkSite, fl.LoopIndex, true);
    if (reporter.HasErrors) return;
    ProcessBlock(body);
    if (reporter.HasErrors) return;
    if (body.Current != null) {
      Err("KMC011", body.Current.Stmt.Tok, "extra unobserved trace packet in loop body");
      return;
    }

    // The false-exit check reuses the static loop check site.
    var exit = state.Current;
    if (exit == null || exit.Index != index + 1) {
      Err("KMC011", fl.Tok, "missing LoopCheck(false,end) immediately after loop");
      return;
    }
    for (int i = index + 1; i < exit.Index; i++) {
      var between = state.Block.Body[i];
      if (!between.IsGhost) {
        Err("KMC011", between.Tok, "executable statement between loop and its false-exit LoopCheck");
        return;
      }
    }
    var exitEvents = new List<Expected> { new Expected { Kind = "LoopCheck", Site = checkSite, Guard = false, Iteration = end } };
    ConsumeEvents(exit, exitEvents, "loop false exit");
    if (reporter.HasErrors) return;
    if (!exit.Consumed) Err("KMC011", exit.Stmt.Tok, "loop false-exit packet has extra observations");
    else state.PacketIndex++;
  }

  void ConsumeLoopCheck(BlockState body, int checkSite, IVariable loopVar, bool guard) {
    var p = body.Current;
    if (p == null) {
      Err("KMC011", body.Block.Tok, "missing LoopCheck(true,iterator) at loop body entry");
      return;
    }
    for (int i = 0; i < p.Index; i++)
      if (!body.Block.Body[i].IsGhost) {
        Err("KMC011", body.Block.Body[i].Tok, "LoopCheck must precede every executable loop-body statement");
        return;
      }
    var leaf = p.Leaves[p.LeafIndex];
    if (!IsMarker(leaf, "LoopCheck")) {
      Err("KMC011", leaf.Tok, "loop body must begin with LoopCheck(true,iterator)");
      return;
    }
    var ev = new Expected { Kind = "LoopCheck", Site = checkSite, Guard = guard, IterationVar = loopVar };
    ConsumeOne(p, ev, "loop entry check");
    if (reporter.HasErrors) return;
    if (p.Consumed) body.PacketIndex++;
  }

  void ProcessIf(IfStmt iff, BlockState state, int index) {
    if (iff.IsBindingGuard) {
      Err("KMC012", iff.Tok, "binding if-guards are unsupported");
      return;
    }
    var ctx = new EvalContext { Block = state.Block, Stmt = iff };
    var events = new List<Expected>();
    EvalGuard(iff.Guard, events, ctx);
    if (reporter.HasErrors) return;
    int branchSite = nextSite++;
    events.Add(new Expected { Kind = "Branch", Site = branchSite, Guard = true, Address = iff.Guard });
    if (state.Current == null || state.Current.Index >= index) {
      Err("KMC012", iff.Tok, "missing PRE packet for the actual branch guard");
      return;
    }
    var pre = TakePrePacket(state, index, iff, false);
    if (pre == null) return;
    ConsumeEvents(pre, events, "if guard");
    if (reporter.HasErrors) return;
    if (!pre.Consumed) Err("KMC012", pre.Stmt.Tok, "if PRE packet has extra observations");
    else state.PacketIndex++;

    var thn = new BlockState { Block = iff.Thn, Packets = PacketsForBlock(iff.Thn) };
    ProcessBlock(thn);
    if (thn.Current != null) Err("KMC012", thn.Current.Stmt.Tok, "extra unobserved packet in then-branch");
    if (iff.Els is BlockStmt els) {
      var eb = new BlockState { Block = els, Packets = PacketsForBlock(els) };
      ProcessBlock(eb);
      if (eb.Current != null) Err("KMC012", eb.Current.Stmt.Tok, "extra unobserved packet in else-branch");
    } else if (iff.Els != null) {
      Err("KMC012", iff.Els.Tok, "else branch must be a block");
    }
  }

  void EvalGuard(Expression e, List<Expected> events, EvalContext ctx) {
    e = Strip(e);
    if (e is LiteralExpr lit && lit.Value is bool) return;
    if (e is IdentifierExpr || e is AutoGhostIdentifierExpr) return;
    if (e is UnaryOpExpr u && u.ResolvedOp == UnaryOpExpr.ResolvedOpcode.BoolNot) {
      EvalGuard(u.E, events, ctx);
      return;
    }
    if (e is BinaryExpr b && IsComparison(b.ResolvedOp)) {
      bool numeric = IsNumericType(b.E0.Type) && IsNumericType(b.E1.Type);
      bool boolean = b.E0.Type.NormalizeExpand() is BoolType && b.E1.Type.NormalizeExpand() is BoolType;
      if (!numeric && !boolean) {
        Err("KMC012", b.Tok, "branch guard comparison must use admitted numeric (or Boolean) operands");
        return;
      }
      EvalExpr(b.E0, events, ctx, false);
      EvalExpr(b.E1, events, ctx, false);
      return;
    }
    Err("KMC012", e.Tok, "unsupported branch guard expression " + e.GetType().Name);
  }

  void EvalExpr(Expression e, List<Expected> events, EvalContext ctx, bool allowPure) {
    if (e == null) return;
    e = Strip(e);
    if (e is IdentifierExpr || e is AutoGhostIdentifierExpr || e is LiteralExpr) {
      bool array = e.Type.NormalizeExpand() is UserDefinedType a && a.IsArrayType &&
        a.AsArrayType?.Dims == 1 && a.TypeArgs.Count == 1 && IsNumericType(a.TypeArgs[0]);
      if (!IsNumericType(e.Type) && e.Type.NormalizeExpand() is not BoolType && !array)
        Err("KMC008", e.Tok, "unsupported executable leaf type " + TypeSig(e.Type));
      return;
    }

    if (e is ConversionExpr cv) {
      if (!IsAdmittedConversion(cv)) {
        Err("KMC008", cv.Tok, "unreviewed conversion from " + TypeSig(cv.E.Type) + " to " + TypeSig(cv.Type));
        return;
      }
      EvalExpr(cv.E, events, ctx, allowPure);
      return;
    }
    if (e is UnaryOpExpr u) {
      if (u.ResolvedOp == UnaryOpExpr.ResolvedOpcode.BVNot) {
        EvalExpr(u.E, events, ctx, allowPure);
        var bit = new int[7];
        bit[5] = 1;
        events.Add(new Expected { Kind = "Ops", Ops = bit });
        return;
      }
      if (u.ResolvedOp == UnaryOpExpr.ResolvedOpcode.BoolNot) {
        EvalExpr(u.E, events, ctx, allowPure);
        return;
      }
      Err("KMC008", u.Tok, "unsupported unary operation " + u.ResolvedOp);
      return;
    }
    if (e is BinaryExpr b) {
      if (IsComparison(b.ResolvedOp)) {
        Err("KMC008", b.Tok, "comparisons are only admitted in branch guards");
        return;
      }
      if (b.ResolvedOp == BinaryExpr.ResolvedOpcode.And || b.ResolvedOp == BinaryExpr.ResolvedOpcode.Or ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Imp || b.ResolvedOp == BinaryExpr.ResolvedOpcode.Iff ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Concat) {
        Err("KMC008", b.Tok, "unsupported runtime binary operation " + b.ResolvedOp);
        return;
      }
      if (!IsArithmetic(b.ResolvedOp)) {
        Err("KMC008", b.Tok, "unsupported runtime binary operation " + b.ResolvedOp);
        return;
      }
      if (!IsNumericType(b.E0.Type) || !IsNumericType(b.E1.Type) || !IsNumericType(b.Type)) {
        Err("KMC008", b.Tok, "non-numeric runtime operation operand");
        return;
      }
      EvalExpr(b.E0, events, ctx, allowPure);
      EvalExpr(b.E1, events, ctx, allowPure);
      events.Add(new Expected { Kind = "Ops", Ops = OpCounts(b.ResolvedOp) });
      return;
    }
    if (e is SeqSelectExpr sel && sel.E1 == null) {
      if (sel.Seq.Type.NormalizeExpand() is not UserDefinedType ut || !ut.IsArrayType ||
          ut.AsArrayType == null || ut.AsArrayType.Dims != 1) {
        Err("KMC008", sel.Seq.Tok, "array read must target a rank-one array");
        return;
      }
      var role = RoleOf(sel.Seq);
      if (role < 0) {
        Err("KMC010", sel.Seq.Tok, "array read has no registered role identity");
        return;
      }
      EvalExpr(sel.E0, events, ctx, allowPure);
      events.Add(new Expected { Kind = "Read", Site = nextSite++, Role = role, Address = sel.E0 });
      return;
    }
    if (e is MemberSelectExpr ms) {
      if (ms.MemberName == "Length" && ms.Obj.Type.NormalizeExpand() is UserDefinedType aut && aut.IsArrayType) {
        EvalExpr(ms.Obj, events, ctx, allowPure);
        return;
      }
      if (ms.Member is DatatypeDestructor && ms.MemberName == "0") {
        var call = DirectCall(ms.Obj);
        if (call != null && !IsAdmittedPure(call.Function)) {
          Err("KMC006", call.Tok, "inline call resolves to an unregistered/shadow pure declaration");
          return;
        }
        if (call != null && IsAdmittedPure(call.Function)) {
          if (!allowPure) {
            Err("KMC006", e.Tok, "pure call is not admitted in this expression context");
            return;
          }
          ProcessPureCall(call, events, ctx);
          return;
        }
        Err("KMC008", e.Tok, "unsupported tuple .0 projection in runtime expression");
        return;
      }
      if (ms.Member is DatatypeDestructor && ms.MemberName == "1") {
        Err("KMC006", e.Tok, "runtime expression may not read a witness child directly");
        return;
      }
      Err("KMC008", e.Tok, "unsupported executable member/field expression " + ms.MemberName);
      return;
    }
    if (e is FunctionCallExpr fc) {
      if (IsAdmittedPure(fc.Function)) {
        Err("KMC006", fc.Tok, "pure function must be used through its inline .0 projection");
        return;
      }
      if (markers.Values.Any(x => ReferenceEquals(x, fc.Function)))
        Err("KMC008", fc.Tok, "SourceTrace marker used in an executable expression");
      else
        Err("KMC008", fc.Tok, "unregistered executable function call " + (fc.Function?.FullName ?? "<unresolved>"));
      return;
    }
    if (e is ApplySuffix ap) {
      var call = DirectCall(ap);
      if (call != null) { EvalExpr(call, events, ctx, allowPure); return; }
      Err("KMC008", e.Tok, "unsupported executable call/apply expression");
      return;
    }
    if (e is ITEExpr || e is MatchExpr || e is NestedMatchExpr || e is StmtExpr || e is LetExpr ||
        e is LetOrFailExpr || e is SeqDisplayExpr || e is SeqUpdateExpr || e is LambdaExpr ||
        e is DatatypeValue) {
      Err("KMC008", e.Tok, "unsupported executable expression " + e.GetType().Name);
      return;
    }
    Err("KMC008", e.Tok, "unsupported executable expression " + e.GetType().Name);
  }

  void ProcessPureCall(FunctionCallExpr call, List<Expected> events, EvalContext ctx) {
    ctx.PureCalls++;
    if (ctx.PureCalls > 1) {
      Err("KMC006", call.Tok, "exactly one pure call per executable statement is supported");
      return;
    }
    var target = TargetOf(call.Function);
    if (target < 0) {
      Err("KMC006", call.Tok, "unregistered pure call target");
      return;
    }
    foreach (var arg in call.Args) EvalExpr(arg, events, ctx, false);
    if (reporter.HasErrors) return;

    var candidates = new List<(VarDeclStmt vd, LocalVariable local, AssignStatement assign, FunctionCallExpr captured)>();
    foreach (var vd in currentMethod.Body.DescendantsAndSelf.OfType<VarDeclStmt>()) {
      if (vd.Locals.Count != 1) continue;
      var local = vd.Locals[0];
      if (!local.IsGhost || !IsGhostTuple(local.Type, out var valueType)) continue;
      if (!TypeEq(local.Type, call.Function.ResultType)) continue;
      if (vd.Assign is not AssignStatement asg || asg.Lhss.Count != 1 || asg.Rhss.Count != 1 ||
          asg.Rhss[0] is not ExprRhs er || !ReferenceEquals(AsVar(asg.Lhss[0]), local)) continue;
      var captured = DirectCall(er.Expr);
      if (captured == null || !ReferenceEquals(captured.Function, call.Function)) continue;
      if (captured.Args.Count != call.Args.Count) continue;
      bool typed = true;
      for (int i = 0; i < call.Args.Count; i++) if (!TypedEq(captured.Args[i], call.Args[i])) { typed = false; break; }
      if (typed) candidates.Add((vd, local, asg, captured));
    }
    if (candidates.Count != 1) {
      Err("KMC006", call.Tok, "expected exactly one full-tuple ghost witness for this exact pure call, found " + candidates.Count);
      return;
    }
    var cand = candidates[0];
    if (!cand.vd.IsGhost || !cand.assign.IsGhost) {
      Err("KMC006", cand.vd.Tok, "snapshot witness must be an explicitly ghost local/assignment");
      return;
    }
    if (!ctx.Block.Body.Contains(cand.vd)) {
      Err("KMC006", cand.vd.Tok, "snapshot witness and actual call must be in the same lexical block");
      return;
    }
    if (!definitions.TryGetValue(cand.local, out var defs) || defs.Count != 1) {
      Err("KMC006", cand.vd.Tok, "snapshot witness must have exactly one definition across the entire method");
      return;
    }
    if (defs[0].Stmt != cand.assign) {
      Err("KMC006", cand.vd.Tok, "snapshot witness definition is not its full-tuple capture");
      return;
    }
    ctx.Snapshots.Add(new Snapshot {
      Witness = cand.local, Function = call.Function, Args = call.Args.ToList(),
      ActualStmt = ctx.Stmt, Block = ctx.Block
    });

    events.Add(new Expected { Kind = "Call", Site = nextSite++, Target = target, Arity = call.Args.Count });
    events.Add(new Expected { Kind = "Child", Child = cand.local, PureChild = true });
  }

  void ValidateSnapshots(EvalContext ctx) {
    foreach (var s in ctx.Snapshots) {
      var block = ctx.Block;
      int actualIndex = block.Body.IndexOf(s.ActualStmt);
      var witnessDecl = block.Body.OfType<VarDeclStmt>()
        .FirstOrDefault(vd => vd.Locals.Count == 1 && ReferenceEquals(vd.Locals[0], s.Witness));
      if (witnessDecl == null) {
        Err("KMC006", s.ActualStmt.Tok, "snapshot witness declaration is not a direct statement of the actual block");
        continue;
      }
      int witnessIndex = block.Body.IndexOf(witnessDecl);
      if (witnessIndex < 0 || actualIndex < 0 || witnessIndex >= actualIndex) {
        Err("KMC006", s.ActualStmt.Tok, "snapshot witness must precede the actual call in the same block");
        continue;
      }
      bool gap = false;
      for (int i = witnessIndex + 1; i < actualIndex; i++)
        if (!block.Body[i].IsGhost) { gap = true; break; }
      if (gap) {
        Err("KMC006", block.Body[actualIndex - 1].Tok, "executable effect between snapshot capture and actual call");
        continue;
      }
      var predecessor = block.Body[actualIndex - 1];
      if (predecessor is not AssertStmt assert || !IsDirectSnapshotAssert(assert, s)) {
        Err("KMC006", predecessor.Tok, "direct full-tuple assertion must be the LAST statement immediately before the actual inline call");
      }
    }
  }

  bool IsDirectSnapshotAssert(AssertStmt assert, Snapshot s) {
    var e = Strip(assert.Expr);
    if (e is not BinaryExpr b || b.ResolvedOp != BinaryExpr.ResolvedOpcode.EqCommon) return false;
    if (!ReferenceEquals(AsVar(b.E0), s.Witness)) return false;
    var call = DirectCall(b.E1);
    if (call == null || !ReferenceEquals(call.Function, s.Function) || call.Args.Count != s.Args.Count) return false;
    for (int i = 0; i < s.Args.Count; i++) if (!TypedEq(call.Args[i], s.Args[i])) return false;
    return true;
  }

  static bool IsMarker(Expression leaf, string kind) {
    var call = DirectCall(leaf);
    return call != null && call.Function != null && call.Function.Name == kind &&
           call.Function.FullName.StartsWith("SourceTrace._default.");
  }

  void ConsumeEvents(TracePacket p, List<Expected> events, string what) {
    foreach (var ev in events) {
      ConsumeOne(p, ev, what);
      if (reporter.HasErrors) return;
    }
  }

  void ConsumeOne(TracePacket p, Expected ev, string what) {
    if (p.LeafIndex >= p.Leaves.Count) {
      Err(ev.Kind == "Child" ? "KMC005" : "KMC004", p.Stmt.Tok, "missing " + ev.Kind + " observation in " + what);
      return;
    }
    var leaf = p.Leaves[p.LeafIndex];
    if (ev.Kind == "Child") {
      if (ev.PureChild) {
        if (!IsWitnessChild(leaf, ev.Child))
          Err("KMC005", leaf.Tok, "expected exact witness child .1 immediately after the Call event");
      } else {
        if (!ReferenceEquals(AsVar(leaf), ev.Child))
          Err("KMC005", leaf.Tok, "expected the exact actual child trace local in the POST packet");
      }
      if (!reporter.HasErrors) p.LeafIndex++;
      return;
    }
    var call = DirectCall(leaf);
    if (call == null || call.Function == null) {
      Err("KMC004", leaf.Tok, "trace packet leaf is not an exact SourceTrace marker");
      return;
    }
    if (!markers.TryGetValue(ev.Kind, out var expectedMarker) || !ReferenceEquals(call.Function, expectedMarker)) {
      Err("KMC004", leaf.Tok, "trace packet event order mismatch: expected " + ev.Kind);
      return;
    }
    switch (ev.Kind) {
      case "Call":
        if (call.Args.Count != 3 || !TryInt(call.Args[0], out var site) || site != ev.Site ||
            !TryInt(call.Args[1], out var target) || target != ev.Target ||
            !TryInt(call.Args[2], out var arity) || arity != ev.Arity) {
          Err("KMC005", call.Tok, "Call event does not match the exact actual callsite/target/arity");
          return;
        }
        break;
      case "Read":
      case "Write":
        if (call.Args.Count != 3 || !TryInt(call.Args[0], out var rsite) || rsite != ev.Site ||
            !TryInt(call.Args[1], out var role) || role != ev.Role) {
          Err("KMC010", call.Tok, ev.Kind + " event site/role does not match the actual access");
          return;
        }
        if (!BoundEq(ev.Address, call.Args[2])) {
          Err("KMC007", call.Args[2].Tok, ev.Kind + " address is not typed-identical to the actual index expression");
          return;
        }
        break;
      case "Alloc":
        if (call.Args.Count != 2 || !TryInt(call.Args[0], out var asite) || asite != ev.Site ||
            !BoundEq(ev.Address, call.Args[1])) {
          Err("KMC010", call.Tok, "Alloc event does not match the actual allocation size/site");
          return;
        }
        break;
      case "LoopBound":
        if (call.Args.Count != 2 || !TryInt(call.Args[0], out var bsite) || bsite != ev.Site ||
            !BoundEq(ev.Address, call.Args[1])) {
          Err("KMC011", call.Tok, "LoopBound event does not match the actual loop bound/site");
          return;
        }
        break;
      case "LoopCheck":
        if (call.Args.Count != 3) {
          Err("KMC011", call.Tok, "LoopCheck must retain its exact three fields");
          return;
        }
        bool iterOk = ev.IterationVar != null ? BoundEqVar(ev.IterationVar, call.Args[2]) : BoundEq(ev.Iteration, call.Args[2]);
        if (call.Args.Count != 3 || !TryInt(call.Args[0], out var csite) || csite != ev.Site ||
            call.Args[1] is not LiteralExpr g || g.Value is not bool gv || gv != ev.Guard || !iterOk) {
          Err("KMC011", call.Tok, "LoopCheck event does not match the actual guard/iteration/site");
          return;
        }
        break;
      case "Ops":
        if (call.Args.Count != 7) {
          Err("KMC004", call.Tok, "Ops event must have exactly seven counts");
          return;
        }
        for (int i = 0; i < 7; i++) {
          if (!TryInt(call.Args[i], out var count) || count != ev.Ops[i]) {
            Err("KMC004", call.Args[i].Tok, "Ops count does not match the actual executable operation at family " + i);
            return;
          }
        }
        break;
      case "Branch":
        if (call.Args.Count != 2 || !TryInt(call.Args[0], out var brsite) || brsite != ev.Site ||
            !TypedEq(ev.Address, call.Args[1])) {
          Err("KMC012", call.Tok, "Branch event does not match the actual guard/site");
          return;
        }
        break;
      default:
        Err("KMC004", leaf.Tok, "unsupported trace event kind " + ev.Kind);
        return;
    }
    p.LeafIndex++;
  }

  static bool BoundEqVar(IVariable actual, Expression marker) {
    var m = Strip(marker);
    if (m is ConversionExpr cv && TypeSig(cv.Type) == "int" && TypeSig(cv.E.Type) == "NativeTypes.I" &&
        ReferenceEquals(AsVar(cv.E), actual)) return true;
    return ReferenceEquals(AsVar(m), actual);
  }

  static bool IsWitnessChild(Expression e, IVariable witness) {
    e = Strip(e);
    if (e is not MemberSelectExpr ms || ms.MemberName != "1") return false;
    if (!ReferenceEquals(AsVar(ms.Obj), witness)) return false;
    if (ms.Member is not DatatypeDestructor dd) return false;
    var wt = witness.Type.NormalizeExpand();
    if (wt is not UserDefinedType ud || ud.ResolvedClass is not TupleTypeDecl tt) return false;
    return ReferenceEquals(dd.EnclosingClass, tt) && TypeSig(ms.Type) == "seq<int>";
  }
}
