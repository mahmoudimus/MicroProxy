using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Microsoft.Dafny;
using Microsoft.Dafny.Plugins;

// Trusted resolved-AST source-coverage checker.  This is NOT a verified
// semantics and NOT a whole-Dafny theorem.  It binds calls/functions/arrays to
// exact resolved declarations, walks every executable expression in evaluation
// order, consumes markers in that same order, and fails closed on every
// statement/expression form it does not explicitly model.
public class SourceCoverageConfiguration : PluginConfiguration {
  public override Rewriter[] GetRewriters(ErrorReporter reporter) => new Rewriter[]{ new SourceCoverageRewriter(reporter) };
}

public class SourceCoverageRewriter : Rewriter {
  readonly ErrorReporter reporter;
  readonly Dictionary<string,Function> markerFuncs = new();
  readonly Dictionary<int,Method> callTargets = new();
  readonly Dictionary<int,Function> funcTargets = new();
  readonly Dictionary<string,Method> fields = new();
  readonly HashSet<Method> allFields = new();
  Formal traceFormal;
  readonly List<object> roleVars = new();
  readonly HashSet<IVariable> ghostCallVars = new(ReferenceEqualityComparer.Instance);
  readonly List<FunctionCallExpr> markers = new();
  readonly Dictionary<FunctionCallExpr,(BlockStmt block,int index)> markerCtx = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<SingleAssignStmt,(BlockStmt block,int index)> traceCtx = new(ReferenceEqualityComparer.Instance);
  BlockStmt curBlock; int curIdx; Method currentMethod;
  int markerIndex;
  int selectAllocCount;
  (BlockStmt block,int index)? selectAllocCtx;
  Statement selectAllocStmt;

  static readonly string[] allFieldNames = {
    "NativeField.ReduceOnce","NativeField.Reduce","NativeField.Add","NativeField.Sub",
    "NativeField.Mul","NativeField.MulSub","NativeField.AddMul"
  };
  static readonly string[] selectRootName = { "NativeMlKem.Select" };
  static readonly string[] allRootNames = allFieldNames.Concat(selectRootName).ToArray();

  sealed class RootShape {
    public string[] Ins;
    public string[] Outs;
    public bool[] OutGhost;
  }
  static readonly Dictionary<string,RootShape> rootShapes = new() {
    ["NativeField.ReduceOnce"] = new RootShape { Ins=new[]{"NativeTypes.I"}, Outs=new[]{"NativeTypes.I","seq<int>"}, OutGhost=new[]{false,true} },
    ["NativeField.Reduce"] = new RootShape { Ins=new[]{"NativeTypes.I"}, Outs=new[]{"NativeTypes.I","seq<int>"}, OutGhost=new[]{false,true} },
    ["NativeField.Add"] = new RootShape { Ins=new[]{"NativeTypes.I","NativeTypes.I"}, Outs=new[]{"NativeTypes.I","seq<int>"}, OutGhost=new[]{false,true} },
    ["NativeField.Sub"] = new RootShape { Ins=new[]{"NativeTypes.I","NativeTypes.I"}, Outs=new[]{"NativeTypes.I","seq<int>"}, OutGhost=new[]{false,true} },
    ["NativeField.Mul"] = new RootShape { Ins=new[]{"NativeTypes.I","NativeTypes.I"}, Outs=new[]{"NativeTypes.I","seq<int>"}, OutGhost=new[]{false,true} },
    ["NativeField.MulSub"] = new RootShape { Ins=new[]{"NativeTypes.I","NativeTypes.I","NativeTypes.I"}, Outs=new[]{"NativeTypes.I","seq<int>"}, OutGhost=new[]{false,true} },
    ["NativeField.AddMul"] = new RootShape { Ins=new[]{"NativeTypes.I","NativeTypes.I","NativeTypes.I","NativeTypes.I"}, Outs=new[]{"NativeTypes.I","seq<int>"}, OutGhost=new[]{false,true} },
    ["NativeKeccak.SetLane"] = new RootShape { Ins=new[]{"array<bv64>","NativeTypes.I","bv64"}, Outs=new[]{"seq<int>"}, OutGhost=new[]{true} },
    ["NativeKeccak.Iota"] = new RootShape { Ins=new[]{"array<bv64>","bv64"}, Outs=new[]{"seq<int>"}, OutGhost=new[]{true} },
    ["NativeKeccak.Theta"] = new RootShape { Ins=new[]{"array<bv64>","array<bv64>"}, Outs=new[]{"seq<int>"}, OutGhost=new[]{true} },
    ["NativeKeccak.RhoPi"] = new RootShape { Ins=new[]{"array<bv64>","array<bv64>","array<NativeTypes.I>","array<NativeTypes.I>"}, Outs=new[]{"seq<int>"}, OutGhost=new[]{true} },
    ["NativeKeccak.Chi"] = new RootShape { Ins=new[]{"array<bv64>","array<bv64>"}, Outs=new[]{"seq<int>"}, OutGhost=new[]{true} },
    ["NativeKeccak.Wipe"] = new RootShape { Ins=new[]{"array<bv64>"}, Outs=new[]{"seq<int>"}, OutGhost=new[]{true} },
    ["NativeMlKem.Select"] = new RootShape { Ins=new[]{"array<bv8>","array<bv8>","array<bv8>","array<bv8>"}, Outs=new[]{"array<bv8>","seq<int>"}, OutGhost=new[]{false,true} },
  };

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
  static string[] FieldNames() {
    var env = Environment.GetEnvironmentVariable("SOURCE_TRACE_ROOTS");
    return string.IsNullOrWhiteSpace(env) ? allFieldNames : env.Split(',', StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
  }

  public SourceCoverageRewriter(ErrorReporter reporter) : base(reporter) { this.reporter = reporter; }

  static readonly HashSet<System.Type> bindingStatementTypes = new() {
    typeof(BlockStmt), typeof(IfStmt), typeof(WhileStmt), typeof(ForLoopStmt),
    typeof(ReturnStmt), typeof(VarDeclStmt), typeof(VarDeclPattern),
    typeof(AssignStatement), typeof(SingleAssignStmt), typeof(CallStmt),
    typeof(AssertStmt), typeof(ForallStmt), typeof(HideRevealStmt)
  };
  static IEnumerable<INode> BindingNodes(INode root) {
    var seen = new HashSet<INode>(ReferenceEqualityComparer.Instance);
    var pending = new Stack<INode>(); pending.Push(root);
    while (pending.Count>0) { var n=pending.Pop(); if(!seen.Add(n)) continue; yield return n; foreach(var c in n.Children) pending.Push(c); }
  }
  void CheckBindingGrammar(Method m) {
    foreach (var s in BindingNodes(m.Body).OfType<Statement>()) {
      if (!bindingStatementTypes.Contains(s.GetType()))
        Error(s.Tok,"unsupported "+(s.IsGhost?"ghost":"executable")+" statement "+s.GetType().Name+" in native binding grammar");
      if (s is CallStmt call) {
        if ((call.IsGhost || call.Method?.IsGhost==true || call.Method?.IsLemmaLike==true) && call.Lhs.Count!=0)
          Error(call.Tok,"ghost/lemma call output binding is unsupported");
        if (call.Lhs.Any(l=>AsVar(l)==traceFormal))
          Error(call.Tok,"actual trace output cannot be rebound by a call");
      }
    }
    foreach (var e in BindingNodes(m.Body).OfType<StmtExpr>())
      Error(e.Tok,"unsupported statement expression in native binding grammar");
  }

  static readonly string[] keccakMethodNames = { "SetLane", "Iota", "Wipe", "Chi", "Theta", "RhoPi" };
  static readonly string[] markerNames = { "Ops", "Call", "Branch", "Read", "Write", "LoopBound", "LoopCheck", "Alloc" };
  Function canonicalEncode;
  readonly Dictionary<string,DatatypeCtor> canonicalCtors = new();

  ModuleDefinition ExactModule(Program program, string name, bool required) {
    var matches = program.Modules().Where(m => m.Name == name).ToList();
    if (matches.Count == 0 && !required) return null;
    if (matches.Count != 1 || matches[0].FullName != name) {
      Error(program.GetStartOfFirstFileToken(), "missing, duplicate or shadowed exact module " + name);
      return null;
    }
    return matches[0];
  }

  DefaultClassDecl ExactDefault(ModuleDefinition module) {
    if (module == null) return null;
    var defaults = module.TopLevelDecls.OfType<DefaultClassDecl>().ToList();
    if (defaults.Count != 1) { Error(module.Tok, "missing exact default class in " + module.FullName); return null; }
    return defaults[0];
  }

  public override void PostResolve(Program program) {
    var methods = new Dictionary<string,Method>();
    var fieldNames = FieldNames();
    var allowedRoots = new HashSet<string>(allRootNames.Concat(keccakMethodNames.Select(n => "NativeKeccak." + n)));
    if (fieldNames.Length == 0 || fieldNames.Distinct().Count() != fieldNames.Length || fieldNames.Any(n => !allowedRoots.Contains(n)))
      Error(program.GetStartOfFirstFileToken(), "unsupported, empty or duplicate root selection");

    // Rotate validation is loadbearing only when a NativeKeccak root is
    // selected.  Select-only rejects any call to NativeKeccak.Rotate as an
    // unregistered executable function; a reachable Rotate can never be
    // silently skipped.  This is a selection-scope gate, not the c96 default
    // root set.
    var selectingKeccak = fieldNames.Any(n => n.StartsWith("NativeKeccak."));
    foreach (var moduleName in new[] { "NativeField", "NativeKeccak" }) {
      var module = ExactModule(program, moduleName, fieldNames.Any(n => n.StartsWith(moduleName + ".")));
      var def = ExactDefault(module);
      if (module == null || def == null) continue;
      var reserved = new HashSet<string>(moduleName == "NativeField"
        ? allFieldNames.Select(n => n.Substring("NativeField.".Length)) : keccakMethodNames);
      foreach (var td in module.TopLevelDecls.OfType<TopLevelDeclWithMembers>())
        foreach (var member in td.Members) {
          if (!reserved.Contains(member.Name) && !(moduleName == "NativeKeccak" && member.Name == "Rotate")) continue;
          if (!ReferenceEquals(td, def) || member.FullName != moduleName + "._default." + member.Name) {
            Error(member.Tok, "reserved native root outside exact default declaration: " + member.FullName);
            continue;
          }
          if (moduleName == "NativeKeccak" && member.Name == "Rotate") {
            if (!selectingKeccak) continue;
            if (member is not Function fn || fn.IsGhost || funcTargets.ContainsKey(20))
              Error(member.Tok, "duplicate or invalid exact NativeKeccak._default.Rotate");
            else funcTargets[20] = fn;
          } else if (member is not Method meth || meth.IsGhost || meth.IsLemmaLike || !methods.TryAdd(moduleName + "." + member.Name, meth))
            Error(member.Tok, "duplicate or invalid exact native method: " + member.FullName);
        }
    }

    Method selectMethod = null;
    if (fieldNames.Contains("NativeMlKem.Select")) {
      var module = ExactModule(program, "NativeMlKem", true);
      var def = ExactDefault(module);
      if (module != null && def != null) {
        foreach (var candidateModule in program.Modules())
          foreach (var td in candidateModule.TopLevelDecls.OfType<TopLevelDeclWithMembers>())
            foreach (var member in td.Members.Where(x => x.Name == "Select")) {
              if (!ReferenceEquals(td, def) || member.FullName != "NativeMlKem._default.Select") {
                Error(member.Tok, "reserved Select root outside exact default declaration: " + member.FullName);
                continue;
              }
              if (member is not Method meth || meth.IsGhost || meth.IsLemmaLike) {
                Error(member.Tok, "invalid exact NativeMlKem._default.Select method");
                continue;
              }
              if (selectMethod != null) { Error(member.Tok, "duplicate exact NativeMlKem._default.Select"); continue; }
              selectMethod = meth;
            }
      }
      if (selectMethod == null) Error(program.GetStartOfFirstFileToken(), "missing required exact root NativeMlKem.Select");
      else methods["NativeMlKem.Select"] = selectMethod;
    }

    var vocab = ExactModule(program, "SourceObservationVocabulary", true);
    var vocabDefault = ExactDefault(vocab);
    if (vocabDefault != null) {
      var encoders = vocabDefault.Members.OfType<Function>().Where(f => f.Name == "Encode").ToList();
      if (encoders.Count != 1 || !encoders[0].IsGhost || encoders[0].FullName != "SourceObservationVocabulary._default.Encode" || encoders[0].Ins.Count != 1 || encoders[0].Body == null)
        Error(vocab.Tok, "missing exact canonical vocabulary Encode");
      else canonicalEncode = encoders[0];
      var events = vocab.TopLevelDecls.OfType<DatatypeDecl>().Where(d => d.Name == "Event" && d.FullName == "SourceObservationVocabulary.Event").ToList();
      if (events.Count != 1) Error(vocab.Tok, "missing exact canonical Event datatype");
      else foreach (var ctor in events[0].Ctors)
        if (!canonicalCtors.TryAdd(ctor.Name, ctor)) Error(ctor.Tok, "duplicate canonical event constructor");
    }

    if (canonicalEncode != null) NativeCanonicalEncoderPolicy.Check(canonicalEncode, canonicalCtors, Error);

    var traceModule = ExactModule(program, "SourceTrace", true);
    var traceDefault = ExactDefault(traceModule);
    if (traceModule != null && traceDefault != null)
      foreach (var td in traceModule.TopLevelDecls.OfType<TopLevelDeclWithMembers>())
        foreach (var member in td.Members) {
          if (!markerNames.Contains(member.Name)) continue;
          if (!ReferenceEquals(td, traceDefault) || member.FullName != "SourceTrace._default." + member.Name || member is not Function fn || !fn.IsGhost || fn.ByMethodDecl != null || fn.ByMethodBody != null)
            Error(member.Tok, "reserved marker outside exact SourceTrace default ghost function: " + member.FullName);
          else if (!markerFuncs.TryAdd(fn.Name, fn)) Error(fn.Tok, "duplicate exact SourceTrace marker " + fn.Name);
        }
    foreach (var name in markerNames)
      if (!markerFuncs.ContainsKey(name)) Error(program.GetStartOfFirstFileToken(), "missing exact SourceTrace marker " + name);
    if (reporter.HasErrors) return;
    foreach (var pair in markerFuncs) CheckMarkerHelper(pair.Key, pair.Value);
    if (funcTargets.TryGetValue(20, out var rotate)) CheckRotateFunction(rotate);

    foreach (var name in fieldNames) {
      if (!methods.TryGetValue(name, out var meth)) { Error(program.GetStartOfFirstFileToken(), "missing required exact root " + name); continue; }
      fields[name] = meth; allFields.Add(meth);
    }
    if (methods.TryGetValue("NativeField.ReduceOnce", out var ro)) callTargets[1] = ro;
    if (methods.TryGetValue("NativeField.Reduce", out var rd)) callTargets[2] = rd;
    if (methods.TryGetValue("NativeKeccak.SetLane", out var sl)) callTargets[10] = sl;
    foreach (var meth in fields.Values) CheckMethod(meth);
    if (!reporter.HasErrors) Console.WriteLine("SOURCE-COVERAGE OK: exact roots [" + string.Join(",",fieldNames) + "]; ordered markers; fail-closed");
  }

  void Error(IOrigin tok, string msg) { reporter.Error(MessageSource.Rewriter, tok, msg); }

  bool CheckRootSignature(Method m) {
    var moduleName = m.EnclosingClass?.EnclosingModuleDefinition?.Name;
    var key = (moduleName ?? "") + "." + m.Name;
    if (!rootShapes.TryGetValue(key, out var shape)) { Error(m.Tok, "missing exact root shape for " + key); return false; }
    if (m.EnclosingClass is not DefaultClassDecl) { Error(m.Tok, "root is not in an exact default class: " + key); return false; }
    bool ok = true;
    if (m.Ins.Count != shape.Ins.Length) { Error(m.Tok, key + ": expected " + shape.Ins.Length + " input formals, found " + m.Ins.Count); ok = false; }
    else for (int i = 0; i < shape.Ins.Length; i++) {
      var actual = TypeSig(m.Ins[i].Type);
      if (actual != shape.Ins[i] || m.Ins[i].IsGhost) { Error(m.Ins[i].Tok, key + ": input " + i + " expected " + shape.Ins[i] + ", found " + actual + (m.Ins[i].IsGhost ? " (ghost)" : "")); ok = false; }
    }
    if (m.Outs.Count != shape.Outs.Length) { Error(m.Tok, key + ": expected " + shape.Outs.Length + " output formals, found " + m.Outs.Count); ok = false; }
    else for (int i = 0; i < shape.Outs.Length; i++) {
      var actual = TypeSig(m.Outs[i].Type);
      if (actual != shape.Outs[i] || m.Outs[i].IsGhost != shape.OutGhost[i]) { Error(m.Outs[i].Tok, key + ": output " + i + " expected " + shape.Outs[i] + (shape.OutGhost[i] ? " ghost" : "") + ", found " + actual + (m.Outs[i].IsGhost ? " ghost" : "")); ok = false; }
    }
    if (m.Outs.Count(o => o.IsGhost && o.Name == "trace") != 1) { Error(m.Tok, key + ": expected exactly one ghost output named trace"); ok = false; }
    return ok;
  }

  static bool IsSelect(Method m) =>
    m != null && m.Name == "Select" &&
    m.EnclosingClass?.EnclosingModuleDefinition?.Name == "NativeMlKem" &&
    m.EnclosingClass is DefaultClassDecl;

  void BuildRoles(Method m) {
    roleVars.Clear();
    foreach (var f in m.Ins) roleVars.Add(f);
    // Select writes its exact non-ghost out buffer; the allocation result role
    // is the output formal itself.  All other reviewed roots keep the original
    // input-only role map.
    if (IsSelect(m)) foreach (var o in m.Outs) if (!o.IsGhost) roleVars.Add(o);
  }

  object ResolveRole(Expression e) {
    while (e is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null && !ReferenceEquals(cse.ResolvedExpression,e)) e=cse.ResolvedExpression;
    if (e is IdentifierExpr ie) return ie.Var;
    if (e is MemberSelectExpr ms && ms.Member is Field fld) return fld;
    return null;
  }

  bool MarkerRoleMatches(FunctionCallExpr m, int argIndex, Expression seq, out int roleId) {
    roleId=-1;
    if (m.Args.Count <= argIndex || !TryInt(m.Args[argIndex],out var rid)) return false;
    roleId=(int)rid;
    if (roleId<0 || roleId>=roleVars.Count) return false;
    var actual=ResolveRole(seq);
    return actual!=null && ReferenceEquals(actual,roleVars[roleId]);
  }

  void CheckMarkerHelper(string name, Function fn) {
    // The entire resolved value must be the actual canonical encoder applied
    // to the actual typed constructor with each helper formal passed through.
    // A matching textual suffix inside a dead branch establishes nothing.
    var body = fn.Body == null ? null : Unwrap(fn.Body);
    if (body is not FunctionCallExpr call || !ReferenceEquals(call.Function, canonicalEncode) || call.Args.Count != 1 ||
        Unwrap(call.Args[0]) is not DatatypeValue value || !canonicalCtors.TryGetValue(name, out var ctor) || !ReferenceEquals(value.Ctor, ctor) ||
        value.Arguments.Count != fn.Ins.Count || value.Arguments.Count != ctor.Formals.Count) {
      Error(fn.Tok, "marker helper is not exact canonical Encode(constructor(positional formals)): " + fn.FullName);
      return;
    }
    for (int i = 0; i < fn.Ins.Count; i++)
      if (!ReferenceEquals(AsVar(value.Arguments[i]), fn.Ins[i]))
        Error(value.Arguments[i].Tok, "marker helper changes or reorders positional formal " + i + ": " + fn.FullName);
  }

  void CheckRotateFunction(Function fn) {
    if (fn.ByMethodDecl != null || fn.ByMethodBody != null) { Error(fn.Tok, "Rotate has unsupported by-method implementation"); return; }
    if (fn.Ins.Count != 2 || fn.Ins.Any(f => f.IsGhost) ||
        fn.Ins[0].Type.NormalizeExpand() is not BitvectorType wordType || wordType.Width != 64 ||
        fn.Ins[1].Type.NormalizeExpand() is not UserDefinedType shiftType || shiftType.ResolvedClass?.FullName != "NativeTypes.I") {
      Error(fn.Tok, "Rotate must have exact (bv64 word, NativeTypes.I public shift) formals"); return;
    }
    var word = fn.Ins[0]; var distance = fn.Ins[1];
    if (fn.Body == null || Unwrap(fn.Body) is not ITEExpr branch || Unwrap(branch.Test) is not BinaryExpr guard ||
        guard.Op != BinaryExpr.Opcode.Eq || !ReferenceEquals(AsVar(guard.E0), distance) || !TryInt(Unwrap(guard.E1), out var zero) || zero != 0) {
      Error(fn.Tok, "Rotate must expose its actual public-shift == 0 branch"); return;
    }
    BigInteger? site = null;
    DatatypeCtor tuple = null;
    CheckRotateAlternative(fn, branch.Thn, true, word, distance, ref site, ref tuple);
    CheckRotateAlternative(fn, branch.Els, false, word, distance, ref site, ref tuple);
  }

  // Validate the value and the ghost observation together, rather than trusting
  // a co-editable RotateTrace model. Supported value nodes are deliberately
  // limited to this native-word implementation; unknown shapes fail closed.
  bool CountRotateValue(Expression value, Formal word, Formal distance, int[] counts) {
    value = Unwrap(value);
    if (value is IdentifierExpr id) return ReferenceEquals(id.Var, word) || ReferenceEquals(id.Var, distance);
    if (value is LiteralExpr) return TryInt(value, out _);
    // Dafny resolves a bv64 shift distance to bv7. Only this public
    // distance conversion is admitted; private/native arbitrary casts reject.
    if (value is ConversionExpr converted && converted.Type.NormalizeExpand() is BitvectorType bits && bits.Width == 7 && !Mentions(converted.E, word))
      return CountRotateValue(converted.E, word, distance, counts);
    if (value is not BinaryExpr binary) { Error(value.Tok, "unsupported Rotate value node " + value.GetType().Name + ": " + value); return false; }
    int op;
    switch (binary.ResolvedOp) {
      case BinaryExpr.ResolvedOpcode.Sub: op = 1; break;
      case BinaryExpr.ResolvedOpcode.BitwiseOr: op = 5; break;
      case BinaryExpr.ResolvedOpcode.LeftShift:
      case BinaryExpr.ResolvedOpcode.RightShift:
        if (Mentions(binary.E1, word)) return false;
        op = 6; break;
      default: return false;
    }
    counts[op]++;
    return CountRotateValue(binary.E0, word, distance, counts) && CountRotateValue(binary.E1, word, distance, counts);
  }

  void CheckRotateAlternative(Function fn, Expression expression, bool outcome, Formal word, Formal distance,
                              ref BigInteger? site, ref DatatypeCtor tuple) {
    expression = Unwrap(expression);
    if (expression is not DatatypeValue pair || pair.Ctor?.EnclosingDatatype is not TupleTypeDecl || pair.Arguments.Count != 2 ||
        pair.Ctor.Formals.Count != 2 || pair.Ctor.Formals[0].IsGhost || !pair.Ctor.Formals[1].IsGhost) {
      Error(expression.Tok, "Rotate alternative must return the actual word/ghost-trace tuple"); return;
    }
    if (tuple == null) tuple = pair.Ctor;
    else if (!ReferenceEquals(tuple, pair.Ctor)) Error(expression.Tok, "Rotate alternatives use different tuple constructors");
    var counts = new int[7];
    if (!CountRotateValue(pair.Arguments[0], word, distance, counts)) {
      Error(pair.Arguments[0].Tok, "unsupported executable Rotate value expression"); return;
    }
    var leaves = ConcatLeaves(pair.Arguments[1]).ToList();
    if (leaves.Count < 1 || leaves.Count > 2 || Unwrap(leaves[0]) is not FunctionCallExpr observedBranch ||
        !ReferenceEquals(observedBranch.Function, markerFuncs["Branch"]) || observedBranch.Args.Count != 2 ||
        !TryInt(Unwrap(observedBranch.Args[0]), out var branchSite) || branchSite < 0 || branchSite > int.MaxValue ||
        Unwrap(observedBranch.Args[1]) is not LiteralExpr taken || taken.Value is not bool flag || flag != outcome) {
      Error(expression.Tok, "Rotate actual trace must begin with its actual branch outcome"); return;
    }
    if (site == null) site = branchSite;
    else if (site != branchSite) Error(observedBranch.Tok, "Rotate branch alternatives use different static site labels");
    if (leaves.Count == 1) {
      if (counts.Any(c => c != 0)) Error(expression.Tok, "Rotate actual trace omits executable word-operation counts");
      return;
    }
    if (Unwrap(leaves[1]) is not FunctionCallExpr ops || !ReferenceEquals(ops.Function, markerFuncs["Ops"]) || ops.Args.Count != 7) {
      Error(expression.Tok, "Rotate actual trace has an unsupported operation-count suffix"); return;
    }
    for (int i = 0; i < counts.Length; i++)
      if (!TryInt(Unwrap(ops.Args[i]), out var observed) || observed != counts[i])
        Error(ops.Args[i].Tok, "Rotate operation observation does not match actual executable count at " + i);
  }

  static bool Mentions(Expression e, IVariable v) {
    foreach (var x in e.DescendantsAndSelf) if (x is IdentifierExpr ie && ie.Var==v) return true;
    return false;
  }

  void CheckMethod(Method m) {
    currentMethod=m;
    selectAllocCount = 0;
    selectAllocCtx = null;
    selectAllocStmt = null;
    if (!CheckRootSignature(m)) return;
    traceFormal = m.Outs.FirstOrDefault(f => ((IVariable)f).Name=="trace" && ((IVariable)f).IsGhost);
    if (traceFormal == null) { Error(m.Tok,m.Name+": missing ghost out formal trace"); return; }
    CheckBindingGrammar(m);
    ghostCallVars.Clear(); markers.Clear(); markerCtx.Clear(); traceCtx.Clear(); calleeDefCtx.Clear(); calleeAppendCount.Clear(); calleeAppendCtx.Clear(); pureCallExprCtx.Clear(); pureAppendCount.Clear(); pureAppendCtx.Clear(); markerIndex = 0; roleVars.Clear();
    BuildRoles(m);
    CollectGhostCallVars(m);
    CollectTraceAssignments(m);
    if (markers.Count == 0) { Error(m.Tok,m.Name+": no trace observation assignment"); return; }
    if (markers[0].Function == markerFuncs["Ops"]) { CheckOpsCounts(m); Advance(); }
    else if (m.Name=="ReduceOnce"||m.Name=="Reduce"||m.Name=="Add"||m.Name=="Sub"||m.Name=="Mul"||m.Name=="MulSub"||m.Name=="AddMul")
      Error(markers[0].Tok,m.Name+": first marker must be exact SourceTrace.Ops");
    WalkBlock(m.Body);
    if (markerIndex != markers.Count) Error(markers[markerIndex].Tok,m.Name+": stale observation "+MarkerName(markers[markerIndex]));
    if (IsSelect(m) && selectAllocCount != 1) Error(m.Tok, m.Name+": expected exactly one exact returned-buffer allocation");
  }

  string MarkerName(FunctionCallExpr fc) => markerFuncs.First(kv=>kv.Value==fc.Function).Key;

  readonly Dictionary<IVariable,int> ghostCallAssignCount = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<IVariable,int> ghostCallDefPos = new(ReferenceEqualityComparer.Instance);
  sealed class CalleeDef {
    public BlockStmt Block;
    public int Index;
    public CallStmt Call;
    public FunctionCallExpr Pure;
  }
  readonly Dictionary<IVariable,CalleeDef> calleeDefCtx = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<IVariable,int> calleeAppendCount = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<IVariable,SingleAssignStmt> calleeAppendCtx = new(ReferenceEqualityComparer.Instance);
  readonly HashSet<IVariable> pureCallVars = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<FunctionCallExpr,CalleeDef> pureCallExprCtx = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<(string name,string file,int start,int end),int> pureAppendCount = new();
  readonly Dictionary<(string name,string file,int start,int end),SingleAssignStmt> pureAppendCtx = new();

  static (string name,string file,int start,int end) VarKey(IVariable v) {
    if (v == null) return (null, null, -1, -1);
    var o = v.Tok;
    return (v.Name, o?.Filepath, o?.StartToken?.pos ?? -1, o?.EndToken?.pos ?? -1);
  }

  static bool SameOrigin(IOrigin a, IOrigin b) =>
    a != null && b != null && a.Filepath == b.Filepath &&
    a.StartToken?.pos == b.StartToken?.pos && a.EndToken?.pos == b.EndToken?.pos;

  bool IsPureCallVar(IVariable v) {
    if (v == null) return false;
    var key = VarKey(v);
    return pureCallVars.Any(p => VarKey(p) == key);
  }

  CalleeDef FindPureDefByVar(IVariable v) {
    if (v == null) return null;
    var key = VarKey(v);
    return calleeDefCtx.FirstOrDefault(kv => VarKey(kv.Key) == key).Value;
  }

  CalleeDef FindPureDefByExpr(FunctionCallExpr fc) {
    if (fc == null) return null;
    foreach (var def in calleeDefCtx.Values)
      if (def.Pure != null && ReferenceEquals(def.Pure.Function, fc.Function) &&
          SameOrigin(def.Pure.Tok, fc.Tok))
        return def;
    return null;
  }

  static bool IsGhostTupleProjection(MemberSelectExpr ms) {
    if (ms.MemberName != "1") return false;
    var t = ms.Obj.Type.NormalizeExpand();
    return t is UserDefinedType u && u.ResolvedClass is TupleTypeDecl;
  }

  void CollectGhostCallVars(Method m) {
    ghostCallAssignCount.Clear(); ghostCallDefPos.Clear(); pureCallVars.Clear();
    foreach (var s in m.Body.DescendantsAndSelf) {
      if (s is SingleAssignStmt sa) {
        var v=AsVar(sa.Lhs);
        if (v is LocalVariable lv && lv.IsGhost) {
          ghostCallAssignCount.TryGetValue(lv,out var c); ghostCallAssignCount[lv]=c+1;
          if (sa.DescendantsAndSelf.OfType<CallStmt>().Any()) ghostCallDefPos[lv]=sa.Tok?.StartToken?.pos ?? -1;
        }
        if (!s.IsGhost && sa.Rhs is ExprRhs per && AsMarkerCall(per.Expr) is FunctionCallExpr pfc && pfc.Function != null && funcTargets.Values.Contains(pfc.Function)) {
          var pv=AsVar(sa.Lhs);
          if (pv is LocalVariable plv) pureCallVars.Add(plv);
        }
      }
      if (s is AssignStatement asg) {
        foreach (var lhs in asg.Lhss) { var v=AsVar(lhs); if (v is LocalVariable lv && lv.IsGhost) {
          ghostCallAssignCount.TryGetValue(lv,out var c); ghostCallAssignCount[lv]=c+1;
          if (asg.DescendantsAndSelf.OfType<CallStmt>().Any()) ghostCallDefPos[lv]=asg.Tok?.StartToken?.pos ?? -1;
        } }
      }
    }
    foreach (var kv in ghostCallAssignCount) if (kv.Value==1 && ghostCallDefPos.ContainsKey(kv.Key)) ghostCallVars.Add(kv.Key);
    ghostCallVars.ExceptWith(pureCallVars);
    CollectCalleeDefs(m);
  }

  void CollectCalleeDefs(Method m) {
    calleeDefCtx.Clear(); pureCallExprCtx.Clear();
    CollectCalleeDefsInBlock(m.Body);
  }

  static bool IsDirectCallShape(Expression e) {
    e = Unwrap(e);
    return e is FunctionCallExpr || e is ApplySuffix;
  }

  static IEnumerable<Expression> AllExprs(Statement s) {
    var seen = new HashSet<Expression>(ReferenceEqualityComparer.Instance);
    var stack = new Stack<Expression>();
    foreach (var st in s.DescendantsAndSelf.OfType<Statement>())
      foreach (var e in st.SubExpressions) stack.Push(e);
    while (stack.Count > 0) {
      var e = stack.Pop();
      if (!seen.Add(e)) continue;
      yield return e;
      foreach (var c in e.SubExpressions) stack.Push(c);
    }
  }

  void CollectCalleeDefsInBlock(BlockStmt b) {
    if (b == null) return;
    for (int idx = 0; idx < b.Body.Count; idx++) {
      var s = b.Body[idx];
      if (s is IfStmt iff) {
        CollectCalleeDefsInBlock(iff.Thn);
        if (iff.Els is BlockStmt eb) CollectCalleeDefsInBlock(eb);
        else if (iff.Els != null) Error(iff.Els.Tok, "unsupported non-block else in callee definition collection");
        continue;
      }
      if (s is WhileStmt wh) { CollectCalleeDefsInBlock(wh.Body); continue; }
      if (s is ForLoopStmt fl) { CollectCalleeDefsInBlock(fl.Body); continue; }
      if (s is BlockStmt bb) { CollectCalleeDefsInBlock(bb); continue; }
      if (s is NestedMatchStmt || s is MatchStmt) continue;
      foreach (var cs in s.DescendantsAndSelf.OfType<CallStmt>()) {
        if (cs.Method == null || cs.Method.IsLemmaLike) continue;
        for (int i = 0; i < cs.Method.Outs.Count && i < cs.Lhs.Count; i++) {
          if (!cs.Method.Outs[i].IsGhost) continue;
          var v = AsVar(cs.Lhs[i]);
          if (v != null && (ghostCallVars.Contains(v) || pureCallVars.Contains(v)))
            calleeDefCtx[v] = new CalleeDef { Block = b, Index = idx, Call = cs };
        }
      }
      if (!s.IsGhost) {
        var allPureSet = new HashSet<FunctionCallExpr>(ReferenceEqualityComparer.Instance);
        foreach (var expr in AllExprs(s)) {
          var fc = AsMarkerCall(expr);
          if (fc != null && fc.Function != null && funcTargets.Values.Contains(fc.Function)) allPureSet.Add(fc);
        }
        var allPure = allPureSet.ToList();
        if (allPure.Count > 0) {
          var supported = new HashSet<FunctionCallExpr>(ReferenceEqualityComparer.Instance);
          foreach (var sa in s.DescendantsAndSelf.OfType<SingleAssignStmt>()) {
            if (sa.Rhs is not ExprRhs er) continue;
            var pv = AsVar(sa.Lhs);
            if (!IsPureCallVar(pv)) continue;
            if (!IsDirectCallShape(er.Expr) || allPure.Count != 1) {
              Error(sa.Tok, "registered pure call result must be a direct single defining call");
              continue;
            }
            var pfc = allPure[0];
            var def = new CalleeDef { Block = b, Index = idx, Pure = pfc };
            calleeDefCtx[pv] = def;
            pureCallExprCtx[pfc] = def;
            supported.Add(pfc);
          }
          foreach (var fc in allPure)
            if (FindPureDefByExpr(fc) == null)
              Error(fc.Tok, "registered pure call must be the direct RHS of one defining assignment");
        }
      }
    }
  }

  SingleAssignStmt FirstTraceUpdateAfter(CalleeDef def) {
    if (def == null || def.Block == null) return null;
    for (int j = def.Index + 1; j < def.Block.Body.Count; j++) {
      var s = def.Block.Body[j];
      if (s.IsGhost) {
        var ta = s.DescendantsAndSelf.OfType<SingleAssignStmt>().FirstOrDefault(a => AsVar(a.Lhs) == traceFormal);
        if (ta != null) return ta;
        continue;
      }
      return null;
    }
    return null;
  }

  static FunctionCallExpr AsMarkerCall(Expression e) {
    e = Unwrap(e);
    if (e is FunctionCallExpr fc) return fc;
    if (e is ApplySuffix ap) {
      if (ap.ResolvedExpression is FunctionCallExpr rf) return rf;
      if (ap.Lhs is FunctionCallExpr f) return f;
      if (ap.Lhs is ConcreteSyntaxExpression cse && cse.ResolvedExpression is FunctionCallExpr lf) return lf;
      var direct = ap.SubExpressions.OfType<FunctionCallExpr>().FirstOrDefault();
      if (direct != null) return direct;
      foreach (var child in ap.SubExpressions) {
        var nested = AsMarkerCall(child);
        if (nested != null) return nested;
      }
      return ap.DescendantsAndSelf.OfType<FunctionCallExpr>().FirstOrDefault();
    }
    return null;
  }

  bool IsExactCallMarker(Expression leaf, CalleeDef def) {
    int targetId; int arity;
    if (def?.Call != null) {
      var pair = callTargets.FirstOrDefault(kv => ReferenceEquals(kv.Value, def.Call.Method));
      if (pair.Value == null) return false;
      targetId = pair.Key; arity = def.Call.Args.Count;
    } else if (def?.Pure != null) {
      var pair = funcTargets.FirstOrDefault(kv => ReferenceEquals(kv.Value, def.Pure.Function));
      if (pair.Value == null) return false;
      targetId = pair.Key; arity = def.Pure.Args.Count;
    } else return false;
    var m = AsMarkerCall(leaf);
    if (m == null || !ReferenceEquals(m.Function, markerFuncs["Call"]) || m.Args.Count != 3) return false;
    if (!TryInt(Unwrap(m.Args[1]), out var id) || id != targetId) return false;
    if (!TryInt(Unwrap(m.Args[2]), out var ar) || ar != arity) return false;
    return true;
  }

  bool HasExactCallMarker(SingleAssignStmt sa, CalleeDef def) {
    if (sa.Rhs is not ExprRhs er) return false;
    return ConcatLeaves(er.Expr).Any(leaf => IsExactCallMarker(leaf, def));
  }

  // The immutable prefix is leaves[0].  A compiled call append must be exactly
  // leaves[0] + exact defining Call marker + its own callee/pure trace leaf.
  // This is deliberately positional: searching for any matching marker allowed
  // a callee's events to be observed before the Call that caused them.
  bool IsOrderedCallChild(List<Expression> leaves, int childIndex, CalleeDef def, IVariable childVar, bool pure) {
    if (childIndex != 2 || leaves.Count < 3) return false;
    if (!IsExactCallMarker(leaves[1], def)) return false;
    var child = leaves[2];
    if (pure) {
      if (child is not MemberSelectExpr ms || !IsGhostTupleProjection(ms)) return false;
      return ReferenceEquals(AsVar(ms.Obj), childVar);
    }
    return ReferenceEquals(AsVar(child), childVar);
  }

  bool ContainsTraceAssign(Statement s) => s.DescendantsAndSelf.OfType<SingleAssignStmt>()
    .Any(sa => AsVar(sa.Lhs)==traceFormal);

  void CollectTraceInBlock(BlockStmt b, List<SingleAssignStmt> list, bool insideControl) {
    if (b==null) return;
    for (int idx=0; idx<b.Body.Count; idx++) {
      var s=b.Body[idx];
      if (s.IsGhost) {
        if (s is IfStmt || s is WhileStmt || s is ForLoopStmt || s is ForallStmt || s is BlockStmt || s is AlternativeLoopStmt) {
          if (ContainsTraceAssign(s)) Error(s.Tok,"trace assignment inside ghost control flow is not executable");
          continue;
        }
        foreach (var sa in s.DescendantsAndSelf.OfType<SingleAssignStmt>())
          if (AsVar(sa.Lhs)==traceFormal) { list.Add(sa); traceCtx[sa]=(b,idx); }
        continue;
      }
      if (s is IfStmt iff) { CollectTraceInBlock(iff.Thn,list,true); if (iff.Els is BlockStmt eb) CollectTraceInBlock(eb,list,true); }
      else if (s is WhileStmt wh) CollectTraceInBlock(wh.Body,list,true);
      else if (s is ForLoopStmt fl) CollectTraceInBlock(fl.Body,list,true);
      else if (s is BlockStmt bb) CollectTraceInBlock(bb,list,insideControl);
    }
  }

  void CollectTraceAssignments(Method m) {
    var assigns = new List<SingleAssignStmt>();
    CollectTraceInBlock(m.Body,assigns,false);
    assigns = assigns.OrderBy(sa => sa.Tok?.StartToken?.pos ?? 0).ThenBy(sa => sa.Tok?.StartToken?.col ?? 0).ToList();
    if (assigns.Count == 0) { Error(m.Tok,m.Name+": no assignment to ghost trace"); return; }
    bool first = true;
    foreach (var sa in assigns) {
      if (!sa.IsGhost) { Error(sa.Tok,m.Name+": trace assignment is not ghost"); continue; }
      if (sa.Rhs is not ExprRhs er) { Error(sa.Tok,m.Name+": trace RHS is not an expression"); continue; }
      var leaves = ConcatLeaves(er.Expr).ToList();
      if (first) {
        if (leaves.Any(x => AsVar(x)==traceFormal)) { Error(sa.Tok,m.Name+": initial trace must not read a previous trace"); continue; }
        foreach (var leaf in leaves) {
          if (leaf is FunctionCallExpr fc && fc.Function != null && markerFuncs.Values.Contains(fc.Function)) { AddMarker(fc,sa); continue; }
          Error(leaf.Tok,m.Name+": initial trace update contains non-marker expression"); 
        }
        first = false;
      } else {
        if (leaves.Count == 0 || AsVar(leaves[0]) != traceFormal) { Error(sa.Tok,m.Name+": later trace update must append to the same trace as its immutable left prefix"); continue; }
        for (int i=1;i<leaves.Count;i++) {
          var leaf=leaves[i];
          if (leaf is FunctionCallExpr fc && fc.Function != null && markerFuncs.Values.Contains(fc.Function)) { AddMarker(fc,sa); continue; }
          if (leaf is MemberSelectExpr ms && IsGhostTupleProjection(ms)) {
            var ov=AsVar(ms.Obj);
            if (IsPureCallVar(ov)) {
              var key = VarKey(ov);
              pureAppendCount.TryGetValue(key,out var pc); pureAppendCount[key]=pc+1;
              var ddef = FindPureDefByVar(ov);
              if (ddef == null) Error(sa.Tok,m.Name+": pure-function trace local has no exact defining call context");
              else {
                if (!ReferenceEquals(FirstTraceUpdateAfter(ddef),sa)) Error(sa.Tok,m.Name+": pure-function trace append is not the first trace update immediately after its defining call");
                if (!HasExactCallMarker(sa,ddef)) Error(sa.Tok,m.Name+": pure-function trace append does not bind its exact defining Call marker");
                else if (!IsOrderedCallChild(leaves,i,ddef,ov,true)) Error(sa.Tok,m.Name+": pure-function trace append must place its exact defining Call marker immediately before its pure trace leaf");
              }
              if (pureAppendCtx.TryGetValue(key,out var prev) && !ReferenceEquals(prev,sa)) Error(sa.Tok,m.Name+": callee trace append is not in its defining call append");
              else pureAppendCtx[key]=sa;
              continue;
            }
          }
          var v=AsVar(leaf);
          if (v!=null && ghostCallVars.Contains(v)) {
            calleeAppendCount.TryGetValue(v,out var cc); calleeAppendCount[v]=cc+1;
            if (!calleeDefCtx.TryGetValue(v,out var ddef2)) Error(sa.Tok,m.Name+": callee trace local has no exact defining call context");
            else {
              if (!ReferenceEquals(FirstTraceUpdateAfter(ddef2),sa)) Error(sa.Tok,m.Name+": callee trace append is not the first trace update immediately after its defining call");
              if (!HasExactCallMarker(sa,ddef2)) Error(sa.Tok,m.Name+": callee trace append does not bind its exact defining Call marker");
              else if (!IsOrderedCallChild(leaves,i,ddef2,v,false)) Error(sa.Tok,m.Name+": callee trace append must place its exact defining Call marker immediately before its callee trace leaf");
            }
            if (calleeAppendCtx.TryGetValue(v,out var prev2) && !ReferenceEquals(prev2,sa)) Error(sa.Tok,m.Name+": callee trace append is not in its defining call append");
            else calleeAppendCtx[v]=sa;
            if (!ghostCallAssignCount.TryGetValue(v,out var cnt) || cnt!=1) { Error(leaf.Tok,m.Name+": callee trace local is not assigned exactly once"); continue; }
            if (ghostCallDefPos.TryGetValue(v,out var dp) && dp > (sa.Tok?.StartToken?.pos ?? 0)) { Error(leaf.Tok,m.Name+": callee trace local appended before its defining call"); continue; }
            continue;
          }
          Error(leaf.Tok,m.Name+": later trace update contains non-approved suffix expression");
        }
      }
    }
    foreach (var v in ghostCallVars) if (!calleeAppendCount.TryGetValue(v,out var c) || c!=1) Error(traceFormal.Tok,m.Name+": callee trace local must be appended exactly once");
    foreach (var v in pureCallVars) if (!pureAppendCount.TryGetValue(VarKey(v),out var c) || c!=1) Error(traceFormal.Tok,m.Name+": pure function trace must be appended exactly once");
  }

  bool HasCallMarker(SingleAssignStmt sa) {
    foreach (var x in sa.DescendantsAndSelf.OfType<SingleAssignStmt>())
      foreach (var e in x.SubExpressions) foreach (var y in e.DescendantsAndSelf)
        if (y is FunctionCallExpr fc && fc.Function == markerFuncs["Call"]) return true;
    return false;
  }

  void AddMarker(FunctionCallExpr fc, SingleAssignStmt sa) {
    markers.Add(fc);
    if (traceCtx.TryGetValue(sa,out var c)) markerCtx[fc]=c;
    else Error(fc.Tok,"marker has no executable trace-context");
  }

  static IEnumerable<Expression> ConcatLeaves(Expression e) {
    while (e is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null && !ReferenceEquals(cse.ResolvedExpression,e)) e=cse.ResolvedExpression;
    if (e is ParensExpression p) return ConcatLeaves(p.E);
    if (e is BinaryExpr b && b.ResolvedOp == BinaryExpr.ResolvedOpcode.Concat) return ConcatLeaves(b.E0).Concat(ConcatLeaves(b.E1));
    return new[]{e};
  }

  void CheckOpsCounts(Method m) {
    var (add,sub,mul,div,mod,bit,shift) = CountOps(m.Body,false);
    var expected = new[]{add,sub,mul,div,mod,bit,shift};
    if (markers.Count==0 || markers[0].Function != markerFuncs["Ops"]) return;
    var args = markers[0].Args;
    if (args.Count != 7) { Error(markers[0].Tok,m.Name+": Ops needs 7 args"); return; }
    for (int i=0;i<7;i++) {
      if (!TryInt(args[i],out var v)) { Error(args[i].Tok,m.Name+": Ops arg is not an integer literal"); continue; }
      if (v != expected[i]) Error(args[i].Tok,m.Name+": Ops arg "+i+"="+v+", source executable count="+expected[i]);
    }
  }

  void WalkBlock(BlockStmt b) {
    if (b==null) return;
    for (int idx=0; idx<b.Body.Count; idx++) { var s=b.Body[idx]; if (!s.IsGhost) WalkStmt(s,b,idx); }
  }

  void WalkStmt(Statement s, BlockStmt b, int idx) {
    curBlock=b; curIdx=idx;
    if (s is BlockStmt blk) { WalkBlock(blk); return; }
    if (s is IfStmt iff) {
      VisitExpr(iff.Guard);
      ExpectMarker("Branch", m => ExprEq(m.Args.Count==2?m.Args[1]:null, iff.Guard), iff.Tok, "branch guard "+iff.Guard);
      WalkBlock(iff.Thn);
      if (iff.Els != null) WalkStmt(iff.Els,b,idx);
      return;
    }
    if (s is ForLoopStmt fl) {
      VisitExpr(fl.Start); VisitExpr(fl.End);
      ExpectMarker("LoopBound", m => m.Args.Count==2 && ExprEq(m.Args[1],fl.Start), fl.Tok, "for start "+fl.Start);
      ExpectMarker("LoopBound", m => m.Args.Count==2 && ExprEq(m.Args[1],fl.End), fl.Tok, "for end "+fl.End);
      WalkBlock(fl.Body);
      return;
    }
    if (s is WhileStmt || s is AlternativeLoopStmt) { Error(s.Tok,"unimplemented executable loop observation: "+s.GetType().Name); return; }
    if (s is VarDeclStmt vd) { if (vd.Assign != null) WalkStmt(vd.Assign,b,idx); return; }
    if (s is AssignStatement asg) {
      var calls = asg.DescendantsAndSelf.OfType<CallStmt>().ToList();
      if (calls.Count > 0) { foreach (var c in calls) WalkCall(c,b,idx); return; }
      foreach (var rhss in asg.Rhss) {
        if (rhss is ExprRhs er) VisitExpr(er.Expr);
        if (rhss is TypeRhs tr) VisitAlloc(tr, asg.Lhss.Count == 1 ? asg.Lhss[0] : null, b, idx);
      }
      foreach (var lhs in asg.Lhss) VisitWrite(lhs);
      return;
    }
    if (s is SingleAssignStmt sa) {
      var calls = sa.DescendantsAndSelf.OfType<CallStmt>().ToList();
      if (calls.Count > 0) { foreach (var c in calls) WalkCall(c,b,idx); return; }
      if (sa.Rhs is ExprRhs er) VisitExpr(er.Expr);
      if (sa.Rhs is TypeRhs tr2) VisitAlloc(tr2, sa.Lhs, b, idx);
      VisitWrite(sa.Lhs);
      return;
    }
    if (s is CallStmt cs) { WalkCall(cs,b,idx); return; }
    if (s is ReturnStmt ret) {
      // Field roots return via out-parameters; a data return statement is not modeled.
      Error(ret.Tok,"unsupported executable return statement in source-coverage root"); return;
    }
    Error(s.Tok,"unsupported executable statement: "+s.GetType().Name);
  }

  void WalkCall(CallStmt cs, BlockStmt b, int idx) {
    if (cs.Method.IsLemmaLike) { Error(cs.Tok,"executable lemma call is not modeled"); return; }
    if (!allFields.Contains(cs.Method)) { Error(cs.Tok,"unregistered executable callee "+cs.Method.FullName); return; }
    if (cs.Receiver != null) VisitExpr(cs.Receiver);
    foreach (var a in cs.Args) VisitExpr(a);
    ExpectMarker("Call", m => {
      if (m.Args.Count!=3 || !TryInt(m.Args[1],out var id) || !TryInt(m.Args[2],out var ar)) return false;
      return callTargets.TryGetValue((int)id,out var target) && ReferenceEquals(target,cs.Method) && ar==cs.Args.Count;
    }, cs.Tok, "call to exact "+cs.Method.FullName+"/"+cs.Args.Count);
  }

  bool IsExactPublic32(Expression e) {
    e = Unwrap(e);
    while (e is ConversionExpr c) e = Unwrap(c.E);
    return TryInt(e, out var value) && value == 32;
  }

  bool IsLiteralZero(Expression e) {
    e = Unwrap(e);
    while (e is ConversionExpr c) e = Unwrap(c.E);
    if (e is LiteralExpr le) {
      if (le.Value is BigInteger bi) return bi == 0;
      if (le.Value is int i) return i == 0;
    }
    return false;
  }

  bool CheckZeroInitializer(Expression init) {
    init = Unwrap(init);
    if (init is not LambdaExpr lambda) {
      Error(init.Tok, "Select allocation initializer must be an exact literal-zero lambda");
      return false;
    }
    foreach (var node in init.DescendantsAndSelf) {
      if (node is SeqSelectExpr) { Error(node.Tok, "Select allocation initializer contains a private/unknown array read or index"); return false; }
      if (node is FunctionCallExpr call) { Error(call.Tok, "Select allocation initializer contains an executable call: " + (call.Function?.FullName ?? "<unresolved>")); return false; }
      if (node is ApplySuffix app) {
        var nestedCall = app.DescendantsAndSelf.OfType<FunctionCallExpr>().FirstOrDefault();
        if (nestedCall != null) Error(nestedCall.Tok, "Select allocation initializer contains an executable call: " + (nestedCall.Function?.FullName ?? "<unresolved>"));
        else Error(app.Tok, "Select allocation initializer contains an unsupported call/apply expression");
        return false;
      }
      if (node is ITEExpr || node is MatchExpr || node is NestedMatchExpr || node is StmtExpr ||
          node is LetExpr || node is LetOrFailExpr ||
          node is SeqUpdateExpr || node is SeqDisplayExpr) {
        Error(node.Tok, "Select allocation initializer contains an unsupported condition/branch/compound expression " + node.GetType().Name);
        return false;
      }
      if (node is IdentifierExpr id && !lambda.BoundVars.Any(b => ReferenceEquals(b, id.Var))) {
        Error(id.Tok, "Select allocation initializer reads a non-lambda value " + id.Var?.Name);
        return false;
      }
    }
    if (!IsLiteralZero(lambda.Body)) {
      Error(lambda.Body.Tok, "Select allocation initializer body is not the exact literal zero");
      return false;
    }
    return true;
  }

  void VisitAlloc(TypeRhs tr, Expression lhs, BlockStmt b, int idx) {
    // None of the reviewed thirteen Field/Keccak roots allocate.  The only
    // allocation profile admitted here is the exact Select out-buffer shape.
    if (!IsSelect(currentMethod)) {
      Error(tr.Start, "unsupported allocation in current native root grammar");
      return;
    }
    if (tr.ArrayDimensions == null || tr.ArrayDimensions.Count != 1) {
      Error(tr.Tok, "Select allocation must have exactly one array dimension");
      return;
    }
    var dim = tr.ArrayDimensions[0];
    if (!IsExactPublic32(dim)) {
      Error(dim.Tok, "Select allocation size must be the exact public literal 32");
      return;
    }
    // F1: the reviewed profile is one allocation at one direct top-level
    // method-body position.  A site count is not a dynamic execution count:
    // an allocation under a loop, conditional, wrapper block or any other
    // control flow can execute repeatedly while the trace has one Alloc.
    if (!ReferenceEquals(b, currentMethod.Body)) {
      Error(tr.Tok, "Select allocation must be a direct top-level statement of the method body; allocation under a loop, conditional, wrapper block or other control flow is unsupported");
      return;
    }
    if (tr.InitCall != null || tr.InitDisplay != null) {
      Error(tr.Tok, "Select allocation uses an unsupported InitCall/InitDisplay initializer form");
      return;
    }
    // F4: the pinned TypeRhs carries Bindings/Path as well as the forms already
    // checked.  The exact array allocation must have the typed defaults; any
    // nondefault binding/path form fails closed rather than being ignored.
    if (tr.Bindings != null || tr.Path != null) {
      Error(tr.Tok, "Select allocation has unsupported nondefault TypeRhs Bindings/Path");
      return;
    }
    if (tr.ElementInit != null && !CheckZeroInitializer(tr.ElementInit)) return;
    // F3: the allocation result is the sole non-ghost output formal by resolved
    // identity, independent of its name.  Role 4 is the output position.
    var nonGhostOuts = currentMethod.Outs.Where(o => !o.IsGhost).ToList();
    if (nonGhostOuts.Count != 1 || TypeSig(nonGhostOuts[0].Type) != "array<bv8>") {
      Error(tr.Tok, "Select must have exactly one non-ghost array<bv8> output formal");
      return;
    }
    var outBuffer = nonGhostOuts[0];
    var bound = AsVar(lhs);
    if (bound == null || !ReferenceEquals(bound, outBuffer)) {
      Error(lhs != null ? lhs.Tok : tr.Tok, "Select allocation result must be the sole non-ghost output formal by resolved identity");
      return;
    }
    selectAllocCount++;
    if (selectAllocCount > 1) {
      Error(tr.Tok, "Select must allocate its returned buffer exactly once");
      return;
    }
    int allocMarkerIndex = markerIndex;
    ExpectMarker("Alloc", m => {
      if (m.Args.Count != 2) return false;
      return TryInt(Unwrap(m.Args[0]), out var site) && site == 0 &&
             TryInt(Unwrap(m.Args[1]), out var size) && size == 32;
    }, tr.Tok, "exact Select allocation Alloc(0,32)");
    if (markerIndex == allocMarkerIndex + 1) {
      var allocMarker = markers[allocMarkerIndex];
      if (markerCtx.TryGetValue(allocMarker, out var allocCtx)) selectAllocCtx = allocCtx;
      selectAllocStmt = b.Body[idx];
    }
  }

  void VisitWrite(Expression lhs) {
    if (lhs is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null && !ReferenceEquals(cse.ResolvedExpression,lhs)) { VisitWrite(cse.ResolvedExpression); return; }
    if (lhs is SeqSelectExpr sel && sel.E0 != null && sel.E1 == null) {
      VisitExpr(sel.Seq); VisitExpr(sel.E0);
      ExpectMarker("Write", m => m.Args.Count==3 && MarkerRoleMatches(m,1,sel.Seq,out _) && ExprEq(m.Args[2],sel.E0), sel.Tok, "array write "+sel);
      return;
    }
    if (lhs is IdentifierExpr) return;
    if (lhs is MemberSelectExpr ms) {
      if (ms.Member is Field)
        Error(lhs.Tok, "unsupported executable class/global field write in reviewed static root grammar");
      return;
    }
    Error(lhs.Tok,"unsupported assignment LHS "+lhs.GetType().Name);
  }

  void VisitExpr(Expression e) {
    if (e == null) return;
    if (e is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null && !ReferenceEquals(cse.ResolvedExpression,e)) { VisitExpr(cse.ResolvedExpression); return; }
    if (e is AutoGhostIdentifierExpr || e is IdentifierExpr || e is NameSegment || e is LiteralExpr || e is ThisExpr || e is StaticReceiverExpr) return;
    if (e is ParensExpression p) { VisitExpr(p.E); return; }
    if (e is ConversionExpr c) { VisitExpr(c.E); return; }
    if (e is UnaryOpExpr u) { VisitExpr(u.E); return; }
    if (e is BinaryExpr b) {
      if (b.ResolvedOp==BinaryExpr.ResolvedOpcode.And || b.ResolvedOp==BinaryExpr.ResolvedOpcode.Or ||
          b.ResolvedOp==BinaryExpr.ResolvedOpcode.Imp || b.ResolvedOp==BinaryExpr.ResolvedOpcode.Iff) {
        Error(b.Tok,"unimplemented short-circuit/logical executable expression"); return;
      }
      VisitExpr(b.E0); VisitExpr(b.E1); return;
    }
    if (e is MemberSelectExpr ms) {
      if (ms.Member is Field fld) {
        var owner = fld.EnclosingClass?.EnclosingModuleDefinition?.Name;
        var ownerClass = fld.EnclosingClass?.Name;
        var objType = ms.Obj.Type.NormalizeExpand();
        bool builtinArrayLength = objType is UserDefinedType at && at.IsArrayType && fld.Name == "Length";
        bool tupleProjection = objType is UserDefinedType tt && tt.ResolvedClass is TupleTypeDecl;
        bool reviewedConstant = owner == "NativeField" && ownerClass == "_default" && fld.Name == "Q" && !fld.IsMutable;
        if (!builtinArrayLength && !tupleProjection && !reviewedConstant)
          Error(e.Tok, "unsupported executable class/global field use in reviewed static root grammar");
      }
      VisitExpr(ms.Obj);
      return;
    }
    if (e is SeqSelectExpr sel && sel.E0 != null && sel.E1 == null) {
      VisitExpr(sel.Seq); VisitExpr(sel.E0);
      ExpectMarker("Read", m => m.Args.Count==3 && MarkerRoleMatches(m,1,sel.Seq,out _) && ExprEq(m.Args[2],sel.E0), sel.Tok, "array read "+sel);
      return;
    }
    if (e is FunctionCallExpr fc) {
      if (fc.Function == null) { Error(fc.Tok,"unresolved executable function call"); return; }
      if (markerFuncs.Values.Contains(fc.Function)) { Error(fc.Tok,"marker function used in executable expression"); return; }
      var targetId = funcTargets.FirstOrDefault(kv=>ReferenceEquals(kv.Value,fc.Function)).Key;
      if (targetId == 0) { Error(fc.Tok,"unregistered executable function call "+fc.Function.FullName); return; }
      if (FindPureDefByExpr(fc) == null) {
        Error(fc.Tok,"registered pure call must be the direct RHS of one defining assignment");
        return;
      }
      foreach (var a in fc.Args) VisitExpr(a);
      ExpectMarker("Call", m => m.Args.Count==3 && TryInt(m.Args[1],out var id) && (int)id==targetId && TryInt(m.Args[2],out var ar) && ar==fc.Args.Count, fc.Tok, "function call "+fc.Function.Name+"/"+fc.Args.Count);
      return;
    }
    if (e is ITEExpr || e is MatchExpr || e is NestedMatchExpr || e is StmtExpr || e is LetExpr || e is LetOrFailExpr ||
        e is ApplySuffix || e is SeqUpdateExpr || e is SeqDisplayExpr || e is MultiSetDisplayExpr || e is MultiSetFormingExpr) {
      Error(e.Tok,"unsupported executable expression "+e.GetType().Name); return;
    }
    Error(e.Tok,"unsupported executable expression "+e.GetType().Name);
  }

  void ExpectMarker(string kind, Func<FunctionCallExpr,bool> pred, IOrigin tok, string what) {
    if (markerIndex >= markers.Count) { Error(tok,"missing "+kind+" observation for "+what); return; }
    var m = markers[markerIndex];
    if (m.Function != markerFuncs[kind]) { Error(m.Tok,"expected exact SourceTrace."+kind+" for "+what+", found "+MarkerName(m)); return; }
    if (!pred(m)) { Error(m.Tok,"mismatched "+kind+" observation for "+what); return; }
    if (!markerCtx.TryGetValue(m,out var ctx)) { Error(m.Tok,"marker has no source block context"); return; }
    if (!ReferenceEquals(ctx.block,curBlock)) { Error(m.Tok,"marker is outside the executable block of "+what); return; }
    if (kind=="Call") {
      if (ctx.index <= curIdx || HasExecutableBetween(curBlock,curIdx+1,ctx.index)) { Error(m.Tok,"Call marker is not the next observation after its call"); return; }
    } else {
      if (ctx.index >= curIdx) { Error(m.Tok,kind+" marker is not adjacent-before its executable operation"); return; }
      if (HasExecutableBetween(curBlock,ctx.index+1,curIdx)) {
        // The reviewed Select trace places the exact Alloc(0,32) and the next
        // loop's public LoopBound markers in one ghost assignment before the
        // allocation.  Permit that gap only for the exact validated allocation
        // statement in that same marker assignment; this is not a general
        // "contains TypeRhs" allowance.
        bool exactSelectAllocGap = kind == "LoopBound" && selectAllocCtx.HasValue && selectAllocStmt != null &&
          ReferenceEquals(ctx.block, selectAllocCtx.Value.block) && ctx.index == selectAllocCtx.Value.index &&
          ExactAllocOnlyBetween(curBlock, ctx.index + 1, curIdx);
        if (!exactSelectAllocGap) { Error(m.Tok,kind+" marker is not adjacent-before its executable operation"); return; }
      }
    }
    markerIndex++;
  }

  bool ExactAllocOnlyBetween(BlockStmt b, int lo, int hi) {
    for (int i = lo; i < hi; i++) {
      var s = b.Body[i];
      if (s.IsGhost) continue;
      if (selectAllocStmt == null || !ReferenceEquals(s, selectAllocStmt)) return false;
    }
    return true;
  }

  static bool HasExecutableBetween(BlockStmt b, int lo, int hi) {
    for (int i=lo;i<hi;i++) if (!b.Body[i].IsGhost) return true;
    return false;
  }

  void Advance() { markerIndex++; }

  (int,int,int,int,int,int,int) CountOps(Statement root, bool unused) {
    var seen = new HashSet<Expression>(ReferenceEqualityComparer.Instance);
    int add=0,sub=0,mul=0,div=0,mod=0,bit=0,shift=0;
    foreach (var st in root.DescendantsAndSelf) {
      if (st.IsGhost) continue;
      foreach (var e0 in st.SubExpressions) foreach (var e in e0.DescendantsAndSelf) if (seen.Add(e) && e is BinaryExpr b) {
        switch (b.ResolvedOp) {
          case BinaryExpr.ResolvedOpcode.Add: add++; break;
          case BinaryExpr.ResolvedOpcode.Sub: sub++; break;
          case BinaryExpr.ResolvedOpcode.Mul: mul++; break;
          case BinaryExpr.ResolvedOpcode.Div: div++; break;
          case BinaryExpr.ResolvedOpcode.Mod: mod++; break;
          case BinaryExpr.ResolvedOpcode.LeftShift: case BinaryExpr.ResolvedOpcode.RightShift: shift++; break;
          case BinaryExpr.ResolvedOpcode.BitwiseAnd: case BinaryExpr.ResolvedOpcode.BitwiseOr: case BinaryExpr.ResolvedOpcode.BitwiseXor: bit++; break;
        }
      }
    }
    return (add,sub,mul,div,mod,bit,shift);
  }

  static string CallName(Expression e) {
    e=Unwrap(e);
    if (e is FunctionCallExpr fc && fc.Function != null) return fc.Function.Name;
    if (e is ApplySuffix ap) {
      var lhs=Unwrap(ap.Lhs);
      if (lhs is NameSegment ns) return ns.Name;
      if (lhs is MemberSelectExpr ms) return ms.MemberName;
    }
    return null;
  }

  static Expression Unwrap(Expression e) {
    while (e is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null && !ReferenceEquals(cse.ResolvedExpression,e)) e=cse.ResolvedExpression;
    return e;
  }

  static IVariable AsVar(Expression e) {
    while (e is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null && !ReferenceEquals(cse.ResolvedExpression,e)) e=cse.ResolvedExpression;
    if (e is IdentifierExpr ie) return ie.Var;
    if (e is AutoGhostIdentifierExpr ag) return ag.Var;
    return null;
  }

  static bool TryInt(Expression e, out BigInteger v) {
    if (e is LiteralExpr le && le.Value is BigInteger bi) { v=bi; return true; }
    if (e is LiteralExpr le2 && le2.Value is int i) { v=i; return true; }
    v=0; return false;
  }

  static bool ArgsEq(IEnumerable<Expression> a, IEnumerable<Expression> b) {
    var aa = a.ToList(); var bb = b.ToList();
    if (aa.Count != bb.Count) return false;
    for (int i = 0; i < aa.Count; i++) if (!ExprEq(aa[i], bb[i])) return false;
    return true;
  }

  // Structural equality of the resolved expression shape used by markers.
  // This is deliberately small and fail-closed; it never uses ToString().
  static bool ExprEq(Expression a, Expression b) {
    if (a==null || b==null) return false;
    if (a is ParensExpression pa) return ExprEq(pa.E,b);
    if (b is ParensExpression pb) return ExprEq(a,pb.E);
    if (a is ConcreteSyntaxExpression wa && wa.ResolvedExpression != null && !ReferenceEquals(wa.ResolvedExpression,a)) return ExprEq(wa.ResolvedExpression,b);
    if (b is ConcreteSyntaxExpression wb && wb.ResolvedExpression != null && !ReferenceEquals(wb.ResolvedExpression,b)) return ExprEq(a,wb.ResolvedExpression);
    if (a is ConversionExpr cva) return ExprEq(cva.E,b);
    if (b is ConversionExpr cvb) return ExprEq(a,cvb.E);
    var va=AsVar(a); var vb=AsVar(b);
    if (va!=null || vb!=null) return va!=null && vb!=null && ReferenceEquals(va,vb);
    if (a is LiteralExpr la && b is LiteralExpr lb) return Equals(la.Value,lb.Value);
    if (a is MemberSelectExpr ma && b is MemberSelectExpr mb) return ReferenceEquals(ma.Member,mb.Member) && ExprEq(ma.Obj,mb.Obj);
    if (a is BinaryExpr ba && b is BinaryExpr bb) return ba.ResolvedOp==bb.ResolvedOp && ExprEq(ba.E0,bb.E0) && ExprEq(ba.E1,bb.E1);
    if (a is UnaryOpExpr ua && b is UnaryOpExpr ub) return ua.ResolvedOp==ub.ResolvedOp && ExprEq(ua.E,ub.E);
    if (a is ConversionExpr ca && b is ConversionExpr cb) return ExprEq(ca.E,cb.E);
    if (a is SeqSelectExpr sa && b is SeqSelectExpr sb) return sa.E0!=null && sb.E0!=null && ExprEq(sa.Seq,sb.Seq) && ExprEq(sa.E0,sb.E0);
    return false;
  }
}
