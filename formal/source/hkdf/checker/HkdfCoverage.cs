using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Dafny;
using Microsoft.Dafny.Plugins;

// Trusted, small source-coverage checker for the four verified HKDF methods.
// It runs in PostResolve over Dafny's official resolved AST.  It is NOT a
// formal theorem and NOT a second executable semantics.
//
// The checker is deliberately fail-closed:
//   * exact resolved function/method/constructor identity, never basenames;
//   * the actual ghost out formal `trace` is bound by identity; local shadows,
//     resets, helper-generated traces and conditional trace construction are
//     rejected;
//   * the trace is initialized once with [] at entry and every later update is
//     an append to the same immutable left prefix of approved marker calls or
//     exact ghost callee outputs;
//   * every executable event is matched to observations in the executable block
//     immediately before it; marker/path placement is dynamic, not a static bag;
//   * unsupported statements/expressions (expect, print, tuple patterns with
//     executable RHS, shadow marker functions, unknown calls, ...) fail closed;
//   * loops record start, per-iteration guard, increment and post-loop false
//     guard; the Dafny loop proof establishes the exit value.
public class HkdfCoverageConfiguration : PluginConfiguration {
  public override Rewriter[] GetRewriters(ErrorReporter reporter) =>
    new Rewriter[] { new HkdfCoverageRewriter(reporter) };
}

public class HkdfCoverageRewriter : Rewriter {
  readonly ErrorReporter reporter;
  static readonly string[] rootNames = { "Extract", "Expand", "LabelInfo", "ExpandLabel" };
  static readonly Dictionary<string,int> markerArity = new() {
    {"EvBranch",2},{"EvLoop",3},{"EvRead",2},{"EvCall",3},{"EvMac",6},
    {"EvAlloc",2},{"EvConcat",3},{"EvSlice",4},{"EvCreate",3},{"EvOps",7},
    {"EvWrite",2},{"EvLoopExit",3}
  };
  readonly Dictionary<string,Function> markerFuncs = new();
  readonly Dictionary<int,string> targetById = new() {
    {1,"VerifiedHkdf._default.Mac"},
    {2,"VerifiedHkdf._default.ValidHash"},
    {3,"VerifiedHkdf._default.LabelInfo"},
    {4,"VerifiedHkdf._default.Expand"},
    {10,"VerifiedHkdf.BytesResult.Success"},
    {11,"VerifiedHkdf.BytesResult.Failure"},
    {20,"VerifiedHkdf.FailureKind.InvalidHash"},
    {21,"VerifiedHkdf.FailureKind.InvalidLength"},
    {22,"VerifiedHkdf.FailureKind.InvalidKey"},
    {23,"VerifiedHkdf.FailureKind.InvalidLabel"},
  };
  IOrigin fallbackTok;
  Formal traceFormal;
  List<Statement> curBody;
  int curIndex = -1;
  sealed class GhostCallCtx {
    public CallStmt Call;
    public List<Statement> Body;
  }
  readonly HashSet<(string name,long pos)> ghostCallKeys = new();
  readonly Dictionary<(string name,long pos),int> ghostCallAppendCount = new();
  readonly Dictionary<(string name,long pos),GhostCallCtx> ghostCallCtx = new();
  readonly Dictionary<SingleAssignStmt,List<Statement>> traceAssignBody = new(ReferenceEqualityComparer.Instance);
  readonly HashSet<FunctionCallExpr> validatedMarkers = new(ReferenceEqualityComparer.Instance);
  readonly HashSet<SingleAssignStmt> actualTraceAssigns = new(ReferenceEqualityComparer.Instance);

  sealed class Mark {
    public string Name;
    public List<Expression> Args;
    public IOrigin Tok;
  }

  public HkdfCoverageRewriter(ErrorReporter reporter) : base(reporter) { this.reporter = reporter; }

  public override void PostResolve(Program program) {
    fallbackTok = program.Modules().SelectMany(m => m.TopLevelDecls).FirstOrDefault()?.Tok;
    var roots = new Dictionary<string,Method>();
    var hkdfModule = program.Modules().FirstOrDefault(m => m.Name == "VerifiedHkdf" && m.FullName == "VerifiedHkdf");
    var defaultClass = hkdfModule?.TopLevelDecls.OfType<TopLevelDeclWithMembers>()
      .FirstOrDefault(td => td is DefaultClassDecl || td.Name == "_default");
    if (hkdfModule == null || defaultClass == null) {
      Error(fallbackTok, "missing exact module VerifiedHkdf._default");
      return;
    }
    // Reserved root/marker names may not be shadowed anywhere in the program,
    // including classes, nested types, ghost methods/lemmas and duplicates.
    foreach (var m in program.Modules())
      foreach (var td in m.TopLevelDecls.OfType<TopLevelDeclWithMembers>())
        foreach (var fn in td.Members.OfType<Function>()) {
          if (fn.ByMethodDecl != null || fn.ByMethodBody != null)
            Error(fn.Tok, "unsupported by-method function in owned HKDF source: " + fn.FullName);
          if (markerArity.ContainsKey(fn.Name)) {
            bool exact = ReferenceEquals(m, hkdfModule) && ReferenceEquals(td, defaultClass) &&
              fn.FullName == "VerifiedHkdf._default." + fn.Name &&
              fn.IsGhost && fn.Ins.Count == markerArity[fn.Name];
            if (!exact) {
              Error(fn.Tok, "reserved marker name outside exact VerifiedHkdf._default ghost declaration: " + fn.FullName);
              continue;
            }
            if (markerFuncs.ContainsKey(fn.Name))
              Error(fn.Tok, "duplicate exact HKDF marker declaration: " + fn.FullName);
            else markerFuncs[fn.Name] = fn;
          }
        }
    foreach (var m in program.Modules())
      foreach (var td in m.TopLevelDecls.OfType<TopLevelDeclWithMembers>())
        foreach (var mem in td.Members.OfType<Method>()) {
          if (mem.IsByMethod)
            Error(mem.Tok, "unsupported by-method implementation in owned HKDF source: " + mem.FullName);
          if (rootNames.Contains(mem.Name)) {
            bool exact = ReferenceEquals(m, hkdfModule) && ReferenceEquals(td, defaultClass) &&
              mem.FullName == "VerifiedHkdf._default." + mem.Name &&
              !mem.IsGhost && !mem.IsLemmaLike;
            if (!exact) {
              Error(mem.Tok, "reserved root name outside exact VerifiedHkdf._default method: " + mem.FullName);
              continue;
            }
            if (roots.ContainsKey(mem.Name))
              Error(mem.Tok, "duplicate exact HKDF root method: " + mem.FullName);
            else roots[mem.Name] = mem;
          }
        }
    foreach (var name in markerArity.Keys)
      if (!markerFuncs.ContainsKey(name))
        Error(fallbackTok, "missing exact HKDF marker function VerifiedHkdf." + name);
    foreach (var name in rootNames) {
      if (!roots.TryGetValue(name, out var method)) {
        Error(fallbackTok, "missing required HKDF source-trace root VerifiedHkdf." + name);
        continue;
      }
      CheckRoot(method);
    }
    if (!reporter.HasErrors) {
      PrintInventory(program);
      Console.WriteLine("HKDF-SOURCE-COVERAGE OK: VerifiedHkdf.Extract/Expand/LabelInfo/ExpandLabel");
    }
  }

  void PrintInventory(Program program) {
    var lines = new List<string>();
    foreach (var m in program.Modules())
      if (m.Name == "VerifiedHkdf" || m.FullName == "VerifiedHkdf")
        foreach (var td in m.TopLevelDecls) {
          if (td is DatatypeDecl dt) {
            var ctors = string.Join(",", dt.Ctors.Select(c => c.Name));
            lines.Add("HKDF-DECL VerifiedHkdf datatype " + dt.Name + " ctors=" + ctors);
            continue;
          }
          if (td is TopLevelDeclWithMembers tw)
            foreach (var mem in tw.Members) {
              if (mem is Method meth) {
                var ghost = meth.Outs.Count(o => o.IsGhost);
                var kind = meth.IsLemmaLike ? "lemma" : "method";
                lines.Add("HKDF-DECL VerifiedHkdf " + kind + " " + td.Name + "." + meth.Name +
                          " ins=" + meth.Ins.Count + " outs=" + meth.Outs.Count + " ghostouts=" + ghost);
              } else if (mem is Function fn) {
                lines.Add("HKDF-DECL VerifiedHkdf function " + td.Name + "." + fn.Name + " ins=" + fn.Ins.Count);
              }
            }
        }
    foreach (var line in lines.OrderBy(x => x, StringComparer.Ordinal))
      Console.WriteLine(line);
  }

  void Error(IOrigin tok, string message) => reporter.Error(MessageSource.Rewriter, tok, message);
  static long Pos(Statement s) => s.Tok?.StartToken?.pos ?? long.MinValue;

  // ------------------------------------------------------------------
  // Resolved identities
  // ------------------------------------------------------------------
  static (string name,long pos) GhostKey(IVariable v) =>
    v == null ? (null, long.MinValue) : (v.Name, v.Tok?.StartToken?.pos ?? long.MinValue);

  IVariable ResolvedVariable(Expression e) {
    e = Unwrap(e);
    if (e is IdentifierExpr id) return id.Var;
    if (e is AutoGhostIdentifierExpr ag) return ag.Var;
    if (e is NameSegment ns && ns.SubExpressions.Count() == 1)
      return ResolvedVariable(ns.SubExpressions.First());
    return null;
  }

  static bool IsScalarType(Microsoft.Dafny.Type t) => t is BoolType || t is IntType || t is BitvectorType;

  bool IsActualTraceLhs(Expression e) => ReferenceEquals(ResolvedVariable(e), traceFormal);

  bool IsTraceNamedLhs(Expression e) {
    var v = ResolvedVariable(e);
    return v != null && v.Name == "trace" && !ReferenceEquals(v, traceFormal);
  }

  bool IsMarker(FunctionCallExpr fc) => fc.Function != null && markerFuncs.Values.Contains(fc.Function);

  string MarkerName(FunctionCallExpr fc) =>
    markerFuncs.FirstOrDefault(kv => ReferenceEquals(kv.Value, fc.Function)).Key;

  bool HasUnexpectedMarker(Statement s) =>
    s.DescendantsAndSelf.OfType<FunctionCallExpr>()
      .Any(fc => markerArity.ContainsKey(fc.Name) && !validatedMarkers.Contains(fc));

  bool TraceShadowIn(Statement s, out IOrigin tok) {
    tok = null;
    foreach (var vd in s.DescendantsAndSelf.OfType<VarDeclStmt>())
      foreach (var lv in vd.Locals)
        if (lv.Name == "trace" && !ReferenceEquals(lv, traceFormal)) { tok = vd.Tok; return true; }
    foreach (var vp in s.DescendantsAndSelf.OfType<VarDeclPattern>())
      foreach (var lv in vp.LocalVars)
        if (lv.Name == "trace" && !ReferenceEquals(lv, traceFormal)) { tok = vp.Tok; return true; }
    foreach (var sa in s.DescendantsAndSelf.OfType<SingleAssignStmt>())
      if (IsTraceNamedLhs(sa.Lhs)) { tok = sa.Tok; return true; }
    foreach (var asg in s.DescendantsAndSelf.OfType<AssignStatement>())
      foreach (var lhs in asg.Lhss)
        if (IsTraceNamedLhs(lhs)) { tok = asg.Tok; return true; }
    return false;
  }

  // ------------------------------------------------------------------
  // Trace construction: one [] initialization, append-only afterwards.
  // ------------------------------------------------------------------
  void CollectGhostCallsInStatements(List<Statement> body, Method m) {
    foreach (var s in body) {
      if (s.IsGhost) continue;
      if (s is IfStmt iff) {
        CollectGhostCallsInStatements(iff.Thn.Body, m);
        if (iff.Els is BlockStmt eb) CollectGhostCallsInStatements(eb.Body, m);
        else if (iff.Els != null) CollectGhostCallsInStatements(new List<Statement>{ iff.Els }, m);
        continue;
      }
      if (s is WhileStmt wh) { CollectGhostCallsInStatements(wh.Body.Body, m); continue; }
      if (s is ForLoopStmt fl) { CollectGhostCallsInStatements(fl.Body.Body, m); continue; }
      if (s is BlockStmt bb) { CollectGhostCallsInStatements(bb.Body, m); continue; }
      if (s is NestedMatchStmt nm) {
        foreach (var c in nm.Cases) CollectGhostCallsInStatements(c.Body, m);
        continue;
      }
      if (s is MatchStmt) continue;
      foreach (var cs in s.DescendantsAndSelf.OfType<CallStmt>()) {
        if (cs.Method == null || cs.Method.IsLemmaLike) continue;
        for (int i = 0; i < cs.Method.Outs.Count && i < cs.Lhs.Count; i++) {
          if (!cs.Method.Outs[i].IsGhost) continue;
          var v = ResolvedVariable(cs.Lhs[i]);
          if (v is LocalVariable lv && lv.IsGhost) {
            var key = GhostKey(lv);
            if (ghostCallKeys.Contains(key)) {
              Error(cs.Tok, "duplicate callee ghost output binding for local " + lv.Name);
              continue;
            }
            ghostCallKeys.Add(key);
            ghostCallCtx[key] = new GhostCallCtx { Call = cs, Body = body };
          }
        }
      }
    }
  }

  void CollectGhostCallVars(Method m) {
    ghostCallKeys.Clear(); ghostCallAppendCount.Clear(); ghostCallCtx.Clear();
    CollectGhostCallsInStatements(m.Body.Body, m);
    foreach (var key in ghostCallKeys) ghostCallAppendCount[key] = 0;
    foreach (var sa in m.Body.DescendantsAndSelf.OfType<SingleAssignStmt>())
      if (ghostCallKeys.Contains(GhostKey(ResolvedVariable(sa.Lhs))))
        Error(sa.Tok, "ghost callee trace output is assigned outside its defining call");
    foreach (var asg in m.Body.DescendantsAndSelf.OfType<AssignStatement>())
      if (!asg.DescendantsAndSelf.OfType<CallStmt>().Any())
        foreach (var lhs in asg.Lhss)
          if (ghostCallKeys.Contains(GhostKey(ResolvedVariable(lhs))))
            Error(asg.Tok, "ghost callee trace output is assigned outside its defining call");
  }

  void CollectTraceInBlock(BlockStmt b, List<SingleAssignStmt> list) {
    if (b != null) CollectTraceInStatements(b.Body, list);
  }

  void CollectTraceInStatements(List<Statement> body, List<SingleAssignStmt> list) {
    foreach (var s in body) {
      if (s.IsGhost) {
        if (s is IfStmt || s is WhileStmt || s is ForLoopStmt || s is ForallStmt ||
            s is BlockStmt || s is AlternativeLoopStmt || s is NestedMatchStmt || s is MatchStmt) {
          if (s.DescendantsAndSelf.OfType<SingleAssignStmt>().Any(a => IsActualTraceLhs(a.Lhs)))
            Error(s.Tok, "trace assignment inside ghost control flow is not executable");
          continue;
        }
        foreach (var sa in s.DescendantsAndSelf.OfType<SingleAssignStmt>())
          if (IsActualTraceLhs(sa.Lhs)) { list.Add(sa); traceAssignBody[sa] = body; }
        continue;
      }
      if (s is IfStmt iff) {
        CollectTraceInBlock(iff.Thn, list);
        if (iff.Els is BlockStmt eb) CollectTraceInBlock(eb, list);
        else if (iff.Els != null) CollectTraceInStatements(new List<Statement>{ iff.Els }, list);
      } else if (s is WhileStmt wh) {
        CollectTraceInBlock(wh.Body, list);
      } else if (s is ForLoopStmt fl) {
        CollectTraceInBlock(fl.Body, list);
      } else if (s is BlockStmt bb) {
        CollectTraceInBlock(bb, list);
      } else if (s is NestedMatchStmt nm) {
        foreach (var c in nm.Cases) CollectTraceInStatements(c.Body, list);
      }
    }
  }

  static IEnumerable<Expression> ConcatLeaves(Expression e) {
    e = UnwrapStatic(e);
    if (e is ParensExpression p) return ConcatLeaves(p.E);
    if (e is BinaryExpr b && b.ResolvedOp == BinaryExpr.ResolvedOpcode.Concat)
      return ConcatLeaves(b.E0).Concat(ConcatLeaves(b.E1));
    return new[] { e };
  }

  static Expression UnwrapStatic(Expression e) {
    while (true) {
      if (e is ParensExpression p) { e = p.E; continue; }
      if (e is ExprDotName d && d.ResolvedExpression != null) { e = d.ResolvedExpression; continue; }
      return e;
    }
  }

  static FunctionCallExpr AsMarkerCall(Expression e) {
    e = UnwrapStatic(e);
    if (e is FunctionCallExpr fc) return fc;
    if (e is ApplySuffix ap) {
      if (ap.Lhs is FunctionCallExpr f) return f;
      if (ap.Lhs is ConcreteSyntaxExpression cse && cse.ResolvedExpression is FunctionCallExpr lf) return lf;
      return ap.DescendantsAndSelf.OfType<FunctionCallExpr>().FirstOrDefault();
    }
    return null;
  }

  void CollectTraceAssignments(Method m) {
    validatedMarkers.Clear(); actualTraceAssigns.Clear(); traceAssignBody.Clear();
    var assigns = new List<SingleAssignStmt>();
    CollectTraceInBlock(m.Body, assigns);
    assigns = assigns.OrderBy(Pos).ThenBy(sa => sa.Tok?.StartToken?.col ?? 0).ToList();
    if (assigns.Count == 0) { Error(m.Tok, m.Name + ": no assignment to the actual ghost trace"); return; }
    long firstExec = m.Body.DescendantsAndSelf.Where(s => !s.IsGhost && !(s is BlockStmt))
      .Select(Pos).DefaultIfEmpty(long.MaxValue).Min();
    bool initialized = false;
    foreach (var sa in assigns) {
      actualTraceAssigns.Add(sa);
      if (!sa.IsGhost) { Error(sa.Tok, m.Name + ": trace assignment is not ghost"); continue; }
      if (sa.Rhs is not ExprRhs er) { Error(sa.Tok, m.Name + ": trace RHS is not an expression"); continue; }
      var leaves = ConcatLeaves(er.Expr).ToList();
      if (!initialized) {
        if (Pos(sa) >= firstExec)
          Error(sa.Tok, m.Name + ": trace must be initialized before the first executable statement");
        if (leaves.Count != 1 || !(leaves[0] is SeqDisplayExpr sd && sd.Elements.Count == 0))
          Error(sa.Tok, m.Name + ": first trace assignment must be exactly trace := []");
        initialized = true;
        continue;
      }
      if (leaves.Count == 0 || !ReferenceEquals(ResolvedVariable(leaves[0]), traceFormal)) {
        Error(sa.Tok, m.Name + ": later trace update must append to the same actual trace prefix");
        continue;
      }
      if (leaves.Count == 1) { Error(sa.Tok, m.Name + ": trace append has no suffix"); continue; }
      for (int i = 1; i < leaves.Count; i++) {
        var leaf = leaves[i];
        var markerCall = AsMarkerCall(leaf);
        if (markerCall != null && IsMarker(markerCall)) {
          var name = MarkerName(markerCall);
          if (markerCall.Args.Count != markerArity[name])
            Error(markerCall.Tok, m.Name + ": marker " + name + " has wrong arity");
          validatedMarkers.Add(markerCall);
          continue;
        }
        var v = ResolvedVariable(leaf);
        var key = GhostKey(v);
        if (v != null && ghostCallKeys.Contains(key)) {
          var ctx = ghostCallCtx[key];
          long callPos = Pos(ctx.Call);
          if (!ctx.Call.Lhs.Any(l => GhostKey(ResolvedVariable(l)) == key))
            Error(leaf.Tok, m.Name + ": callee ghost trace output is not the exact call LHS binding");
          if (callPos >= Pos(sa))
            Error(leaf.Tok, m.Name + ": callee ghost trace appended before its defining call");
          if (!traceAssignBody.TryGetValue(sa, out var appendBody) || !ReferenceEquals(appendBody, ctx.Body))
            Error(leaf.Tok, m.Name + ": callee ghost trace append is not in the call's lexical block");
          if (assigns.Any(other => !ReferenceEquals(other, sa) && Pos(other) > callPos && Pos(other) < Pos(sa)))
            Error(leaf.Tok, m.Name + ": callee ghost trace append is not the first trace update after its call");
          var nextExec = ctx.Body.Where(st => !st.IsGhost && Pos(st) > callPos).OrderBy(Pos).FirstOrDefault();
          if (nextExec != null && Pos(sa) >= Pos(nextExec))
            Error(leaf.Tok, m.Name + ": callee ghost trace append occurs after a following executable statement");
          ghostCallAppendCount[key] = ghostCallAppendCount.TryGetValue(key, out var c) ? c + 1 : 1;
          continue;
        }
        var full = markerCall?.Function?.FullName ?? leaf.GetType().Name;
        Error(leaf.Tok, m.Name + ": trace append contains non-approved suffix " + full);
      }
    }
    if (!initialized) Error(m.Tok, m.Name + ": trace was never initialized with []");
    foreach (var key in ghostCallKeys)
      if (!ghostCallAppendCount.TryGetValue(key, out var c) || c != 1)
        Error(m.Tok, m.Name + ": callee ghost trace output " + key.name + " must be appended exactly once");
    // A marker call must only occur in a validated trace append.
    foreach (var s in m.Body.DescendantsAndSelf)
      foreach (var fc in s.DescendantsAndSelf.OfType<FunctionCallExpr>())
        if (markerArity.ContainsKey(fc.Name) && !validatedMarkers.Contains(fc))
          Error(fc.Tok, m.Name + ": marker call is not in a validated trace append");
    CheckSiteLabels(m);
  }

  void CheckSiteLabels(Method m) {
    var seen = new Dictionary<int,FunctionCallExpr>();
    foreach (var fc in validatedMarkers) {
      var name = MarkerName(fc);
      if (name == "EvOps") continue; // Ops counts have no site-label field.
      if (fc.Args.Count == 0 || !(Unwrap(fc.Args[0]) is LiteralExpr)) {
        Error(fc.Tok, m.Name + ": site label must be an integer literal");
        continue;
      }
      if (!TryInt(fc.Args[0], out var id)) continue; // range error already reported
      if (id < 0) {
        Error(fc.Tok, m.Name + ": site label must be non-negative");
        continue;
      }
      if (seen.ContainsKey(id))
        Error(fc.Tok, m.Name + ": duplicate site label " + id + " within root");
      else seen[id] = fc;
    }
  }

  // ------------------------------------------------------------------
  // Root / block traversal
  // ------------------------------------------------------------------
  sealed class LoopCtx {
    public WhileStmt Loop;
    public LoopCtx Parent;
    public bool FirstStatementPending = true;
  }

  void CheckRoot(Method m) {
    traceFormal = m.Outs.OfType<Formal>().FirstOrDefault(o => o.IsGhost && o.Name == "trace");
    if (traceFormal == null) { Error(m.Tok, m.Name + ": missing exact ghost out formal trace"); return; }
    if (m.Body == null) { Error(m.Tok, m.Name + ": missing executable body"); return; }
    CheckBindingGrammar(m);
    CollectGhostCallVars(m);
    CollectTraceAssignments(m);
    CheckBlock(m.Body.Body, null, m);
  }

  // Ghost code is part of the coverage boundary too. Ignoring an unfamiliar
  // statement can miss a write to a previously checked callee output (for
  // example `encTrace :| encTrace == []`). Check every resolved descendant,
  // including proof/ghost blocks, against an exact, positive grammar before
  // the event walk. New AST subclasses require review rather than inheriting
  // acceptance from a base class or an assignment-descendant heuristic.
  static readonly HashSet<System.Type> bindingStatementTypes = new() {
    typeof(BlockStmt), typeof(IfStmt), typeof(WhileStmt), typeof(NestedMatchStmt),
    typeof(ReturnStmt), typeof(VarDeclPattern), typeof(VarDeclStmt),
    typeof(AssignStatement), typeof(SingleAssignStmt), typeof(CallStmt),
    typeof(AssertStmt)
  };

  // Statement.DescendantsAndSelf and Expression.DescendantsAndSelf each stay
  // within their respective node kind. Traverse official Node.Children instead
  // so a statement expression cannot hide a proof statement from this scan.
  static IEnumerable<INode> BindingNodes(INode root) {
    var seen = new HashSet<INode>(ReferenceEqualityComparer.Instance);
    var pending = new Stack<INode>();
    pending.Push(root);
    while (pending.Count > 0) {
      var node = pending.Pop();
      if (!seen.Add(node)) continue;
      yield return node;
      foreach (var child in node.Children) pending.Push(child);
    }
  }

  void CheckBindingGrammar(Method m) {
    var nodes = BindingNodes(m.Body).ToList();
    foreach (var s in nodes.OfType<Statement>()) {
      if (!bindingStatementTypes.Contains(s.GetType()))
        Error(s.Tok, "unsupported " + (s.IsGhost ? "ghost" : "executable") +
          " statement " + s.GetType().Name + " in HKDF binding grammar");
      if (s is CallStmt call) {
        // Lemma/ghost-method outs are another assignment form. They cannot
        // substitute a model trace for a real callee's returned observation.
        if ((call.IsGhost || call.Method?.IsGhost == true || call.Method?.IsLemmaLike == true) && call.Lhs.Count != 0)
          Error(call.Tok, "ghost call output binding is unsupported in HKDF binding grammar");
        if (call.Lhs.Any(IsActualTraceLhs))
          Error(call.Tok, "actual trace output cannot be rebound by a call");
      }
    }
    // Statement expressions can contain proof statements outside the ordinary
    // executable block walk. This component has no need for them; fail closed.
    foreach (var e in nodes.OfType<StmtExpr>())
      Error(e.Tok, "unsupported statement expression in HKDF binding grammar");
  }

  List<Mark> MarkersIn(Statement s) {
    var outList = new List<Mark>();
    foreach (var sa in s.DescendantsAndSelf.OfType<SingleAssignStmt>().Where(a => actualTraceAssigns.Contains(a))) {
      if (sa.Rhs is not ExprRhs er) continue;
      foreach (var leaf in ConcatLeaves(er.Expr)) {
        var fc = AsMarkerCall(leaf);
        if (fc != null && validatedMarkers.Contains(fc))
          outList.Add(new Mark { Name = MarkerName(fc), Args = fc.Args, Tok = fc.Tok });
      }
    }
    return outList;
  }

  bool IsDirectTraceAssignment(Statement s) =>
    s.DescendantsAndSelf.OfType<SingleAssignStmt>().Any(a => actualTraceAssigns.Contains(a) && IsActualTraceLhs(a.Lhs));

  void CheckBlock(List<Statement> body, LoopCtx loop, Method method) {
    var pending = new List<Mark>();
    WhileStmt exitPending = null;
    for (int idx = 0; idx < body.Count; idx++) {
      var s = body[idx];
      if (s.IsGhost) {
        if (TraceShadowIn(s, out var shadowTok))
          Error(shadowTok, "local/shadow trace variable is not the actual ghost out formal");
        var marks = MarkersIn(s);
        if (marks.Count > 0) {
          if (!IsDirectTraceAssignment(s))
            Error(s.Tok, "marker inside ghost control flow is not an executable observation");
          else pending.AddRange(marks);
        } else if (HasUnexpectedMarker(s)) {
          Error(s.Tok, "marker appears outside a validated trace append");
        }
        continue;
      }
      if (s is BlockStmt b) {
        if (exitPending != null) {
          var exit = pending.FirstOrDefault(x => x.Name == "EvLoopExit");
          if (exit == null) Error(exitPending.Tok, "missing post-loop false-guard observation");
          else { CheckLoopExit(exit, exitPending); pending.Remove(exit); }
          exitPending = null;
        }
        if (pending.Count > 0)
          Error(s.Tok, "pending observations at standalone block boundary");
        CheckBlock(b.Body, loop, method);
        continue;
      }
      if (loop != null && loop.FirstStatementPending) {
        var iter = pending.FirstOrDefault(x => x.Name == "EvLoop");
        if (iter == null) Error(s.Tok, "loop body does not begin with its EvLoop iteration marker");
        else { CheckLoopIteration(iter, loop.Loop); pending.Remove(iter); }
        loop.FirstStatementPending = false;
      } else if (loop != null && pending.Any(x => x.Name == "EvLoop")) {
        Error(s.Tok, "EvLoop iteration marker is not at the loop body head");
      }
      if (exitPending != null) {
        var exit = pending.FirstOrDefault(x => x.Name == "EvLoopExit");
        if (exit == null) Error(s.Tok, "missing post-loop false-guard observation");
        else { CheckLoopExit(exit, exitPending); pending.Remove(exit); }
        exitPending = null;
      }
      curBody = body; curIndex = idx;
      CheckStatement(s, pending, loop, method);
      if (s is WhileStmt wh) exitPending = wh;
      pending.Clear();
    }
    if (exitPending != null) {
      var exit = pending.FirstOrDefault(x => x.Name == "EvLoopExit");
      if (exit == null) Error(exitPending.Tok, "missing post-loop false-guard observation");
      else { CheckLoopExit(exit, exitPending); pending.Remove(exit); }
    }
    if (pending.Count > 0) Error(pending[0].Tok, "stale observation block at end of scope");
  }

  void CheckStatement(Statement s, List<Mark> group, LoopCtx loop, Method method) {
    if (s is IfStmt iff) {
      var expected = new List<Ev>();
      AddGuardEvents(iff.Guard, expected, loop, method);
      Match(group, expected, s, "if guard");
      CheckBlock(iff.Thn.Body, loop, method);
      if (iff.Els is BlockStmt eb) CheckBlock(eb.Body, loop, method);
      else if (iff.Els != null) CheckStatement(iff.Els, new List<Mark>(), loop, method);
      return;
    }
    if (s is WhileStmt wh) {
      var (index, bound) = LoopGuardParts(wh.Guard);
      if (index == null || bound == null) { Error(wh.Tok, "unsupported while guard shape"); return; }
      var loopVar = ResolvedVariable(index);
      if (loopVar == null) { Error(wh.Tok, "loop guard variable is not resolved"); return; }
      var init = FindLoopInitializer(wh, loopVar);
      if (init == null) { Error(wh.Tok, "loop variable has no observed initializer before the loop"); return; }
      CheckLoopIncrement(wh, loopVar, index);
      var expected = new List<Ev>();
      AddLoopEntry(wh, expected, init);
      AddExpressionEvents(wh.Guard, expected, method, false);
      Match(group, expected, s, "while guard");
      CheckBlock(wh.Body.Body, new LoopCtx { Loop = wh, Parent = loop }, method);
      return;
    }
    if (s is ForLoopStmt fl) { Error(fl.Tok, "unsupported executable for-loop in HKDF trace root"); return; }
    if (s is NestedMatchStmt nm) { CheckMatch(nm, group, loop, method); return; }
    if (s is MatchStmt) { Error(s.Tok, "unsupported executable MatchStmt; expected NestedMatchStmt"); return; }
    if (s is ReturnStmt) {
      if (group.Count != 0) Error(s.Tok, "return has an unmatched observation block");
      return;
    }
    if (s is VarDeclPattern vp) {
      var events = new List<Ev>();
      if (vp.RHS != null) AddExpressionEvents(vp.RHS, events, method, false);
      Match(group, events, s, "pattern binding");
      return;
    }
    if (!(s is VarDeclStmt || s is AssignStatement || s is SingleAssignStmt || s is CallStmt)) {
      Error(s.Tok, "unsupported executable statement " + s.GetType().Name);
      return;
    }
    var simple = new List<Ev>();
    AddSimpleStatementEvents(s, simple, method);
    Match(group, simple, s, "statement");
  }

  void CheckMatch(NestedMatchStmt nm, List<Mark> group, LoopCtx loop, Method method) {
    var sourceEvents = new List<Ev>();
    AddExpressionEvents(nm.Source, sourceEvents, method, false);
    if (group.Count != sourceEvents.Count + 1) {
      Error(nm.Tok, "match requires source observations plus exactly one shape observation");
      return;
    }
    for (int i = 0; i < sourceEvents.Count; i++)
      if (!EventMatches(sourceEvents[i], group[i])) {
        Error(group[i].Tok, "match source observation does not match the executable source expression");
        return;
      }
    var branch = group[sourceEvents.Count];
    if (branch.Name != "EvBranch") { Error(branch.Tok, "match shape observation must be EvBranch"); return; }
    if (!IsShapeDiscriminator(branch.Args, nm.Source, out var why))
      Error(branch.Tok, "match branch is not a public discriminator of the match source: " + why);
    foreach (var c in nm.Cases) CheckBlock(c.Body, loop, method);
  }

  bool IsShapeDiscriminator(List<Expression> args, Expression source, out string why) {
    why = "";
    if (args.Count != 2) { why = "marker arity"; return false; }
    var e = Unwrap(args[1]);
    if (e is MemberSelectExpr ms) {
      if (ms.Member == null || !(ms.Member.Name == "Success?" || ms.Member.Name == "Failure?")) {
        why = "not a Success?/Failure? member"; return false;
      }
      if (!ExprEq(ms.Obj, source)) { why = "different match source"; return false; }
      return true;
    }
    why = "not a member discriminator"; return false;
  }

  // ------------------------------------------------------------------
  // Loops
  // ------------------------------------------------------------------
  (Expression index, Expression bound) LoopGuardParts(Expression guard) {
    guard = Unwrap(guard);
    if (guard is BinaryExpr b && (b.ResolvedOp == BinaryExpr.ResolvedOpcode.Lt ||
        b.ResolvedOp == BinaryExpr.ResolvedOpcode.Le)) return (b.E0, b.E1);
    return (null, null);
  }

  Expression FindLoopInitializer(WhileStmt wh, IVariable loopVar) {
    if (curBody == null || curIndex < 0) {
      Error(wh.Tok, "loop initializer is not an unconditional same-block definition");
      return null;
    }
    for (int i = curIndex - 1; i >= 0; i--) {
      var s = curBody[i];
      if (s.IsGhost) continue;
      if (s is IfStmt || s is WhileStmt || s is ForLoopStmt || s is AlternativeLoopStmt ||
          s is NestedMatchStmt || s is MatchStmt) {
        Error(s.Tok, "loop initializer is not an unconditional same-block definition");
        return null;
      }
      var writes = s.DescendantsAndSelf.OfType<SingleAssignStmt>()
        .Where(a => ReferenceEquals(ResolvedVariable(a.Lhs), loopVar)).ToList();
      if (writes.Count == 0) continue;
      if (writes.Count != 1 || !(s is VarDeclStmt || s is AssignStatement || s is SingleAssignStmt)) {
        Error(s.Tok, "loop initializer has an unsupported or ambiguous definition");
        return null;
      }
      var sa = writes[0];
      if (sa.Rhs is not ExprRhs er) {
        Error(sa.Tok, "loop initializer is not a simple expression definition");
        return null;
      }
      return er.Expr;
    }
    Error(wh.Tok, "loop initializer is not an unconditional same-block definition");
    return null;
  }

  void CheckLoopIncrement(WhileStmt wh, IVariable loopVar, Expression loopIndex) {
    var writes = wh.Body.DescendantsAndSelf.OfType<SingleAssignStmt>()
      .Where(sa => ReferenceEquals(ResolvedVariable(sa.Lhs), loopVar)).ToList();
    if (writes.Count != 1) {
      Error(wh.Tok, "loop variable must have exactly one executable increment in the body, found " + writes.Count);
      return;
    }
    var sa = writes[0];
    if (sa.Rhs is not ExprRhs er || er.Expr is not BinaryExpr b ||
        b.ResolvedOp != BinaryExpr.ResolvedOpcode.Add ||
        !ExprEq(b.E0, loopIndex) || !TryInt(b.E1, out var step) || step <= 0)
      Error(sa.Tok, "loop increment must be loopVar := loopVar + positiveLiteral");
  }

  void AddLoopEntry(WhileStmt wh, List<Ev> ev, Expression initializer) {
    var (_, bound) = LoopGuardParts(wh.Guard);
    if (bound == null) { Error(wh.Tok, "unsupported while guard shape"); return; }
    ev.Add(new Ev { Kind = "EvLoop", A = initializer, B = bound });
  }

  void CheckLoopIteration(Mark m, WhileStmt wh) {
    var (index, bound) = LoopGuardParts(wh.Guard);
    if (bound == null || index == null) { Error(wh.Tok, "unsupported while guard shape"); return; }
    if (m.Args.Count != 3) { Error(m.Tok, "EvLoop iteration arity"); return; }
    if (!ExprEq(m.Args[1], index)) Error(m.Tok, "EvLoop iteration index does not match the loop guard");
    if (!ExprEq(m.Args[2], bound)) Error(m.Tok, "EvLoop iteration bound does not match the loop guard");
  }

  void CheckLoopExit(Mark m, WhileStmt wh) {
    var (index, bound) = LoopGuardParts(wh.Guard);
    if (bound == null || index == null) { Error(wh.Tok, "unsupported while guard shape"); return; }
    if (m.Args.Count != 3) { Error(m.Tok, "EvLoopExit arity"); return; }
    if (!ExprEq(m.Args[1], index)) Error(m.Tok, "EvLoopExit index does not match the loop variable");
    if (!ExprEq(m.Args[2], bound)) Error(m.Tok, "EvLoopExit bound does not match the loop bound");
  }

  // ------------------------------------------------------------------
  // Events (post-order, exactly the marker order)
  // ------------------------------------------------------------------
  sealed class Ev {
    public string Kind;
    public string Target;
    public int Arity;
    public Expression A, B, C, D;
    public int IntA = int.MinValue;
    public bool UseIntA;
  }

  void AddGuardEvents(Expression guard, List<Ev> ev, LoopCtx loop, Method method) {
    guard = Unwrap(guard);
    if (guard is BinaryExpr b &&
        (b.ResolvedOp == BinaryExpr.ResolvedOpcode.And || b.ResolvedOp == BinaryExpr.ResolvedOpcode.Or)) {
      AddGuardEvents(b.E0, ev, loop, method);
      AddGuardEvents(b.E1, ev, loop, method);
      return;
    }
    AddExpressionEvents(guard, ev, method, true);
    ev.Add(new Ev { Kind = "EvBranch", A = guard });
  }

  void AddExpressionEvents(Expression e, List<Ev> ev, Method method, bool guardSubexpressions) {
    if (e == null) return;
    e = Unwrap(e);
    // Recursively inspect children first (post-order).
    foreach (var child in e.SubExpressions) AddExpressionEvents(child, ev, method, guardSubexpressions);
    if (e is IdentifierExpr || e is AutoGhostIdentifierExpr || e is NameSegment ||
        e is LiteralExpr || e is StaticReceiverExpr || e is ThisExpr || e is LambdaExpr ||
        e is ApplySuffix || e is MemberSelectExpr || e is ConversionExpr || e is UnaryOpExpr)
      return;
    if (e is BinaryExpr b) {
      if (b.ResolvedOp == BinaryExpr.ResolvedOpcode.EqCommon ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.NeqCommon ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Lt ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Le ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Gt ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Ge) {
        if (!IsScalarType(b.E0.Type) || !IsScalarType(b.E1.Type)) {
          Error(b.Tok, "unsupported executable equality/order on non-scalar operand type");
          return;
        }
      }
      if (b.ResolvedOp == BinaryExpr.ResolvedOpcode.SeqEq ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.SeqNeq ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Prefix ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.ProperPrefix ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.InSeq ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.NotInSeq ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.SetEq ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.SetNeq ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Disjoint ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.InSet ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.NotInSet ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.MultiSetEq ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.MultiSetNeq ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.MultiSetDisjoint ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.InMultiSet ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.NotInMultiSet ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.MapEq ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.MapNeq ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.InMap ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.NotInMap) {
        Error(b.Tok, "unsupported executable sequence/collection comparison operator");
        return;
      }
      if (b.ResolvedOp == BinaryExpr.ResolvedOpcode.Concat) {
        ev.Add(new Ev { Kind = "EvConcat", A = b.E0, B = b.E1 });
        return;
      }
      if (b.ResolvedOp == BinaryExpr.ResolvedOpcode.And || b.ResolvedOp == BinaryExpr.ResolvedOpcode.Or ||
          b.ResolvedOp == BinaryExpr.ResolvedOpcode.Imp || b.ResolvedOp == BinaryExpr.ResolvedOpcode.Iff) {
        if (!guardSubexpressions)
          Error(b.Tok, "unsupported executable short-circuit/logical expression");
        return;
      }
      return;
    }
    if (e is SeqSelectExpr sel && sel.SelectOne) {
      if (method != null) CheckReadSource(sel.Seq, method);
      ev.Add(new Ev { Kind = "EvRead", A = sel.E0 });
      return;
    }
    if (e is SeqSelectExpr slice && !slice.SelectOne) {
      if (slice.E0 != null || slice.E1 == null) { Error(slice.Tok, "unsupported executable slice shape"); return; }
      ev.Add(new Ev { Kind = "EvSlice", A = slice.Seq, B = null, C = slice.E1 });
      return;
    }
    if (e is SeqDisplayExpr sd) {
      ev.Add(new Ev { Kind = "EvAlloc", UseIntA = true, IntA = sd.Elements.Count });
      return;
    }
    if (e is SeqConstructionExpr sc) {
      ev.Add(new Ev { Kind = "EvAlloc", A = sc.N });
      return;
    }
    if (e is FunctionCallExpr fc) {
      if (fc.Function == null) { Error(fc.Tok, "unresolved function call"); return; }
      if (IsMarker(fc)) { Error(fc.Tok, "marker function used in an executable expression"); return; }
      var full = fc.Function.FullName;
      if (full == "VerifiedHkdf._default.Mac") {
        if (fc.Args.Count != 3) { Error(fc.Tok, "Mac arity changed"); return; }
        ev.Add(new Ev { Kind = "EvMac", Target = full, Arity = 3,
          A = fc.Args[0], B = fc.Args[1], C = fc.Args[2], D = null });
      } else if (full == "VerifiedHkdf._default.ValidHash") {
        ev.Add(new Ev { Kind = "EvCall", Target = full, Arity = fc.Args.Count });
      } else {
        Error(fc.Tok, "unobserved compiled function call " + full);
      }
      return;
    }
    if (e is DatatypeValue dv) {
      if (dv.Ctor == null) { Error(dv.Tok, "unresolved datatype constructor"); return; }
      var full = dv.Ctor.EnclosingDatatype.FullName + "." + dv.Ctor.Name;
      ev.Add(new Ev { Kind = "EvCreate", Target = full, Arity = dv.Arguments.Count,
        A = (full == "VerifiedHkdf.BytesResult.Success" && dv.Arguments.Count == 1) ? dv.Arguments[0] : null });
      return;
    }
    Error(e.Tok, "unsupported executable expression " + e.GetType().Name);
  }

  void AddSimpleStatementEvents(Statement s, List<Ev> ev, Method method) {
    var exprs = new List<Expression>();
    CollectAssignmentExpressions(s, exprs);
    foreach (var cs in s.DescendantsAndSelf.OfType<CallStmt>()) {
      if (cs.Method == null) { Error(cs.Tok, "unresolved method call"); continue; }
      if (cs.Method.IsLemmaLike) { Error(cs.Tok, "executable lemma call is not modeled"); continue; }
      CheckMethodSignature(cs);
      ev.Add(new Ev { Kind = "EvCall", Target = cs.Method.FullName, Arity = cs.Args.Count });
      if (cs.Receiver != null) exprs.Add(cs.Receiver);
      exprs.AddRange(cs.Args);
    }
    foreach (var e in exprs) AddExpressionEvents(e, ev, method, false);
  }

  void CheckMethodSignature(CallStmt cs) {
    if (cs.Method.Ins.Count != cs.Args.Count)
      Error(cs.Tok, "call argument count does not match the resolved method signature");
    if (cs.Method.FullName == "VerifiedHkdf._default.LabelInfo" ||
        cs.Method.FullName == "VerifiedHkdf._default.Expand") {
      var ghost = cs.Method.Outs.Where(o => o.IsGhost).ToList();
      if (ghost.Count != 1 || ghost[0].Name != "trace")
        Error(cs.Tok, "owned HKDF callee no longer has exactly one ghost trace out-parameter");
      if (cs.Lhs.Count != cs.Method.Outs.Count)
        Error(cs.Tok, "caller does not bind every actual and ghost output of the owned callee");
    }
  }

  void CollectAssignmentExpressions(Statement s, List<Expression> exprs) {
    if (s is VarDeclStmt vd) { if (vd.Assign != null) CollectAssignmentExpressions(vd.Assign, exprs); return; }
    if (s is AssignStatement asg) { foreach (var rhs in asg.Rhss) CollectRhs(rhs, exprs); return; }
    if (s is SingleAssignStmt sa) { CollectRhs(sa.Rhs, exprs); return; }
    if (s is CallStmt) {
      // Call arguments are added once by AddSimpleStatementEvents' CallStmt loop.
      return;
    }
    Error(s.Tok, "unsupported executable assignment statement " + s.GetType().Name);
  }

  void CollectRhs(AssignmentRhs rhs, List<Expression> exprs) {
    if (rhs is ExprRhs er) { exprs.Add(er.Expr); return; }
    if (rhs is TypeRhs) { Error(rhs.Tok, "unsupported executable allocation"); return; }
    Error(rhs.Tok, "unsupported assignment RHS " + rhs.GetType().Name);
  }

  void CheckReadSource(Expression seq, Method method) {
    seq = Unwrap(seq);
    IVariable v = ResolvedVariable(seq);
    if (v == null || v.Name != "labelUnits" || !method.Ins.Contains(v))
      Error(seq.Tok, "sequence read source is not the method's formal labelUnits");
  }

  // ------------------------------------------------------------------
  // Ordered matching
  // ------------------------------------------------------------------
  void Match(List<Mark> markers, List<Ev> events, Statement s, string where) {
    if (markers.Count != events.Count) {
      Error(s.Tok, where + ": observation count " + markers.Count + " != executable event count " + events.Count);
      foreach (var m in markers) Error(m.Tok, where + ": unmatched marker " + m.Name);
      return;
    }
    for (int i = 0; i < events.Count; i++)
      if (!EventMatches(events[i], markers[i])) {
        Error(markers[i].Tok, where + ": marker " + markers[i].Name + " does not match executable event " + events[i].Kind);
        return;
      }
  }

  bool EventMatches(Ev e, Mark m) {
    if (e.Kind != m.Name) return false;
    switch (e.Kind) {
      case "EvBranch": return m.Args.Count == 2 && ExprEq(m.Args[1], e.A);
      case "EvLoop":
        if (m.Args.Count != 3) return false;
        if (e.UseIntA) { if (!IntEq(m.Args[1], e.IntA)) return false; }
        else if (!ExprEq(m.Args[1], e.A)) return false;
        return ExprEq(m.Args[2], e.B);
      case "EvRead": return m.Args.Count == 2 && ExprEq(m.Args[1], e.A);
      case "EvAlloc":
        if (m.Args.Count != 2) return false;
        return e.UseIntA ? IntEq(m.Args[1], e.IntA) : ExprEq(m.Args[1], e.A);
      case "EvConcat": return m.Args.Count == 3 && IsLengthOf(m.Args[1], e.A) && IsLengthOf(m.Args[2], e.B);
      case "EvSlice":
        return m.Args.Count == 4 && IsLengthOf(m.Args[1], e.A) &&
          ExprEq(m.Args[2], e.B ?? new LiteralExpr(e.A?.Tok, 0)) && ExprEq(m.Args[3], e.C);
      case "EvCall": return m.Args.Count == 3 && TargetEq(m.Args[1], e.Target) && IntEq(m.Args[2], e.Arity);
      case "EvMac":
        if (m.Args.Count != 6 || !TargetEq(m.Args[1], e.Target)) return false;
        return ExprEq(m.Args[2], e.A) && IsLengthOf(m.Args[3], e.B) &&
          IsLengthOf(m.Args[4], e.C) && ExprEq(m.Args[5], e.D ?? e.A);
      case "EvCreate":
        if (m.Args.Count != 3 || !TargetEq(m.Args[1], e.Target)) return false;
        return e.A == null ? IntEq(m.Args[2], 0) : IsLengthOf(m.Args[2], e.A);
      default: return false;
    }
  }

  bool TargetEq(Expression markerTarget, string expected) {
    if (!TryInt(markerTarget, out var id)) return false;
    return targetById.TryGetValue(id, out var actual) && actual == expected;
  }

  bool IntEq(Expression e, int value) => TryInt(e, out var actual) && actual == value;

  bool TryInt(Expression e, out int value) {
    e = Unwrap(e);
    if (e is LiteralExpr lit && lit.Value is System.Numerics.BigInteger bi) {
      if (bi < int.MinValue || bi > int.MaxValue) {
        Error(e.Tok, "marker integer is outside supported 32-bit range");
        value = 0; return false;
      }
      value = (int)bi; return true;
    }
    value = 0; return false;
  }

  bool IsLengthOf(Expression lengthExpr, Expression seq) {
    lengthExpr = Unwrap(lengthExpr);
    return lengthExpr is UnaryOpExpr u && u.ResolvedOp == UnaryOpExpr.ResolvedOpcode.SeqLength && ExprEq(u.E, seq);
  }

  // ------------------------------------------------------------------
  // Resolved structural equality
  // ------------------------------------------------------------------
  Expression Unwrap(Expression e) {
    while (true) {
      if (e is ParensExpression p) { e = p.E; continue; }
      if (e is ExprDotName d && d.ResolvedExpression != null) { e = d.ResolvedExpression; continue; }
      return e;
    }
  }

  bool ExprEq(Expression a, Expression b) {
    if (a == null || b == null) return a == null && b == null;
    a = Unwrap(a); b = Unwrap(b);
    if (a.GetType() != b.GetType()) return false;
    if (a is IdentifierExpr ia && b is IdentifierExpr ib) return ReferenceEquals(ia.Var, ib.Var);
    if (a is NameSegment na && b is NameSegment nb) return na.Name == nb.Name && SeqEq(na.SubExpressions, nb.SubExpressions);
    if (a is AutoGhostIdentifierExpr aa && b is AutoGhostIdentifierExpr ab) return ReferenceEquals(aa.Var, ab.Var);
    if (a is LiteralExpr la && b is LiteralExpr lb) return Equals(la.Value, lb.Value);
    if (a is BinaryExpr ba && b is BinaryExpr bb)
      return ba.ResolvedOp == bb.ResolvedOp && ExprEq(ba.E0, bb.E0) && ExprEq(ba.E1, bb.E1);
    if (a is UnaryOpExpr ua && b is UnaryOpExpr ub)
      return ua.ResolvedOp == ub.ResolvedOp && ExprEq(ua.E, ub.E);
    if (a is ConversionExpr ca && b is ConversionExpr cb)
      return ca.Type.ToString() == cb.Type.ToString() && ExprEq(ca.E, cb.E);
    if (a is SeqSelectExpr sa && b is SeqSelectExpr sb)
      return sa.SelectOne == sb.SelectOne && ExprEq(sa.Seq, sb.Seq) && ExprEq(sa.E0, sb.E0) && ExprEq(sa.E1, sb.E1);
    if (a is SeqDisplayExpr da && b is SeqDisplayExpr db) return SeqEq(da.Elements, db.Elements);
    if (a is SeqConstructionExpr sca && b is SeqConstructionExpr scb) return ExprEq(sca.N, scb.N);
    if (a is FunctionCallExpr fa && b is FunctionCallExpr fb)
      return ReferenceEquals(fa.Function, fb.Function) && SeqEq(fa.Args, fb.Args);
    if (a is MemberSelectExpr ma && b is MemberSelectExpr mb)
      return ReferenceEquals(ma.Member, mb.Member) && ExprEq(ma.Obj, mb.Obj);
    if (a is DatatypeValue dva && b is DatatypeValue dvb)
      return ReferenceEquals(dva.Ctor, dvb.Ctor) && SeqEq(dva.Arguments, dvb.Arguments);
    if (a is ApplySuffix apa && b is ApplySuffix apb)
      return ExprEq(apa.Lhs, apb.Lhs) && SeqEq(apa.Args, apb.Args);
    if (!a.SubExpressions.Any() && !b.SubExpressions.Any()) return a.ToString() == b.ToString();
    return false;
  }

  bool SeqEq(IEnumerable<Expression> a, IEnumerable<Expression> b) {
    var aa = a.ToList(); var bb = b.ToList();
    if (aa.Count != bb.Count) return false;
    for (int i = 0; i < aa.Count; i++) if (!ExprEq(aa[i], bb[i])) return false;
    return true;
  }
}
