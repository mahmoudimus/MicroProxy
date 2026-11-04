using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Microsoft.Dafny;
using Microsoft.Dafny.Plugins;

// TRUSTED resolved-AST source-coverage checker for the NativePolynomial
// observation component.  This is NOT a verified semantics and NOT a
// whole-Dafny theorem.  It binds every executable call/function to an exact
// resolved declaration, walks executable nodes in evaluation order, consumes
// flat SourceTrace markers in that order, and fails closed on every statement
// or expression form it does not explicitly model.
public class PolynomialSourceCoverageConfiguration : PluginConfiguration {
  public override Rewriter[] GetRewriters(ErrorReporter reporter) => new Rewriter[]{ new PolynomialSourceCoverageRewriter(reporter) };
}

public class PolynomialSourceCoverageRewriter : Rewriter {
  readonly ErrorReporter reporter;
  readonly Dictionary<string,Function> markerFuncs = new();
  readonly HashSet<Function> markerSet = new(ReferenceEqualityComparer.Instance);
  Function canonicalEncode;
  readonly Dictionary<string,DatatypeCtor> canonicalCtors = new();
  readonly Dictionary<int,Method> methodTargets = new();
  readonly Dictionary<int,Function> funcTargets = new();
  readonly Dictionary<string,Method> methods = new();
  readonly Dictionary<string,Function> funcs = new();
  readonly HashSet<Function> pureFuncs = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<Function,int> funcIds = new(ReferenceEqualityComparer.Instance);
  Formal traceFormal;
  readonly List<object> roleVars = new();
  readonly HashSet<IVariable> ghostCallVars = new(ReferenceEqualityComparer.Instance);
  readonly List<FunctionCallExpr> markers = new();
  readonly List<(Function fn, List<Expression> args, BlockStmt block, int index)> realPureCalls = new();
  readonly List<(FunctionCallExpr fc, IOrigin tok, BlockStmt block, int index)> ghostProjections = new();
  readonly Dictionary<FunctionCallExpr,(BlockStmt block,int index)> markerCtx = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<SingleAssignStmt,(BlockStmt block,int index)> traceCtx = new(ReferenceEqualityComparer.Instance);
  BlockStmt curBlock; int curIdx;
  int markerIndex;

  static string[] RootNames() {
    var env = Environment.GetEnvironmentVariable("POLY_TRACE_ROOTS");
    if (!string.IsNullOrWhiteSpace(env)) return env.Split(',', StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
    return rootNames.Concat(fieldNames).ToArray();
  }
  static readonly string[] rootNames = {
    "NativePolynomial.NewZetas","NativePolynomial.NewGammas","NativePolynomial.Add",
    "NativePolynomial.Sub","NativePolynomial.Copy","NativePolynomial.ForwardStage",
    "NativePolynomial.InverseStage","NativePolynomial.Scale","NativePolynomial.Ntt",
    "NativePolynomial.InverseNtt","NativePolynomial.BaseCase","NativePolynomial.NttMul",
    "NativePolynomial.Wipe"
  };
  static readonly string[] fieldNames = {
    "NativeField.ReduceOnce","NativeField.Reduce","NativeField.Add","NativeField.Sub",
    "NativeField.Mul","NativeField.MulSub","NativeField.AddMul"
  };
  static readonly string[] chunkFuncs = {
    "NativePolynomial.Len","NativePolynomial.ZetasChunk0","NativePolynomial.ZetasChunk1",
    "NativePolynomial.ZetasChunk2","NativePolynomial.ZetasChunk3","NativePolynomial.ZetasChunk4",
    "NativePolynomial.ZetasChunk5","NativePolynomial.ZetasChunk6","NativePolynomial.ZetasChunk7",
    "NativePolynomial.ZetasValue","NativePolynomial.GammasChunk0","NativePolynomial.GammasChunk1",
    "NativePolynomial.GammasChunk2","NativePolynomial.GammasChunk3","NativePolynomial.GammasChunk4",
    "NativePolynomial.GammasChunk5","NativePolynomial.GammasChunk6","NativePolynomial.GammasChunk7",
    "NativePolynomial.GammasValue"
  };

  public PolynomialSourceCoverageRewriter(ErrorReporter reporter) : base(reporter) { this.reporter = reporter; }

  public override void PostResolve(Program program) {
    foreach (var m in program.Modules())
      foreach (var td in m.TopLevelDecls.OfType<TopLevelDeclWithMembers>())
        foreach (var mem in td.Members) {
          if (mem is Method meth) methods[meth.FullName] = meth;
          if (mem is Function fn) funcs[fn.FullName] = fn;
        }
    var vocab = ExactModule(program,"SourceObservationVocabulary",true);
    var vocabDefault = ExactDefault(vocab);
    if (vocabDefault != null) {
      var encoders = vocabDefault.Members.OfType<Function>().Where(f => f.Name == "Encode").ToList();
      if (encoders.Count != 1 || !encoders[0].IsGhost || encoders[0].FullName != "SourceObservationVocabulary._default.Encode"
          || encoders[0].Ins.Count != 1 || encoders[0].Body == null)
        Error(vocab.Tok, "missing exact canonical vocabulary Encode");
      else canonicalEncode = encoders[0];
      var events = vocab.TopLevelDecls.OfType<DatatypeDecl>().Where(d => d.Name == "Event" && d.FullName == "SourceObservationVocabulary.Event").ToList();
      if (events.Count != 1) Error(vocab.Tok, "missing exact canonical Event datatype");
      else foreach (var ctor in events[0].Ctors)
        if (!canonicalCtors.TryAdd(ctor.Name, ctor)) Error(ctor.Tok, "duplicate canonical event constructor");
    }
    var traceModule = ExactModule(program,"SourceTrace",true);
    var traceDefault = ExactDefault(traceModule);
    if (traceModule != null && traceDefault != null)
      foreach (var td in traceModule.TopLevelDecls.OfType<TopLevelDeclWithMembers>())
        foreach (var mem in td.Members) {
          if (mem.Name is not ("Ops" or "Call" or "Branch" or "Read" or "Write" or "LoopBound" or "LoopCheck" or "Alloc")) continue;
          if (!ReferenceEquals(td,traceDefault) || mem.FullName != "SourceTrace._default."+mem.Name
              || mem is not Function fn || !fn.IsGhost || fn.ByMethodDecl != null || fn.ByMethodBody != null)
            Error(mem.Tok, "reserved marker outside exact SourceTrace default ghost function: "+mem.FullName);
          else markerFuncs[fn.Name]=fn;
        }
    foreach (var n in new[]{"Ops","Call","Branch","Read","Write","LoopBound","LoopCheck","Alloc"})
      if (!markerFuncs.ContainsKey(n)) { Error(program.GetStartOfFirstFileToken(),"missing exact SourceTrace."+n); return; }
    if (reporter.HasErrors) return;
    foreach (var pair in markerFuncs) CheckMarkerHelper(pair.Key,pair.Value);
    if (reporter.HasErrors) return;
    foreach (var fn in markerFuncs.Values) markerSet.Add(fn);

    // Exact method targets.
    void TargetM(int id, string full) {
      if ((FindM(full)) is Method m) methodTargets[id]=m;
      else Error(program.GetStartOfFirstFileToken(),"missing required method target "+full);
    }
    TargetM(1,"NativeField.ReduceOnce"); TargetM(2,"NativeField.Reduce");
    TargetM(3,"NativeField.Add"); TargetM(4,"NativeField.Sub"); TargetM(5,"NativeField.Mul");
    TargetM(6,"NativeField.MulSub"); TargetM(7,"NativeField.AddMul");
    TargetM(11,"NativePolynomial.NewZetas"); TargetM(12,"NativePolynomial.NewGammas");
    TargetM(13,"NativePolynomial.Copy"); TargetM(14,"NativePolynomial.ForwardStage");
    TargetM(15,"NativePolynomial.InverseStage"); TargetM(16,"NativePolynomial.Scale");
    TargetM(17,"NativePolynomial.Ntt"); TargetM(18,"NativePolynomial.InverseNtt");
    TargetM(19,"NativePolynomial.BaseCase"); TargetM(20,"NativePolynomial.NttMul");
    TargetM(21,"NativePolynomial.Wipe");

    // Exact pure-function targets and companions.
    void TargetF(int id, string full) {
      if ((FindF(full)) is Function f) { funcTargets[id]=f; pureFuncs.Add(f); funcIds[f]=id; }
      else Error(program.GetStartOfFirstFileToken(),"missing required pure function target "+full);
    }
    TargetF(30,"NativePolynomial.Len");
    for (int c=0;c<8;c++) TargetF(31+c,$"NativePolynomial.ZetasChunk{c}");
    TargetF(39,"NativePolynomial.ZetasValue");
    for (int c=0;c<8;c++) TargetF(41+c,$"NativePolynomial.GammasChunk{c}");
    TargetF(49,"NativePolynomial.GammasValue");

    CheckPrefixHelpers(program);
    foreach (var name in RootNames()) {
      if ((FindM(name)) is not Method m) { Error(program.GetStartOfFirstFileToken(),"missing required root "+name); continue; }
    }
    foreach (var name in fieldNames) {
      if ((FindM(name)) is not Method _) { Error(program.GetStartOfFirstFileToken(),"missing required Field helper "+name); continue; }
    }

    foreach (var name in RootNames()) if ((FindM(name)) is Method m) CheckMethod(m);
    foreach (var name in chunkFuncs) if ((FindF(name)) is Function f) CheckPureFunction(f);
    var controlEnv = Environment.GetEnvironmentVariable("POLY_TRACE_FUNCS");
    if (!string.IsNullOrWhiteSpace(controlEnv))
      foreach (var name in controlEnv.Split(',', StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries))
        if ((FindF(name)) is Function f) CheckControlFunction(f);
        else Error(program.GetStartOfFirstFileToken(),"missing control function "+name);
    if (!reporter.HasErrors) Console.WriteLine("POLYNOMIAL-SOURCE-COVERAGE OK: exact resolved roots ["+string.Join(",",RootNames())+"]; actual (real,ghost) function tuple paths; ordered flat markers; fail-closed");
  }

  void Error(IOrigin tok, string msg) { reporter.Error(MessageSource.Rewriter, tok, msg); }

  void BuildRoles(Method m) {
    roleVars.Clear();
    foreach (var f in m.Ins) roleVars.Add(f);
    foreach (var f in m.Outs) if (!f.IsGhost) roleVars.Add(f);
    var cls = m.EnclosingClass as TopLevelDeclWithMembers;
    if (cls != null) foreach (var mem in cls.Members) if (mem is Field fld) roleVars.Add(fld);
    var locals = m.Body.DescendantsAndSelf.OfType<VarDeclStmt>()
      .OrderBy(vd => vd.Tok?.StartToken?.pos ?? 0).ToList();
    foreach (var vd in locals)
      foreach (var lv in vd.Locals)
        if (!lv.IsGhost && lv.Type is UserDefinedType ud && ud.Name=="array")
          roleVars.Add(lv);
  }

  object ResolveRole(Expression e) {
    while (e is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null && !ReferenceEquals(cse.ResolvedExpression,e)) e=cse.ResolvedExpression;
    if (e is IdentifierExpr ie) return ie.Var;
    if (e is MemberSelectExpr ms && ms.Member is Field fld) return fld;
    return null;
  }

  bool MarkerRoleMatches(FunctionCallExpr m, int roleArg, Expression seq, out int roleId) {
    roleId=-1;
    if (m.Args.Count <= roleArg || !TryInt(m.Args[roleArg],out var rid)) return false;
    roleId=(int)rid;
    if (roleId<0 || roleId>=roleVars.Count) return false;
    var actual=ResolveRole(seq);
    return actual!=null && ReferenceEquals(actual,roleVars[roleId]);
  }

  void CheckMethod(Method m) {
    traceFormal = m.Outs.FirstOrDefault(f => ((IVariable)f).Name=="trace" && ((IVariable)f).IsGhost);
    if (traceFormal == null) { Error(m.Tok,m.Name+": missing ghost out formal trace"); return; }
    ghostCallVars.Clear(); markers.Clear(); markerCtx.Clear(); traceCtx.Clear(); markerIndex = 0; roleVars.Clear(); realPureCalls.Clear(); ghostProjections.Clear(); callMarkers.Clear(); ghostAppends.Clear();
    BuildRoles(m);
    CollectGhostTraceVars(m);
    CollectTraceAssignments(m);
    if (markers.Count == 0) { Error(m.Tok,m.Name+": no trace observation assignment"); return; }
    if (markers[0].Function != markerFuncs["Ops"]) { Error(markers[0].Tok,m.Name+": first marker must be exact SourceTrace.Ops"); return; }
    CheckOpsCounts(m); Advance();
    WalkBlock(m.Body);
    foreach (var ga in ghostAppends) {
      if (!ghostCallDefCtx.TryGetValue(ga.local,out var def)) { Error(ga.tok,m.Name+": appended callee local has no exact defining call"); continue; }
      if (!callMarkers.TryGetValue(def.cs,out var marker)) { Error(ga.tok,m.Name+": appended callee local's ST.Call marker was not consumed for its defining call"); continue; }
      if (marker.Function!=markerFuncs["Call"] || marker.Args.Count!=3 || !TryInt(marker.Args[1],out var id) || !TryInt(marker.Args[2],out var ar)) { Error(ga.tok,m.Name+": appended callee local's marker is not a well-formed Call"); continue; }
      if (!methodTargets.TryGetValue((int)id,out var target) || !ReferenceEquals(target,def.cs.Method) || (int)ar!=def.cs.Args.Count) { Error(ga.tok,m.Name+": appended callee local is not the output of the call whose exact ST.Call marker was consumed"); continue; }
      if (def.outIndex>=def.cs.Method.Outs.Count || !def.cs.Method.Outs[def.outIndex].IsGhost) { Error(ga.tok,m.Name+": appended callee local is not a ghost formal output"); continue; }
      if (!ReferenceEquals(def.block,ga.block) || def.index>=ga.index || HasExecutableBetween(def.block,def.index+1,ga.index)) { Error(ga.tok,m.Name+": appended callee local is not in the same executable statement context as its defining call"); continue; }
    }
    static bool ArgsEq(List<Expression> a, List<Expression> b) =>
      a.Count==b.Count && a.Zip(b).All(pair => ExprEq(pair.First,pair.Second));
    static bool StableArg(Expression e) {
      e=Unwrap(e);
      if (e is IdentifierExpr || e is LiteralExpr) return true;
      if (e is ConversionExpr c) return StableArg(c.E);
      if (e is UnaryOpExpr u) return StableArg(u.E);
      if (e is BinaryExpr b) return StableArg(b.E0) && StableArg(b.E1);
      return false;
    }
    foreach (var gp in ghostProjections) {
      bool match=realPureCalls.Any(rc => ReferenceEquals(rc.fn,gp.fc.Function) && ArgsEq(rc.args,gp.fc.Args)
        && ReferenceEquals(rc.block,gp.block) && rc.index<gp.index && !HasExecutableBetween(rc.block,rc.index+1,gp.index));
      if (!match) Error(gp.tok,m.Name+": ghost projection "+gp.fc.Function.Name+" is not immediately after an actual call with the same arguments");
      if (!gp.fc.Args.All(StableArg)) Error(gp.tok,m.Name+": ghost projection argument is not stable");
    }
    foreach (var rc in realPureCalls) {
      int count=ghostProjections.Count(gp => ReferenceEquals(gp.fc.Function,rc.fn) && ArgsEq(gp.fc.Args,rc.args)
        && ReferenceEquals(gp.block,rc.block) && rc.index<gp.index && !HasExecutableBetween(rc.block,rc.index+1,gp.index));
      if (count!=1) Error(rc.block.Body[rc.index].Tok,m.Name+": actual pure call "+rc.fn.Name+" has "+count+" immediate ghost projections");
      if (!rc.args.All(StableArg)) Error(rc.block.Body[rc.index].Tok,m.Name+": actual pure call argument is not stable");
    }
    if (markerIndex != markers.Count) Error(markers[markerIndex].Tok,m.Name+": stale observation "+MarkerName(markers[markerIndex]));
  }

  string MarkerName(FunctionCallExpr fc) => markerFuncs.First(kv=>kv.Value==fc.Function).Key;

  readonly Dictionary<IVariable,int> ghostCallAssignCount = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<IVariable,(BlockStmt block,int index,CallStmt cs,List<Expression> args,int outIndex)> ghostCallDefCtx = new(ReferenceEqualityComparer.Instance);
  readonly Dictionary<CallStmt,FunctionCallExpr> callMarkers = new(ReferenceEqualityComparer.Instance);
  readonly List<(IVariable local,IOrigin tok,BlockStmt block,int index)> ghostAppends = new();

  void CollectGhostTraceVars(Method m) {
    ghostCallAssignCount.Clear(); ghostCallDefCtx.Clear(); ghostCallVars.Clear();

    void ScanExpr(Expression e, IOrigin tok) {
      if (e==null) return;
      foreach (var x in e.DescendantsAndSelf) {
        if (x is StmtExpr) { Error(tok,m.Name+": unsupported hidden statement expression in ghost-binding scan"); return; }
        if (x is LetExpr || x is LetOrFailExpr || x is MatchExpr || x is NestedMatchExpr) {
          Error(tok,m.Name+": unsupported binding expression in ghost-binding scan: "+x.GetType().Name); return;
        }
      }
    }
    void ScanStatementSubexprs(Statement st, IOrigin tok) {
      foreach (var e in st.SubExpressions) ScanExpr(e,tok);
    }
    void DoRecord(List<Expression> lhss, CallStmt cs, IOrigin tok, BlockStmt b, int idx) {
      bool ghostLhs = lhss.Any(l => AsVar(l) is LocalVariable lv && lv.IsGhost);
      if (ghostLhs && cs != null && cs.Method.IsLemmaLike) {
        Error(tok,m.Name+": ghost lemma-out binding is unsupported");
      } else if (ghostLhs && cs != null && !methodTargets.Values.Contains(cs.Method)) {
        Error(tok,m.Name+": ghost binding from unregistered call "+cs.Method.FullName);
      }
      for (int oi=0;oi<lhss.Count;oi++) {
        var v=AsVar(lhss[oi]);
        if (v is LocalVariable lv && lv.IsGhost) {
          ghostCallAssignCount.TryGetValue(lv,out var c); ghostCallAssignCount[lv]=c+1;
          bool exact = cs!=null && !cs.Method.IsLemmaLike && methodTargets.Values.Contains(cs.Method)
            && lhss.Count==cs.Method.Outs.Count && oi<cs.Method.Outs.Count && cs.Method.Outs[oi].IsGhost;
          if (exact && !ghostCallDefCtx.ContainsKey(lv))
            ghostCallDefCtx[lv]=(b,idx,cs,cs.Args.ToList(),oi);
        }
      }
    }
    void ScanRhs(AssignmentRhs rhs, IOrigin tok) {
      foreach (var e in rhs.SubExpressions) ScanExpr(e,tok);
    }
    void Record(Statement stmt, ConcreteAssignStatement asg, BlockStmt b, int idx) {
      if (asg is AssignSuchThatStmt) { Error(asg.Tok,m.Name+": AssignSuchThatStmt ghost binding is unsupported"); return; }
      if (asg is not AssignStatement cas) { Error(asg.Tok,m.Name+": unsupported concrete assignment form "+asg.GetType().Name); return; }
      var calls=stmt.DescendantsAndSelf.OfType<CallStmt>().ToList();
      if (calls.Count>1) { Error(stmt.Tok,m.Name+": multiple calls in one ghost-output statement"); return; }
      DoRecord(cas.Lhss, calls.Count==1?calls[0]:null, stmt.Tok, b, idx);
      foreach (var r in cas.Rhss) ScanRhs(r, r.Tok);
    }
    void RecordS(SingleAssignStmt sa, BlockStmt b, int idx) {
      var calls=sa.DescendantsAndSelf.OfType<CallStmt>().ToList();
      if (calls.Count>1) { Error(sa.Tok,m.Name+": multiple calls in one ghost-output statement"); return; }
      DoRecord(new List<Expression>{sa.Lhs}, calls.Count==1?calls[0]:null, sa.Tok, b, idx);
      if (sa.Rhs!=null) ScanRhs(sa.Rhs, sa.Tok);
    }
    void Visit(Statement s, BlockStmt b, int idx) {
      string tn=s.GetType().Name;
      if (tn=="VarDeclStmt") {
        var vd=(VarDeclStmt)s;
        if (vd.Assign!=null) Record(vd, vd.Assign, b, idx);
        return;
      }
      if (tn=="AssignStatement") { var asg=(AssignStatement)s; Record(asg,asg,b,idx); return; }
      if (tn=="SingleAssignStmt") { RecordS((SingleAssignStmt)s,b,idx); return; }
      if (tn=="CallStmt") {
        var cs=(CallStmt)s;
        if (cs.Receiver!=null) ScanExpr(cs.Receiver,cs.Tok);
        foreach (var a in cs.Args) ScanExpr(a,cs.Tok);
        if (cs.Lhs.Count>0) DoRecord(cs.Lhs, cs, cs.Tok, b, idx);
        return;
      }
      if (tn=="BlockStmt") { VisitBlock((BlockStmt)s); return; }
      if (tn=="IfStmt") {
        var iff=(IfStmt)s;
        ScanExpr(iff.Guard,iff.Tok);
        VisitBlock(iff.Thn);
        if (iff.Els is BlockStmt eb) VisitBlock(eb);
        else if (iff.Els != null) Error(iff.Els.Tok,m.Name+": unsupported non-block else in ghost-binding scan");
        return;
      }
      if (tn=="WhileStmt") { var wh=(WhileStmt)s; ScanExpr(wh.Guard,wh.Tok); VisitBlock(wh.Body); return; }
      if (tn=="ForLoopStmt") { var fl=(ForLoopStmt)s; ScanExpr(fl.Start,fl.Tok); ScanExpr(fl.End,fl.Tok); VisitBlock(fl.Body); return; }
      if (tn=="AssertStmt" || tn=="AssumeStmt" || tn=="ExpectStmt" || tn=="PredicateStmt") { ScanStatementSubexprs(s,s.Tok); return; }
      if (tn=="ReturnStmt" || tn=="BreakOrContinueStmt" || tn=="ModifyStmt" || tn=="HideRevealStmt" || tn=="PrintStmt") { ScanStatementSubexprs(s,s.Tok); return; }
      Error(s.Tok,m.Name+": unsupported statement class in ghost-binding scan: "+tn);
    }
    void VisitBlock(BlockStmt b) {
      if (b==null) return;
      for (int i=0;i<b.Body.Count;i++) Visit(b.Body[i],b,i);
    }
    VisitBlock(m.Body);
    foreach (var kv in ghostCallAssignCount) if (kv.Value==1 && ghostCallDefCtx.ContainsKey(kv.Key)) ghostCallVars.Add(kv.Key);
  }

  bool ContainsTraceAssign(Statement s) => s.DescendantsAndSelf.OfType<SingleAssignStmt>()
    .Any(sa => AsVar(sa.Lhs)==traceFormal);

  void CollectTraceInBlock(BlockStmt b, List<SingleAssignStmt> list) {
    if (b==null) return;
    foreach (var s in b.Body) {
      if (s.IsGhost) {
        if (s is IfStmt || s is WhileStmt || s is ForLoopStmt || s is ForallStmt || s is BlockStmt || s is AlternativeLoopStmt) {
          if (ContainsTraceAssign(s)) Error(s.Tok,"trace assignment inside ghost control flow is not executable");
          continue;
        }
        foreach (var sa in s.DescendantsAndSelf.OfType<SingleAssignStmt>())
          if (AsVar(sa.Lhs)==traceFormal) { list.Add(sa); traceCtx[sa]=(b,IndexIn(b,sa)); }
        continue;
      }
      if (s is IfStmt iff) { CollectTraceInBlock(iff.Thn,list); if (iff.Els is BlockStmt eb) CollectTraceInBlock(eb,list); }
      else if (s is WhileStmt wh) CollectTraceInBlock(wh.Body,list);
      else if (s is ForLoopStmt fl) CollectTraceInBlock(fl.Body,list);
      else if (s is BlockStmt bb) CollectTraceInBlock(bb,list);
    }
  }

  int IndexIn(BlockStmt b, Statement s) {
    for (int i=0;i<b.Body.Count;i++) if (ReferenceEquals(b.Body[i],s) || b.Body[i].DescendantsAndSelf.Contains(s)) return i;
    return -1;
  }

  void CollectTraceAssignments(Method m) {
    var assigns = new List<SingleAssignStmt>();
    CollectTraceInBlock(m.Body,assigns);
    assigns = assigns.OrderBy(sa => sa.Tok?.StartToken?.pos ?? 0).ThenBy(sa => sa.Tok?.StartToken?.col ?? 0).ToList();
    if (assigns.Count == 0) { Error(m.Tok,m.Name+": no assignment to ghost trace"); return; }
    bool first = true;
    foreach (var sa in assigns) {
      if (!sa.IsGhost) { Error(sa.Tok,m.Name+": trace assignment is not ghost"); continue; }
      if (!traceCtx.TryGetValue(sa,out var ctx)) { Error(sa.Tok,m.Name+": trace assignment has no executable context"); continue; }
      if (sa.Rhs is not ExprRhs er) { Error(sa.Tok,m.Name+": trace RHS is not an expression"); continue; }
      var leaves = ConcatLeaves(er.Expr).ToList();
      if (first) {
        if (leaves.Any(x => AsVar(x)==traceFormal)) { Error(sa.Tok,m.Name+": initial trace must not read a previous trace"); continue; }
        foreach (var leaf in leaves) {
          if (leaf is FunctionCallExpr fc && fc.Function != null && markerSet.Contains(fc.Function)) { AddMarker(fc,sa); continue; }
          Error(leaf.Tok,m.Name+": initial trace update contains non-marker expression");
        }
        first = false;
      } else {
        if (leaves.Count == 0 || AsVar(leaves[0]) != traceFormal) { Error(sa.Tok,m.Name+": later trace update must append to the same trace"); continue; }
        for (int i=1;i<leaves.Count;i++) {
          var leaf=leaves[i];
          if (leaf is FunctionCallExpr fc && fc.Function != null && markerSet.Contains(fc.Function)) { AddMarker(fc,sa); continue; }
          if (TryActualGhostProjection(leaf,out var gproj)) { ghostProjections.Add((gproj,leaf.Tok,ctx.block,ctx.index)); continue; }
          var v=AsVar(leaf);
          if (v is LocalVariable lv && lv.IsGhost) {
            if (!ghostCallAssignCount.TryGetValue(lv,out var cnt)) { Error(leaf.Tok,m.Name+": ghost trace local has no counted assignment site"); continue; }
            if (cnt!=1) { Error(leaf.Tok,m.Name+": ghost trace local has "+cnt+" assignments; exactly one exact ghost-out call is required (rebinding)"); continue; }
            if (!ghostCallDefCtx.TryGetValue(lv,out var def)) { Error(leaf.Tok,m.Name+": ghost trace local is assigned by a non-call/rebound expression; exactly one exact ghost-out call is required"); continue; }
            if (!ReferenceEquals(def.block,ctx.block) || def.index>=ctx.index || HasExecutableBetween(def.block,def.index+1,ctx.index)) { Error(leaf.Tok,m.Name+": callee trace local is not appended immediately after its defining call"); continue; }
            if (!methodTargets.Values.Contains(def.cs.Method)) { Error(leaf.Tok,m.Name+": callee trace local comes from an unregistered method"); continue; }
            if (def.outIndex>=def.cs.Method.Outs.Count || !def.cs.Method.Outs[def.outIndex].IsGhost) { Error(leaf.Tok,m.Name+": callee trace local is not tied to the ghost formal output"); continue; }
            ghostAppends.Add((lv,leaf.Tok,ctx.block,ctx.index));
            continue;
          }
          Error(leaf.Tok,m.Name+": later trace update contains non-approved suffix expression");
        }
      }
    }
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
    var (add,sub,mul,div,mod,bit,shift) = CountOps(m.Body);
    var expected = new[]{add,sub,mul,div,mod,bit,shift};
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
      ExpectMarker("Branch", m => m.Args.Count==2 && ExprEq(m.Args[1], iff.Guard), iff.Tok, "branch guard", false);
      WalkBlock(iff.Thn);
      if (iff.Els != null) WalkStmt(iff.Els,b,idx);
      return;
    }
    if (s is ForLoopStmt fl) {
      VisitExpr(fl.Start); VisitExpr(fl.End);
      ExpectMarker("LoopBound", m => m.Args.Count==2 && ExprEq(m.Args[1],fl.End), fl.Tok, "loop bound", false);
      int firstExec=0; while (firstExec<fl.Body.Body.Count && fl.Body.Body[firstExec].IsGhost) firstExec++;
      var saveB=curBlock; var saveI=curIdx;
      curBlock=fl.Body; curIdx=firstExec;
      ExpectMarker("LoopCheck", m => m.Args.Count==3 && IsTrue(m.Args[1]) && ReferenceEquals(AsVar(m.Args[2]),fl.LoopIndex), fl.Tok, "loop iteration", false);
      WalkBlock(fl.Body);
      curBlock=saveB; curIdx=saveI;
      ExpectMarker("LoopCheck", m => m.Args.Count==3 && !IsTrue(m.Args[1]) && ExprEq(m.Args[2],fl.End), fl.Tok, "loop exit", true);
      return;
    }
    if (s is WhileStmt || s is AlternativeLoopStmt) { Error(s.Tok,"unimplemented executable loop observation: "+s.GetType().Name); return; }
    if (s is VarDeclStmt vd) { if (vd.Assign != null) WalkStmt(vd.Assign,b,idx); return; }
    if (s is AssignStatement asg) {
      var calls = asg.DescendantsAndSelf.OfType<CallStmt>().ToList();
      if (calls.Count > 0) { foreach (var c in calls) WalkCall(c); foreach (var lhs in asg.Lhss) VisitWrite(lhs); return; }
      foreach (var rhss in asg.Rhss) VisitRhs(rhss);
      foreach (var lhs in asg.Lhss) VisitWrite(lhs);
      return;
    }
    if (s is SingleAssignStmt sa) {
      var calls = sa.DescendantsAndSelf.OfType<CallStmt>().ToList();
      if (calls.Count > 0) { foreach (var c in calls) WalkCall(c); VisitWrite(sa.Lhs); return; }
      VisitRhs(sa.Rhs);
      VisitWrite(sa.Lhs);
      return;
    }
    if (s is CallStmt cs) { WalkCall(cs); return; }
    if (s is ReturnStmt ret) { Error(ret.Tok,"unsupported executable return statement in source-coverage root"); return; }
    Error(s.Tok,"unsupported executable statement: "+s.GetType().Name);
  }

  void WalkCall(CallStmt cs) {
    if (cs.Method.IsLemmaLike) { Error(cs.Tok,"executable lemma call is not modeled"); return; }
    if (!methodTargets.Values.Contains(cs.Method)) { Error(cs.Tok,"unregistered executable callee "+cs.Method.FullName); return; }
    if (cs.Receiver != null) VisitExpr(cs.Receiver);
    foreach (var a in cs.Args) VisitExpr(a);
    int before=markerIndex;
    ExpectMarker("Call", m => {
      if (m.Args.Count!=3 || !TryInt(m.Args[1],out var id) || !TryInt(m.Args[2],out var ar)) return false;
      return methodTargets.TryGetValue((int)id,out var target) && ReferenceEquals(target,cs.Method) && ar==cs.Args.Count;
    }, cs.Tok, "call to exact "+cs.Method.FullName+"/"+cs.Args.Count, false);
    if (markerIndex==before+1 && before<markers.Count && markers[before].Function==markerFuncs["Call"])
      callMarkers[cs]=markers[before];
  }

  void VisitRhs(AssignmentRhs rhs) {
    if (rhs is ExprRhs er) { VisitExpr(er.Expr); return; }
    if (rhs is TypeRhs tr) {
      if (tr.ElementInit != null || tr.InitDisplay != null || tr.InitCall != null) { Error(tr.Tok,"unsupported array initializer in allocation"); return; }
      if (tr.ArrayDimensions == null || tr.ArrayDimensions.Count != 1) { Error(tr.Tok,"unsupported allocation dimensions"); return; }
      var dim=tr.ArrayDimensions[0];
      VisitExpr(dim);
      ExpectMarker("Alloc", m => m.Args.Count==2 && ExprEq(m.Args[1],dim), tr.Tok, "array allocation", false);
      return;
    }
    Error(rhs.Tok,"unsupported assignment right-hand side "+rhs.GetType().Name);
  }

  void VisitWrite(Expression lhs) {
    if (lhs is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null && !ReferenceEquals(cse.ResolvedExpression,lhs)) { VisitWrite(cse.ResolvedExpression); return; }
    if (lhs is SeqSelectExpr sel && sel.E0 != null && sel.E1 == null) {
      VisitExpr(sel.Seq); VisitExpr(sel.E0);
      ExpectMarker("Write", m => m.Args.Count==3 && MarkerRoleMatches(m,1,sel.Seq,out _) && ExprEq(m.Args[2],sel.E0), sel.Tok, "array write", true);
      return;
    }
    if (lhs is IdentifierExpr || lhs is MemberSelectExpr) return;
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
    if (e is MemberSelectExpr ms) { VisitExpr(ms.Obj); return; }
    if (e is SeqSelectExpr sel && sel.E0 != null && sel.E1 == null) {
      VisitExpr(sel.Seq); VisitExpr(sel.E0);
      ExpectMarker("Read", m => m.Args.Count==3 && MarkerRoleMatches(m,1,sel.Seq,out _) && ExprEq(m.Args[2],sel.E0), sel.Tok, "array read", false);
      return;
    }
    if (e is SeqConstructionExpr sc) {
      VisitExpr(sc.N);
      ExpectMarker("Alloc", m => m.Args.Count==2 && ExprEq(m.Args[1],sc.N), e.Tok, "array allocation", false);
      return;
    }
    if (e is FunctionCallExpr fc) {
      if (fc.Function == null) { Error(fc.Tok,"unresolved executable function call"); return; }
      if (markerSet.Contains(fc.Function)) { Error(fc.Tok,"marker function used in executable expression"); return; }
      if (pureFuncs.Contains(fc.Function)) {
        realPureCalls.Add((fc.Function, fc.Args.ToList(), curBlock, curIdx));
        foreach (var a in fc.Args) VisitExpr(a);
        ExpectMarker("Call", m => {
          if (m.Args.Count!=3 || !TryInt(m.Args[1],out var id) || !TryInt(m.Args[2],out var ar)) return false;
          return funcTargets.TryGetValue((int)id,out var target) && ReferenceEquals(target,fc.Function) && ar==fc.Args.Count;
        }, fc.Tok, "function call to exact "+fc.Function.FullName+"/"+fc.Args.Count, false);
        return;
      }
      Error(fc.Tok,"unregistered executable function call "+fc.Function.FullName); return;
    }
    if (e is ITEExpr || e is MatchExpr || e is NestedMatchExpr || e is StmtExpr || e is LetExpr || e is LetOrFailExpr ||
        e is ApplySuffix || e is SeqUpdateExpr || e is SeqDisplayExpr || e is MultiSetDisplayExpr || e is MultiSetFormingExpr) {
      Error(e.Tok,"unsupported executable expression "+e.GetType().Name); return;
    }
    Error(e.Tok,"unsupported executable expression "+e.GetType().Name);
  }

  void ExpectMarker(string kind, Func<FunctionCallExpr,bool> pred, IOrigin tok, string what, bool after) {
    if (markerIndex >= markers.Count) { Error(tok,"missing "+kind+" observation for "+what); return; }
    var m = markers[markerIndex];
    if (m.Function != markerFuncs[kind]) { Error(m.Tok,"expected exact SourceTrace."+kind+" for "+what+", found "+MarkerName(m)); return; }
    if (!pred(m)) { Error(m.Tok,"mismatched "+kind+" observation for "+what); return; }
    if (!markerCtx.TryGetValue(m,out var ctx)) { Error(m.Tok,"marker has no source block context"); return; }
    if (!ReferenceEquals(ctx.block,curBlock)) { Error(m.Tok,"marker is outside the executable block of "+what); return; }
    if (kind=="Call") {
      bool before = ctx.index < curIdx && !HasExecutableBetween(curBlock,ctx.index+1,curIdx);
      bool afterCall = ctx.index > curIdx && !HasExecutableBetween(curBlock,curIdx+1,ctx.index);
      if (!before && !afterCall) { Error(m.Tok,kind+" marker is not adjacent to "+what); return; }
    } else if (after) {
      if (ctx.index <= curIdx || HasExecutableBetween(curBlock,curIdx+1,ctx.index)) { Error(m.Tok,kind+" marker is not the next observation after "+what); return; }
    } else {
      if (ctx.index >= curIdx || HasExecutableBetween(curBlock,ctx.index+1,curIdx)) { Error(m.Tok,kind+" marker is not adjacent-before "+what); return; }
    }
    markerIndex++;
  }

  static bool HasExecutableBetween(BlockStmt b, int lo, int hi) {
    for (int i=lo;i<hi && i<b.Body.Count;i++) if (!b.Body[i].IsGhost) return true;
    return false;
  }

  void Advance() { markerIndex++; }

  (int,int,int,int,int,int,int) CountOps(Statement root) {
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

  static IVariable AsVar(Expression e) {
    while (true) {
      while (e is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null && !ReferenceEquals(cse.ResolvedExpression,e)) e=cse.ResolvedExpression;
      if (e is ParensExpression p) { e=p.E; continue; }
      if (e is ConversionExpr cv) { e=cv.E; continue; }
      break;
    }
    if (e is IdentifierExpr ie) return ie.Var;
    return null;
  }

  static bool TryInt(Expression e, out BigInteger v) {
    if (e is LiteralExpr le && le.Value is BigInteger bi) { v=bi; return true; }
    if (e is LiteralExpr le2 && le2.Value is int i) { v=i; return true; }
    v=0; return false;
  }

  static bool IsTrue(Expression e) {
    if (e is LiteralExpr le && le.Value is bool b) return b;
    return false;
  }

  static bool ExprEq(Expression a, Expression b, Dictionary<IVariable,IVariable> map=null) {
    if (a==null || b==null) return false;
    if (a is ParensExpression pa) return ExprEq(pa.E,b,map);
    if (b is ParensExpression pb) return ExprEq(a,pb.E,map);
    if (a is ConcreteSyntaxExpression wa && wa.ResolvedExpression != null && !ReferenceEquals(wa.ResolvedExpression,a)) return ExprEq(wa.ResolvedExpression,b,map);
    if (b is ConcreteSyntaxExpression wb && wb.ResolvedExpression != null && !ReferenceEquals(wb.ResolvedExpression,b)) return ExprEq(a,wb.ResolvedExpression,map);
    if (a is ConversionExpr cva) return ExprEq(cva.E,b,map);
    if (b is ConversionExpr cvb) return ExprEq(a,cvb.E,map);
    var va=AsVar(a); var vb=AsVar(b);
    if (va!=null || vb!=null) {
      if (va==null || vb==null) return false;
      if (map!=null && map.TryGetValue(va,out var mapped)) return ReferenceEquals(mapped,vb);
      return ReferenceEquals(va,vb);
    }
    if (a is LiteralExpr la && b is LiteralExpr lb) return Equals(la.Value,lb.Value);
    if (a is MemberSelectExpr ma && b is MemberSelectExpr mb) return ReferenceEquals(ma.Member,mb.Member) && ExprEq(ma.Obj,mb.Obj,map);
    if (a is BinaryExpr ba && b is BinaryExpr bb) return ba.ResolvedOp==bb.ResolvedOp && ExprEq(ba.E0,bb.E0,map) && ExprEq(ba.E1,bb.E1,map);
    if (a is UnaryOpExpr ua && b is UnaryOpExpr ub) return ua.ResolvedOp==ub.ResolvedOp && ExprEq(ua.E,ub.E,map);
    if (a is SeqSelectExpr sa && b is SeqSelectExpr sb) return sa.E0!=null && sb.E0!=null && ExprEq(sa.Seq,sb.Seq,map) && ExprEq(sa.E0,sb.E0,map);
    return false;
  }

  // ---- Pure-function structural companion check (trusted, not a theorem) ----
  class IteChain {
    public List<(Expression test, Expression thn)> arms = new();
    public Expression last;
  }

  static Expression Unwrap(Expression e) {
    while (true) {
      while (e is ConcreteSyntaxExpression cse && cse.ResolvedExpression != null && !ReferenceEquals(cse.ResolvedExpression,e)) e=cse.ResolvedExpression;
      if (e is StmtExpr se && se.S.IsGhost) { e=se.E; continue; }
      return e;
    }
  }

  static IteChain Chain(Expression e) {
    var c = new IteChain();
    e = Unwrap(e);
    while (e is ITEExpr ite) { c.arms.Add((ite.Test,ite.Thn)); e=Unwrap(ite.Els); }
    c.last=e;
    return c;
  }

  static Expression ArmExpr(IteChain c, int i) => i < c.arms.Count ? Unwrap(c.arms[i].thn) : Unwrap(c.last);

  bool TryActualGhostProjection(Expression e, out FunctionCallExpr fc) {
    fc=null;
    e=Unwrap(e);
    if (e is MemberSelectExpr ms && ms.MemberName=="1" && Unwrap(ms.Obj) is FunctionCallExpr call && call.Function!=null && pureFuncs.Contains(call.Function)) {
      fc=call; return true;
    }
    return false;
  }

  static bool IsGhostTuple(Function f) {
    if (f.ResultType is UserDefinedType ud && ud.ResolvedClass is TupleTypeDecl tt && tt.Dims==2) {
      var g=tt.ArgumentGhostness;
      return g.Count==2 && !g[0] && g[1];
    }
    return false;
  }

  static List<Expression> TupleArgs(Expression e) {
    e=Unwrap(e);
    if (e is DatatypeValue dv && dv.Arguments.Count==2) return dv.Arguments;
    return null;
  }

  static FunctionCallExpr RealChildCall(Expression e) {
    e=Unwrap(e);
    if (e is MemberSelectExpr ms && ms.MemberName=="0" && Unwrap(ms.Obj) is FunctionCallExpr fc) return fc;
    return null;
  }

  static FunctionCallExpr GhostChildCall(Expression e) {
    e=Unwrap(e);
    if (e is MemberSelectExpr ms && ms.MemberName=="1" && Unwrap(ms.Obj) is FunctionCallExpr fc) return fc;
    return null;
  }

  static bool IsFormalTest(Expression test, IVariable v, BinaryExpr.ResolvedOpcode op, int lit, bool isLess) {
    test=Unwrap(test);
    if (test is not BinaryExpr b || b.ResolvedOp!=op) return false;
    if (!ReferenceEquals(AsVar(b.E0),v)) return false;
    if (!TryInt(b.E1,out var n)) return false;
    return (int)n==lit;
  }

  bool IsCallTo(Expression e, Function f, int arity, out FunctionCallExpr fc) {
    fc=Unwrap(e) as FunctionCallExpr;
    return fc!=null && fc.Function!=null && ReferenceEquals(fc.Function,f) && fc.Args.Count==arity;
  }
  static bool IsInt(Expression e,int v) => TryInt(e,out var n) && (int)n==v;
  static bool IsFalse(Expression e) {
    e=Unwrap(e);
    return e is LiteralExpr le && le.Value is bool b && !b;
  }
  static bool IsTrueLit(Expression e) {
    e=Unwrap(e);
    return e is LiteralExpr le && le.Value is bool b && b;
  }
  static bool IsEmptySeq(Expression e) {
    e=Unwrap(e);
    return e is SeqDisplayExpr sd && sd.Elements.Count==0;
  }
  static bool MentionsVar(Expression e, IVariable v) {
    e=Unwrap(e);
    if (ReferenceEquals(AsVar(e),v)) return true;
    if (e is BinaryExpr b && (b.ResolvedOp==BinaryExpr.ResolvedOpcode.Add || b.ResolvedOp==BinaryExpr.ResolvedOpcode.Sub))
      return MentionsVar(b.E0,v) || MentionsVar(b.E1,v);
    return false;
  }
  static bool MentionsInt(Expression e,int lit) {
    e=Unwrap(e);
    if (TryInt(e,out var n)) return (int)n==lit;
    if (e is BinaryExpr b && (b.ResolvedOp==BinaryExpr.ResolvedOpcode.Add || b.ResolvedOp==BinaryExpr.ResolvedOpcode.Sub))
      return MentionsInt(b.E0,lit) || MentionsInt(b.E1,lit);
    return false;
  }

  Method FindM(string name) {
    if (methods.TryGetValue(name,out var m)) return m;
    int i=name.IndexOf('.');
    if (i>0 && methods.TryGetValue(name.Substring(0,i)+"._default."+name.Substring(i+1),out m)) return m;
    return null;
  }
  Function FindF(string name) {
    if (funcs.TryGetValue(name,out var f)) return f;
    int i=name.IndexOf('.');
    if (i>0 && funcs.TryGetValue(name.Substring(0,i)+"._default."+name.Substring(i+1),out f)) return f;
    return null;
  }

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
  void CheckMarkerHelper(string name, Function fn) {
    var body = fn.Body == null ? null : Unwrap(fn.Body);
    if (body is not FunctionCallExpr call || !ReferenceEquals(call.Function, canonicalEncode) || call.Args.Count != 1
        || Unwrap(call.Args[0]) is not DatatypeValue value || !canonicalCtors.TryGetValue(name, out var ctor)
        || !ReferenceEquals(value.Ctor, ctor) || value.Arguments.Count != fn.Ins.Count || value.Arguments.Count != ctor.Formals.Count) {
      Error(fn.Tok, "marker helper is not exact canonical Encode(constructor(positional formals)): " + fn.FullName);
      return;
    }
    for (int i = 0; i < fn.Ins.Count; i++)
      if (!ReferenceEquals(AsVar(value.Arguments[i]), fn.Ins[i]))
        Error(value.Arguments[i].Tok, "marker helper changes or reorders positional formal " + i + ": " + fn.FullName);
  }

  void CheckPrefixHelpers(Program program) {
    if ((FindF("NativePolynomial.BranchFalsePrefix")) is not Function bfp) {
      Error(program.GetStartOfFirstFileToken(),"missing exact BranchFalsePrefix"); return;
    }
    if ((FindF("NativePolynomial.ChunkTrace")) is not Function ct) {
      Error(program.GetStartOfFirstFileToken(),"missing exact ChunkTrace"); return;
    }
    var bb=Unwrap(bfp.Body);
    if (bb is not ITEExpr bite) { Error(bfp.Tok,"BranchFalsePrefix body is not the exact conditional"); return; }
    var test=Unwrap(bite.Test);
    if (!(test is BinaryExpr tb && tb.ResolvedOp==BinaryExpr.ResolvedOpcode.Le
          && ReferenceEquals(AsVar(tb.E0),bfp.Ins[1]) && IsInt(tb.E1,0))) {
      Error(bfp.Tok,"BranchFalsePrefix guard is not k <= 0"); return;
    }
    if (!IsEmptySeq(bite.Thn)) { Error(bfp.Tok,"BranchFalsePrefix base is not []"); return; }
    var bleaves=ConcatLeaves(bite.Els).ToList();
    if (bleaves.Count!=2) { Error(bfp.Tok,"BranchFalsePrefix else is not two leaves"); return; }
    if (!IsCallTo(bleaves[0],bfp,2,out var rec) || !ReferenceEquals(AsVar(rec.Args[0]),bfp.Ins[0]) || !MentionsVar(rec.Args[1],bfp.Ins[1]) || !MentionsInt(rec.Args[1],1)) {
      Error(bfp.Tok,"BranchFalsePrefix recursive leaf is not exact"); return;
    }
    if (!IsCallTo(bleaves[1],markerFuncs["Branch"],2,out var br) || !MentionsVar(br.Args[0],bfp.Ins[0]) || !MentionsVar(br.Args[0],bfp.Ins[1]) || !MentionsInt(br.Args[0],1) || !IsFalse(br.Args[1])) {
      Error(bfp.Tok,"BranchFalsePrefix false-event leaf is not exact"); return;
    }
    var cleaves=ConcatLeaves(Unwrap(ct.Body)).ToList();
    if (cleaves.Count!=3) { Error(ct.Tok,"ChunkTrace body is not three leaves"); return; }
    if (!IsCallTo(cleaves[0],bfp,2,out var cr) || !ReferenceEquals(AsVar(cr.Args[0]),ct.Ins[0]) || !ReferenceEquals(AsVar(cr.Args[1]),ct.Ins[1])) {
      Error(ct.Tok,"ChunkTrace prefix leaf is not exact"); return;
    }
    if (!IsCallTo(cleaves[1],markerFuncs["Branch"],2,out var cb) || !MentionsVar(cb.Args[0],ct.Ins[0]) || !MentionsVar(cb.Args[0],ct.Ins[1]) || !IsTrueLit(cb.Args[1])) {
      Error(ct.Tok,"ChunkTrace true-event leaf is not exact"); return;
    }
    if (!IsCallTo(cleaves[2],markerFuncs["Ops"],7,out var co) || !Enumerable.Range(0,7).All(i => IsInt(co.Args[i],0))) {
      Error(ct.Tok,"ChunkTrace ops leaf is not exact"); return;
    }
  }

  void CheckPureFunction(Function f) {
    string name=f.Name;
    if (f.ByMethodBody!=null || f.ByMethodDecl!=null || f.ByMethodTok!=null) {
      Error(f.Tok,name+": function-by-method is unsupported; the actual imperative body is not checked"); return;
    }
    if (!IsGhostTuple(f)) { Error(f.Tok,name+": result is not a (real, ghost) two-tuple"); return; }
    if (f.Ins.Count!=1) { Error(f.Tok,name+": expected exactly one public index parameter"); return; }
    var a=Chain(f.Body);
    int n=a.arms.Count+1;
    bool zetas = name.StartsWith("Zetas");
    bool chunk = name.StartsWith("ZetasChunk") || name.StartsWith("GammasChunk");
    bool len = name=="Len";
    bool value = name=="ZetasValue" || name=="GammasValue";
    if (chunk) {
      if (n!=16) { Error(f.Tok,name+": expected 16 literal arms"); return; }
      int c=int.Parse(name.Substring(name.StartsWith("ZetasChunk")?"ZetasChunk".Length:"GammasChunk".Length));
      int baseSite = zetas ? 1000+32*c : 2000+32*c;
      var ctf = FindF("NativePolynomial.ChunkTrace");
      for (int i=0;i<16;i++) {
        if (i<a.arms.Count && !IsFormalTest(a.arms[i].test,f.Ins[0],BinaryExpr.ResolvedOpcode.EqCommon,i,false)) { Error(a.arms[i].test.Tok,name+": arm "+i+" guard is not exact index==literal"); return; }
        var tup=TupleArgs(ArmExpr(a,i)); if (tup==null) { Error(ArmExpr(a,i).Tok,name+": arm "+i+" is not a real/ghost tuple"); return; }
        if (!TryInt(tup[0],out _)) { Error(tup[0].Tok,name+": arm "+i+" real result is not a literal"); return; }
        if (!IsCallTo(tup[1],ctf,2,out var gc) || !IsInt(gc.Args[0],baseSite) || !IsInt(gc.Args[1],i)) {
          Error(tup[1].Tok,name+": arm "+i+" ghost is not exact ChunkTrace("+baseSite+","+i+")"); return;
        }
      }
      return;
    }
    if (len) {
      if (n!=7) { Error(f.Tok,name+": expected 7 literal arms"); return; }
      for (int i=0;i<7;i++) {
        if (i<a.arms.Count && !IsFormalTest(a.arms[i].test,f.Ins[0],BinaryExpr.ResolvedOpcode.EqCommon,i,false)) { Error(a.arms[i].test.Tok,name+": arm "+i+" guard is not exact s==literal"); return; }
        var tup=TupleArgs(ArmExpr(a,i)); if (tup==null) { Error(ArmExpr(a,i).Tok,name+": arm "+i+" is not a real/ghost tuple"); return; }
        if (!TryInt(tup[0],out _)) { Error(tup[0].Tok,name+": arm "+i+" real result is not a literal"); return; }
        var leaves=ConcatLeaves(tup[1]).ToList();
        if (leaves.Count!=3) { Error(tup[1].Tok,name+": arm "+i+" ghost is not exactly [BranchFalsePrefix,Branch,Ops]"); return; }
        if (!IsCallTo(leaves[0],FindF("NativePolynomial.BranchFalsePrefix"),2,out var pf) || !IsInt(pf.Args[0],900) || !IsInt(pf.Args[1],i)) { Error(leaves[0].Tok,name+": arm "+i+" prefix is not exact BranchFalsePrefix(900,"+i+")"); return; }
        if (!IsCallTo(leaves[1],markerFuncs["Branch"],2,out var br) || !IsInt(br.Args[0],900+i) || !IsTrueLit(br.Args[1])) { Error(leaves[1].Tok,name+": arm "+i+" true event is not exact"); return; }
        if (!IsCallTo(leaves[2],markerFuncs["Ops"],7,out var op) || !Enumerable.Range(0,7).All(j => IsInt(op.Args[j],0))) { Error(leaves[2].Tok,name+": arm "+i+" Ops payload is not exact zeros"); return; }
      }
      return;
    }
    if (!value) { Error(f.Tok,name+": unsupported pure function shape"); return; }
    if (n!=8) { Error(f.Tok,name+": expected 8 value arms"); return; }
    int branchBase = zetas ? 800 : 850;
    int callSiteBase = zetas ? 430 : 440;
    int targetBase = zetas ? 31 : 41;
    for (int i=0;i<8;i++) {
      if (i<a.arms.Count && !IsFormalTest(a.arms[i].test,f.Ins[0],BinaryExpr.ResolvedOpcode.Lt,16*(i+1),true)) { Error(a.arms[i].test.Tok,name+": arm "+i+" guard is not exact index<literal"); return; }
      var tup=TupleArgs(ArmExpr(a,i)); if (tup==null) { Error(ArmExpr(a,i).Tok,name+": arm "+i+" is not a real/ghost tuple"); return; }
      var realCall=RealChildCall(tup[0]);
      var expected=FindF($"NativePolynomial.{(zetas?"Zetas":"Gammas")}Chunk{i}");
      if (realCall==null || realCall.Function==null || !ReferenceEquals(realCall.Function,expected) || realCall.Args.Count!=1) {
        Error(tup[0].Tok,name+": arm "+i+" real result is not a .0 projection of the exact chunk function"); return;
      }
      var leaves=ConcatLeaves(tup[1]).ToList();
      if (leaves.Count!=5) { Error(tup[1].Tok,name+": arm "+i+" ghost is not exactly five ordered leaves"); return; }
      if (!IsCallTo(leaves[0],FindF("NativePolynomial.BranchFalsePrefix"),2,out var pf) || !IsInt(pf.Args[0],branchBase) || !IsInt(pf.Args[1],i)) { Error(leaves[0].Tok,name+": arm "+i+" prefix is not exact BranchFalsePrefix("+branchBase+","+i+")"); return; }
      if (!IsCallTo(leaves[1],markerFuncs["Branch"],2,out var br) || !IsInt(br.Args[0],branchBase+i) || !IsTrueLit(br.Args[1])) { Error(leaves[1].Tok,name+": arm "+i+" true event is not exact"); return; }
      if (!IsCallTo(leaves[2],markerFuncs["Ops"],7,out var op) || !IsInt(op.Args[0],0) || !IsInt(op.Args[1],1) || !IsInt(op.Args[2],0) || !IsInt(op.Args[3],0) || !IsInt(op.Args[4],0) || !IsInt(op.Args[5],0) || !IsInt(op.Args[6],0)) { Error(leaves[2].Tok,name+": arm "+i+" Ops payload is not exact (0,1,0,0,0,0,0)"); return; }
      if (!IsCallTo(leaves[3],markerFuncs["Call"],3,out var ca) || !IsInt(ca.Args[0],callSiteBase+i) || !IsInt(ca.Args[1],targetBase+i) || !IsInt(ca.Args[2],1)) { Error(leaves[3].Tok,name+": arm "+i+" Call payload is not exact"); return; }
      var child=GhostChildCall(leaves[4]);
      if (child==null || child.Function==null || !ReferenceEquals(child.Function,expected) || child.Args.Count!=1 || !ExprEq(child.Args[0],realCall.Args[0])) {
        Error(leaves[4].Tok,name+": arm "+i+" last leaf is not actual child .1 with the same argument"); return;
      }
    }
  }

  void CheckControlFunction(Function f) {
    if (f.ByMethodBody!=null || f.ByMethodDecl!=null || f.ByMethodTok!=null) {
      Error(f.Tok,f.Name+": function-by-method is unsupported; the actual imperative body is not checked"); return;
    }
    if (!IsGhostTuple(f)) { Error(f.Tok,f.Name+": result is not a (real, ghost) two-tuple"); return; }
    var roles=new List<object>();
    foreach (var p in f.Ins) roles.Add(p);
    var cls=f.EnclosingClass as TopLevelDeclWithMembers;
    if (cls!=null) foreach (var mem in cls.Members) if (mem is Field fld) roles.Add(fld);
    object RoleOf(Expression e) {
      e=Unwrap(e);
      if (e is IdentifierExpr ie) return ie.Var;
      if (e is MemberSelectExpr ms && ms.Member is Field fld) return fld;
      return null;
    }
    var a=Chain(f.Body);
    int n=a.arms.Count+1;
    int? branchSite=null;
    for (int i=0;i<n;i++) {
      var tup=TupleArgs(ArmExpr(a,i));
      if (tup==null) { Error(ArmExpr(a,i).Tok,f.Name+": arm "+i+" is not a real/ghost tuple"); return; }
      var ghost=Unwrap(tup[1]);
      var calls=ghost.DescendantsAndSelf.OfType<FunctionCallExpr>().ToList();
      if (a.arms.Count>0) {
        bool want = i<a.arms.Count;
        var branches=calls.Where(fc => fc.Function==markerFuncs["Branch"] && fc.Args.Count==2 && TryInt(fc.Args[0],out _)).ToList();
        if (branches.Count==0) { Error(tup[1].Tok,f.Name+": arm "+i+" is missing Branch observation"); return; }
        bool has= branches.Any(fc => IsTrue(fc.Args[1])==want);
        if (!has) { Error(tup[1].Tok,f.Name+": arm "+i+" Branch taken value is inconsistent"); return; }
        foreach (var br in branches) {
          if (!TryInt(br.Args[0],out var sv)) { Error(br.Tok,f.Name+": Branch site is not literal"); return; }
          if (branchSite==null) branchSite=(int)sv;
          else if (branchSite!=(int)sv) { Error(br.Tok,f.Name+": Branch site differs between arms"); return; }
        }
        if (i<a.arms.Count && !IsFormalTest(a.arms[i].test,f.Ins[0],BinaryExpr.ResolvedOpcode.EqCommon,0,false)) {
          // The control guards may compare a formal to 0; accept Eq or Lt forms.
          var test=Unwrap(a.arms[i].test);
          if (!(test is BinaryExpr tb && (tb.ResolvedOp==BinaryExpr.ResolvedOpcode.EqCommon || tb.ResolvedOp==BinaryExpr.ResolvedOpcode.Lt) && ReferenceEquals(AsVar(tb.E0),f.Ins[0]) && tb.E1 is LiteralExpr)) {
            Error(a.arms[i].test.Tok,f.Name+": arm "+i+" guard is not a literal comparison on the first parameter"); return;
          }
        }
      }
      foreach (var sel in Unwrap(tup[0]).DescendantsAndSelf.OfType<SeqSelectExpr>()) {
        if (sel.E0==null || sel.E1!=null) continue;
        var actual=RoleOf(sel.Seq);
        bool ok=calls.Any(fc => fc.Function==markerFuncs["Read"] && fc.Args.Count==3 && TryInt(fc.Args[1],out var rid) && rid>=0 && rid<roles.Count && ReferenceEquals(roles[(int)rid],actual) && ExprEq(fc.Args[2],sel.E0));
        if (!ok) { Error(tup[1].Tok,f.Name+": arm "+i+" is missing exact Read for array address"); return; }
      }
      foreach (var call in Unwrap(tup[0]).DescendantsAndSelf.OfType<FunctionCallExpr>()) {
        if (call.Function==null || !pureFuncs.Contains(call.Function)) continue;
        bool ok=calls.Any(fc => fc.Function==markerFuncs["Call"] && fc.Args.Count==3 && TryInt(fc.Args[1],out var tid) && funcIds.TryGetValue(call.Function,out var wantId) && (int)tid==wantId && TryInt(fc.Args[2],out var ar) && (int)ar==call.Args.Count);
        if (!ok) { Error(tup[1].Tok,f.Name+": arm "+i+" is missing exact Call for child function"); return; }
      }
    }
  }
}
