using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Microsoft.Dafny;

// Trusted structural policy for the fixed canonical wire codec. This checks
// resolved constructor/binder identities and actual returned values; it is not
// an additional encoder, interpreter, or proof of the C# adapter itself.
public static class NativeCanonicalEncoderPolicy {
  sealed class Layout {
    public int Tag;
    public int[] Fields;
    public int BoolField;
    public Layout(int tag, int boolField, params int[] fields) { Tag=tag; Fields=fields; BoolField=boolField; }
  }
  static readonly Dictionary<string,Layout> layouts = new() {
    {"Call", new(1,-1,0,1,2)}, {"Branch", new(2,1,0,1,-1)},
    {"Read", new(3,-1,0,1,2)}, {"Write", new(4,-1,0,1,2)},
    {"LoopBound", new(5,-1,0,1,-1)}, {"Ops", new(6,-1,0,1,2,3,4,5,6)},
    {"Alloc", new(7,-1,0,1,-1)}, {"ProviderCall", new(8,-1,0,1,2,3,4,5,6)},
    {"LoopCheck", new(9,1,0,1,2)}
  };
  static Expression Unwrap(Expression e) {
    while (e is ConcreteSyntaxExpression c && c.ResolvedExpression != null && !ReferenceEquals(c.ResolvedExpression,e)) e=c.ResolvedExpression;
    return e;
  }
  static bool Variable(Expression e, IVariable expected) => Unwrap(e) is IdentifierExpr id && ReferenceEquals(id.Var,expected);
  static bool Integer(Expression e, int value) {
    e=Unwrap(e);
    return e is LiteralExpr literal && ((literal.Value is BigInteger big && big == value) || (literal.Value is int small && small == value));
  }
  public static void Check(Function encode, Dictionary<string,DatatypeCtor> constructors, Action<IOrigin,string> error) {
    const string label="canonical Encode does not implement the exact typed wire layout";
    var body=encode.Body == null ? null : Unwrap(encode.Body);
    if (encode.Ins.Count != 1 || body is not NestedMatchExpr match || !Variable(match.Source,encode.Ins[0]) ||
        constructors.Count != layouts.Count || match.Cases.Count != layouts.Count) {
      error(encode.Tok,label+": expected complete direct Event match"); return;
    }
    var seen=new HashSet<DatatypeCtor>(ReferenceEqualityComparer.Instance);
    foreach (var branch in match.Cases) {
      if (branch.Pat is not IdPattern pattern || pattern.Ctor == null ||
          !layouts.TryGetValue(pattern.Ctor.Name,out var layout) ||
          !constructors.TryGetValue(pattern.Ctor.Name,out var expected) || !ReferenceEquals(pattern.Ctor,expected) ||
          !seen.Add(pattern.Ctor) || pattern.Arguments == null || pattern.Arguments.Count != expected.Formals.Count) {
        error(branch.Tok,label+": constructor/pattern identity"); continue;
      }
      var variables=new List<IVariable>();
      foreach (var argument in pattern.Arguments) {
        if (argument is not IdPattern id || id.Arguments != null || id.BoundVar == null || id.ResolvedLit != null || id.IsWildcardPattern) {
          error(argument.Tok,label+": unsupported field pattern"); continue;
        }
        variables.Add(id.BoundVar);
      }
      if (variables.Count != expected.Formals.Count || variables.Distinct(ReferenceEqualityComparer.Instance).Count() != variables.Count ||
          Unwrap(branch.Body) is not SeqDisplayExpr sequence || sequence.Elements.Count != layout.Fields.Length+1 || !Integer(sequence.Elements[0],layout.Tag)) {
        error(branch.Tok,label+": field count/tag/value"); continue;
      }
      for (int i=0;i<layout.Fields.Length;i++) {
        var field=layout.Fields[i]; var value=sequence.Elements[i+1];
        if (field == -1) {
          if (!Integer(value,0)) error(value.Tok,label+": padding must be zero");
        } else if (field < 0 || field >= variables.Count) {
          error(branch.Tok,label+": field layout/schema mismatch");
        } else if (field == layout.BoolField) {
          if (Unwrap(value) is not ITEExpr choice || !Variable(choice.Test,variables[field]) || !Integer(choice.Thn,1) || !Integer(choice.Els,0))
            error(value.Tok,label+": Boolean metadata not retained");
        } else if (!Variable(value,variables[field])) {
          error(value.Tok,label+": field metadata changed or reordered");
        }
      }
    }
    if (seen.Count != layouts.Count) error(encode.Tok,label+": missing constructor case");
  }
}
