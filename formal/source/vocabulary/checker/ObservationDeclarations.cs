using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Dafny;
using Microsoft.Dafny.Plugins;

// Trusted, tiny resolved-AST policy adapter.  Dafny's official pinned parser
// supplies declarations, attributes, contracts and bodies; this code does not
// lex or parse Dafny source.  It only rejects owned declarations with no
// implementation.  It is not a theorem and not a second executable semantics.
public class ObservationDeclarationsConfiguration : PluginConfiguration {
  public override Rewriter[] GetRewriters(ErrorReporter reporter) =>
    new Rewriter[] { new ObservationDeclarationsRewriter(reporter) };
}

public class ObservationDeclarationsRewriter : Rewriter {
  readonly ErrorReporter reporter;

  public ObservationDeclarationsRewriter(ErrorReporter reporter) : base(reporter) {
    this.reporter = reporter;
  }

  static string PathOf(IOrigin token) {
    if (token == null) return null;
    var path = token.Filepath;
    if (string.IsNullOrEmpty(path) && token.Uri != null && token.Uri.IsFile)
      path = token.Uri.LocalPath;
    if (string.IsNullOrEmpty(path)) return null;
    try { return Path.GetFullPath(path); }
    catch { return null; }
  }

  static string PathOf(Uri uri) {
    if (uri == null || !uri.IsFile || string.IsNullOrEmpty(uri.LocalPath)) return null;
    try { return Path.GetFullPath(uri.LocalPath); }
    catch { return null; }
  }

  void Error(IOrigin token, string message) {
    reporter.Error(MessageSource.Rewriter, token ?? Token.NoToken, message);
  }

  public override void PostResolve(Program program) {
    var raw = Environment.GetEnvironmentVariable("OBSERVATION_DECLARATION_FILES") ?? "";
    var owned = new HashSet<string>(
      raw.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
         .Select(Path.GetFullPath),
      StringComparer.Ordinal);
    if (owned.Count == 0) {
      Error(program.GetStartOfFirstFileToken(), "missing owned source file list");
      return;
    }

    var seenFiles = new SortedSet<string>(StringComparer.Ordinal);
    var checkedModules = new HashSet<string>(StringComparer.Ordinal);
    var checkedTypes = new HashSet<string>(StringComparer.Ordinal);
    var checkedMembers = new HashSet<string>(StringComparer.Ordinal);
    void Seen(IOrigin token) {
      var path = PathOf(token);
      if (path != null && owned.Contains(path)) seenFiles.Add(path);
    }

    // Official compiler file evidence: root URIs cover declaration-free entries,
    // while Program.Files include edges cover the rest of the parser closure.
    if (program.Compilation != null)
      foreach (var uri in program.Compilation.RootSourceUris) {
        var root = PathOf(uri);
        if (root != null && owned.Contains(root)) seenFiles.Add(root);
      }
    foreach (var file in program.Files)
      foreach (var include in file.Includes) {
        var includer = PathOf(include.IncluderFilename);
        var included = PathOf(include.IncludedFilename);
        if (includer != null && owned.Contains(includer)) seenFiles.Add(includer);
        if (included != null && owned.Contains(included)) seenFiles.Add(included);
      }

    foreach (var module in program.Modules()) {
      Seen(module.Tok);
      var moduleOwned = PathOf(module.Tok) is string modulePath && owned.Contains(modulePath);
      if (moduleOwned) {
        checkedModules.Add(module.FullName);
        if (module.ModuleKind != ModuleKindEnum.Concrete)
          Error(module.Tok, "unsupported owned abstract module: " + module.FullName);
      }

      foreach (var td in module.TopLevelDecls) {
        var tdOwned = PathOf(td.Tok) is string tdPath && owned.Contains(tdPath);
        if (tdOwned) seenFiles.Add(PathOf(td.Tok));
        if (tdOwned) {
          if (td is ModuleDecl) {
            // The referenced ModuleDefinition is checked separately.
          } else if (td is AbstractTypeDecl) {
            Error(td.Tok, "unsupported owned abstract type: " + td.FullName);
          } else if (td is TraitDecl) {
            Error(td.Tok, "unsupported owned trait: " + td.FullName);
          } else if (td is TypeSynonymDecl || td is NewtypeDecl || td is SubsetTypeDecl) {
            checkedTypes.Add(td.FullName);
            if (Attributes.Contains(td.Attributes, "opaque"))
              Error(td.Tok, "unsupported owned opaque type: " + td.FullName);
          } else if (td is DatatypeDecl || td is ClassDecl) {
            checkedTypes.Add(td.FullName);
          } else {
            Error(td.Tok, "unsupported owned declaration form: " + td.GetType().Name + " " + td.FullName);
          }
        }

        if (td is not TopLevelDeclWithMembers tw) continue;
        foreach (var mem in tw.Members) {
          var memPath = PathOf(mem.Tok);
          // An authored {:auto_generated} attribute is forgeable; it does not
          // establish a synthesized origin. Check every owned source member.
          if (memPath == null || !owned.Contains(memPath) ||
              !mem.Tok.IsSourceToken) continue;
          seenFiles.Add(memPath);
          checkedMembers.Add(mem.FullName);
          if (mem is Function fn) {
            if (fn.Body == null)
              Error(mem.Tok, "owned declaration missing implementation: " + fn.WhatKind + " " + fn.FullName);
          } else if (mem is Method method) {
            if (method.Body == null)
              Error(mem.Tok, "owned declaration missing implementation: " + method.WhatKind + " " + method.FullName);
          } else if (mem is ConstantField constant) {
            if (constant.Rhs == null)
              Error(mem.Tok, "owned declaration missing implementation: const " + constant.FullName);
          } else if (mem is Field) {
            // Class vars are storage declarations, not algorithm implementations.
          } else {
            Error(mem.Tok, "unsupported owned member form: " + mem.GetType().Name + " " + mem.FullName);
          }
        }
      }
    }

    foreach (var path in owned)
      if (!seenFiles.Contains(path))
        Error(program.GetStartOfFirstFileToken(), "unseen owned source file: " + path);

    foreach (var path in seenFiles)
      Console.WriteLine("OBSERVATION-DECLARATIONS FILE " + path);
    if (!reporter.HasErrors)
      Console.WriteLine("OBSERVATION-DECLARATIONS OK: files=" + seenFiles.Count +
                        " modules=" + checkedModules.Count + " types=" + checkedTypes.Count +
                        " members=" + checkedMembers.Count);
  }
}
