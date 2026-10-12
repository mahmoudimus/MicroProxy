#!/usr/bin/env python3
"""Checks that the documentation still says everything an older README said.

Used once, when the README was split into docs/, and kept for the next restructure:

    python3 docs/scripts/check_fidelity.py <old README.md> [README.md docs/]

Three checks, against the new README and every Markdown page under docs/:

1. Lines: every non-blank line of the old README, with links reduced to their text, run-in bold
   heads and heading marks removed and whitespace collapsed, appears in the new text.
2. Code spans: every `...` of the old README (flags, properties, stat names, operators, Starlark
   functions, classes) appears as a code span of the new text.
3. Headings: every heading of the old README appears as a heading (or bold head) of the new text.

Whatever is missing is printed; exit status 1 if anything is.
"""
import glob
import os
import re
import sys


def unlink(text):
    text = re.sub(r"<a id=\"[^\"]*\"></a>", "", text)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    return text


def norm(line):
    line = unlink(line).strip()
    line = re.sub(r"^#+\s+", "", line)
    line = re.sub(r"^\*\*([^*]+)\*\*\s*", "", line) if re.match(r"^\*\*[^*]+[.:]\*\*", line) else line
    return " ".join(line.split())


def spans(text):
    text = re.sub(r"(?ms)^\s*```.*?^\s*```[^\n]*$", "", text)
    return set(s.strip() for s in re.findall(r"`([^`\n]+)`", text))


def headings(text):
    out, fence = set(), False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence
        elif not fence:
            m = re.match(r"^#+\s+(.*)$", line)
            if m:
                out.add(" ".join(unlink(m.group(1)).split()).lower())
            m = re.match(r"^(?:<a id=\"[^\"]*\"></a>)?\*\*([^*]+?)[.:]?\*\*", line)
            if m:
                out.add(" ".join(m.group(1).split()).lower())
    return out


def main(argv):
    old = open(argv[1], encoding="utf-8").read()
    old_lines = unlink(old).splitlines()  # links may span lines
    sources = argv[2:] or ["README.md", "docs"]
    files = []
    for s in sources:
        files += sorted(glob.glob(os.path.join(s, "**", "*.md"), recursive=True)) if os.path.isdir(s) else [s]
    new = "\n".join(open(f, encoding="utf-8").read() for f in files)
    new_flat = " ".join(norm(l) for l in unlink(new).splitlines() if l.strip())
    new_flat = " " + " ".join(new_flat.split()) + " "

    missing_lines = []
    for n, line in enumerate(old_lines, 1):
        t = norm(line)
        if t and t not in new_flat:
            missing_lines.append((n, line))
    new_spans = spans(new)
    missing_spans = sorted(s for s in spans(old) if s not in new_spans)
    new_heads = headings(new)
    missing_heads = sorted(h for h in headings(old) if h not in new_heads)

    for n, line in missing_lines:
        print("line %d: %s" % (n, line))
    for s in missing_spans:
        print("code span: `%s`" % s)
    for h in missing_heads:
        print("heading: %s" % h)
    print("%d lines, %d code spans, %d headings of the old README not found (of %d lines, %d spans, %d headings)"
          % (len(missing_lines), len(missing_spans), len(missing_heads), len(old_lines),
             len(spans(old)), len(headings(old))))
    return 1 if missing_lines or missing_spans or missing_heads else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
