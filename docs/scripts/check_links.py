#!/usr/bin/env python3
"""Checks the links of every Markdown file in the repository, as GitHub resolves them.

`mkdocs build --strict` checks the links between pages of docs/; this also covers the README, the
module READMEs and the other Markdown files, and the links from docs/ to files outside it:

- a relative link must name an existing file, and its #anchor a heading (by GitHub's slug rules)
  or an explicit <a id="..."> / name="..." in that file;
- an absolute link into this repository (https://github.com/mahmoudimus/MicroProxy/blob/main/...
  or /tree/main/...) is checked the same way against the working tree;
- a bare #anchor must exist in the same file.

    python3 docs/scripts/check_links.py          # exit status 1 if any link is broken

CHANGELOG.md is reported but never fails the check: it records links as they were.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO_URL = re.compile(r"^https://github\.com/mahmoudimus/MicroProxy/(?:blob|tree)/main/([^#?]*)(?:#(.*))?$")
LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)|\[[^\]]*\]:\s*(\S+)")
NOT_ENFORCED = {"CHANGELOG.md"}


def markdown_files():
    out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "*.md"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    return sorted(p for p in out.split() if not p.startswith(("site/", "target/")) and "/target/" not in p)


def strip_code(text):
    """Removes fenced code blocks and inline code, which hold no links."""
    text = re.sub(r"(?ms)^\s*(```|~~~).*?^\s*\1[^\n]*$", "", text)
    return re.sub(r"`[^`\n]*`", "", text)


def gh_slug(heading):
    t = re.sub(r"<[^>]+>", "", heading)
    t = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = t.replace("`", "").strip().lower()
    t = re.sub(r"[^\w\- ]", "", t)
    return t.replace(" ", "-")


_anchor_cache = {}


def anchors(path):
    if path in _anchor_cache:
        return _anchor_cache[path]
    found, counts = set(), {}
    with open(path, encoding="utf-8") as f:
        text = f.read()
    fence = False
    for line in text.splitlines():
        if re.match(r"^\s*(```|~~~)", line):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            slug = gh_slug(m.group(1))
            n = counts.get(slug, 0)
            counts[slug] = n + 1
            found.add(slug if n == 0 else "%s-%d" % (slug, n))
        found.update(re.findall(r"""<a\s+(?:id|name)=["']([^"']+)["']""", line))
    _anchor_cache[path] = found
    return found


def check(target_path, fragment, source, raw):
    if not os.path.exists(target_path):
        return "%s: %s: no such file" % (source, raw)
    if fragment and target_path.endswith(".md") and os.path.isfile(target_path):
        if fragment.lower() not in anchors(target_path) and fragment not in anchors(target_path):
            return "%s: %s: no anchor #%s" % (source, raw, fragment)
    return None


def main():
    errors, warnings = [], []
    for rel in markdown_files():
        path = os.path.join(ROOT, rel)
        with open(path, encoding="utf-8") as f:
            text = strip_code(f.read())
        for m in LINK.finditer(text):
            raw = m.group(1) or m.group(2)
            problem = None
            repo = REPO_URL.match(raw)
            if repo:
                problem = check(os.path.join(ROOT, repo.group(1)), repo.group(2), rel, raw)
            elif re.match(r"^[a-z][a-z0-9+.-]*:", raw) or raw.startswith("//"):
                continue
            elif raw.startswith("#"):
                problem = check(path, raw[1:], rel, raw)
            else:
                file, _, fragment = raw.partition("#")
                problem = check(os.path.normpath(os.path.join(os.path.dirname(path), file)), fragment, rel, raw)
            if problem:
                (warnings if rel in NOT_ENFORCED else errors).append(problem)
    for w in warnings:
        print("warning: " + w)
    for e in errors:
        print("error: " + e)
    print("%d broken links" % len(errors))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
