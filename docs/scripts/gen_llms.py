#!/usr/bin/env python3
"""Generates llms.txt and llms-full.txt (https://llmstxt.org) from mkdocs.yml and docs/.

llms.txt is the site's title, a summary and a link list of every page in the navigation, each
with the first sentence of the page's summary paragraph (the paragraph right after its H1).
llms-full.txt is every page's Markdown, in navigation order, with relative links made absolute.

    python3 docs/scripts/gen_llms.py write          # rewrite docs/llms.txt (committed)
    python3 docs/scripts/gen_llms.py check          # fail if docs/llms.txt is stale
    python3 docs/scripts/gen_llms.py site <dir>     # write llms.txt and llms-full.txt into <dir>

The MkDocs hook in hooks.py runs the "site" step after every build, so the published site
always has both files at its root. Only the standard library and PyYAML (an MkDocs dependency)
are used.
"""
import os
import posixpath
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Navigation sections whose pages are listed under llms.txt's "Optional" heading: an agent with a
# small context can skip them.
OPTIONAL_SECTIONS = {"Project"}


class _Loader(yaml.SafeLoader):
    """A safe loader that tolerates MkDocs' !!python/... tags (it never calls them)."""


_Loader.add_multi_constructor("tag:yaml.org,2002:python/", lambda loader, suffix, node: None)
_Loader.add_multi_constructor("!", lambda loader, suffix, node: None)


def load_config(root=ROOT):
    with open(os.path.join(root, "mkdocs.yml"), encoding="utf-8") as f:
        config = yaml.load(f, Loader=_Loader)
    config.setdefault("docs_dir", "docs")
    return config


def nav_pages(nav, section=None):
    """Yields (section, title, path) for every Markdown page of the navigation, in order."""
    for item in nav:
        if isinstance(item, str):
            yield section, None, item
            continue
        for title, value in item.items():
            if isinstance(value, list):
                yield from nav_pages(value, title)
            elif isinstance(value, str) and value.endswith(".md"):
                yield section, title, value


def page_url(site_url, path):
    """The page's URL with MkDocs' directory URLs: guides/http2.md -> <site>/guides/http2/."""
    stem = path[:-3]
    if stem == "index":
        return site_url
    if stem.endswith("/index"):
        stem = stem[: -len("/index")]
    return site_url + stem + "/"


def read_page(docs_dir, path):
    with open(os.path.join(docs_dir, path), encoding="utf-8") as f:
        return f.read()


def title_and_summary(markdown):
    """The H1 and the first paragraph after it (skipping HTML comments)."""
    lines = markdown.splitlines()
    title, i = None, 0
    for i, line in enumerate(lines):
        if line.startswith("# "):
            title = line[2:].strip()
            break
    paragraph = []
    for line in lines[i + 1:]:
        if not line.strip():
            if paragraph:
                break
            continue
        if line.lstrip().startswith(("<!--", "#", "```", "|", "-", ">")) and not paragraph:
            continue
        paragraph.append(line.strip())
    return title, " ".join(paragraph)


def strip_markdown(text):
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return text.replace("**", "")


def first_sentence(text):
    text = strip_markdown(text)
    m = re.search(r"(?<=[.!?])\s+(?=[A-Z`\[])", text)
    return text[: m.start()] if m else text


def absolute_links(markdown, path, site_url):
    """Rewrites relative .md links (and anchors) of the page at `path` into site URLs."""
    base = posixpath.dirname(path)

    def repl(m):
        target = m.group(2)
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("/"):
            return m.group(0)
        file, _, fragment = target.partition("#")
        if not file:
            url = page_url(site_url, path)
        elif file.endswith(".md"):
            url = page_url(site_url, posixpath.normpath(posixpath.join(base, file)))
        else:
            return m.group(0)
        return "%s(%s%s)" % (m.group(1), url, "#" + fragment if fragment else "")

    return re.sub(r"(\]|\]: ?)\(([^)\s]+)\)", repl, markdown)


def llms_txt(config, root=ROOT):
    docs_dir = os.path.join(root, config["docs_dir"])
    site_url = config["site_url"]
    out = ["# " + config["site_name"], "", "> " + " ".join(config["site_description"].split()), ""]
    out += [
        "MicroProxy's documentation, one page per topic. Each link below is a page of the site, with",
        "the first sentence of its summary. " + site_url + "llms-full.txt has every page in one",
        "Markdown file, and the Java API (Javadoc) is at " + site_url + "api/.",
        "",
    ]
    sections, optional = {}, []
    for section, title, path in nav_pages(config["nav"]):
        page_title, summary = title_and_summary(read_page(docs_dir, path))
        entry = "- [%s](%s): %s" % (title or page_title, page_url(site_url, path), first_sentence(summary))
        if section in OPTIONAL_SECTIONS:
            optional.append(entry)
        else:
            if section is None:
                section = "Overview" if path == "index.md" else "More"
            sections.setdefault(section, []).append(entry)
    for section, entries in sections.items():
        out += ["## " + section, ""] + entries + [""]
    out += ["## Optional", "", "- [Java API (Javadoc)](%sapi/): the aggregated Javadoc of the published modules" % site_url]
    out += optional + [""]
    return "\n".join(out)


def llms_full_txt(config, root=ROOT):
    docs_dir = os.path.join(root, config["docs_dir"])
    site_url = config["site_url"]
    out = ["# " + config["site_name"], "", "> " + " ".join(config["site_description"].split()), ""]
    for _, _, path in nav_pages(config["nav"]):
        markdown = absolute_links(read_page(docs_dir, path), path, site_url).strip()
        out += ["", "<!-- " + page_url(site_url, path) + " -->", "", markdown, ""]
    return "\n".join(out)


def main(argv):
    config = load_config()
    committed = os.path.join(ROOT, config["docs_dir"], "llms.txt")
    if len(argv) == 2 and argv[1] == "write":
        with open(committed, "w", encoding="utf-8") as f:
            f.write(llms_txt(config))
        return 0
    if len(argv) == 2 and argv[1] == "check":
        with open(committed, encoding="utf-8") as f:
            if f.read() != llms_txt(config):
                print("docs/llms.txt is stale: run python3 docs/scripts/gen_llms.py write", file=sys.stderr)
                return 1
        return 0
    if len(argv) == 3 and argv[1] == "site":
        write_site(config, argv[2])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


def write_site(config, site_dir, root=ROOT):
    os.makedirs(site_dir, exist_ok=True)
    with open(os.path.join(site_dir, "llms.txt"), "w", encoding="utf-8") as f:
        f.write(llms_txt(config, root))
    with open(os.path.join(site_dir, "llms-full.txt"), "w", encoding="utf-8") as f:
        f.write(llms_full_txt(config, root))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
