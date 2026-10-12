"""MkDocs hooks, registered in mkdocs.yml under `hooks:`.

- on_page_markdown: in table rows, `a\\|b` code spans become `a|b`. GitHub needs the backslash to
  keep a pipe inside a code span from splitting the cell; Python-Markdown's tables already respect
  code spans, and would show the backslash.
- on_post_build: writes llms.txt and llms-full.txt at the root of the built site (the generation
  is in gen_llms.py, which can also run on its own; see its docstring).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gen_llms  # noqa: E402

_CODE_SPAN = re.compile(r"`[^`\n]*`")


def on_page_markdown(markdown, **kwargs):
    lines, fence = [], False
    for line in markdown.split("\n"):
        if line.lstrip().startswith("```"):
            fence = not fence
        elif not fence and line.lstrip().startswith("|"):
            line = _CODE_SPAN.sub(lambda m: m.group(0).replace("\\|", "|"), line)
        lines.append(line)
    return "\n".join(lines)


def on_post_build(config, **kwargs):
    gen_llms.write_site(gen_llms.load_config(), config["site_dir"])
