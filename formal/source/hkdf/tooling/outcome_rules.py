"""Finite coverage outcome rules. Data-only; no execution or proof authority."""
import re
BAD = re.compile(r'parse error|internal error|unhandled exception|timed? out|out of resource|CLI: Error',re.I)
DIAGNOSTIC = re.compile(r'^[^\r\n|]+\([0-9]+,[0-9]+\): Error: ([^\r\n]+)$',re.M)
def named_rejection(ordinary_exit, ordinary_text, plugin_exit, plugin_text, needle):
    if ordinary_exit != 0 or 'warning' in ordinary_text.lower() or BAD.search(ordinary_text): return False
    if plugin_exit != 2 or BAD.search(plugin_text): return False
    messages = DIAGNOSTIC.findall(plugin_text)
    if any('missing required HKDF source-trace root' in m for m in messages): return False
    return any(needle in message for message in messages)
