package org.microproxy.thirdparty.larky.modules.re;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.microproxy.thirdparty.larky.modules.re.PyRegexTranslator.Translation;

import org.microproxy.thirdparty.starlark.eval.EvalException;

/**
 * A Python {@code re} pattern running on {@link java.util.regex}.
 *
 * <p>The pattern is translated once per class mode (Unicode for str input, ASCII for bytes input).
 * Matching uses a region with transparent, non-anchoring bounds, so that {@code ^}, {@code \A},
 * look-behind and {@code \b} see the text before {@code pos}, as in Python; the text is cut at
 * {@code endpos} by the caller. An empty match is rejected where a search must advance (after an
 * empty match) by a variant that fails when it ends at {@code \G} (the search start), so the engine
 * backtracks into a non-empty alternative there, as CPython's does.
 *
 * <p>All positions are UTF-16 indices, like Starlark's string indices.
 *
 * <p>Java's engine backtracks: a pathological pattern can take exponential time. Every match runs
 * on a {@link Deadline} input that aborts once the calling thread's deadline passes.
 */
final class PyRegex {

  static final int SEARCH = 0;
  static final int MATCH = 1;
  static final int FULLMATCH = 2;

  final String source;
  final int flags;
  private final Translation unicode;
  private volatile Translation ascii;
  // [ascii][mustAdvance]; Patterns are immutable, so a racy lazy init is harmless.
  private final Pattern[] compiled = new Pattern[4];

  PyRegex(String source, int flags) throws EvalException {
    this.source = source;
    this.flags = flags;
    this.unicode = PyRegexTranslator.translate(source, flags, false);
    // Compile the main variant now so that errors Java reports surface at compile time.
    pattern(false, false);
  }

  int groups() {
    return unicode.groups;
  }

  Map<String, Integer> groupIndex() {
    return unicode.groupIndex;
  }

  private Translation translation(boolean asciiMode) throws EvalException {
    if (!asciiMode) {
      return unicode;
    }
    Translation t = ascii;
    if (t == null) {
      t = PyRegexTranslator.translate(source, flags, true);
      ascii = t;
    }
    return t;
  }

  /** The Java source of the main (str input) pattern. */
  String javaSource() throws EvalException {
    return pattern(false, false).pattern();
  }

  private Pattern pattern(boolean asciiMode, boolean mustAdvance) throws EvalException {
    int key = (asciiMode ? 2 : 0) + (mustAdvance ? 1 : 0);
    Pattern p = compiled[key];
    if (p != null) {
      return p;
    }
    Translation t = translation(asciiMode);
    String java = PyRegexTranslator.javaFlags(t.flags, asciiMode)
        + (mustAdvance ? "(?:" + t.pattern + ")(?<!\\G)" : t.pattern);
    try {
      p = Pattern.compile(java);
    } catch (PatternSyntaxException e) {
      throw new EvalException("re.error: " + e.getDescription() + " (java.util.regex)");
    } catch (StackOverflowError e) {
      throw new EvalException("re.error: pattern too complex");
    }
    compiled[key] = p;
    return p;
  }

  /**
   * Runs the pattern on {@code text} (already cut at endpos) from {@code pos}, giving up after
   * {@code deadline} (epoch millis). Returns the group spans {start0, end0, start1, end1, ...} (-1
   * for groups that did not participate), or null.
   *
   * <p>{@code mustAdvance} (for searches that continue after an empty match at {@code pos}) rejects
   * an empty match at {@code pos}.
   */
  int[] run(CharSequence text, int pos, int kind, boolean mustAdvance, boolean asciiMode,
      long deadline) throws EvalException {
    int n = text.length();
    if (pos > n) {
      return null;
    }
    Matcher m = pattern(asciiMode, mustAdvance && kind == SEARCH)
        .matcher(new Deadline(text, deadline));
    m.useTransparentBounds(true);
    m.useAnchoringBounds(false);
    m.region(pos, n);
    boolean found;
    try {
      switch (kind) {
        case SEARCH:
          found = m.find();
          break;
        case MATCH:
          found = m.lookingAt();
          break;
        default:
          found = m.matches();
      }
    } catch (Deadline.Expired e) {
      throw new EvalException("re.error: regular expression ran past the deadline");
    } catch (StackOverflowError e) {
      throw new EvalException("re.error: regular expression too complex for this input");
    }
    return found ? spans(m) : null;
  }

  private static int[] spans(Matcher m) {
    int groups = m.groupCount();
    int[] spans = new int[2 * (groups + 1)];
    for (int g = 0; g <= groups; g++) {
      int s = m.start(g);
      spans[2 * g] = s;
      spans[2 * g + 1] = s < 0 ? -1 : m.end(g);
    }
    return spans;
  }

  /**
   * Python's re.split: pieces of the text between matches, and the groups of each match.
   * Returns flat (start, end) pairs, (-1, -1) for groups that did not participate.
   */
  int[] split(CharSequence text, int maxsplit, boolean asciiMode, long deadline)
      throws EvalException {
    List<int[]> out = new ArrayList<>();
    int last = 0;
    int pos = 0;
    int count = 0;
    boolean mustAdvance = false;
    while (maxsplit <= 0 || count < maxsplit) {
      int[] s = run(text, pos, SEARCH, mustAdvance, asciiMode, deadline);
      if (s == null) {
        break;
      }
      out.add(new int[] {last, s[0]});
      for (int g = 1; 2 * g < s.length; g++) {
        out.add(new int[] {s[2 * g], s[2 * g + 1]});
      }
      last = s[1];
      pos = s[1];
      mustAdvance = s[0] == s[1];
      count++;
    }
    out.add(new int[] {last, text.length()});
    int[] flat = new int[out.size() * 2];
    for (int k = 0; k < out.size(); k++) {
      flat[2 * k] = out.get(k)[0];
      flat[2 * k + 1] = out.get(k)[1];
    }
    return flat;
  }

  // --- Replacement templates ------------------------------------------------------------------

  /**
   * Parses a replacement template as CPython's {@code re._parser.parse_template} does. Returns a
   * list of literal Strings and Integer group numbers.
   */
  List<Object> parseTemplate(String repl) throws EvalException {
    List<Object> items = new ArrayList<>();
    StringBuilder literal = new StringBuilder();
    int n = repl.length();
    int i = 0;
    while (i < n) {
      char c = repl.charAt(i);
      if (c != '\\') {
        literal.append(c);
        i++;
        continue;
      }
      int start = i;
      i++;
      if (i >= n) {
        throw PyRegexTranslator.error("bad escape (end of pattern)", start);
      }
      c = repl.charAt(i);
      i++;
      if (c == 'g') {
        if (i >= n || repl.charAt(i) != '<') {
          throw PyRegexTranslator.error("missing <", i);
        }
        i++;
        int nameStart = i;
        int close = repl.indexOf('>', i);
        if (close < 0) {
          throw PyRegexTranslator.error("missing >, unterminated name", nameStart);
        }
        String name = repl.substring(nameStart, close);
        if (name.isEmpty()) {
          throw PyRegexTranslator.error("missing group name", nameStart);
        }
        i = close + 1;
        int index;
        if (name.chars().allMatch(ch -> ch >= '0' && ch <= '9')) {
          try {
            index = Integer.parseInt(name);
          } catch (NumberFormatException e) {
            index = Integer.MAX_VALUE;
          }
          if (index > groups()) {
            throw PyRegexTranslator.error("invalid group reference " + name, nameStart);
          }
        } else if (PyRegexTranslator.isIdentifier(name)) {
          Integer idx = groupIndex().get(name);
          if (idx == null) {
            throw new EvalException(
                "IndexError: unknown group name " + PyRegexTranslator.pyRepr(name));
          }
          index = idx;
        } else {
          throw PyRegexTranslator.error(
              "bad character in group name " + PyRegexTranslator.pyRepr(name), nameStart);
        }
        addGroup(items, literal, index);
      } else if (c == '0') {
        int value = 0;
        for (int k = 0; k < 2 && i < n && isOctal(repl.charAt(i)); k++) {
          value = value * 8 + (repl.charAt(i++) - '0');
        }
        literal.append((char) (value & 0xff));
      } else if (c >= '1' && c <= '9') {
        int digitsEnd = i;
        if (i < n && Character.isDigit(repl.charAt(i)) && repl.charAt(i) < 128) {
          digitsEnd = i + 1;
          if (isOctal(c) && isOctal(repl.charAt(i)) && i + 1 < n && isOctal(repl.charAt(i + 1))) {
            int value = (c - '0') * 64 + (repl.charAt(i) - '0') * 8 + (repl.charAt(i + 1) - '0');
            if (value > 0377) {
              throw PyRegexTranslator.error("octal escape value " + repl.substring(start, i + 2)
                  + " outside of range 0-0o377", start);
            }
            literal.append((char) value);
            i += 2;
            continue;
          }
        }
        int group = Integer.parseInt(repl.substring(start + 1, digitsEnd));
        i = digitsEnd;
        if (group > groups()) {
          throw PyRegexTranslator.error("invalid group reference " + group, start + 1);
        }
        addGroup(items, literal, group);
      } else {
        switch (c) {
          case 'a':
            literal.append((char) 7);
            break;
          case 'b':
            literal.append('\b');
            break;
          case 'f':
            literal.append('\f');
            break;
          case 'n':
            literal.append('\n');
            break;
          case 'r':
            literal.append('\r');
            break;
          case 't':
            literal.append('\t');
            break;
          case 'v':
            literal.append((char) 0x0b);
            break;
          case '\\':
            literal.append('\\');
            break;
          default:
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
              throw PyRegexTranslator.error("bad escape \\" + c, start);
            }
            // Unknown escapes of other characters are kept as they are.
            literal.append('\\').append(c);
        }
      }
    }
    if (literal.length() > 0) {
      items.add(literal.toString());
    }
    return items;
  }

  private static void addGroup(List<Object> items, StringBuilder literal, int group) {
    if (literal.length() > 0) {
      items.add(literal.toString());
      literal.setLength(0);
    }
    items.add(group);
  }

  private static boolean isOctal(char c) {
    return c >= '0' && c <= '7';
  }

  /** Input that aborts matching once a deadline passes. */
  static final class Deadline implements CharSequence {

    static final class Expired extends RuntimeException {
      private static final long serialVersionUID = 1L;

      Expired() {
        super(null, null, false, false);
      }
    }

    private final CharSequence s;
    private final long deadline;
    private int reads;

    Deadline(CharSequence s, long deadline) {
      this.s = s;
      this.deadline = deadline;
    }

    @Override
    public char charAt(int index) {
      if ((++reads & 0xFFF) == 0 && System.currentTimeMillis() > deadline) {
        throw new Expired();
      }
      return s.charAt(index);
    }

    @Override
    public int length() {
      return s.length();
    }

    @Override
    public CharSequence subSequence(int start, int end) {
      return s.subSequence(start, end);
    }

    @Override
    public String toString() {
      return s.toString();
    }
  }
}
