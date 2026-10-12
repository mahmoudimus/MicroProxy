package org.microproxy.thirdparty.starlark.eval;

import java.util.Map;

/**
 * MicroProxy: the approximate sizes in bytes of the values Starlark code creates, which {@link
 * StarlarkThread#allocate} counts against a thread's budget. They are estimates for a 64-bit JVM
 * (an object header of {@value #OBJECT} bytes, references of {@value #REFERENCE}), not
 * measurements: a string is counted at two bytes a character although a compact Latin-1 string
 * takes one, and ints, floats and booleans are not counted at all. They count what a call creates,
 * not what stays reachable.
 */
public final class Allocations {

  /** The bytes counted for an object header. */
  public static final int OBJECT = 16;

  /** The bytes counted for a reference: an element slot of a list, tuple or dict. */
  public static final int REFERENCE = 8;

  /** The bytes counted for one dict entry beyond its key and value (a hash map node and slot). */
  public static final int DICT_ENTRY = 48;

  // How deep sizeOf looks into nested values; deeper ones count as one object each.
  private static final int MAX_DEPTH = 32;

  private Allocations() {}

  /**
   * A string of {@code length} characters: the object, its array and two bytes a character.
   *
   * @param length the number of characters
   * @return the estimate in bytes
   */
  public static long string(long length) {
    return 2L * OBJECT + 8 + 2 * length;
  }

  /**
   * A bytes value of {@code length} bytes: the object, its array and the bytes.
   *
   * @param length the number of bytes
   * @return the estimate in bytes
   */
  public static long bytes(long length) {
    return 2L * OBJECT + length;
  }

  /**
   * An array of {@code slots} references, such as a list's backing array after it grows.
   *
   * @param slots the number of element slots
   * @return the estimate in bytes
   */
  public static long array(long slots) {
    return OBJECT + REFERENCE * slots;
  }

  /**
   * A list or tuple of {@code size} elements (not counting the elements themselves).
   *
   * @param size the number of elements
   * @return the estimate in bytes
   */
  public static long sequence(long size) {
    return OBJECT + 8 + array(size);
  }

  /**
   * A dict of {@code size} entries (not counting the keys and values themselves).
   *
   * @param size the number of entries
   * @return the estimate in bytes
   */
  public static long dict(long size) {
    return 4L * OBJECT + DICT_ENTRY * size;
  }

  /**
   * A struct or object with {@code fields} fields (not counting the field values).
   *
   * @param fields the number of fields
   * @return the estimate in bytes
   */
  public static long struct(long fields) {
    return dict(fields);
  }

  /**
   * What a builtin that has just made {@code value} (a decoded JSON document, the matches of a
   * regular expression) still has to count: lists, tuples, dicts and bytes count themselves when
   * they are made, so this is the strings in it, down to {@value #MAX_DEPTH} levels of lists,
   * tuples and dicts, and one {@link #OBJECT} for every other value but ints, floats, booleans and
   * {@code None}. It walks the whole value, so it is meant for values whose making took as long.
   *
   * @param value a Starlark value, or a Java string
   * @return the estimate in bytes
   */
  public static long ofResult(Object value) {
    return ofResult(value, 0);
  }

  private static long ofResult(Object value, int depth) {
    if (value instanceof String s) {
      return string(s.length());
    } else if (value instanceof StarlarkBytes
        || value instanceof Boolean
        || value instanceof StarlarkInt
        || value instanceof StarlarkFloat
        || value == Starlark.NONE) {
      return 0;
    } else if (value instanceof StarlarkList<?> || value instanceof Tuple) {
      long n = 0;
      if (depth < MAX_DEPTH) {
        for (Object x : (Sequence<?>) value) {
          n += ofResult(x, depth + 1);
        }
      }
      return n;
    } else if (value instanceof Dict<?, ?> dict) {
      long n = 0;
      if (depth < MAX_DEPTH) {
        for (Map.Entry<?, ?> e : dict.entrySet()) {
          n += ofResult(e.getKey(), depth + 1) + ofResult(e.getValue(), depth + 1);
        }
      }
      return n;
    }
    return OBJECT;
  }
}
