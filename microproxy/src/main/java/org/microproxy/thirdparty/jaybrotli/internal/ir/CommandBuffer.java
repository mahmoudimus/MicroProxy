/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.ir;

import java.util.*;

/** Mutable parser builder. Completed blocks receive an immutable {@link CommandSequence}. */
public final class CommandBuffer implements org.microproxy.thirdparty.jaybrotli.spi.CommandSink {
  public static final class Entry {
    public int insertOffset, insertLen, copyLen, copyCovered, distance;
    public boolean dictionary;
  }

  private Entry[] entries = new Entry[16];
  private int size;
  private int cursor;

  public CommandBuffer() {}

  public static CommandBuffer fromEntries(Entry[] entries) {
    var b = new CommandBuffer();
    b.entries = copyEntries(entries, entries.length);
    b.size = entries.length;
    if (entries.length > 0) {
      Entry last = b.entries[b.size - 1];
      b.cursor = last.insertOffset + last.insertLen + last.copyCovered;
    }
    return b;
  }

  private Entry add() {
    if (size == entries.length) entries = Arrays.copyOf(entries, Math.max(16, size * 2));
    return entries[size++] = new Entry();
  }

  public void insert(int offset, int length) {
    accept(new Command.Insert(offset, length));
  }

  public void copy(int distance, int length) {
    accept(new Command.Copy(distance, length));
  }

  public void dictionary(int distance, int wordLength, int length) {
    accept(new Command.DictionaryCopy(distance, wordLength, length));
  }

  public void accept(Command command) {
    switch (command) {
      case Command.Insert i -> {
        Entry e;
        if (size > 0
            && entries[size - 1].copyCovered == 0
            && entries[size - 1].insertOffset + entries[size - 1].insertLen == i.offset())
          e = entries[size - 1];
        else {
          e = add();
          e.insertOffset = i.offset();
        }
        e.insertLen += i.length();
        cursor = i.offset() + i.length();
      }
      case Command.Copy c -> copy(c.distance(), c.length(), c.length(), false);
      case Command.DictionaryCopy c -> copy(c.distance(), c.wordLength(), c.length(), true);
    }
  }

  private void copy(int distance, int wire, int covered, boolean dict) {
    Entry e;
    if (size > 0 && entries[size - 1].copyCovered == 0) e = entries[size - 1];
    else {
      e = add();
      e.insertOffset = cursor;
    }
    e.distance = distance;
    e.copyLen = wire;
    e.copyCovered = covered;
    e.dictionary = dict;
    cursor += covered;
  }

  public Entry[] entries() {
    return copyEntries(entries, size);
  }

  /** Freezes parser scratch into an independently owned immutable command sequence. */
  public CommandSequence snapshot() {
    var result = new ArrayList<CommandSequence.Entry>(size);
    for (int i = 0; i < size; i++) {
      Entry e = entries[i];
      result.add(
          new CommandSequence.Entry(
              e.insertOffset, e.insertLen, e.copyLen, e.copyCovered, e.distance, e.dictionary));
    }
    return new CommandSequence(result);
  }

  private static Entry[] copyEntries(Entry[] source, int length) {
    Entry[] result = new Entry[length];
    for (int i = 0; i < length; i++) {
      Entry e = Objects.requireNonNull(source[i]);
      Entry copy = new Entry();
      copy.insertOffset = e.insertOffset;
      copy.insertLen = e.insertLen;
      copy.copyLen = e.copyLen;
      copy.copyCovered = e.copyCovered;
      copy.distance = e.distance;
      copy.dictionary = e.dictionary;
      result[i] = copy;
    }
    return result;
  }

  public List<Command> commands() {
    return snapshot().commands();
  }
}
