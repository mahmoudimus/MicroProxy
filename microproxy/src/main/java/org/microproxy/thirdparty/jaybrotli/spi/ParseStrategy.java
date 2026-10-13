/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.spi;

/**
 * Per-parse provider with a stable name and public no-argument constructor or module provider factory.
 * Factories must return independent instances.
 */
public interface ParseStrategy {
  String name();

  void parse(ParseContext context, MatchFinder finder, CommandSink output);
}
