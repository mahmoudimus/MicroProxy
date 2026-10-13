/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.spi;

/**
 * Per-parse state; providers must have a public no-argument constructor or module provider factory.
 * Factories must return independent instances. Provider names must remain stable.
 */
public interface MatchFinder {
  String name();

  void reset(ParseContext context);

  Match find(int position);

  void advance(int position);
}
