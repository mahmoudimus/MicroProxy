#!/usr/bin/env bash
# Re-vendors jaybrotli (https://github.com/mahmoudimus/jaybrotli), the pure-Java Brotli encoder and
# decoder, into the core module under org.microproxy.thirdparty.jaybrotli.
#
#   scripts/vendor-jaybrotli.sh <path-to-a-jaybrotli-checkout | commit>
#
# With a directory, its checked-out commit is vendored (it must be a clean git checkout); with
# anything else, that commit is fetched from GitHub into a temporary directory. The vendored tree is
# rebuilt from scratch, so running this at the recorded commit reproduces the committed files
# exactly, and an update is the diff this script leaves behind. Needs git, sed, find and
# sha256sum (or shasum).
#
# What it does, mechanically:
#   1. copies src/io/mahmoudimus/jaybrotli/** (not module-info.java: the core module has none) and
#      experimental/vector/.../VectorComparisons.java (the optional Vector API comparisons, which
#      upstream compiles into its main jar too);
#   2. renames the package io.mahmoudimus.jaybrotli to org.microproxy.thirdparty.jaybrotli,
#      everywhere (packages, imports, Javadoc and the Class.forName strings);
#   3. copies resources/dictionary.bin next to the class that loads it, and writes that class,
#      DictionaryData, in place of the one upstream generates at build time (a byte array literal);
#   4. applies the patches in scripts/jaybrotli-patches/, in order;
#   5. writes the README.md next to the code, which records the commit.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <path-to-a-jaybrotli-checkout | commit>" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_URL=https://github.com/mahmoudimus/jaybrotli
JAVA_DIR="$ROOT/microproxy/src/main/java/org/microproxy/thirdparty/jaybrotli"
RES_DIR="$ROOT/microproxy/src/main/resources/org/microproxy/thirdparty/jaybrotli"
PATCHES="$ROOT/scripts/jaybrotli-patches"

TMP=""
cleanup() { if [[ -n "$TMP" ]]; then rm -rf "$TMP"; fi; }
trap cleanup EXIT

if [[ -d "$1" ]]; then
    SRC="$(cd "$1" && pwd)"
    if [[ -n "$(git -C "$SRC" status --porcelain --untracked-files=no)" ]]; then
        echo "$SRC has uncommitted changes; vendor a commit" >&2
        exit 1
    fi
else
    TMP="$(mktemp -d)"
    SRC="$TMP/jaybrotli"
    git init -q "$SRC"
    git -C "$SRC" fetch -q --depth 1 "$UPSTREAM_URL" "$1"
    git -C "$SRC" checkout -q FETCH_HEAD
fi
COMMIT="$(git -C "$SRC" rev-parse HEAD)"

if [[ ! -f "$SRC/src/io/mahmoudimus/jaybrotli/Brotli.java" || ! -f "$SRC/resources/dictionary.bin" ]]; then
    echo "$SRC does not look like a jaybrotli checkout" >&2
    exit 1
fi

sha256() {
    if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

rename() {  # rename <from> <to>: copies one source file with the package renamed
    mkdir -p "$(dirname "$2")"
    sed -e 's/io\.mahmoudimus\.jaybrotli/org.microproxy.thirdparty.jaybrotli/g' "$1" > "$2"
}

# 1 and 2: the sources.
rm -rf "$JAVA_DIR" "$RES_DIR"
(cd "$SRC/src/io/mahmoudimus/jaybrotli" && find . -type f -name '*.java' | LC_ALL=C sort) | while read -r f; do
    rename "$SRC/src/io/mahmoudimus/jaybrotli/$f" "$JAVA_DIR/$f"
done
rename "$SRC/experimental/vector/io/mahmoudimus/jaybrotli/internal/match/VectorComparisons.java" \
    "$JAVA_DIR/internal/match/VectorComparisons.java"

# 3: the static dictionary, loaded from the class path.
DICT_SIZE=122784
mkdir -p "$RES_DIR/internal/history"
cp "$SRC/resources/dictionary.bin" "$RES_DIR/internal/history/dictionary.bin"
if [[ "$(wc -c < "$RES_DIR/internal/history/dictionary.bin" | tr -d ' ')" != "$DICT_SIZE" ]]; then
    echo "dictionary.bin is not $DICT_SIZE bytes" >&2
    exit 1
fi
DICT_SHA256="$(sha256 "$RES_DIR/internal/history/dictionary.bin")"
cat > "$JAVA_DIR/internal/history/DictionaryData.java" <<EOF
/*
 * DictionaryData.java
 *
 * SPDX-License-Identifier: Apache-2.0
 * Written for MicroProxy by scripts/vendor-jaybrotli.sh, in place of the class jaybrotli generates
 * at build time (tools/GenerateDictionary.java), which holds the dictionary as an array literal.
 * Dictionary bytes are from RFC 7932 Appendix A.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.microproxy.thirdparty.jaybrotli.internal.history;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * The RFC 7932 static dictionary ($DICT_SIZE bytes), read once from the class path resource {@code
 * dictionary.bin} next to this class and checked against its SHA-256.
 */
public final class DictionaryData {

  private static final int SIZE = $DICT_SIZE;
  private static final String SHA256 = "$DICT_SHA256";

  public static final byte[] BYTES = load();

  private DictionaryData() {}

  private static byte[] load() {
    byte[] bytes;
    try (InputStream in = DictionaryData.class.getResourceAsStream("dictionary.bin")) {
      if (in == null) {
        throw new IllegalStateException("the Brotli dictionary (dictionary.bin) is missing");
      }
      bytes = in.readNBytes(SIZE + 1);
    } catch (IOException e) {
      throw new UncheckedIOException("cannot read the Brotli dictionary", e);
    }
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
      if (bytes.length != SIZE || !HexFormat.of().formatHex(digest).equals(SHA256)) {
        throw new IllegalStateException("the Brotli dictionary (dictionary.bin) is damaged");
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return bytes;
  }
}
EOF

# 4: MicroProxy's changes.
for p in "$PATCHES"/*.patch; do
    [[ -e "$p" ]] || continue
    git -C "$ROOT" apply --whitespace=nowarn "$p"
done

# 5: the README.
cat > "$JAVA_DIR/README.md" <<EOF
# Vendored jaybrotli

The pure-Java Brotli encoder and decoder [jaybrotli]($UPSTREAM_URL) (commit
\`$COMMIT\`), Apache License 2.0. Its static dictionary comes from the Brotli
Authors under the MIT License; that notice ships in the jar as \`META-INF/LICENSE-brotli.txt\` and
is reproduced in MicroProxy's \`NOTICE\`. \`org.microproxy.http.HttpBodies\` uses it to decode and
encode \`Content-Encoding: br\`, and needs a commit at least as recent as
\`74d7dc3\`: it relies on the decoder rejecting, as the reference decoder does, commands that run
past the end of their meta-block and (with \`TrailingData.REJECT\`) any byte after the end of the
stream, where earlier commits accepted some such streams.

Generated by \`scripts/vendor-jaybrotli.sh\`; do not edit by hand. To update, run the script with
a checkout or a commit and review the diff. Running it at the commit above reproduces these files
exactly.

Copied: everything under upstream's \`src/io/mahmoudimus/jaybrotli\`, and
\`experimental/vector/.../internal/match/VectorComparisons.java\` (the Vector API comparisons,
which upstream compiles into its main jar too). The dictionary, upstream's
\`resources/dictionary.bin\`, is in \`microproxy/src/main/resources/org/microproxy/thirdparty/jaybrotli/internal/history\`.

Not copied: \`module-info.java\` (the core module has none, so none of these packages is exported
anywhere; MicroProxy treats them as internal), the tests, benchmarks and tools, the off-heap
history in \`experimental/ffm\` (JDK 22+, built by upstream only with \`-Pffm\`; asking for
\`DecoderOptions.withOffHeap(true)\` fails as it does in upstream's default build), and
\`resources/transforms.txt\` (a copy of the reference C header, which no code reads).

Changes from upstream:

- The package is renamed from \`io.mahmoudimus.jaybrotli\` to \`org.microproxy.thirdparty.jaybrotli\`,
  including the names \`Class.forName\` loads.
- \`internal/history/DictionaryData.java\` is written by the script: it reads \`dictionary.bin\`
  from the class path and checks its SHA-256, where upstream generates a class with the bytes as
  an array literal.
- The patches in \`scripts/jaybrotli-patches\`:
  - \`0001-simd-follows-microproxy.patch\`: \`internal/match/ByteComparisons\`, which picks the match
    finders' byte comparisons, follows MicroProxy's own SIMD choice (\`org.microproxy.simd.Simd\`,
    the \`microproxy.simd\` property) unless \`jaybrotli.simd\` is set. Upstream defaults to the
    scalar comparisons.
- Without the service declarations of \`module-info.java\`, the built-in match finders and parse
  strategies are used directly (\`internal/parse/StrategyRegistry\` falls back to them), unless a
  class path \`META-INF/services\` entry names others.
EOF

echo "Vendored jaybrotli $COMMIT into $JAVA_DIR"
