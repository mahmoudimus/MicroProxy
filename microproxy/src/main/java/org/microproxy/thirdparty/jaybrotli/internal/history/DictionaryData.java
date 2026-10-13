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
 * The RFC 7932 static dictionary (122784 bytes), read once from the class path resource {@code
 * dictionary.bin} next to this class and checked against its SHA-256.
 */
public final class DictionaryData {

  private static final int SIZE = 122784;
  private static final String SHA256 = "20e42eb1b511c21806d4d227d07e5dd06877d8ce7b3a817f378f313653f35c70";

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
