/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli;

import org.microproxy.thirdparty.jaybrotli.config.DecoderOptions;
import org.microproxy.thirdparty.jaybrotli.config.EncoderOptions;

/**
 * Factory for independent encoder and decoder instances.
 *
 * <p>{@link #standard()} returns a shared stateless factory; each creation call returns a new,
 * single-owner codec. Use this interface when application code accepts a codec factory. Direct
 * {@link Encoder#Encoder(EncoderOptions)} and {@link Decoder#Decoder(DecoderOptions)} construction
 * remains supported. The IO helpers construct the standard codecs directly and do not accept an
 * injected factory. Virtual threads can run independent blocking IO tasks; codec computation runs
 * on the calling thread.
 */
public interface Codec {
  /**
   * Creates a new encoder with initial options and no registered output callback.
   *
   * @param options initial encoder configuration; setters may override settings before encoding
   * @return independent encoder; register onCompressed before use
   */
  Encoder encoder(EncoderOptions options);

  /**
   * Creates a new decoder with initial options and the default no-op handler.
   *
   * @param options initial decoder configuration; setters may override individual settings
   * @return independent decoder; register onContent to consume output
   */
  Decoder decoder(DecoderOptions options);

  /**
   * Returns the shared factory for the standard implementation.
   *
   * @return stateless factory, safe to share; created codecs are single-owner
   */
  static Codec standard() {
    return Standard.INSTANCE;
  }

  enum Standard implements Codec {
    INSTANCE;

    public Encoder encoder(EncoderOptions options) {
      return new Encoder(options);
    }

    public Decoder decoder(DecoderOptions options) {
      return new Decoder(options);
    }
  }
}
