/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.io;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.Decoder;
import org.microproxy.thirdparty.jaybrotli.Encoder;
import org.microproxy.thirdparty.jaybrotli.config.DecoderOptions;
import org.microproxy.thirdparty.jaybrotli.config.EncoderOptions;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.Flow;

/** Unicast, demand-driven processors. Each output buffer owns its bytes. */
public final class FlowAdapters {
  private FlowAdapters() {}

  public static Flow.Processor<ByteBuffer, ByteBuffer> encoding(EncoderOptions options) {
    return new Processor(options, null, 64L << 20);
  }

  public static Flow.Processor<ByteBuffer, ByteBuffer> decoding(DecoderOptions options) {
    return new Processor(null, options, 64L << 20);
  }

  public static Flow.Processor<ByteBuffer, ByteBuffer> encoding(
      EncoderOptions options, long maxBufferedBytes) {
    return new Processor(options, null, maxBufferedBytes);
  }

  public static Flow.Processor<ByteBuffer, ByteBuffer> decoding(
      DecoderOptions options, long maxBufferedBytes) {
    return new Processor(null, options, maxBufferedBytes);
  }

  private static final class Processor implements Flow.Processor<ByteBuffer, ByteBuffer> {
    private final Encoder encoder;
    private final Decoder decoder;
    private final long maxBuffered;
    private final ArrayDeque<ByteBuffer> queue = new ArrayDeque<>();
    private Flow.Subscriber<? super ByteBuffer> downstream;
    private Flow.Subscription upstream;
    private long demand, buffered;
    private boolean awaiting, finished, cancelled, terminal, draining, processing;
    private Throwable failure;

    Processor(EncoderOptions e, DecoderOptions d, long max) {
      if (max < 1) throw new IllegalArgumentException("maxBufferedBytes");
      maxBuffered = max;
      encoder = e == null ? null : new Encoder(e).onCompressed(this::enqueue);
      decoder = d == null ? null : new Decoder(d).onContent((b, end) -> enqueue(b));
    }

    private void enqueue(ByteBuffer bytes) throws BrotliException {
      if (cancelled || failure != null) return;
      int n = bytes.remaining();
      if (n == 0) return;
      if (n > maxBuffered - buffered)
        throw new BrotliException("Flow output buffer limit exceeded");
      byte[] owned = new byte[n];
      bytes.get(owned);
      queue.add(ByteBuffer.wrap(owned).asReadOnlyBuffer());
      buffered += n;
    }

    public synchronized void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {
      Objects.requireNonNull(subscriber);
      if (downstream != null) {
        subscriber.onSubscribe(
            new Flow.Subscription() {
              public void request(long n) {}

              public void cancel() {}
            });
        subscriber.onError(new IllegalStateException("Only one subscriber is supported"));
        return;
      }
      downstream = subscriber;
      subscriber.onSubscribe(
          new Flow.Subscription() {
            public void request(long n) {
              Processor.this.request(n);
            }

            public void cancel() {
              Processor.this.cancel();
            }
          });
      drain();
    }

    private synchronized void request(long n) {
      if (cancelled || terminal) return;
      if (n <= 0) {
        fail(new IllegalArgumentException("Demand must be positive"));
        drain();
        return;
      }
      demand = n > Long.MAX_VALUE - demand ? Long.MAX_VALUE : demand + n;
      drain();
    }

    private synchronized void cancel() {
      if (cancelled) return;
      cancelled = true;
      queue.clear();
      buffered = 0;
      if (upstream != null) upstream.cancel();
      release();
    }

    public synchronized void onSubscribe(Flow.Subscription subscription) {
      Objects.requireNonNull(subscription);
      if (upstream != null || cancelled || finished || failure != null) {
        subscription.cancel();
        return;
      }
      upstream = subscription;
      drain();
    }

    public synchronized void onNext(ByteBuffer item) {
      Objects.requireNonNull(item);
      if (cancelled || finished || failure != null) return;
      if (!awaiting) {
        fail(new IllegalStateException("Upstream delivered without demand"));
        drain();
        return;
      }
      awaiting = false;
      processing = true;
      try {
        if (encoder != null) encoder.receive(item);
        else decoder.receive(item);
      } catch (Throwable t) {
        fail(t);
      } finally {
        processing = false;
      }
      drain();
    }

    public synchronized void onError(Throwable error) {
      Objects.requireNonNull(error);
      if (cancelled || finished || failure != null) return;
      fail(error);
      drain();
    }

    public synchronized void onComplete() {
      if (cancelled || finished || failure != null) return;
      awaiting = false;
      processing = true;
      try {
        if (encoder != null) encoder.close();
        else decoder.close();
        finished = true;
      } catch (Throwable t) {
        fail(t);
      } finally {
        processing = false;
      }
      drain();
    }

    private void release() {
      try {
        if (encoder != null) encoder.close();
        else decoder.abort();
      } catch (Exception ignored) {
      }
    }

    private void fail(Throwable t) {
      failure = t;
      queue.clear();
      buffered = 0;
      if (upstream != null) upstream.cancel();
      if (!processing) release();
    }

    private void drain() {
      if (draining || processing || downstream == null || cancelled || terminal) return;
      draining = true;
      try {
        while (!cancelled && !terminal) {
          if (failure != null) {
            terminal = true;
            release();
            downstream.onError(failure);
            return;
          }
          if (demand > 0 && !queue.isEmpty()) {
            ByteBuffer next = queue.remove();
            buffered -= next.remaining();
            if (demand != Long.MAX_VALUE) demand--;
            try {
              downstream.onNext(next);
            } catch (Throwable t) {
              cancel();
              return;
            }
            continue;
          }
          if (finished && queue.isEmpty()) {
            terminal = true;
            downstream.onComplete();
            return;
          }
          if (demand > 0 && queue.isEmpty() && upstream != null && !awaiting && !finished) {
            awaiting = true;
            upstream.request(1);
            if (!awaiting) continue;
          }
          return;
        }
      } finally {
        draining = false;
      }
    }
  }
}
