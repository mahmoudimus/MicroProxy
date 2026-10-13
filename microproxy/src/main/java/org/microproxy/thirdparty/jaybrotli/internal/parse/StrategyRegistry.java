/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.parse;

import org.microproxy.thirdparty.jaybrotli.internal.match.BinaryTreeFinder;
import org.microproxy.thirdparty.jaybrotli.internal.match.HashChainFinder;
import org.microproxy.thirdparty.jaybrotli.internal.match.SuffixFinder;
import org.microproxy.thirdparty.jaybrotli.spi.MatchFinder;
import org.microproxy.thirdparty.jaybrotli.spi.ParseStrategy;
import java.lang.ref.SoftReference;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

/**
 * Resolves strategy names to fresh {@link MatchFinder} and {@link ParseStrategy} instances.
 *
 * <p>Providers are discovered with {@link ServiceLoader} through the thread context class loader,
 * once per loader. Discovery (which reads class path resources) never runs while a lock is held, so
 * concurrent first uses on virtual threads do not pin carriers; two threads may race to discover
 * the same loader, and the first result is kept. Mutable strategy instances are never cached.
 */
public final class StrategyRegistry {
  private StrategyRegistry() {}

  /**
   * Catalogs of loaders that live at least as long as this class (the bootstrap and system
   * loaders, and this class's loader and its ancestors), held strongly: they never need
   * rediscovery and holding them leaks nothing.
   */
  private static final ConcurrentHashMap<Object, Catalog> PERMANENT = new ConcurrentHashMap<>();

  private static final Object BOOTSTRAP = new Object();

  /**
   * Catalogs of other loaders, such as plugin loaders. Provider objects reference their defining
   * loader, so a strong value would keep its weak key alive forever. Soft values let an unused
   * loader be reclaimed under memory pressure while surviving ordinary collections. Guarded by
   * {@link #LOCK}; never held across discovery.
   */
  private static final Map<ClassLoader, SoftReference<Catalog>> TRANSIENT = new WeakHashMap<>();

  private static final ReentrantLock LOCK = new ReentrantLock();

  private record Catalog(
      Map<String, ServiceLoader.Provider<MatchFinder>> finders,
      Map<String, ServiceLoader.Provider<ParseStrategy>> parsers) {}

  private static Catalog catalog() {
    ClassLoader loader = Thread.currentThread().getContextClassLoader();
    if (isPermanent(loader)) {
      Object key = loader == null ? BOOTSTRAP : loader;
      Catalog catalog = PERMANENT.get(key);
      if (catalog == null) {
        catalog = discover(loader);
        Catalog raced = PERMANENT.putIfAbsent(key, catalog);
        if (raced != null) catalog = raced;
      }
      return catalog;
    }
    Catalog catalog = cached(loader);
    if (catalog != null) return catalog;
    catalog = discover(loader);
    LOCK.lock();
    try {
      SoftReference<Catalog> reference = TRANSIENT.get(loader);
      Catalog raced = reference == null ? null : reference.get();
      if (raced != null) return raced;
      TRANSIENT.put(loader, new SoftReference<>(catalog));
      return catalog;
    } finally {
      LOCK.unlock();
    }
  }

  private static Catalog cached(ClassLoader loader) {
    LOCK.lock();
    try {
      SoftReference<Catalog> reference = TRANSIENT.get(loader);
      return reference == null ? null : reference.get();
    } finally {
      LOCK.unlock();
    }
  }

  private static boolean isPermanent(ClassLoader loader) {
    if (loader == null || loader == ClassLoader.getSystemClassLoader()) return true;
    for (ClassLoader own = StrategyRegistry.class.getClassLoader();
        own != null;
        own = own.getParent()) {
      if (own == loader) return true;
    }
    return false;
  }

  private static Catalog discover(ClassLoader loader) {
    return new Catalog(
        discover(MatchFinder.class, loader, MatchFinder::name),
        discover(ParseStrategy.class, loader, ParseStrategy::name));
  }

  private static <T> Map<String, ServiceLoader.Provider<T>> discover(
      Class<T> service, ClassLoader loader, Function<T, String> name) {
    Map<String, ServiceLoader.Provider<T>> providers = new LinkedHashMap<>();
    ServiceLoader.load(service, loader).stream().forEach(provider -> {
      // Instantiate once to learn its SPI name, then retain only the factory.
      providers.putIfAbsent(name.apply(provider.get()), provider);
    });
    return Map.copyOf(providers);
  }

  public static MatchFinder finder(String name) {
    var provider = catalog().finders().get(name);
    if (provider != null) return provider.get();
    return switch (name) {
      case "hash-chain" -> new HashChainFinder();
      case "binary-tree" -> new BinaryTreeFinder();
      case "suffix" -> new SuffixFinder();
      default -> throw new IllegalArgumentException("Unknown match finder: " + name);
    };
  }

  public static ParseStrategy parser(String name) {
    var provider = catalog().parsers().get(name);
    if (provider != null) return provider.get();
    return switch (name) {
      case "greedy" -> new GreedyParser();
      case "lazy" -> new LazyParser();
      case "optimal" -> new OptimalParser();
      case "beam" -> new BeamParser();
      default -> throw new IllegalArgumentException("Unknown parser: " + name);
    };
  }
}
