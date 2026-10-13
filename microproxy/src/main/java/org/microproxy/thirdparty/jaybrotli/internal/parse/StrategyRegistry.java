/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.parse;

import org.microproxy.thirdparty.jaybrotli.internal.match.BinaryTreeFinder;
import org.microproxy.thirdparty.jaybrotli.internal.match.HashChainFinder;
import org.microproxy.thirdparty.jaybrotli.internal.match.SuffixFinder;
import org.microproxy.thirdparty.jaybrotli.spi.MatchFinder;
import org.microproxy.thirdparty.jaybrotli.spi.ParseStrategy;
import java.lang.ref.WeakReference;
import java.util.*;
import java.util.function.Function;

public final class StrategyRegistry {
  private StrategyRegistry() {}

  // Both sides are weak: Provider objects can retain their defining class loader.
  // Catalogs may be rediscovered after reclamation; mutable strategy instances are never cached.
  private static final Map<ClassLoader, WeakReference<Catalog>> CATALOGS = new WeakHashMap<>();

  private record Catalog(
      Map<String, ServiceLoader.Provider<MatchFinder>> finders,
      Map<String, ServiceLoader.Provider<ParseStrategy>> parsers) {}

  private static Catalog catalog() {
    ClassLoader loader = Thread.currentThread().getContextClassLoader();
    synchronized (CATALOGS) {
      WeakReference<Catalog> reference = CATALOGS.get(loader);
      Catalog catalog = reference == null ? null : reference.get();
      if (catalog == null) {
        catalog = new Catalog(
            discover(MatchFinder.class, loader, MatchFinder::name),
            discover(ParseStrategy.class, loader, ParseStrategy::name));
        CATALOGS.put(loader, new WeakReference<>(catalog));
      }
      return catalog;
    }
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
