// Public-argument context for the same runtime helper: admitted.
public class PublicEuclidean {
  public static int run(int value) {
    return dafny.DafnyEuclidean.EuclideanModulus(value, 3);
  }
}
