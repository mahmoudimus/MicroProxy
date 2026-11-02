// The pinned DafnyRuntime EuclideanModulus body branches on the dividend, so a
// private argument must be rejected by the external-runtime classification.
public class PrivateEuclidean {
  public static int run(int secret) {
    return dafny.DafnyEuclidean.EuclideanModulus(secret, 3);
  }
}
