// Same guard for the EuclideanDivision family.
public class PrivateEuclideanDivision {
  public static int run(int secret) {
    return dafny.DafnyEuclidean.EuclideanDivision(secret, 3);
  }
}
