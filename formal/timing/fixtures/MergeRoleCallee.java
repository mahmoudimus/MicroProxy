// Unit-test-only callee whose array-parameter role is merged with another role
// at a public control-flow join. The inliner must reject these exact roles
// instead of aliasing them to a caller role (F2).
public class MergeRoleCallee {
  static int pickAlloc(int[] a, int flag) {
    int[] b = new int[8];
    int[] c;
    if (flag != 0) { c = a; } else { c = b; }
    return c[0];
  }

  static int pickTwo(int[] a, int[] b, int flag) {
    int[] c;
    if (flag != 0) { c = a; } else { c = b; }
    return c.length + c[0];
  }
}
