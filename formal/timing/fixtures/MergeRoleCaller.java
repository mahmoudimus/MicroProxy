// Unit-test-only callers for the merged-role composition controls.
public class MergeRoleCaller {
  public static int allocMerge(int[] a, int flag) { return MergeRoleCallee.pickAlloc(a, flag); }
  public static int twoMerge(int[] a, int[] b, int flag) { return MergeRoleCallee.pickTwo(a, b, flag); }
}
