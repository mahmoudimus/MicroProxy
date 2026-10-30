import Std

/-!
Resource-accounting models for the DNSSEC work budget and expiring LRU cache.

These are mathematical models, not a translation or extraction of Java. `Nat`
models nonnegative Java values only. In particular, callers of Java `consume`
must supply nonnegative costs. The cache uses newest-first list order; Java's
access-order LinkedHashMap iterates oldest first. Cache transitions use one
fixed clock observation. Java reads its clock twice in `put`, so exact
observation comparison requires those readings to agree (e.g. a fixed clock).
No statement here concerns cryptographic correctness, synchronization, Java
integer overflow, allocation, real-time expiry, or lookup promotion.
-/

namespace MicroProxy.Resources

/-- Charge before work; failure clears the remaining allowance. -/
def charge (remaining cost : Nat) : Bool × Nat :=
  if cost ≤ remaining then (true, remaining - cost) else (false, 0)

/-- Every individual charge leaves at most the original allowance. -/
theorem charge_no_increase (remaining cost : Nat) :
    (charge remaining cost).2 ≤ remaining := by
  simp only [charge]
  split <;> simp_all <;> omega

/-- Acceptance is precisely affordability, including a zero-cost call. -/
theorem charge_accepted_iff (remaining cost : Nat) :
    (charge remaining cost).1 = true ↔ cost ≤ remaining := by
  simp only [charge]
  split <;> simp_all

/-- Accepted work and the remaining allowance exactly conserve the input. -/
theorem charge_accepted_conservation (remaining cost : Nat)
    (accepted : (charge remaining cost).1 = true) :
    cost + (charge remaining cost).2 = remaining := by
  have affordable := (charge_accepted_iff remaining cost).mp accepted
  simp only [charge, ite_eq_left affordable]
  omega

/-- An over-budget charge rejects and exhausts the allowance. -/
theorem charge_rejects_excess (remaining cost : Nat) (excess : remaining < cost) :
    charge remaining cost = (false, 0) := by
  simp [charge, Nat.not_le.mpr excess]

/-- Exhaustion rejects every positive charge; zero-cost calls remain allowed. -/
theorem charge_exhausted_rejects (cost : Nat) (positive : 0 < cost) :
    charge 0 cost = (false, 0) := by
  exact charge_rejects_excess 0 cost positive

/-- Run any finite sequence, stopping on the first rejected charge. -/
def chargeAll (remaining : Nat) : List Nat → Bool × Nat
  | [] => (true, remaining)
  | cost :: costs =>
      if cost ≤ remaining then chargeAll (remaining - cost) costs else (false, 0)

/-- The list runner is exactly repeated application of the bridge transition. -/
theorem chargeAll_step (remaining cost : Nat) (costs : List Nat) :
    chargeAll remaining (cost :: costs) =
      let next := charge remaining cost
      if next.1 then chargeAll next.2 costs else (false, 0) := by
  simp only [chargeAll, charge]
  split <;> rfl

/-- Successful arbitrary-length runs conserve the total allowance exactly. -/
theorem chargeAll_accepted_conservation (initial : Nat) (costs : List Nat)
    (accepted : (chargeAll initial costs).1 = true) :
    costs.sum + (chargeAll initial costs).2 = initial := by
  induction costs generalizing initial with
  | nil => simp [chargeAll]
  | cons cost costs ih =>
      simp only [chargeAll] at accepted ⊢
      split at accepted
      next affordable =>
        simp only [ite_eq_left affordable]
        have rest := ih (initial - cost) accepted
        simp only [List.sum_cons]
        omega
      next unaffordable => simp at accepted

/-- A successful sequence of any length cannot spend more than its budget. -/
theorem chargeAll_accepted_sum_le (initial : Nat) (costs : List Nat)
    (accepted : (chargeAll initial costs).1 = true) :
    costs.sum ≤ initial := by
  have conserved := chargeAll_accepted_conservation initial costs accepted
  omega

/-- Even a failing run cannot increase the allowance. -/
theorem chargeAll_no_increase (initial : Nat) (costs : List Nat) :
    (chargeAll initial costs).2 ≤ initial := by
  induction costs generalizing initial with
  | nil => simp [chargeAll]
  | cons cost costs ih =>
      simp only [chargeAll]
      split
      next affordable =>
        have rest := ih (initial - cost)
        omega
      next unaffordable => simp

structure Entry where
  key : Nat
  value : Nat
  expires : Nat
  deriving DecidableEq, Repr

/-- Retain entries with strictly future expiration at this observation. -/
def purge (now : Nat) (entries : List Entry) : List Entry :=
  entries.filter (fun e => now < e.expires)

/-- Remove expiry and replacement key, then prepend the newest entry.
    Taking the newest `capacity - 1` survivors models eviction of the oldest. -/
def put (capacity now key value expires : Nat) (entries : List Entry) : List Entry :=
  let remaining := (purge now entries).filter (fun e => e.key != key)
  if capacity = 0 ∨ expires ≤ now then remaining
  else { key := key, value := value, expires := expires } :: remaining.take (capacity - 1)

/-- Expiration cleanup cannot increase cache cardinality. -/
theorem purge_no_growth (now : Nat) (entries : List Entry) :
    (purge now entries).length ≤ entries.length := by
  exact List.length_filter_le _ _

/-- Every survivor is unexpired at the modeled clock observation. -/
theorem purge_future (now : Nat) (entries : List Entry) (entry : Entry)
    (member : entry ∈ purge now entries) :
    now < entry.expires := by
  have retained := (List.mem_filter.mp member).2
  simpa only [decide_eq_true_eq] using retained

/-- Insertion preserves the capacity bound, including zero TTL/replacement.
    The precondition is needed when insertion returns early after cleanup. -/
theorem put_bounded (capacity now key value expires : Nat) (entries : List Entry)
    (bounded : entries.length ≤ capacity) :
    (put capacity now key value expires entries).length ≤ capacity := by
  have cleaned := purge_no_growth now entries
  have removed := List.length_filter_le (fun e : Entry => e.key != key) (purge now entries)
  simp only [put]
  split
  next skip =>
    exact Nat.le_trans removed (Nat.le_trans cleaned bounded)
  next insert =>
    have positive : 0 < capacity := by omega
    simp only [List.length_cons, List.length_take]
    have taken : min (capacity - 1)
        (((purge now entries).filter (fun e => e.key != key)).length) ≤ capacity - 1 :=
      Nat.min_le_left _ _
    omega

/-- Insertion leaves only entries unexpired at the modeled clock time. -/
theorem put_future (capacity now key value expires : Nat) (entries : List Entry)
    (entry : Entry) (member : entry ∈ put capacity now key value expires entries) :
    now < entry.expires := by
  simp only [put] at member
  split at member
  next skip =>
    have inPurge : entry ∈ purge now entries := (List.mem_filter.mp member).1
    exact purge_future now entries entry inPurge
  next insert =>
    rcases List.mem_cons.mp member with equal | old
    · subst entry
      simp only
      omega
    · have inRemaining := List.mem_of_mem_take old
      have inPurge := (List.mem_filter.mp inRemaining).1
      exact purge_future now entries entry inPurge

/-- The abstract representation of a map has no repeated keys. -/
def UniqueKeys : List Entry → Prop
  | [] => True
  | entry :: entries =>
      (∀ other ∈ entries, entry.key ≠ other.key) ∧ UniqueKeys entries

private theorem uniqueKeys_filter (predicate : Entry → Bool) (entries : List Entry)
    (unique : UniqueKeys entries) : UniqueKeys (entries.filter predicate) := by
  induction entries with
  | nil => trivial
  | cons entry entries ih =>
      rcases unique with ⟨headUnique, tailUnique⟩
      simp only [List.filter_cons]
      split
      next keep =>
        constructor
        · intro other member
          exact headUnique other (List.mem_filter.mp member).1
        · exact ih tailUnique
      next discard => exact ih tailUnique

private theorem uniqueKeys_take (count : Nat) (entries : List Entry)
    (unique : UniqueKeys entries) : UniqueKeys (entries.take count) := by
  induction entries generalizing count with
  | nil => simp [UniqueKeys]
  | cons entry entries ih =>
      cases count with
      | zero => trivial
      | succ count =>
          rcases unique with ⟨headUnique, tailUnique⟩
          constructor
          · intro other member
            exact headUnique other (List.mem_of_mem_take member)
          · exact ih count tailUnique

/-- Expiry cleanup preserves the unique-key representation invariant. -/
theorem purge_unique (now : Nat) (entries : List Entry) (unique : UniqueKeys entries) :
    UniqueKeys (purge now entries) := by
  exact uniqueKeys_filter _ entries unique

/-- Replacing a key and evicting old entries preserves unique keys. -/
theorem put_unique (capacity now key value expires : Nat) (entries : List Entry)
    (unique : UniqueKeys entries) :
    UniqueKeys (put capacity now key value expires entries) := by
  have remainingUnique := uniqueKeys_filter (fun entry : Entry => entry.key != key)
    (purge now entries) (purge_unique now entries unique)
  simp only [put]
  split
  next skip => exact remainingUnique
  next insert =>
    constructor
    · intro other member
      have inRemaining := List.mem_of_mem_take member
      have different := (List.mem_filter.mp inRemaining).2
      have differentKey : other.key ≠ key := by simpa using different
      exact Ne.symm differentKey
    · exact uniqueKeys_take _ _ remainingUnique

/- Finite boundary checks are examples only; the theorems above are universal. -/
example : charge 8 8 = (true, 0) := by decide
example : charge 8 9 = (false, 0) := by decide
example : charge 0 0 = (true, 0) := by decide
example : chargeAll 10 [3, 4, 3] = (true, 0) := by decide
example : chargeAll 10 [3, 4, 4] = (false, 0) := by decide
example : put 2 10 3 30 20
    [{key := 2, value := 20, expires := 20}, {key := 1, value := 10, expires := 20}] =
    [{key := 3, value := 30, expires := 20}, {key := 2, value := 20, expires := 20}] := by decide
example : put 2 10 2 99 10
    [{key := 2, value := 20, expires := 20}, {key := 1, value := 10, expires := 20}] =
    [{key := 1, value := 10, expires := 20}] := by decide
example : put 0 10 1 10 20 [] = [] := by decide

#print axioms charge_no_increase
#print axioms charge_accepted_iff
#print axioms charge_accepted_conservation
#print axioms charge_rejects_excess
#print axioms charge_exhausted_rejects
#print axioms chargeAll_step
#print axioms chargeAll_accepted_conservation
#print axioms chargeAll_accepted_sum_le
#print axioms chargeAll_no_increase
#print axioms purge_no_growth
#print axioms purge_future
#print axioms put_bounded
#print axioms put_future
#print axioms purge_unique
#print axioms put_unique

end MicroProxy.Resources
