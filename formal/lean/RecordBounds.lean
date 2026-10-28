import Std

set_option warningAsError true

/-!
# Per-key TLS record sequence accounting

This is a mathematical model of the guarded sequence allocation in
`TlsRecordLayer.Protection.exhausted`, `writeRecord`, and the TLS AEAD protection
implementations. It is not a refinement proof of the Java program.

`next` is a `Nat`: Java's separate rejection of negative signed counters is a
precondition of this model. A valid initial state satisfies `start <= limit`.
The Java guard rejects `next >= limit`; protection uses `next` and increments it.
Consequently an allocation is consumed even if later cryptography or I/O fails.

One invocation of `issueMany` describes one direction under one unchanged key.
There is deliberately no reset transition inside an epoch. Installing fresh
protection starts a new epoch at zero, but freshness of the actual derived key
material is an external cryptographic assumption. An epoch label alone does not
make repeated key material fresh. The reset theorem below exhibits why this
distinction matters.

No claim is made about TLS correctness, AEAD security, key derivation, nonce
encoding, Java integer semantics, concurrency, or JVM constant-time behavior.
-/

namespace MicroProxy.Records

/-- Allocate the current per-key sequence and advance, or reject without one. -/
def issue (limit next : Nat) : Option (Nat × Nat) :=
  if next < limit then some (next, next + 1) else none

/-- Execute an arbitrary requested number of allocations under one fixed key. -/
def issueMany (limit start : Nat) : Nat → Option (List Nat × Nat)
  | 0 => some ([], start)
  | count + 1 =>
      match issue limit start with
      | none => none
      | some (sequence, next) =>
          match issueMany limit next count with
          | none => none
          | some (sequences, final) => some (sequence :: sequences, final)

/-- A successful allocation issues exactly the previous counter below the cap. -/
theorem issue_success_iff (limit next sequence after : Nat) :
    issue limit next = some (sequence, after) ↔
      next < limit ∧ sequence = next ∧ after = next + 1 := by
  by_cases h : next < limit
  · simp [issue, h, Prod.mk.injEq, eq_comm]
  · simp [issue, h]

/-- At and beyond the cap, allocation produces no sequence/nonce input. -/
theorem issue_rejects_at_or_above_cap (limit next : Nat) (h : limit ≤ next) :
    issue limit next = none := by
  simp [issue, Nat.not_lt.mpr h]

/-- Rejection at the exact cap cannot yield any allocated sequence. -/
theorem no_nonce_at_cap (limit sequence after : Nat) :
    issue limit limit ≠ some (sequence, after) := by
  simp [issue]

/--
The transition itself establishes the invariants for every finite successful
trace; the invariants are not assumptions on the trace.
-/
theorem accepted_trace_accounting
    (limit start count : Nat) (sequences : List Nat) (final : Nat)
    (hstart : start ≤ limit)
    (hrun : issueMany limit start count = some (sequences, final)) :
    (∀ sequence ∈ sequences, start ≤ sequence ∧ sequence < limit) ∧
      sequences.Nodup ∧
      final = start + sequences.length ∧
      final ≤ limit ∧
      sequences.length = count := by
  induction count generalizing start sequences final with
  | zero =>
      simp only [issueMany, Option.some.injEq, Prod.mk.injEq] at hrun
      rcases hrun with ⟨rfl, rfl⟩
      simp [hstart]
  | succ count ih =>
      by_cases hguard : start < limit
      · simp only [issueMany, issue, ite_eq_left hguard] at hrun
        cases htail : issueMany limit (start + 1) count with
        | none => simp [htail] at hrun
        | some result =>
            rcases result with ⟨tail, tailFinal⟩
            simp only [htail, Option.some.injEq, Prod.mk.injEq] at hrun
            rcases hrun with ⟨rfl, rfl⟩
            have hnext : start + 1 ≤ limit := by omega
            obtain ⟨hvalues, hnodup, hfinal, hbound, hlength⟩ :=
              ih (start + 1) tail tailFinal hnext htail
            refine ⟨?_, ?_, ?_, hbound, ?_⟩
            · intro sequence hmem
              simp only [List.mem_cons] at hmem
              rcases hmem with hhead | htailmem
              · subst sequence
                exact ⟨Nat.le_refl _, hguard⟩
              · obtain ⟨hlower, hupper⟩ := hvalues sequence htailmem
                exact ⟨by omega, hupper⟩
            · apply List.nodup_cons.mpr
              refine ⟨?_, hnodup⟩
              intro hmem
              have hlower := (hvalues start hmem).1
              omega
            · simp only [List.length_cons]
              omega
            · simp only [List.length_cons]
              omega
      · simp [issueMany, issue, hguard] at hrun

/-- No sequence value is allocated twice within a successful fixed-key epoch. -/
theorem accepted_trace_no_repeated_sequence
    (limit start count : Nat) (sequences : List Nat) (final : Nat)
    (hstart : start ≤ limit)
    (hrun : issueMany limit start count = some (sequences, final)) :
    sequences.Nodup :=
  (accepted_trace_accounting limit start count sequences final hstart hrun).2.1

/-- Every allocated sequence is strictly below the per-key limit. -/
theorem accepted_trace_sequences_below_limit
    (limit start count : Nat) (sequences : List Nat) (final : Nat)
    (hstart : start ≤ limit)
    (hrun : issueMany limit start count = some (sequences, final)) :
    ∀ sequence ∈ sequences, sequence < limit := by
  intro sequence hmem
  exact (accepted_trace_accounting limit start count sequences final hstart hrun).1
    sequence hmem |>.2

/-- Every successful trace leaves the next counter at or below its cap. -/
theorem accepted_trace_next_at_most_limit
    (limit start count : Nat) (sequences : List Nat) (final : Nat)
    (hstart : start ≤ limit)
    (hrun : issueMany limit start count = some (sequences, final)) :
    final ≤ limit :=
  (accepted_trace_accounting limit start count sequences final hstart hrun).2.2.2.1

/-- The total successful allocation count is bounded by the remaining capacity. -/
theorem accepted_trace_count_bounded
    (limit start count : Nat) (sequences : List Nat) (final : Nat)
    (hstart : start ≤ limit)
    (hrun : issueMany limit start count = some (sequences, final)) :
    count ≤ limit - start := by
  obtain ⟨_, _, hfinal, hbound, hlength⟩ :=
    accepted_trace_accounting limit start count sequences final hstart hrun
  omega

/-- Every request that fits the remaining capacity has a successful trace. -/
theorem issueMany_accepts_within_capacity
    (limit start count : Nat) (hcapacity : start + count ≤ limit) :
    ∃ sequences final, issueMany limit start count = some (sequences, final) := by
  induction count generalizing start with
  | zero => exact ⟨[], start, rfl⟩
  | succ count ih =>
      have hguard : start < limit := by omega
      have htailCapacity : start + 1 + count ≤ limit := by omega
      obtain ⟨tail, final, htail⟩ := ih (start + 1) htailCapacity
      exact ⟨start :: tail, final, by simp [issueMany, issue, hguard, htail]⟩

/-- Exact acceptance condition: the safety result is not vacuous. -/
theorem issueMany_accepts_iff
    (limit start count : Nat) (hstart : start ≤ limit) :
    (∃ sequences final, issueMany limit start count = some (sequences, final)) ↔
      count ≤ limit - start := by
  constructor
  · rintro ⟨sequences, final, hrun⟩
    exact accepted_trace_count_bounded limit start count sequences final hstart hrun
  · intro hcapacity
    apply issueMany_accepts_within_capacity
    omega

/-- A trace that has used its whole capacity rejects the next allocation. -/
theorem accepted_trace_exhaustion_rejects
    (limit start count : Nat) (sequences : List Nat) (final : Nat)
    (hstart : start ≤ limit)
    (hrun : issueMany limit start count = some (sequences, final))
    (hexhausted : count = limit - start) :
    issue limit final = none := by
  obtain ⟨_, _, hfinal, hbound, hlength⟩ :=
    accepted_trace_accounting limit start count sequences final hstart hrun
  apply issue_rejects_at_or_above_cap
  omega

/--
A reset to zero is a new accounting epoch, but reusing the same actual key would
repeat sequence zero. This deliberately does not infer key freshness from reset.
-/
theorem resetting_same_key_can_repeat (limit : Nat) (hlimit : 0 < limit) :
    issue limit 0 = some (0, 1) ∧ ¬ ([0, 0] : List Nat).Nodup := by
  simp [issue, hlimit]

-- Audit all exported security theorems for hidden axioms and proof placeholders.
#print axioms issue_success_iff
#print axioms issue_rejects_at_or_above_cap
#print axioms no_nonce_at_cap
#print axioms accepted_trace_accounting
#print axioms accepted_trace_no_repeated_sequence
#print axioms accepted_trace_sequences_below_limit
#print axioms accepted_trace_next_at_most_limit
#print axioms accepted_trace_count_bounded
#print axioms issueMany_accepts_within_capacity
#print axioms issueMany_accepts_iff
#print axioms accepted_trace_exhaustion_rejects
#print axioms resetting_same_key_can_repeat

end MicroProxy.Records
