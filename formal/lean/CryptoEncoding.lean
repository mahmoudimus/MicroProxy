import Std

set_option warningAsError true

/-!
# TLS/QUIC cryptographic input encoding

These proofs concern MicroProxy's input glue around trusted cryptographic
primitives. The nonce is a 96-bit IV XOR a zero-padded 64-bit unsigned sequence,
interpreted as big-endian bytes. This is the construction used by TLS 1.3,
TLS 1.2 ChaCha20-Poly1305, and QUIC `PacketKey.nonce`.

The label encoder models the bytes of TLS 1.3 HKDF-Expand-Label: a two-byte
output length, a one-byte full-label length, the six-byte `tls13 ` prefix, label
bytes, a one-byte context length, and context bytes. Bytes are unsigned `Nat`s
with an explicit `< 256` predicate. Labels here are already bytes, not Java
Strings; the String-to-ASCII conversion must be checked separately. In
particular, replacement of non-ASCII characters is not injective.

The proofs do not establish AES/ChaCha/HMAC security, HKDF output uniqueness,
freshness of actual derived keys, constant-time execution, or a refinement of
the Java byte-manipulation loops. Distinct encoding inputs do not imply
distinct cryptographic outputs. Nonce injectivity requires a fixed IV and no
reuse of the same sequence under the same actual key.
-/

namespace MicroProxy.CryptoEncoding

/-- XOR the fixed 96-bit IV with the sequence in the low 64 bits. -/
def nonce (iv : BitVec 96) (sequence : BitVec 64) : BitVec 96 :=
  iv ^^^ sequence.zeroExtend 96

/-- Zero extension loses no sequence bits; XOR by a fixed IV is cancellative. -/
theorem nonce_injective (iv : BitVec 96) : Function.Injective (nonce iv) := by
  intro first second heq
  have hwide : first.setWidth 96 = second.setWidth 96 :=
    (BitVec.xor_right_inj iv).mp heq
  have hnat : first.toNat = second.toNat := by
    simpa only [BitVec.toNat_setWidth_of_le (by decide : 64 ≤ 96)] using
      congrArg BitVec.toNat hwide
  exact BitVec.eq_of_toNat_eq hnat

/-- Equal nonces under one fixed IV have exactly equal 64-bit sequences. -/
theorem nonce_eq_iff (iv : BitVec 96) (first second : BitVec 64) :
    nonce iv first = nonce iv second ↔ first = second := by
  constructor
  · intro heq
    exact nonce_injective iv heq
  · intro heq
    exact congrArg (nonce iv) heq

/-- Distinct sequence values cannot collide in the fixed-IV nonce construction. -/
theorem distinct_sequences_distinct_nonces
    (iv : BitVec 96) (first second : BitVec 64) (hdistinct : first ≠ second) :
    nonce iv first ≠ nonce iv second := by
  intro heq
  exact hdistinct (nonce_injective iv heq)

/-- Unsigned bytes represented as naturals. -/
def Bytes (data : List Nat) : Prop := ∀ byte ∈ data, byte < 256

/-- The exact ASCII bytes for the mandatory `tls13 ` label prefix. -/
def labelPrefix : List Nat := [116, 108, 115, 49, 51, 32]

/-- Legal, untruncated TLS HKDF label fields. -/
def LegalLabel (length : Nat) (label context : List Nat) : Prop :=
  length < 65536 ∧ label.length ≤ 249 ∧ context.length ≤ 255 ∧
    Bytes label ∧ Bytes context

/-- Executable byte serialization, including the Java casts to one-byte fields. -/
def encodeLabel (length : Nat) (label context : List Nat) : List Nat :=
  [length / 256 % 256, length % 256, (6 + label.length) % 256] ++
    labelPrefix ++ label ++ [context.length % 256] ++ context

/--
Parse field boundaries and the required prefix. This decoder is an inverse on
legal encodings; it is not claimed to be a complete TLS input validator.
-/
def decodeLabel : List Nat → Option (Nat × List Nat × List Nat)
  | high :: low :: fullLength :: body =>
      let fullLabel := body.take fullLength
      match body.drop fullLength with
      | contextLength :: context =>
          if fullLabel.take 6 = labelPrefix ∧
              fullLabel.length = fullLength ∧ context.length = contextLength then
            some (high * 256 + low, fullLabel.drop 6, context)
          else none
      | [] => none
  | _ => none

private theorem labelPrefix_length : labelPrefix.length = 6 := rfl

private theorem uint16_reconstruct (length : Nat) (h : length < 65536) :
    (length / 256 % 256) * 256 + length % 256 = length := by
  have hhigh : length / 256 < 256 := by omega
  rw [Nat.mod_eq_of_lt hhigh]
  omega

/-- Every byte of a legal encoding is within the unsigned byte range. -/
theorem encodeLabel_bytes (length : Nat) (label context : List Nat)
    (hlegal : LegalLabel length label context) :
    Bytes (encodeLabel length label context) := by
  obtain ⟨_, _, _, hlabel, hcontext⟩ := hlegal
  intro byte hmem
  simp only [encodeLabel, List.mem_append] at hmem
  rcases hmem with (((hheader | hprefix) | hlabelmem) | hcontextLengthMem) | hcontextMem
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at hheader
    rcases hheader with hhigh | hlow | hfull
    · subst byte
      exact Nat.mod_lt _ (by decide)
    · subst byte
      exact Nat.mod_lt _ (by decide)
    · subst byte
      exact Nat.mod_lt _ (by decide)
  · simp only [labelPrefix, List.mem_cons, List.not_mem_nil, or_false] at hprefix
    omega
  · exact hlabel byte hlabelmem
  · have heq : byte = context.length % 256 := by simpa using hcontextLengthMem
    subst byte
    exact Nat.mod_lt _ (by decide)
  · exact hcontext byte hcontextMem

/-- The field lengths and fixed prefix make every legal input recoverable. -/
theorem decode_encodeLabel (length : Nat) (label context : List Nat)
    (hlegal : LegalLabel length label context) :
    decodeLabel (encodeLabel length label context) = some (length, label, context) := by
  obtain ⟨hlength, hlabelLength, hcontextLength, _, _⟩ := hlegal
  have hfull : 6 + label.length < 256 := by omega
  have hcontext : context.length < 256 := by omega
  have hprefixLength : (labelPrefix ++ label).length = 6 + label.length := by
    simp [labelPrefix_length]
  have htake :
      (labelPrefix ++ label ++ [context.length % 256] ++ context).take
        (6 + label.length) = labelPrefix ++ label := by
    rw [List.append_assoc, ← hprefixLength, List.take_append_length]
  have hdrop :
      (labelPrefix ++ label ++ [context.length % 256] ++ context).drop
        (6 + label.length) = context.length % 256 :: context := by
    rw [List.append_assoc, ← hprefixLength, List.drop_append_length]
    rfl
  have hprefix : (labelPrefix ++ label).take 6 = labelPrefix := by
    rw [← labelPrefix_length]
    exact List.take_append_length
  have hunprefix : (labelPrefix ++ label).drop 6 = label := by
    rw [← labelPrefix_length]
    exact List.drop_append_length
  simp only [encodeLabel, List.cons_append, List.nil_append,
    decodeLabel, Nat.mod_eq_of_lt hfull]
  rw [htake, hdrop]
  simp only [hprefix, hprefixLength, Nat.mod_eq_of_lt hcontext, hunprefix,
    and_self, ite_true, uint16_reconstruct length hlength]

/-- Equality of legal encodings forces equality of all three HKDF label inputs. -/
theorem encodeLabel_injective
    (length₁ length₂ : Nat) (label₁ label₂ context₁ context₂ : List Nat)
    (hlegal₁ : LegalLabel length₁ label₁ context₁)
    (hlegal₂ : LegalLabel length₂ label₂ context₂)
    (heq : encodeLabel length₁ label₁ context₁ = encodeLabel length₂ label₂ context₂) :
    length₁ = length₂ ∧ label₁ = label₂ ∧ context₁ = context₂ := by
  have hdecoded := congrArg decodeLabel heq
  rw [decode_encodeLabel length₁ label₁ context₁ hlegal₁,
    decode_encodeLabel length₂ label₂ context₂ hlegal₂] at hdecoded
  simpa only [Option.some.injEq, Prod.mk.injEq] using hdecoded

/-- Distinct legal inputs have distinct serialized HKDF info/domain inputs. -/
theorem distinct_label_inputs_distinct_encodings
    (length₁ length₂ : Nat) (label₁ label₂ context₁ context₂ : List Nat)
    (hlegal₁ : LegalLabel length₁ label₁ context₁)
    (hlegal₂ : LegalLabel length₂ label₂ context₂)
    (hdistinct : length₁ ≠ length₂ ∨ label₁ ≠ label₂ ∨ context₁ ≠ context₂) :
    encodeLabel length₁ label₁ context₁ ≠ encodeLabel length₂ label₂ context₂ := by
  intro heq
  obtain ⟨hlength, hlabel, hcontext⟩ :=
    encodeLabel_injective length₁ length₂ label₁ label₂ context₁ context₂
      hlegal₁ hlegal₂ heq
  rcases hdistinct with hd | hd | hd
  · exact hd hlength
  · exact hd hlabel
  · exact hd hcontext

#print axioms nonce_injective
#print axioms nonce_eq_iff
#print axioms distinct_sequences_distinct_nonces
#print axioms encodeLabel_bytes
#print axioms decode_encodeLabel
#print axioms encodeLabel_injective
#print axioms distinct_label_inputs_distinct_encodings

end MicroProxy.CryptoEncoding
