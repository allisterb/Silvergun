---
name: feedback-verify-structural-commutativity-claims
description: How to audit "commutative/total by construction" claims in ext/analysis-net type-lattice code (StackTypePromotion, TypeHelper joins) — classify each result arm, then check sentinel propagation
metadata:
  type: feedback
---

When a change to `ext/analysis-net` claims a join/promotion function is **commutative and total
by construction** (e.g. `Model/Types/StackTypePromotion.Combine`, `TypeHelper`'s binary-operation
helpers), do not settle for reading the sweep test result. Three mechanical checks find the real
holes:

1. **Partition the result arms into "returns a constant" vs "returns an operand".** Constant arms
   (`PlatformTypes.Int32` etc.) are symmetric for free. Only operand-returning arms can be
   order-dependent. For each one, prove from the table which input class combinations can reach it
   and that the selection is driven by the operand's *class*, not by its *position*. Example that
   passes: `case ManagedPointer: return leftClass == ManagedPointer ? left : right;` is safe only
   because the `& x &` cell yields native int, so exactly one operand is ever `&` there — an
   invariant held by the table, not by the arm.
2. **Check symmetry "up to what".** An arm that returns `left` when `Equals(left, right)` is
   symmetric under `Equals` but not under `Assert.Same`. Say which one, and check the test's
   comparison helper matches (a sweep using `Assert.Same` would false-fail; one using `Equals`
   both directions is right).
3. **Trace every sentinel through every arm.** The load-bearing sentinels here are `null`
   ("not yet known") and `PlatformTypes.Unknown` (`UnknownType`, not an `IBasicType`, so it
   classifies as `O`). Ask for each arm whether the sentinel propagates or gets laundered into a
   confident answer. Real finding from the 2026-07-29 review: `Combine(Unknown, Int32)` returns
   `Unknown` but `Combine(Unknown, String)` returns `PlatformTypes.Object`, because the both-`O`
   arm falls back to a common root. Inconsistent sentinel handling is invisible to a
   commutativity sweep — both orders agree, they just agree on the wrong thing.

4. **When a comment justifies "return `null`, not `PlatformTypes.Unknown`" by citing
   `TypeInferenceAnalysis`'s *fill-only* operand back-propagation, open the cited lines and read
   the actual guard condition.** There are six back-propagation sites, not two
   (`Visit` of `LoadInstruction`, `StoreInstruction`, `ReturnInstruction`, `MethodCallInstruction`,
   `IndirectMethodCallInstruction`, and the `Eq`/`Neq` arm of `BinaryInstruction`), and most fill
   on `Type == null` **or** `Type.Equals(PlatformTypes.Object)` **or** `result is Boolean` — not on
   null alone. That `Object` disjunct is load-bearing for the argument, not a detail: it is exactly
   why a laundered `PlatformTypes.Object` is recoverable by a later iteration while a laundered
   `Unknown` (which does not override `Equals`, so it matches no disjunct) is not.

**Why:** these functions have no operator argument, so commutativity is provable without an oracle
and the whole point of the rewrite is the structural guarantee. A sweep test proves the property
holds for the corpus it enumerates; only the arm-by-arm argument proves it holds for inputs nobody
listed. See [[project_cci_signature_decoding]] for the analogous "verify the derivation, not the
return value" habit in the signature decoder.

**How to apply:** any future edit to `StackTypePromotion`'s table/`Classify`, or to
`TypeHelper.BinarySignedNumericOperationType` / `BinaryLogicalOperationType` /
`UnsignedEquivalent`. Also: never suggest `Debug.Assert` to pin an invariant in this fork —
ADR-0021, it routes to `Environment.FailFast` (exit 35) and kills the run. Use a comment or a
lenient fallback branch instead.
