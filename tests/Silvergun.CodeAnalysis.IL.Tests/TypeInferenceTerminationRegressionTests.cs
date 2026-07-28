namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Reflection;

using Backend.Analyses;
using Backend.Model;
using Model.ThreeAddressCode.Instructions;
using Model.ThreeAddressCode.Values;
using Model.Types;

using Xunit;

/// <summary>
/// Regression coverage for the three termination controls added to
/// <c>ext/analysis-net</c>'s <see cref="TypeInferenceAnalysis"/> — see
/// <c>docs/agent/measurements/typeinference-nontermination.md</c> (spike, then
/// <c>typeinference-bound-sizing</c>, then the architect's <c>cycle-detection-review</c>
/// follow-up, which is the direct trigger for this file: "No xUnit coverage for
/// <c>ComputeStateHash</c>, <c>StatesEqual</c>, or window eviction... required before it is
/// wired in").
/// <para>
/// <c>TypeInferenceAnalysis</c> previously ran an unbounded <c>do { ... } while (changed)</c> —
/// a method whose types never stabilised hung forever, a DoS vector against untrusted IL. It now
/// bounds the loop (<see cref="TypeInferenceAnalysis.DefaultMaxIterations"/>,
/// <see cref="TypeInferenceAnalysis.ReachedIterationLimit"/>) and additionally detects exact
/// state cycles before the bound is reached (<c>detectCycles</c>,
/// <see cref="TypeInferenceAnalysis.CycleDetected"/>), so the ~81% of the measured corpus's
/// non-terminating methods that were genuine oscillators (not null-forever stalls) resolve in
/// single-digit iterations instead of burning the full bound.
/// </para>
/// <para>
/// <b>Fixture strategy.</b> These need a real <see cref="ControlFlowGraph"/> and
/// <see cref="Backend.Model.CFGNode"/> instructions — heavier than the pure-getter tests in
/// <see cref="NullGuardRegressionTests"/>/<see cref="BasicTypeCoreLibraryEqualityTests"/>, but
/// still hand-buildable in-process (no CCI host, no compiled assembly, unlike
/// <see cref="VoidReturnLiftingRegressionTests"/>). The oscillating fixture below exploits the
/// <em>one</em> genuinely non-monotonic rule in <c>TypeInferer</c> —
/// <c>TypeHelper.BinarySignedNumericOperationType</c>'s reference-type/<c>UIntPtr</c> swap (the
/// same mechanism the measurement doc traced in ~13 of the corpus's 17 real oscillators) — via a
/// single self-referencing <see cref="BinaryInstruction"/> whose <c>Result</c> is also its own
/// <c>RightOperand</c>, so each fixed-point iteration reads the type it wrote last iteration.
/// </para>
/// <para>
/// <b>Honest gap: items 3 and 7 of this task's "what to test" are not covered as literally
/// specified, and that was verified, not assumed.</b> Item 3 wants a bound-firing input that is
/// non-cyclic (never repeats at all); item 7 wants a real cycle with period &gt;
/// <c>CycleDetectionWindow</c> (20) so eviction is exercised. Both require a per-variable
/// transfer function with more than two reachable states under self-reference. Empirically
/// tried and confirmed NOT constructible from <c>TypeInferer</c>'s actual <c>Visit(...)</c>
/// rules: the reference/<c>UIntPtr</c> rule is intrinsically a two-element domain (its output
/// depends only on whether the input "is a reference type" or "is exactly <c>UIntPtr</c>", never
/// on which specific type), so single self-references, two-variable rings, and chains of up to
/// 30 sequential self-writes with structurally distinct pointer identities all settle into an
/// exact period-2 cycle — never a longer period, never a non-repeating trajectory. A genuinely
/// longer or non-repeating state space would need a different non-monotonic rule with more than
/// two reachable categories; none exists elsewhere in <c>TypeInferer</c> without also requiring
/// real CCI-resolved <c>IBasicType</c> hierarchies (<c>TypeHelper.MergedType</c>'s
/// <c>IBasicType</c> overload, which calls <c>ResolvedType</c>) — disproportionate machinery for
/// a unit fixture, and the task's own guidance is to report rather than force it.
/// <see cref="Analyze_WhenMaxIterationsIsSmallerThanTheCyclePeriod_ReachesLimitBeforeCycleWouldBeDetected"/>
/// covers the closest reachable adjacent case: the bound firing before cycle detection gets the
/// chance to observe a repeat, using the same real oscillator.
/// </para>
/// </summary>
public sealed class TypeInferenceTerminationRegressionTests
{
    #region Constants pinned against the measurement doc (item 1)
    [Fact]
    public void DefaultMaxIterations_Is100()
    {
        // >14x margin over the measured legitimate-convergence max (7 iterations, corpus-wide,
        // 65,028 methods) -- see "Phase 2 -- bound chosen" in the measurement doc.
        Assert.Equal(100, TypeInferenceAnalysis.DefaultMaxIterations);
    }

    [Fact]
    public void CycleDetectionWindow_Is20()
    {
        // Private const -- not part of the public surface, but deliberately sized (>3x margin
        // over the measured max real cycle period of 6) and worth pinning so a future edit can't
        // silently drift it without a red test. Reflection is required only because it's private;
        // GetValue(null) on a literal field reads the metadata constant directly.
        var field = typeof(TypeInferenceAnalysis).GetField(
            "CycleDetectionWindow", BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(field);
        Assert.Equal(20, (int)field!.GetValue(null)!);
    }
    #endregion

    #region Cycle detection fires on an oscillating input (item 2)
    // No explicit test-level timeout: unlike the FailFast hazard elsewhere in this codebase
    // (ADR-0021), the method under test here IS the fix -- Analyze() is now provably bounded by
    // maxIterations (default 100) regardless of whether the fixture's own transfer function
    // converges, cycles, or does neither, so there is no path back to the old unbounded
    // do-while(changed) this suite exists to guard against.
    [Fact]
    public void Analyze_WhenTypeOscillatesBetweenPointerAndUIntPtr_DetectsCycleWithoutReachingBound()
    {
        var (cfg, _) = BuildOscillatingCfg();
        var analysis = new TypeInferenceAnalysis(cfg, null);

        analysis.Analyze();

        Assert.True(analysis.CycleDetected);
        Assert.False(analysis.ReachedIterationLimit);
        Assert.True(analysis.IterationCount < TypeInferenceAnalysis.DefaultMaxIterations);
        // Real corpus cases resolved at iterations 4-6; this minimal single-instruction fixture
        // has no "settling" transient before the cycle, so it resolves even faster.
        Assert.Equal(3, analysis.IterationCount);
    }
    #endregion

    #region Bound fires before cycle detection can observe a repeat (adjacent to item 3 -- see class remarks)
    [Fact]
    public void Analyze_WhenMaxIterationsIsSmallerThanTheCyclePeriod_ReachesLimitBeforeCycleWouldBeDetected()
    {
        // The oscillator above needs 3 iterations before cycle detection can see a REPEAT (the
        // state recorded at iteration 1 and the state recorded at iteration 3 must both exist
        // for StatesEqual to compare them). Capping maxIterations at 2 forces the bound to fire
        // first, on real oscillating state, without cycle detection ever getting the chance --
        // exercising the actual race between the two mechanisms.
        var (cfg, _) = BuildOscillatingCfg();
        var analysis = new TypeInferenceAnalysis(cfg, null);

        analysis.Analyze(maxIterations: 2);

        Assert.True(analysis.ReachedIterationLimit);
        Assert.False(analysis.CycleDetected);
        Assert.Equal(2, analysis.IterationCount);
    }
    #endregion

    #region DidNotConverge and mutual exclusivity, across all three real outcomes (item 4)
    [Fact]
    public void DidNotConverge_MatchesEitherFlag_AndTheFlagsAreMutuallyExclusive_AcrossConvergingCyclingAndBoundedRuns()
    {
        var (convergingCfg, _) = BuildConvergingCfg();
        var converging = new TypeInferenceAnalysis(convergingCfg, null);
        converging.Analyze();
        AssertConvergenceInvariant(converging);
        Assert.False(converging.DidNotConverge);

        var (cyclingCfg, _) = BuildOscillatingCfg();
        var cycling = new TypeInferenceAnalysis(cyclingCfg, null);
        cycling.Analyze();
        AssertConvergenceInvariant(cycling);
        Assert.True(cycling.DidNotConverge);
        Assert.True(cycling.CycleDetected);
        Assert.False(cycling.ReachedIterationLimit);

        var (boundedCfg, _) = BuildOscillatingCfg();
        var bounded = new TypeInferenceAnalysis(boundedCfg, null);
        bounded.Analyze(detectCycles: false);
        AssertConvergenceInvariant(bounded);
        Assert.True(bounded.DidNotConverge);
        Assert.True(bounded.ReachedIterationLimit);
        Assert.False(bounded.CycleDetected);

        static void AssertConvergenceInvariant(TypeInferenceAnalysis analysis)
        {
            Assert.Equal(analysis.ReachedIterationLimit || analysis.CycleDetected, analysis.DidNotConverge);
            Assert.False(
                analysis.ReachedIterationLimit && analysis.CycleDetected,
                "ReachedIterationLimit and CycleDetected both fired -- review traced these as mutually exclusive.");
        }
    }
    #endregion

    #region detectCycles: false disables the detector (item 5)
    [Fact]
    public void Analyze_WhenDetectCyclesIsFalse_OscillatingInputFallsThroughToTheBoundInstead()
    {
        var (cfg, _) = BuildOscillatingCfg();
        var analysis = new TypeInferenceAnalysis(cfg, null);

        analysis.Analyze(detectCycles: false);

        Assert.False(analysis.CycleDetected);
        Assert.True(analysis.ReachedIterationLimit);
        Assert.Equal(TypeInferenceAnalysis.DefaultMaxIterations, analysis.IterationCount);
    }
    #endregion

    #region Converging input: the positive control (item 6)
    [Fact]
    public void Analyze_WhenTypesConverge_SetsNeitherFlagAndReportsASmallIterationCount()
    {
        // Without this, a bug that always reported non-convergence would still pass every other
        // test in this file -- this is what proves ReachedIterationLimit/CycleDetected aren't
        // vacuously true.
        var (cfg, z) = BuildConvergingCfg();
        var analysis = new TypeInferenceAnalysis(cfg, null);

        analysis.Analyze();

        Assert.False(analysis.ReachedIterationLimit);
        Assert.False(analysis.CycleDetected);
        Assert.False(analysis.DidNotConverge);
        Assert.Same(PlatformTypes.Int32, z.Type);
        // Real corpus max for legitimate convergence was 7 iterations; this trivial fixture needs
        // far fewer.
        Assert.Equal(2, analysis.IterationCount);
    }
    #endregion

    #region Fixtures
    // Single node, single self-referencing BinaryInstruction: Result and RightOperand are the
    // SAME variable, so each outer do-while iteration reads the type written by the previous
    // one. LeftOperand is a fixed pointer type that never changes (nothing ever assigns to it).
    // TypeHelper.BinarySignedNumericOperationType's "left is IReferenceType" branch then gives an
    // exact period-2 swap: reference-type input -> UIntPtr; UIntPtr input -> the fixed pointer
    // type again. Seeding the variable's type as a reference type before Analyze() runs mirrors
    // the real-world trigger (a reused stack-temp slot that already carries a type from an
    // earlier, unrelated write) rather than starting from "unknown" (which would hit the
    // null-forever guard, not oscillation).
    private static (ControlFlowGraph Cfg, IVariable S) BuildOscillatingCfg()
    {
        var cfg = new ControlFlowGraph();
        var node = new CFGNode(2);

        var s = new LocalVariable("s");
        var p = new LocalVariable("p") { Type = new PointerType(PlatformTypes.Int32) };

        node.Instructions.Add(new BinaryInstruction(0, s, p, BinaryOperation.Add, s));

        cfg.ConnectNodes(cfg.Entry, node);
        cfg.ConnectNodes(node, cfg.Exit);

        s.Type = new PointerType(PlatformTypes.Int32);

        return (cfg, s);
    }

    // Single node, single BinaryInstruction over two FIXED Int32 operands: not self-referencing,
    // so the result is deterministic and constant from the first iteration onward -- a genuine
    // fixed point, not an oscillation, giving a small, known IterationCount.
    private static (ControlFlowGraph Cfg, IVariable Z) BuildConvergingCfg()
    {
        var cfg = new ControlFlowGraph();
        var node = new CFGNode(2);

        var z = new LocalVariable("z");
        var a = new LocalVariable("a") { Type = PlatformTypes.Int32 };
        var b = new LocalVariable("b") { Type = PlatformTypes.Int32 };

        node.Instructions.Add(new BinaryInstruction(0, z, a, BinaryOperation.Add, b));

        cfg.ConnectNodes(cfg.Entry, node);
        cfg.ConnectNodes(node, cfg.Exit);

        return (cfg, z);
    }
    #endregion
}
