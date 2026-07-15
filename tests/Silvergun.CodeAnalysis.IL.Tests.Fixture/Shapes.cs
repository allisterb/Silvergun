namespace Silvergun.CodeAnalysis.IL.Tests.Fixture;

using System;

/// <summary>
/// Deterministic, non-trivial method bodies exercising distinct CIL control-flow
/// shapes. This assembly is the target under analysis in the IL analyzer tests.
/// </summary>
public class Shapes
{
    /// <summary>No branches: a few arithmetic statements.</summary>
    public int Straight()
    {
        var a = 7;
        var b = a * 3;
        var c = b + a - 2;
        return c * 2;
    }

    /// <summary>if/else returning different values.</summary>
    public int Branch(int x)
    {
        if (x > 0)
        {
            return x + 100;
        }
        else
        {
            return x - 100;
        }
    }

    /// <summary>for loop accumulating a value.</summary>
    public int Loop(int n)
    {
        var sum = 0;
        for (var i = 0; i < n; i++)
        {
            sum += i * 2;
        }
        return sum;
    }

    /// <summary>try/catch(FormatException) with int.Parse.</summary>
    public int TryCatch(string s)
    {
        try
        {
            return int.Parse(s);
        }
        catch (FormatException)
        {
            return -1;
        }
    }

    /// <summary>Calls at least two of the other methods.</summary>
    public int Calls()
    {
        var a = Straight();
        var b = Branch(a);
        return a + b;
    }
}
