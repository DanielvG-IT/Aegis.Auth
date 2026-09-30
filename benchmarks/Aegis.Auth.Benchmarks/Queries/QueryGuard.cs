namespace Aegis.Auth.Benchmarks.Queries;

/// <summary>
/// Setup-time check that every variant returns the same row, so a fast number is never a wrong answer.
/// </summary>
internal static class QueryGuard
{
    public static void Expect(bool condition, string benchmark)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"{benchmark}: a variant returned an unexpected result; the numbers would not be comparable.");
        }
    }
}
