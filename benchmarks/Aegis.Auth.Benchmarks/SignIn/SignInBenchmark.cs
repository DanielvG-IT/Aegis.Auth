using Aegis.Auth.Benchmarks.Infrastructure;
using Aegis.Auth.Features.SignIn;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;

using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Benchmarks.SignIn;

/// <summary>
/// <c>ISignInService.SignInEmail</c> end to end with the default password hasher (BCrypt, work factor 11):
/// user lookup, BCrypt verify, session insert. The failure rows check that an unknown email costs about the same
/// as a wrong password, which is what keeps sign-in from revealing which accounts exist.
/// </summary>
[BenchmarkCategory("SignIn")]
[SimpleJob(RunStrategy.Monitoring, launchCount: 1, warmupCount: 3, iterationCount: 20)]
public class SignInBenchmark
{
    private BenchDatabase _database = null!;
    private ServiceProvider _services = null!;
    private string _email = string.Empty;

    [ParamsSource(typeof(BenchEnvironment), nameof(BenchEnvironment.AvailableProviders))]
    public DatabaseProvider Provider { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        _database = await BenchDatabase.CreateAsync(Provider, BCrypt.Net.BCrypt.EnhancedHashPassword(BenchDatabase.Password));
        _services = AegisServices.Build(_database);
        _email = BenchDatabase.Email(BenchDatabase.TargetIndex);

        if (await Success() is not true || await WrongPassword() is not false || await UnknownEmail() is not false)
        {
            throw new InvalidOperationException($"{nameof(SignInBenchmark)}: sign-in did not behave as expected.");
        }
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await _services.DisposeAsync();
        await _database.DisposeAsync();
    }

    [Benchmark(Baseline = true)]
    public Task<bool> Success() => SignInAsync(_email, BenchDatabase.Password);

    [Benchmark]
    public Task<bool> WrongPassword() => SignInAsync(_email, "not the password");

    [Benchmark]
    public Task<bool> UnknownEmail() => SignInAsync("nobody@bench.aegis.local", BenchDatabase.Password);

    private async Task<bool> SignInAsync(string email, string password)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        Result<SignInResult> result = await scope.ServiceProvider.GetRequiredService<ISignInService>().SignInEmail(new SignInEmailInput
        {
            Email = email,
            Password = password,
            IpAddress = "203.0.113.10",
            UserAgent = "Aegis.Auth.Benchmarks",
        });
        return result.IsSuccess;
    }
}
