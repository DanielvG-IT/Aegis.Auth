using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

using Aegis.Auth.Entities;
using Aegis.Auth.TestPlugins.Workspaces;
using Aegis.Auth.Tests.Helpers;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Tests.Http;

/// <summary>
/// Runs the organization-shaped test plugin (built against the public API only) through the real pipeline.
/// </summary>
public sealed class WorkspacesPluginTests
{
    private static readonly string Credential = new('c', 16);

    [Fact]
    public async Task Create_MakesCallerOwner_AndSetsActiveWorkspaceOnSession()
    {
        await using AegisTestHost host = await StartAsync();
        var alice = await SignUpAsync(host, "alice@example.com");

        var workspaceId = await CreateWorkspaceAsync(host, alice, "acme");

        ActiveWorkspaceResponse? active = await GetActiveAsync(host, alice);
        Assert.Equal(new ActiveWorkspaceResponse(workspaceId, "owner"), active);
    }

    [Fact]
    public async Task Endpoints_RequireSignIn()
    {
        await using AegisTestHost host = await StartAsync();

        HttpResponseMessage response = await host.Client.GetAsync("/api/auth/workspace/active");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task SetActive_OtherUsersWorkspace_IsForbidden()
    {
        await using AegisTestHost host = await StartAsync();
        var alice = await SignUpAsync(host, "alice@example.com");
        var mallory = await SignUpAsync(host, "mallory@example.com");
        var acme = await CreateWorkspaceAsync(host, alice, "acme");
        var evil = await CreateWorkspaceAsync(host, mallory, "evil");

        HttpResponseMessage response = await SendAsync(host, mallory, HttpMethod.Post, "/api/auth/workspace/set-active", new { workspaceId = acme });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(WorkspacesPlugin.NotMember, await ErrorCodeAsync(response));
        Assert.Equal(evil, (await GetActiveAsync(host, mallory))?.WorkspaceId);
    }

    [Fact]
    public async Task Active_AfterMembershipRemoved_IsCleared()
    {
        await using AegisTestHost host = await StartAsync();
        var alice = await SignUpAsync(host, "alice@example.com");
        var acme = await CreateWorkspaceAsync(host, alice, "acme");

        using (IServiceScope scope = host.Services.CreateScope())
        {
            TestDbContext db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
            await db.Set<WorkspaceMember>().Where(m => m.WorkspaceId == acme).ExecuteDeleteAsync();
        }

        Assert.Equal(new ActiveWorkspaceResponse(null, null), await GetActiveAsync(host, alice));
    }

    [Fact]
    public async Task Create_DuplicateSlug_IsConflict()
    {
        await using AegisTestHost host = await StartAsync();
        var alice = await SignUpAsync(host, "alice@example.com");
        await CreateWorkspaceAsync(host, alice, "acme");

        HttpResponseMessage response = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/workspace/create", new { name = "Acme 2", slug = "ACME" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(WorkspacesPlugin.SlugTaken, await ErrorCodeAsync(response));
    }

    [Fact]
    public async Task Create_OverLimit_IsForbidden()
    {
        await using AegisTestHost host = await StartAsync(o => o.WorkspaceLimit = 1);
        var alice = await SignUpAsync(host, "alice@example.com");
        await CreateWorkspaceAsync(host, alice, "one");

        HttpResponseMessage response = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/workspace/create", new { name = "Two", slug = "two" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(WorkspacesPlugin.LimitReached, await ErrorCodeAsync(response));
    }

    [Fact]
    public async Task DeletingUser_CascadesToMemberships()
    {
        await using AegisTestHost host = await StartAsync();
        var alice = await SignUpAsync(host, "alice@example.com");
        await CreateWorkspaceAsync(host, alice, "acme");

        using IServiceScope scope = host.Services.CreateScope();
        TestDbContext db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        await db.Users.Where(u => u.Email == "alice@example.com").ExecuteDeleteAsync();

        Assert.Empty(db.Set<WorkspaceMember>());
    }

    [Fact]
    public async Task ActiveWorkspace_IsAShadowColumnOnSession()
    {
        await using AegisTestHost host = await StartAsync();

        using IServiceScope scope = host.Services.CreateScope();
        TestDbContext db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        Microsoft.EntityFrameworkCore.Metadata.IProperty? property = db.Model.FindEntityType(typeof(Session))?.FindProperty(WorkspacesPlugin.ActiveWorkspaceIdProperty);

        Assert.NotNull(property);
        Assert.True(property.IsShadowProperty());
    }

    [Fact]
    public async Task InvalidPluginOptions_FailStartup()
    {
        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(o => o.WorkspaceLimit = 0));

        Assert.Contains("WorkspaceOptions.WorkspaceLimit must be greater than 0.", ex.Failures);
    }

    [Fact]
    public async Task DependentPlugin_WithoutItsDependency_FailsStartup()
    {
        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new WorkspaceSsoPlugin())));

        Assert.Contains("Aegis plugin 'workspace-sso' requires plugin 'workspace'. Register it with AddPlugin.", ex.Failures);
    }

    [Fact]
    public async Task DependentPlugin_RegisteredBeforeItsDependency_Starts()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(configureAegis: a => a
            .AddPlugin(new WorkspaceSsoPlugin())
            .AddWorkspaces());
    }

    [Fact]
    public async Task ModelPlugin_WithoutUseAegisAuth_FailsStartup()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AegisTestHost.StartAsync(
                configureAegis: a => a.AddWorkspaces(),
                configureServices: s =>
                {
                    // Replace the host's UseAegisAuth registration with one that only sets the provider.
                    s.RemoveAll<IDbContextOptionsConfiguration<TestDbContext>>();
                    s.AddDbContext<TestDbContext>(o => o.UseSqlite("Data Source=:memory:"));
                }));

        Assert.Contains("'workspace'", ex.Message);
        Assert.Contains("UseAegisAuth", ex.Message);
    }

    private static Task<AegisTestHost> StartAsync(Action<WorkspaceOptions>? configure = null) =>
        AegisTestHost.StartAsync(configureAegis: a => a.AddWorkspaces(configure));

    /// <summary>Signs up and returns the session cookies to send as the user.</summary>
    private static async Task<string> SignUpAsync(AegisTestHost host, string email)
    {
        HttpResponseMessage response = await host.Client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = email, email, password = Credential });
        response.EnsureSuccessStatusCode();
        return string.Join("; ", response.Headers.GetValues("Set-Cookie").Select(c => c.Split(';')[0]));
    }

    private static async Task<string> CreateWorkspaceAsync(AegisTestHost host, string cookies, string slug)
    {
        HttpResponseMessage response = await SendAsync(host, cookies, HttpMethod.Post, "/api/auth/workspace/create", new { name = slug, slug });
        response.EnsureSuccessStatusCode();
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("id").GetString()!;
    }

    private static async Task<ActiveWorkspaceResponse?> GetActiveAsync(AegisTestHost host, string cookies)
    {
        HttpResponseMessage response = await SendAsync(host, cookies, HttpMethod.Get, "/api/auth/workspace/active");
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<ActiveWorkspaceResponse>();
    }

    private static Task<HttpResponseMessage> SendAsync(AegisTestHost host, string cookies, HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("Cookie", cookies);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return host.Client.SendAsync(request);
    }

    private static async Task<string?> ErrorCodeAsync(HttpResponseMessage response)
    {
        using JsonDocument problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return problem.RootElement.GetProperty("errorCode").GetString();
    }
}
