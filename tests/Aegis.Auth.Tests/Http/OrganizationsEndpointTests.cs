using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

using Aegis.Auth.Organizations;
using Aegis.Auth.Plugins;
using Aegis.Auth.Tests.Helpers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Tests.Http;

public sealed class OrganizationsEndpointTests
{
    private static readonly string Credential = new('c', 16);

    [Fact]
    public async Task Create_MakesCallerOwner_SetsActive_AndListsIt()
    {
        await using AegisTestHost host = await StartAsync();
        User alice = await SignUpAsync(host, "alice@example.com");

        var orgId = await CreateAsync(host, alice, "acme");

        Member? active = await GetJsonAsync<Member>(host, alice, "/api/auth/organization/active-member");
        Assert.Equal(orgId, active!.OrganizationId);
        Assert.Equal("owner", active.Role);

        List<Organization>? list = await GetJsonAsync<List<Organization>>(host, alice, "/api/auth/organization/list");
        Assert.Equal("acme", Assert.Single(list!).Slug);

        using JsonDocument full = JsonDocument.Parse(await (await SendAsync(host, alice, HttpMethod.Get, "/api/auth/organization/full")).Content.ReadAsStringAsync());
        Assert.Equal(orgId, full.RootElement.GetProperty("organization").GetProperty("id").GetString());
        Assert.Equal(1, full.RootElement.GetProperty("members").GetArrayLength());
    }

    [Fact]
    public async Task Endpoints_RequireSignIn()
    {
        await using AegisTestHost host = await StartAsync();

        HttpResponseMessage response = await host.Client.PostAsJsonAsync("/api/auth/organization/create", new { name = "Acme", slug = "acme" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Slug_IsValidated_Normalized_AndUnique()
    {
        await using AegisTestHost host = await StartAsync();
        User alice = await SignUpAsync(host, "alice@example.com");
        await CreateAsync(host, alice, "Acme");

        Assert.False((await GetJsonAsync<CheckSlugResponse>(host, alice, "/api/auth/organization/check-slug?slug=acme"))!.Available);
        Assert.True((await GetJsonAsync<CheckSlugResponse>(host, alice, "/api/auth/organization/check-slug?slug=other"))!.Available);

        HttpResponseMessage taken = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/organization/create", new { name = "Acme 2", slug = "ACME" });
        Assert.Equal(HttpStatusCode.Conflict, taken.StatusCode);
        Assert.Equal(OrganizationErrors.SlugTaken, await ErrorCodeAsync(taken));

        HttpResponseMessage invalid = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/organization/create", new { name = "Bad", slug = "no spaces!" });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.Equal(OrganizationErrors.InvalidSlug, await ErrorCodeAsync(invalid));
    }

    [Fact]
    public async Task CrossTenant_MemberOfB_CannotReadUpdateDeleteOrSetActiveA()
    {
        await using AegisTestHost host = await StartAsync();
        User alice = await SignUpAsync(host, "alice@example.com");
        User bob = await SignUpAsync(host, "bob@example.com");
        var orgA = await CreateAsync(host, alice, "org-a");
        await CreateAsync(host, bob, "org-b");

        (HttpMethod, string, object?)[] attempts =
        [
            (HttpMethod.Get, $"/api/auth/organization/full?organizationId={orgA}", null),
            (HttpMethod.Post, "/api/auth/organization/update", new { organizationId = orgA, name = "Pwned" }),
            (HttpMethod.Post, "/api/auth/organization/delete", new { organizationId = orgA }),
            (HttpMethod.Post, "/api/auth/organization/set-active", new { organizationId = orgA }),
            (HttpMethod.Post, "/api/auth/organization/leave", new { organizationId = orgA }),
            (HttpMethod.Post, "/api/auth/organization/members/remove", new { organizationId = orgA, memberId = "x" }),
        ];

        foreach ((HttpMethod method, var path, var body) in attempts)
        {
            HttpResponseMessage response = await SendAsync(host, bob, method, path, body);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal(OrganizationErrors.NotMember, await ErrorCodeAsync(response));
        }

        // An unknown id gets the same answer, so ids can't be probed.
        HttpResponseMessage unknown = await SendAsync(host, bob, HttpMethod.Get, "/api/auth/organization/full?organizationId=does-not-exist");
        Assert.Equal(OrganizationErrors.NotMember, await ErrorCodeAsync(unknown));

        using IServiceScope scope = host.Services.CreateScope();
        Organization a = await scope.ServiceProvider.GetRequiredService<TestDbContext>().Set<Organization>().SingleAsync(o => o.Id == orgA);
        Assert.Equal("org-a", a.Name);
    }

    [Fact]
    public async Task Member_CannotUpdateOrganization_AdminCan()
    {
        await using AegisTestHost host = await StartAsync();
        User alice = await SignUpAsync(host, "alice@example.com");
        User bob = await SignUpAsync(host, "bob@example.com");
        User carol = await SignUpAsync(host, "carol@example.com");
        var orgId = await CreateAsync(host, alice, "acme");
        await AddMemberAsync(host, orgId, bob, "member");
        await AddMemberAsync(host, orgId, carol, "admin");

        HttpResponseMessage asMember = await SendAsync(host, bob, HttpMethod.Post, "/api/auth/organization/update", new { organizationId = orgId, name = "Nope" });
        Assert.Equal(HttpStatusCode.Forbidden, asMember.StatusCode);
        Assert.Equal(OrganizationErrors.Forbidden, await ErrorCodeAsync(asMember));

        HttpResponseMessage asAdmin = await SendAsync(host, carol, HttpMethod.Post, "/api/auth/organization/update", new { organizationId = orgId, name = "Acme Inc" });
        Assert.Equal(HttpStatusCode.OK, asAdmin.StatusCode);

        HttpResponseMessage adminDelete = await SendAsync(host, carol, HttpMethod.Post, "/api/auth/organization/delete", new { organizationId = orgId });
        Assert.Equal(OrganizationErrors.Forbidden, await ErrorCodeAsync(adminDelete));
    }

    [Fact]
    public async Task Admin_CannotEscalate_OrTouchOwner()
    {
        await using AegisTestHost host = await StartAsync();
        User alice = await SignUpAsync(host, "alice@example.com");
        User bob = await SignUpAsync(host, "bob@example.com");
        User carol = await SignUpAsync(host, "carol@example.com");
        var orgId = await CreateAsync(host, alice, "acme");
        Member bobMember = await AddMemberAsync(host, orgId, bob, "member");
        await AddMemberAsync(host, orgId, carol, "admin");
        var aliceMemberId = (await MemberOfAsync(host, orgId, alice)).Id;

        HttpResponseMessage promote = await SendAsync(host, carol, HttpMethod.Post, "/api/auth/organization/members/update-role", new { organizationId = orgId, memberId = bobMember.Id, role = "owner" });
        Assert.Equal(OrganizationErrors.Forbidden, await ErrorCodeAsync(promote));

        HttpResponseMessage demoteOwner = await SendAsync(host, carol, HttpMethod.Post, "/api/auth/organization/members/update-role", new { organizationId = orgId, memberId = aliceMemberId, role = "member" });
        Assert.Equal(OrganizationErrors.Forbidden, await ErrorCodeAsync(demoteOwner));

        HttpResponseMessage removeOwner = await SendAsync(host, carol, HttpMethod.Post, "/api/auth/organization/members/remove", new { organizationId = orgId, memberId = aliceMemberId });
        Assert.Equal(OrganizationErrors.Forbidden, await ErrorCodeAsync(removeOwner));

        HttpResponseMessage unknownRole = await SendAsync(host, carol, HttpMethod.Post, "/api/auth/organization/members/update-role", new { organizationId = orgId, memberId = bobMember.Id, role = "superuser" });
        Assert.Equal(OrganizationErrors.RoleNotFound, await ErrorCodeAsync(unknownRole));

        HttpResponseMessage toAdmin = await SendAsync(host, carol, HttpMethod.Post, "/api/auth/organization/members/update-role", new { organizationId = orgId, memberId = bobMember.Id, role = "admin" });
        Assert.Equal(HttpStatusCode.OK, toAdmin.StatusCode);
        Assert.Equal("admin", (await MemberOfAsync(host, orgId, bob)).Role);
    }

    [Fact]
    public async Task LastOwner_CannotLeave_BeDemoted_OrRemoved()
    {
        await using AegisTestHost host = await StartAsync();
        User alice = await SignUpAsync(host, "alice@example.com");
        User bob = await SignUpAsync(host, "bob@example.com");
        var orgId = await CreateAsync(host, alice, "acme");
        var aliceMemberId = (await MemberOfAsync(host, orgId, alice)).Id;

        HttpResponseMessage leave = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/organization/leave", new { organizationId = orgId });
        Assert.Equal(HttpStatusCode.Conflict, leave.StatusCode);
        Assert.Equal(OrganizationErrors.LastOwner, await ErrorCodeAsync(leave));

        HttpResponseMessage demote = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/organization/members/update-role", new { organizationId = orgId, memberId = aliceMemberId, role = "admin" });
        Assert.Equal(OrganizationErrors.LastOwner, await ErrorCodeAsync(demote));

        HttpResponseMessage remove = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/organization/members/remove", new { organizationId = orgId, memberId = aliceMemberId });
        Assert.Equal(OrganizationErrors.LastOwner, await ErrorCodeAsync(remove));
        Assert.Equal("owner", (await MemberOfAsync(host, orgId, alice)).Role);

        // With a second owner, the first can leave.
        await AddMemberAsync(host, orgId, bob, "owner");
        HttpResponseMessage leaveNow = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/organization/leave", new { organizationId = orgId });
        Assert.Equal(HttpStatusCode.NoContent, leaveNow.StatusCode);
    }

    [Fact]
    public async Task RemovedMember_LosesAccess_AndActiveOrganization()
    {
        await using AegisTestHost host = await StartAsync();
        User alice = await SignUpAsync(host, "alice@example.com");
        User bob = await SignUpAsync(host, "bob@example.com");
        var orgId = await CreateAsync(host, alice, "acme");
        Member bobMember = await AddMemberAsync(host, orgId, bob, "member");
        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(host, bob, HttpMethod.Post, "/api/auth/organization/set-active", new { organizationId = orgId })).StatusCode);

        HttpResponseMessage removed = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/organization/members/remove", new { organizationId = orgId, memberId = bobMember.Id });
        Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);

        HttpResponseMessage active = await SendAsync(host, bob, HttpMethod.Get, "/api/auth/organization/active-member");
        Assert.Equal(OrganizationErrors.NoActiveOrganization, await ErrorCodeAsync(active));
        HttpResponseMessage full = await SendAsync(host, bob, HttpMethod.Get, $"/api/auth/organization/full?organizationId={orgId}");
        Assert.Equal(OrganizationErrors.NotMember, await ErrorCodeAsync(full));
    }

    [Fact]
    public async Task Delete_RemovesOrganizationAndMembers()
    {
        await using AegisTestHost host = await StartAsync();
        User alice = await SignUpAsync(host, "alice@example.com");
        User bob = await SignUpAsync(host, "bob@example.com");
        var orgId = await CreateAsync(host, alice, "acme");
        await AddMemberAsync(host, orgId, bob, "member");

        HttpResponseMessage deleted = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/organization/delete", new { organizationId = orgId });
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        using IServiceScope scope = host.Services.CreateScope();
        TestDbContext db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        Assert.False(await db.Set<Organization>().AnyAsync());
        Assert.False(await db.Set<Member>().AnyAsync());
        Assert.Empty((await GetJsonAsync<List<Organization>>(host, alice, "/api/auth/organization/list"))!);
    }

    [Fact]
    public async Task DeletingUser_RemovesTheirMemberships()
    {
        await using AegisTestHost host = await StartAsync();
        User alice = await SignUpAsync(host, "alice@example.com");
        User bob = await SignUpAsync(host, "bob@example.com");
        var orgId = await CreateAsync(host, alice, "acme");
        await AddMemberAsync(host, orgId, bob, "member");

        using IServiceScope scope = host.Services.CreateScope();
        TestDbContext db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        await db.Users.Where(u => u.Id == bob.Id).ExecuteDeleteAsync();

        Assert.False(await db.Set<Member>().AnyAsync(m => m.UserId == bob.Id));
    }

    [Fact]
    public async Task RequireOrganizationPermission_UsesTheActiveOrganization()
    {
        await using AegisTestHost host = await StartAsync(
            o => o.Roles[OrganizationRoles.Admin].Permissions.Add("project:create"),
            new ProjectsPlugin());
        User alice = await SignUpAsync(host, "alice@example.com");
        User bob = await SignUpAsync(host, "bob@example.com");
        var orgA = await CreateAsync(host, alice, "org-a");
        var orgB = await CreateAsync(host, alice, "org-b");
        await AddMemberAsync(host, orgA, bob, "admin");
        await AddMemberAsync(host, orgB, bob, "member");

        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(host, bob, HttpMethod.Post, "/api/auth/projects")).StatusCode);

        await SendAsync(host, bob, HttpMethod.Post, "/api/auth/organization/set-active", new { organizationId = orgA });
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(host, bob, HttpMethod.Post, "/api/auth/projects")).StatusCode);

        await SendAsync(host, bob, HttpMethod.Post, "/api/auth/organization/set-active", new { organizationId = orgB });
        HttpResponseMessage asMember = await SendAsync(host, bob, HttpMethod.Post, "/api/auth/projects");
        Assert.Equal(HttpStatusCode.Forbidden, asMember.StatusCode);
        Assert.Equal(OrganizationErrors.Forbidden, await ErrorCodeAsync(asMember));

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Client.PostAsync("/api/auth/projects", null)).StatusCode);
    }

    [Fact]
    public async Task AddMemberEndpoint_IsOffByDefault_AndBlocksEscalationWhenOn()
    {
        await using (AegisTestHost host = await StartAsync())
        {
            User alice = await SignUpAsync(host, "alice@example.com");
            HttpResponseMessage response = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/organization/members/add", new { userId = "x", role = "member" });
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }

        await using (AegisTestHost host = await StartAsync(o => o.MapAddMemberEndpoint = true))
        {
            User alice = await SignUpAsync(host, "alice@example.com");
            User carol = await SignUpAsync(host, "carol@example.com");
            User dave = await SignUpAsync(host, "dave@example.com");
            var orgId = await CreateAsync(host, alice, "acme");
            await AddMemberAsync(host, orgId, carol, "admin");

            HttpResponseMessage escalate = await SendAsync(host, carol, HttpMethod.Post, "/api/auth/organization/members/add", new { organizationId = orgId, userId = dave.Id, role = "owner" });
            Assert.Equal(OrganizationErrors.Forbidden, await ErrorCodeAsync(escalate));

            HttpResponseMessage ok = await SendAsync(host, carol, HttpMethod.Post, "/api/auth/organization/members/add", new { organizationId = orgId, userId = dave.Id, role = "member" });
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

            HttpResponseMessage again = await SendAsync(host, carol, HttpMethod.Post, "/api/auth/organization/members/add", new { organizationId = orgId, userId = dave.Id, role = "member" });
            Assert.Equal(OrganizationErrors.AlreadyMember, await ErrorCodeAsync(again));
        }
    }

    [Fact]
    public async Task Limits_AndCreationPolicy_AreEnforced()
    {
        await using AegisTestHost host = await StartAsync(o =>
        {
            o.OrganizationLimit = 1;
            o.AllowUserToCreateOrganization = u => Task.FromResult(u.Email != "blocked@example.com");
        });
        User alice = await SignUpAsync(host, "alice@example.com");
        User blocked = await SignUpAsync(host, "blocked@example.com");
        await CreateAsync(host, alice, "one");

        HttpResponseMessage second = await SendAsync(host, alice, HttpMethod.Post, "/api/auth/organization/create", new { name = "Two", slug = "two" });
        Assert.Equal(OrganizationErrors.OrganizationLimitReached, await ErrorCodeAsync(second));

        HttpResponseMessage denied = await SendAsync(host, blocked, HttpMethod.Post, "/api/auth/organization/create", new { name = "Mine", slug = "mine" });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Equal(OrganizationErrors.CreationDisabled, await ErrorCodeAsync(denied));
    }

    [Fact]
    public async Task InvalidOptions_FailStartup()
    {
        OptionsValidationException ex = await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(o =>
        {
            o.OrganizationLimit = 0;
            o.CreatorRole = "nope";
        }));

        Assert.Contains(ex.Failures, f => f.Contains("OrganizationLimit", StringComparison.Ordinal));
        Assert.Contains(ex.Failures, f => f.Contains("CreatorRole", StringComparison.Ordinal));
    }

    private sealed class ProjectsPlugin : AegisPlugin
    {
        public override string Id => "projects";

        public override IEnumerable<string> Dependencies => [OrganizationsPlugin.PluginId];

        public override void MapEndpoints(RouteGroupBuilder group) =>
            group.MapPost("/projects", () => Results.Ok()).RequireOrganizationPermission("project:create");
    }

    private static Task<AegisTestHost> StartAsync(Action<OrganizationOptions>? configure = null, AegisPlugin? extra = null) =>
        AegisTestHost.StartAsync(configureAegis: a =>
        {
            a.AddOrganizations(configure);
            if (extra is not null)
            {
                a.AddPlugin(extra);
            }
        });

    private sealed record User(string Id, string Email, string Cookies);

    private static async Task<User> SignUpAsync(AegisTestHost host, string email)
    {
        HttpResponseMessage response = await host.Client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = email, email, password = Credential });
        response.EnsureSuccessStatusCode();
        var cookies = string.Join("; ", response.Headers.GetValues("Set-Cookie").Select(c => c.Split(';')[0]));

        using IServiceScope scope = host.Services.CreateScope();
        var id = await scope.ServiceProvider.GetRequiredService<TestDbContext>().Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync();
        return new User(id, email, cookies);
    }

    private static async Task<string> CreateAsync(AegisTestHost host, User user, string slug)
    {
        HttpResponseMessage response = await SendAsync(host, user, HttpMethod.Post, "/api/auth/organization/create", new { name = slug, slug });
        response.EnsureSuccessStatusCode();
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("id").GetString()!;
    }

    /// <summary>Adds a member through the trusted server-side API, as an app would after its own checks.</summary>
    private static async Task<Member> AddMemberAsync(AegisTestHost host, string orgId, User user, string role)
    {
        using IServiceScope scope = host.Services.CreateScope();
        Result<Member> result = await scope.ServiceProvider.GetRequiredService<IOrganizationService>().AddMemberAsync(null, orgId, user.Id, role);
        Assert.True(result.IsSuccess, result.Message);
        return result.Value!;
    }

    private static async Task<Member> MemberOfAsync(AegisTestHost host, string orgId, User user)
    {
        using IServiceScope scope = host.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<TestDbContext>().Set<Member>().AsNoTracking().SingleAsync(m => m.OrganizationId == orgId && m.UserId == user.Id);
    }

    private static async Task<T?> GetJsonAsync<T>(AegisTestHost host, User user, string path)
    {
        HttpResponseMessage response = await SendAsync(host, user, HttpMethod.Get, path);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<T>();
    }

    private static Task<HttpResponseMessage> SendAsync(AegisTestHost host, User user, HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("Cookie", user.Cookies);
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
