using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Extensions;
using Aegis.Auth.Features.EmailVerification;
using Aegis.Auth.Options;
using Aegis.Auth.Plugins;
using Aegis.Auth.Tests.Helpers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Tests.Http;

/// <summary>
/// Proves each part of the plugin contract through the real HTTP pipeline with a test-only plugin.
/// </summary>
public sealed class PluginContractTests
{
    [Fact]
    public async Task Plugin_Entity_IsAddedToModelAndPersisted()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new WidgetPlugin()));

        HttpResponseMessage response = await host.Client.PostAsJsonAsync("/api/auth/widgets", new { name = "first" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using IServiceScope scope = host.Services.CreateScope();
        var db = (DbContext)scope.ServiceProvider.GetRequiredService<IAuthDbContext>();
        Widget widget = Assert.Single(db.Set<Widget>());
        Assert.Equal("first", widget.Name);
    }

    [Fact]
    public async Task Plugin_Model_IsNotSharedWithContextsWithoutThePlugin()
    {
        await using AegisTestHost withPlugin = await AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new WidgetPlugin()));
        await using AegisTestHost withoutPlugin = await AegisTestHost.StartAsync();

        Assert.NotNull(GetModel(withPlugin).FindEntityType(typeof(Widget)));
        Assert.Null(GetModel(withoutPlugin).FindEntityType(typeof(Widget)));
    }

    [Fact]
    public async Task Plugin_Services_AreRegistered()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new WidgetPlugin()));

        Assert.NotNull(host.Services.GetService<WidgetMarker>());
    }

    [Fact]
    public async Task Plugin_ErrorCode_MapsToCustomStatus()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new WidgetPlugin(maxWidgets: 1)));

        HttpResponseMessage first = await host.Client.PostAsJsonAsync("/api/auth/widgets", new { name = "first" });
        HttpResponseMessage second = await host.Client.PostAsJsonAsync("/api/auth/widgets", new { name = "second" });

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        using JsonDocument problem = JsonDocument.Parse(await second.Content.ReadAsStringAsync());
        Assert.Equal(WidgetPlugin.LimitReached, problem.RootElement.GetProperty("errorCode").GetString());
        Assert.Equal("Conflict", problem.RootElement.GetProperty("title").GetString());
        Assert.Equal(409, problem.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task Plugin_ValidationError_FailsStartup()
    {
        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new WidgetPlugin(maxWidgets: 0))));

        Assert.Contains("WidgetPlugin.MaxWidgets must be greater than 0.", ex.Failures);
    }

    [Fact]
    public async Task Plugin_Validation_SeesConfiguredOptions()
    {
        // The widget plugin requires email/password, which the test host enables.
        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            AegisTestHost.StartAsync(
                o => o.EmailAndPassword.Enabled = false,
                configureAegis: a => a.AddPlugin(new WidgetPlugin())));

        Assert.Contains("WidgetPlugin requires EmailAndPassword.Enabled.", ex.Failures);
    }

    [Fact]
    public async Task DuplicatePluginId_FailsStartup()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new WidgetPlugin()).AddPlugin(new WidgetPlugin(routePrefix: "/other"))));

        Assert.Contains("id 'widgets' is already registered", ex.Message);
    }

    [Fact]
    public async Task BuiltInPluginId_CannotBeRegisteredTwice()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new EmailVerificationPlugin())));

        Assert.Contains("'email-verification' is already registered", ex.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Widgets")]
    [InlineData("my_widgets")]
    [InlineData("-widgets")]
    [InlineData("widgets-")]
    public async Task InvalidPluginId_FailsStartup(string id)
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new WidgetPlugin(id: id))));

        Assert.Contains("must be kebab-case", ex.Message);
    }

    [Fact]
    public async Task PluginRoute_CollidingWithCoreRoute_FailsStartup()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new RoutePlugin("hijack", "POST", "/sign-in/email"))));

        Assert.Contains("plugin 'hijack'", ex.Message);
        Assert.Contains("Aegis core", ex.Message);
    }

    [Fact]
    public async Task PluginRoute_CollidingWithEarlierPlugin_FailsStartup()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AegisTestHost.StartAsync(configureAegis: a => a
                .AddPlugin(new RoutePlugin("first", "GET", "/things/{id}"))
                .AddPlugin(new RoutePlugin("second", "GET", "/Things/{thingId}/"))));

        Assert.Contains("plugin 'second'", ex.Message);
        Assert.Contains("plugin 'first'", ex.Message);
    }

    [Fact]
    public async Task PluginRoute_SamePathDifferentMethod_IsAllowed()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(configureAegis: a => a
            .AddPlugin(new RoutePlugin("reader", "GET", "/sign-in/email")));

        HttpResponseMessage response = await host.Client.GetAsync("/api/auth/sign-in/email");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task PluginErrorCode_ConflictingWithCoreStatus_FailsStartup()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(
                new RoutePlugin("remap", "GET", "/remap", new Dictionary<string, int> { [AuthErrors.Identity.InvalidCredentials] = 409 }))));

        Assert.Contains("'INVALID_CREDENTIALS'", ex.Message);
    }

    [Fact]
    public async Task PluginErrorCode_OutsideErrorRange_FailsStartup()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(
                new RoutePlugin("ok", "GET", "/ok", new Dictionary<string, int> { ["ALL_GOOD"] = 200 }))));

        Assert.Contains("between 400 and 599", ex.Message);
    }

    [Fact]
    public async Task PluginRateLimitRules_AreCollected()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(configureAegis: a => a.AddPlugin(new WidgetPlugin()));

        AegisPluginRegistry registry = host.Services.GetRequiredService<AegisPluginRegistry>();

        Assert.Contains(registry.RateLimitRules, r => r.PluginId == "widgets" && r.Rule.Path == "/widgets" && r.Rule.MaxRequests == 3);
        Assert.Contains(registry.RateLimitRules, r => r.PluginId == EmailVerificationPlugin.PluginId && r.Rule.Path == "/email-verify/verify");
    }

    [Fact]
    public async Task EmailVerification_IsRegisteredAsPlugin()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync();

        AegisPluginRegistry registry = host.Services.GetRequiredService<AegisPluginRegistry>();

        Assert.IsType<EmailVerificationPlugin>(Assert.Single(registry.Plugins));
        Assert.Equal(403, registry.GetStatusCode(AuthErrors.System.VerificationEmailNotEnabled));
    }

    [Fact]
    public async Task EmailVerification_MapToggleOff_HidesPluginRoutes()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(
            o => o.EmailVerification.SendVerificationEmail = (_, _) => Task.CompletedTask,
            e => e.MapEmailVerification = false);

        Assert.DoesNotContain(RoutePatterns(host), r => r.Contains("email-verify"));
    }

    [Fact]
    public async Task PluginEndpoints_IgnoreConfiguration_WhenRespectConfigurationIsOff()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(configureEndpoints: e => e.RespectConfiguration = false);

        Assert.Contains("/api/auth/email-verify/verify", RoutePatterns(host));
    }

    [Fact]
    public void UseAegisAuth_BeforeDatabaseProvider_Throws()
    {
        using ServiceProvider services = new ServiceCollection().BuildServiceProvider();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            new DbContextOptionsBuilder<TestDbContext>().UseAegisAuth(services));

        Assert.Contains("before calling UseAegisAuth", ex.Message);
    }

    [Fact]
    public void UseAegisAuth_WithoutAddAegisAuth_Throws()
    {
        using ServiceProvider services = new ServiceCollection().BuildServiceProvider();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            new DbContextOptionsBuilder<TestDbContext>().UseInMemoryDatabase("no-aegis").UseAegisAuth(services));

        Assert.Contains("AddAegisAuth", ex.Message);
    }

    private static Microsoft.EntityFrameworkCore.Metadata.IModel GetModel(AegisTestHost host)
    {
        using IServiceScope scope = host.Services.CreateScope();
        return ((DbContext)scope.ServiceProvider.GetRequiredService<IAuthDbContext>()).Model;
    }

    private static IReadOnlyList<string> RoutePatterns(AegisTestHost host) =>
        [.. host.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Select(e => e.RoutePattern.RawText ?? string.Empty)];

    internal sealed class Widget
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
    }

    internal sealed record CreateWidgetRequest(string Name);

    internal sealed class WidgetMarker;

    private sealed class WidgetPlugin(int maxWidgets = 10, string id = "widgets", string routePrefix = "") : AegisPlugin
    {
        public const string LimitReached = "WIDGET_LIMIT_REACHED";

        public override string Id => id;

        public override void ConfigureServices(IServiceCollection services) => services.AddSingleton<WidgetMarker>();

        public override void ConfigureModel(ModelBuilder modelBuilder) =>
            modelBuilder.Entity<Widget>(entity =>
            {
                entity.HasKey(w => w.Id);
                entity.Property(w => w.Name).HasMaxLength(100).IsRequired();
                entity.HasIndex(w => w.Name);
            });

        public override void MapEndpoints(RouteGroupBuilder group) =>
            group.MapPost($"{routePrefix}/widgets", async (HttpContext httpContext, IAuthDbContext authDb, CreateWidgetRequest request) =>
            {
                var db = (DbContext)authDb;
                if (await db.Set<Widget>().CountAsync() >= maxWidgets)
                {
                    return AegisResults.Problem(httpContext, LimitReached, "Widget limit reached.");
                }

                db.Add(new Widget { Id = Guid.NewGuid().ToString(), Name = request.Name });
                await db.SaveChangesAsync();
                return Results.Ok();
            });

        public override IEnumerable<AegisRateLimitRule> RateLimitRules => [new("/widgets") { MaxRequests = 3, Window = TimeSpan.FromMinutes(1) }];

        public override IReadOnlyDictionary<string, int> ErrorStatusCodes { get; } = new Dictionary<string, int>
        {
            [LimitReached] = StatusCodes.Status409Conflict,
        };

        public override void Validate(AegisAuthOptions options, IList<string> errors)
        {
            if (maxWidgets <= 0)
            {
                errors.Add("WidgetPlugin.MaxWidgets must be greater than 0.");
            }

            if (options.EmailAndPassword.Enabled is false)
            {
                errors.Add("WidgetPlugin requires EmailAndPassword.Enabled.");
            }
        }
    }

    private sealed class RoutePlugin(string id, string method, string path, IReadOnlyDictionary<string, int>? errors = null) : AegisPlugin
    {
        public override string Id => id;

        public override void MapEndpoints(RouteGroupBuilder group) =>
            group.MapMethods(path, [method], () => Results.Ok());

        public override IReadOnlyDictionary<string, int> ErrorStatusCodes => errors ?? new Dictionary<string, int>();
    }
}
