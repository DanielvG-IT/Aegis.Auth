using Aegis.Auth.Options;

using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Plugins;

/// <summary>
/// A feature that plugs into Aegis: services, EF model, endpoints, error codes, rate-limit rules
/// and startup validation. Register it with <see cref="IAegisAuthBuilder.AddPlugin"/>.
/// This is an abstract class rather than an interface so members can be added without breaking plugins.
/// </summary>
public abstract class AegisPlugin
{
    /// <summary>
    /// Unique, kebab-case identifier, e.g. <c>organization</c>. Registering two plugins with the same id fails.
    /// </summary>
    public abstract string Id { get; }

    /// <summary>
    /// Ids of plugins this one builds on, e.g. <c>["organization"]</c> for SSO or teams. Startup fails when one
    /// of them is not registered. Registration order does not matter.
    /// </summary>
    public virtual IEnumerable<string> Dependencies => [];

    /// <summary>
    /// Registers the plugin's services. Called once, when the plugin is added.
    /// </summary>
    public virtual void ConfigureServices(IServiceCollection services) { }

    /// <summary>
    /// Adds the plugin's entities, indexes and shadow properties. Runs after the core model and before the
    /// app's <c>OnModelCreating</c>, for contexts configured with <c>UseAegisAuth</c>. The result is cached
    /// per context type and plugin set, so it must not depend on anything but the plugin's own configuration.
    /// When a plugin overrides this, startup fails unless the Aegis context is configured with <c>UseAegisAuth</c>.
    /// </summary>
    public virtual void ConfigureModel(ModelBuilder modelBuilder) { }

    /// <summary>
    /// Maps the plugin's endpoints under the Aegis base path. Called by <c>MapAegisAuthEndpoints</c>
    /// after the core endpoints, in plugin registration order. Routes that collide fail at startup.
    /// </summary>
    public virtual void MapEndpoints(RouteGroupBuilder group) { }

    /// <summary>
    /// Whether <see cref="MapEndpoints"/> should run for this configuration. Only consulted when
    /// <c>AegisAuthEndpointMapOptions.RespectConfiguration</c> is on (the default).
    /// </summary>
    public virtual bool ShouldMapEndpoints(AegisAuthOptions options) => true;

    /// <summary>
    /// Per-path rate-limit rules for the plugin's endpoints. Collected at registration; paths are relative
    /// to the Aegis base path.
    /// </summary>
    public virtual IEnumerable<AegisRateLimitRule> RateLimitRules => [];

    /// <summary>
    /// HTTP status for each error code the plugin returns. Codes without an entry map to 400.
    /// </summary>
    public virtual IReadOnlyDictionary<string, int> ErrorStatusCodes => new Dictionary<string, int>();

    /// <summary>
    /// Adds a message to <paramref name="errors"/> for every invalid setting. Runs with the core option
    /// validation at startup, so the app fails to start with all messages at once.
    /// </summary>
    public virtual void Validate(AegisAuthOptions options, IList<string> errors) { }
}
