using Aegis.Auth.Entities;
using Aegis.Auth.Options;
using Aegis.Auth.Plugins;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.TestPlugins.Workspaces;

/// <summary>
/// A cut-down organizations plugin (#100) that exercises what the real one needs from the contract:
/// its own tables with a cascade from <see cref="User"/>, a shadow column on <see cref="Session"/>
/// for the active workspace, signed-in endpoints with a server-side membership check, its own options
/// and error codes, and a dependent plugin.
/// </summary>
public sealed class WorkspacesPlugin(WorkspaceOptions options) : AegisPlugin
{
    public const string PluginId = "workspace";
    public const string ActiveWorkspaceIdProperty = "ActiveWorkspaceId";

    public const string NotMember = "WORKSPACE_NOT_MEMBER";
    public const string SlugTaken = "WORKSPACE_SLUG_TAKEN";
    public const string LimitReached = "WORKSPACE_LIMIT_REACHED";

    public override string Id => PluginId;

    public override void ConfigureServices(IServiceCollection services) => services.AddSingleton(options);

    public override void ConfigureModel(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Workspace>(entity =>
        {
            entity.HasKey(w => w.Id);
            entity.Property(w => w.Id).HasMaxLength(36);
            entity.Property(w => w.Name).HasMaxLength(100).IsRequired();
            entity.Property(w => w.Slug).HasMaxLength(64).IsRequired();
            entity.HasIndex(w => w.Slug).IsUnique();
        });

        modelBuilder.Entity<WorkspaceMember>(entity =>
        {
            entity.HasKey(m => m.Id);
            entity.Property(m => m.Id).HasMaxLength(36);
            entity.Property(m => m.WorkspaceId).HasMaxLength(36);
            entity.Property(m => m.Role).HasMaxLength(64).IsRequired();
            entity.HasIndex(m => new { m.WorkspaceId, m.UserId }).IsUnique();
            entity.HasIndex(m => m.UserId);
            entity.HasOne<Workspace>().WithMany().HasForeignKey(m => m.WorkspaceId).OnDelete(DeleteBehavior.Cascade);
            entity.HasOne<User>().WithMany().HasForeignKey(m => m.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Session>().Property<string?>(ActiveWorkspaceIdProperty).HasMaxLength(36);
    }

    public override void MapEndpoints(RouteGroupBuilder group) => group.MapWorkspaces();

    public override IEnumerable<AegisRateLimitRule> RateLimitRules => [new("/workspace/create") { MaxRequests = 10 }];

    public override IReadOnlyDictionary<string, int> ErrorStatusCodes { get; } = new Dictionary<string, int>
    {
        [NotMember] = StatusCodes.Status403Forbidden,
        [SlugTaken] = StatusCodes.Status409Conflict,
        [LimitReached] = StatusCodes.Status403Forbidden,
    };

    public override void Validate(AegisAuthOptions authOptions, IList<string> errors)
    {
        if (options.WorkspaceLimit <= 0)
        {
            errors.Add("WorkspaceOptions.WorkspaceLimit must be greater than 0.");
        }
    }
}

/// <summary>
/// Stands in for a plugin that builds on workspaces, like SSO or teams on organizations.
/// </summary>
public sealed class WorkspaceSsoPlugin : AegisPlugin
{
    public override string Id => "workspace-sso";

    public override IEnumerable<string> Dependencies => [WorkspacesPlugin.PluginId];
}

public sealed class WorkspaceOptions
{
    /// <summary>Workspaces a user can be a member of.</summary>
    public int WorkspaceLimit { get; set; } = 5;
}

public sealed class Workspace
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Slug { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

public sealed class WorkspaceMember
{
    public string Id { get; set; } = string.Empty;
    public string WorkspaceId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

public static class WorkspacesAegisAuthBuilderExtensions
{
    /// <summary>
    /// The registration pattern for plugin packages: an extension on the builder that takes the plugin's options.
    /// </summary>
    public static IAegisAuthBuilder AddWorkspaces(this IAegisAuthBuilder builder, Action<WorkspaceOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new WorkspaceOptions();
        configure?.Invoke(options);
        return builder.AddPlugin(new WorkspacesPlugin(options));
    }
}
