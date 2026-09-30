using Aegis.Auth.Entities;
using Aegis.Auth.Options;
using Aegis.Auth.Plugins;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Organizations;

public sealed class OrganizationsPlugin(OrganizationOptions options) : AegisPlugin
{
    public const string PluginId = "organization";

    public override string Id => PluginId;

    public override void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton(options);
        services.AddScoped<IOrganizationService, OrganizationService>();
    }

    public override void ConfigureModel(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Organization>(entity =>
        {
            entity.ToTable("Organizations");
            entity.HasKey(o => o.Id);
            entity.Property(o => o.Id).HasMaxLength(36);
            entity.Property(o => o.Name).HasMaxLength(100).IsRequired();
            entity.Property(o => o.Slug).HasMaxLength(64).IsRequired();
            entity.HasIndex(o => o.Slug).IsUnique();
            entity.Property(o => o.Logo).HasMaxLength(2048);
        });

        modelBuilder.Entity<Member>(entity =>
        {
            entity.ToTable("OrganizationMembers");
            entity.HasKey(m => m.Id);
            entity.Property(m => m.Id).HasMaxLength(36);
            entity.Property(m => m.OrganizationId).HasMaxLength(36);
            entity.Property(m => m.Role).HasMaxLength(256).IsRequired();
            entity.HasIndex(m => new { m.OrganizationId, m.UserId }).IsUnique();
            entity.HasIndex(m => m.UserId);
            entity.HasOne<Organization>().WithMany().HasForeignKey(m => m.OrganizationId).OnDelete(DeleteBehavior.Cascade);

            // Deleting a user removes their memberships.
            entity.HasOne<User>().WithMany().HasForeignKey(m => m.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Session>().Property<string?>(OrganizationService.ActiveOrganizationIdProperty).HasMaxLength(36);
    }

    public override void MapEndpoints(RouteGroupBuilder group) => group.MapOrganizations(options);

    public override IEnumerable<AegisRateLimitRule> RateLimitRules => [new("/organization/create") { MaxRequests = 10 }];

    public override IReadOnlyDictionary<string, int> ErrorStatusCodes { get; } = new Dictionary<string, int>
    {
        [OrganizationErrors.NotMember] = StatusCodes.Status403Forbidden,
        [OrganizationErrors.Forbidden] = StatusCodes.Status403Forbidden,
        [OrganizationErrors.CreationDisabled] = StatusCodes.Status403Forbidden,
        [OrganizationErrors.OrganizationLimitReached] = StatusCodes.Status403Forbidden,
        [OrganizationErrors.MembershipLimitReached] = StatusCodes.Status403Forbidden,
        [OrganizationErrors.SlugTaken] = StatusCodes.Status409Conflict,
        [OrganizationErrors.AlreadyMember] = StatusCodes.Status409Conflict,
        [OrganizationErrors.LastOwner] = StatusCodes.Status409Conflict,
        [OrganizationErrors.MemberNotFound] = StatusCodes.Status404NotFound,
        [OrganizationErrors.NoActiveOrganization] = StatusCodes.Status400BadRequest,
    };

    public override void Validate(AegisAuthOptions authOptions, IList<string> errors)
    {
        if (options.OrganizationLimit <= 0)
        {
            errors.Add("OrganizationOptions.OrganizationLimit must be greater than 0.");
        }

        if (options.MembershipLimit <= 0)
        {
            errors.Add("OrganizationOptions.MembershipLimit must be greater than 0.");
        }

        if (options.Roles.ContainsKey(OrganizationRoles.Owner) is false)
        {
            errors.Add("OrganizationOptions.Roles must define the 'owner' role.");
        }

        if (options.Roles.ContainsKey(options.CreatorRole) is false)
        {
            errors.Add($"OrganizationOptions.CreatorRole '{options.CreatorRole}' is not a defined role.");
        }
    }
}

public static class OrganizationsAegisAuthBuilderExtensions
{
    /// <summary>Adds organizations. The DbContext must call <c>UseAegisAuth(sp)</c> so the tables are part of the model.</summary>
    public static IAegisAuthBuilder AddOrganizations(this IAegisAuthBuilder builder, Action<OrganizationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new OrganizationOptions();
        configure?.Invoke(options);
        return builder.AddPlugin(new OrganizationsPlugin(options));
    }
}
