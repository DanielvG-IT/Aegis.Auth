using System.Data;
using System.Text.Json;
using System.Text.RegularExpressions;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Organizations;

public sealed record OrganizationDetails(Organization Organization, IReadOnlyList<Member> Members);

public interface IOrganizationService
{
    Task<Result<Organization>> CreateAsync(string userId, string? sessionId, string name, string slug, string? logo = null, string? metadata = null, CancellationToken ct = default);
    Task<bool> IsSlugAvailableAsync(string slug, CancellationToken ct = default);
    Task<Result<Organization>> UpdateAsync(string userId, string organizationId, string? name, string? slug, string? logo, string? metadata, CancellationToken ct = default);
    Task<Result> DeleteAsync(string userId, string organizationId, CancellationToken ct = default);
    Task<IReadOnlyList<Organization>> ListAsync(string userId, CancellationToken ct = default);
    Task<Result<OrganizationDetails>> GetFullAsync(string userId, string organizationId, CancellationToken ct = default);

    /// <summary>Sets the session's active organization; <c>null</c> clears it. The user must be a member.</summary>
    Task<Result> SetActiveAsync(string userId, string sessionId, string? organizationId, CancellationToken ct = default);

    /// <summary>The caller's membership in the session's active organization, re-checked against the database.</summary>
    Task<Member?> GetActiveMemberAsync(string userId, string sessionId, CancellationToken ct = default);

    /// <summary>
    /// Adds a member. With <paramref name="actorUserId"/> <c>null</c> this is a trusted server-side call; otherwise the actor
    /// needs <c>member:create</c> and cannot grant a role above their own.
    /// </summary>
    Task<Result<Member>> AddMemberAsync(string? actorUserId, string organizationId, string userId, string role, CancellationToken ct = default);
    Task<Result> RemoveMemberAsync(string actorUserId, string organizationId, string memberId, CancellationToken ct = default);
    Task<Result<Member>> UpdateMemberRoleAsync(string actorUserId, string organizationId, string memberId, string role, CancellationToken ct = default);
    Task<Result> LeaveAsync(string userId, string organizationId, CancellationToken ct = default);

    /// <summary>Whether the caller's role in the session's <b>active</b> organization grants <paramref name="permission"/>.</summary>
    Task<bool> HasPermissionAsync(string userId, string sessionId, string permission, CancellationToken ct = default);
}

internal sealed partial class OrganizationService(
    IAuthDbContext authDb,
    OrganizationOptions options,
    TimeProvider time,
    ILogger<OrganizationService> logger) : IOrganizationService
{
    public const string ActiveOrganizationIdProperty = "ActiveOrganizationId";

    private readonly DbContext _db = authDb.GetDbContext();

    private DbSet<Organization> Organizations => _db.Set<Organization>();
    private DbSet<Member> Members => _db.Set<Member>();

    public async Task<Result<Organization>> CreateAsync(string userId, string? sessionId, string name, string slug, string? logo = null, string? metadata = null, CancellationToken ct = default)
    {
        User? user = await authDb.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || await options.AllowUserToCreateOrganization(user) is false)
        {
            return Result<Organization>.Failure(OrganizationErrors.CreationDisabled, "You are not allowed to create organizations.");
        }

        if (ValidateFields(name, ref slug, metadata) is { } invalid)
        {
            return Result<Organization>.Failure(invalid.ErrorCode!, invalid.Message!);
        }

        if (await Members.CountAsync(m => m.UserId == userId, ct) >= options.OrganizationLimit)
        {
            return Result<Organization>.Failure(OrganizationErrors.OrganizationLimitReached, "Organization limit reached.");
        }

        if (await Organizations.AnyAsync(o => o.Slug == slug, ct))
        {
            return Result<Organization>.Failure(OrganizationErrors.SlugTaken, "This slug is already taken.");
        }

        DateTime now = time.GetUtcNow().UtcDateTime;
        var organization = new Organization
        {
            Id = Guid.CreateVersion7().ToString(),
            Name = name.Trim(),
            Slug = slug,
            Logo = logo,
            Metadata = metadata,
            CreatedAt = now,
            UpdatedAt = now,
        };
        Organizations.Add(organization);
        Members.Add(new Member { Id = Guid.CreateVersion7().ToString(), OrganizationId = organization.Id, UserId = userId, Role = options.CreatorRole, CreatedAt = now });

        // The creator's session switches to the new organization in the same save.
        Session? session = sessionId is null ? null : await authDb.Sessions.FirstOrDefaultAsync(s => s.Id == sessionId && s.UserId == userId, ct);
        if (session is not null)
        {
            _db.Entry(session).Property(ActiveOrganizationIdProperty).CurrentValue = organization.Id;
        }

        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Lost a race on the unique slug index.
            _db.ChangeTracker.Clear();
            return Result<Organization>.Failure(OrganizationErrors.SlugTaken, "This slug is already taken.");
        }

        LogOrganizationCreated(organization.Id, userId);
        return organization;
    }

    public async Task<bool> IsSlugAvailableAsync(string slug, CancellationToken ct = default)
    {
        slug = NormalizeSlug(slug);
        return IsValidSlug(slug) && await Organizations.AnyAsync(o => o.Slug == slug, ct) is false;
    }

    public async Task<Result<Organization>> UpdateAsync(string userId, string organizationId, string? name, string? slug, string? logo, string? metadata, CancellationToken ct = default)
    {
        if (await RequirePermissionAsync(userId, organizationId, OrganizationRoles.Permissions.OrganizationUpdate, ct) is { } denied)
        {
            return Result<Organization>.Failure(denied.ErrorCode!, denied.Message!);
        }

        Organization organization = await Organizations.FirstAsync(o => o.Id == organizationId, ct);
        var newSlug = slug ?? organization.Slug;
        if (ValidateFields(name ?? organization.Name, ref newSlug, metadata) is { } invalid)
        {
            return Result<Organization>.Failure(invalid.ErrorCode!, invalid.Message!);
        }

        if (newSlug != organization.Slug && await Organizations.AnyAsync(o => o.Slug == newSlug, ct))
        {
            return Result<Organization>.Failure(OrganizationErrors.SlugTaken, "This slug is already taken.");
        }

        organization.Name = name?.Trim() ?? organization.Name;
        organization.Slug = newSlug;
        organization.Logo = logo ?? organization.Logo;
        organization.Metadata = metadata ?? organization.Metadata;
        organization.UpdatedAt = time.GetUtcNow().UtcDateTime;

        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            _db.ChangeTracker.Clear();
            return Result<Organization>.Failure(OrganizationErrors.SlugTaken, "This slug is already taken.");
        }

        return organization;
    }

    public async Task<Result> DeleteAsync(string userId, string organizationId, CancellationToken ct = default)
    {
        if (await RequirePermissionAsync(userId, organizationId, OrganizationRoles.Permissions.OrganizationDelete, ct) is { } denied)
        {
            return denied;
        }

        await InTransactionAsync(async () =>
        {
            await ClearActiveOrganizationAsync(organizationId, userId: null, ct);
            await Members.Where(m => m.OrganizationId == organizationId).ExecuteDeleteAsync(ct);
            await Organizations.Where(o => o.Id == organizationId).ExecuteDeleteAsync(ct);
            return Result.Success();
        }, ct);

        LogOrganizationDeleted(organizationId, userId);
        return Result.Success();
    }

    public async Task<IReadOnlyList<Organization>> ListAsync(string userId, CancellationToken ct = default) =>
        await Organizations
            .Where(o => Members.Any(m => m.OrganizationId == o.Id && m.UserId == userId))
            .OrderBy(o => o.Name)
            .AsNoTracking()
            .ToListAsync(ct);

    public async Task<Result<OrganizationDetails>> GetFullAsync(string userId, string organizationId, CancellationToken ct = default)
    {
        if (await FindMemberAsync(organizationId, userId, ct) is null)
        {
            return Result<OrganizationDetails>.Failure(OrganizationErrors.NotMember, NotMemberMessage);
        }

        Organization organization = await Organizations.AsNoTracking().FirstAsync(o => o.Id == organizationId, ct);
        List<Member> members = await Members.AsNoTracking().Where(m => m.OrganizationId == organizationId).OrderBy(m => m.CreatedAt).ToListAsync(ct);
        return new OrganizationDetails(organization, members);
    }

    public async Task<Result> SetActiveAsync(string userId, string sessionId, string? organizationId, CancellationToken ct = default)
    {
        // Never trust the id from the request: the caller must be a member, checked against the database.
        if (organizationId is not null && await FindMemberAsync(organizationId, userId, ct) is null)
        {
            return Result.Failure(OrganizationErrors.NotMember, NotMemberMessage);
        }

        await authDb.Sessions
            .Where(s => s.Id == sessionId && s.UserId == userId)
            .ExecuteUpdateAsync(s => s.SetProperty(x => EF.Property<string?>(x, ActiveOrganizationIdProperty), organizationId), ct);
        return Result.Success();
    }

    public async Task<Member?> GetActiveMemberAsync(string userId, string sessionId, CancellationToken ct = default)
    {
        var activeId = await authDb.Sessions
            .Where(s => s.Id == sessionId && s.UserId == userId)
            .Select(s => EF.Property<string?>(s, ActiveOrganizationIdProperty))
            .FirstOrDefaultAsync(ct);

        // Membership can be revoked after the organization was made active, so re-check it on every read.
        return activeId is null ? null : await Members.AsNoTracking().FirstOrDefaultAsync(m => m.OrganizationId == activeId && m.UserId == userId, ct);
    }

    public async Task<Result<Member>> AddMemberAsync(string? actorUserId, string organizationId, string userId, string role, CancellationToken ct = default)
    {
        if (ValidateRoles(role) is { } badRole)
        {
            return Result<Member>.Failure(badRole.ErrorCode!, badRole.Message!);
        }

        if (actorUserId is not null)
        {
            if (await RequirePermissionAsync(actorUserId, organizationId, OrganizationRoles.Permissions.MemberCreate, ct) is { } denied)
            {
                return Result<Member>.Failure(denied.ErrorCode!, denied.Message!);
            }

            Member actor = (await FindMemberAsync(organizationId, actorUserId, ct))!;
            if (Rank(role) > Rank(actor.Role))
            {
                return Result<Member>.Failure(OrganizationErrors.Forbidden, "You cannot grant a role higher than your own.");
            }
        }
        else if (await Organizations.AnyAsync(o => o.Id == organizationId, ct) is false)
        {
            return Result<Member>.Failure(OrganizationErrors.NotMember, "Organization not found.");
        }

        if (await authDb.Users.AnyAsync(u => u.Id == userId, ct) is false)
        {
            return Result<Member>.Failure(OrganizationErrors.MemberNotFound, "User not found.");
        }

        if (await FindMemberAsync(organizationId, userId, ct) is not null)
        {
            return Result<Member>.Failure(OrganizationErrors.AlreadyMember, "The user is already a member.");
        }

        if (await Members.CountAsync(m => m.OrganizationId == organizationId, ct) >= options.MembershipLimit)
        {
            return Result<Member>.Failure(OrganizationErrors.MembershipLimitReached, "Membership limit reached.");
        }

        if (await Members.CountAsync(m => m.UserId == userId, ct) >= options.OrganizationLimit)
        {
            return Result<Member>.Failure(OrganizationErrors.OrganizationLimitReached, "The user has reached the organization limit.");
        }

        var member = new Member { Id = Guid.CreateVersion7().ToString(), OrganizationId = organizationId, UserId = userId, Role = role, CreatedAt = time.GetUtcNow().UtcDateTime };
        Members.Add(member);
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Lost a race on the unique (OrganizationId, UserId) index.
            _db.ChangeTracker.Clear();
            return Result<Member>.Failure(OrganizationErrors.AlreadyMember, "The user is already a member.");
        }

        return member;
    }

    public async Task<Result> RemoveMemberAsync(string actorUserId, string organizationId, string memberId, CancellationToken ct = default)
    {
        if (await RequirePermissionAsync(actorUserId, organizationId, OrganizationRoles.Permissions.MemberDelete, ct) is { } denied)
        {
            return denied;
        }

        Member actor = (await FindMemberAsync(organizationId, actorUserId, ct))!;
        Member? target = await Members.AsNoTracking().FirstOrDefaultAsync(m => m.Id == memberId && m.OrganizationId == organizationId, ct);
        if (target is null)
        {
            return Result.Failure(OrganizationErrors.MemberNotFound, "Member not found.");
        }

        if (Rank(target.Role) > Rank(actor.Role))
        {
            return Result.Failure(OrganizationErrors.Forbidden, "You cannot remove a member who outranks you.");
        }

        return await DeleteMembershipAsync(target, ct);
    }

    public async Task<Result<Member>> UpdateMemberRoleAsync(string actorUserId, string organizationId, string memberId, string role, CancellationToken ct = default)
    {
        if (ValidateRoles(role) is { } badRole)
        {
            return Result<Member>.Failure(badRole.ErrorCode!, badRole.Message!);
        }

        if (await RequirePermissionAsync(actorUserId, organizationId, OrganizationRoles.Permissions.MemberUpdate, ct) is { } denied)
        {
            return Result<Member>.Failure(denied.ErrorCode!, denied.Message!);
        }

        Member actor = (await FindMemberAsync(organizationId, actorUserId, ct))!;
        Member? target = await Members.AsNoTracking().FirstOrDefaultAsync(m => m.Id == memberId && m.OrganizationId == organizationId, ct);
        if (target is null)
        {
            return Result<Member>.Failure(OrganizationErrors.MemberNotFound, "Member not found.");
        }

        var actorRank = Rank(actor.Role);
        if (Rank(role) > actorRank || Rank(target.Role) > actorRank)
        {
            return Result<Member>.Failure(OrganizationErrors.Forbidden, "You cannot grant or change a role higher than your own.");
        }

        Result result = await InTransactionAsync(async () =>
        {
            await Members.Where(m => m.Id == memberId).ExecuteUpdateAsync(m => m.SetProperty(x => x.Role, role), ct);
            return await EnsureOwnerRemainsAsync(organizationId, ct);
        }, ct);

        if (result.IsSuccess is false)
        {
            return Result<Member>.Failure(result.ErrorCode!, result.Message!);
        }

        target.Role = role;
        return target;
    }

    public async Task<Result> LeaveAsync(string userId, string organizationId, CancellationToken ct = default)
    {
        Member? member = await FindMemberAsync(organizationId, userId, ct);
        return member is null
            ? Result.Failure(OrganizationErrors.NotMember, NotMemberMessage)
            : await DeleteMembershipAsync(member, ct);
    }

    public async Task<bool> HasPermissionAsync(string userId, string sessionId, string permission, CancellationToken ct = default)
    {
        Member? member = await GetActiveMemberAsync(userId, sessionId, ct);
        return member is not null && Grants(member.Role, permission);
    }

    private const string NotMemberMessage = "You are not a member of this organization.";

    private async Task<Result> DeleteMembershipAsync(Member member, CancellationToken ct) =>
        await InTransactionAsync(async () =>
        {
            await Members.Where(m => m.Id == member.Id).ExecuteDeleteAsync(ct);
            Result owners = await EnsureOwnerRemainsAsync(member.OrganizationId, ct);
            if (owners.IsSuccess)
            {
                await ClearActiveOrganizationAsync(member.OrganizationId, member.UserId, ct);
            }

            return owners;
        }, ct);

    /// <summary>
    /// Runs after the change inside its transaction, so the check sees the new state and a failure rolls it back.
    /// </summary>
    private async Task<Result> EnsureOwnerRemainsAsync(string organizationId, CancellationToken ct)
    {
        List<string> roles = await Members.Where(m => m.OrganizationId == organizationId).Select(m => m.Role).ToListAsync(ct);
        return roles.Any(r => OrganizationRoles.Parse(r).Contains(OrganizationRoles.Owner))
            ? Result.Success()
            : Result.Failure(OrganizationErrors.LastOwner, "An organization must keep at least one owner.");
    }

    private Task ClearActiveOrganizationAsync(string organizationId, string? userId, CancellationToken ct) =>
        authDb.Sessions
            .Where(s => EF.Property<string?>(s, ActiveOrganizationIdProperty) == organizationId && (userId == null || s.UserId == userId))
            .ExecuteUpdateAsync(s => s.SetProperty(x => EF.Property<string?>(x, ActiveOrganizationIdProperty), (string?)null), ct);

    /// <summary>
    /// Returns <c>null</c> when allowed. Non-members and unknown organizations get the same answer, so ids can't be probed.
    /// </summary>
    private async Task<Result?> RequirePermissionAsync(string userId, string organizationId, string permission, CancellationToken ct)
    {
        Member? member = await FindMemberAsync(organizationId, userId, ct);
        if (member is null)
        {
            return Result.Failure(OrganizationErrors.NotMember, NotMemberMessage);
        }

        return Grants(member.Role, permission) ? null : Result.Failure(OrganizationErrors.Forbidden, $"Your role does not grant '{permission}'.");
    }

    private Task<Member?> FindMemberAsync(string organizationId, string userId, CancellationToken ct) =>
        Members.AsNoTracking().FirstOrDefaultAsync(m => m.OrganizationId == organizationId && m.UserId == userId, ct);

    private bool Grants(string roles, string permission) =>
        OrganizationRoles.Parse(roles).Any(r => options.Roles.TryGetValue(r, out OrganizationRole? role) && role.Permissions.Contains(permission));

    private int Rank(string roles) =>
        OrganizationRoles.Parse(roles).Select(r => options.Roles.TryGetValue(r, out OrganizationRole? role) ? role.Rank : 0).DefaultIfEmpty(0).Max();

    private Result? ValidateRoles(string roles)
    {
        string[] names = OrganizationRoles.Parse(roles ?? string.Empty);
        if (names.Length == 0 || names.Any(n => options.Roles.ContainsKey(n) is false))
        {
            return Result.Failure(OrganizationErrors.RoleNotFound, "Unknown role.");
        }

        return null;
    }

    private static Result? ValidateFields(string name, ref string slug, string? metadata)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Trim().Length > 100)
        {
            return Result.Failure(OrganizationErrors.InvalidRequest, "Name is required and at most 100 characters.");
        }

        slug = NormalizeSlug(slug);
        if (IsValidSlug(slug) is false)
        {
            return Result.Failure(OrganizationErrors.InvalidSlug, "Slug must be 1-64 lowercase letters, digits and single hyphens.");
        }

        if (metadata is not null)
        {
            try
            {
                using var _ = JsonDocument.Parse(metadata);
            }
            catch (JsonException)
            {
                return Result.Failure(OrganizationErrors.InvalidRequest, "Metadata must be valid JSON.");
            }
        }

        return null;
    }

    private static string NormalizeSlug(string? slug) => (slug ?? string.Empty).Trim().ToLowerInvariant();

    private static bool IsValidSlug(string slug) => slug.Length <= 64 && SlugPattern().IsMatch(slug);

    [GeneratedRegex("^[a-z0-9]+(?:-[a-z0-9]+)*$")]
    private static partial Regex SlugPattern();

    private async Task<Result> InTransactionAsync(Func<Task<Result>> work, CancellationToken ct)
    {
        if (_db.Database.IsRelational() is false)
        {
            return await work();
        }

        IExecutionStrategy strategy = _db.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async () =>
        {
            // Serializable so two owners demoting each other at once can't both commit and leave no owner.
            await using IDbContextTransaction tx = await _db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            Result result = await work();
            if (result.IsSuccess)
            {
                await tx.CommitAsync(ct);
            }
            else
            {
                await tx.RollbackAsync(ct);
            }

            return result;
        });
    }

    [LoggerMessage(EventId = 10001, Level = LogLevel.Information, Message = "Organization {OrganizationId} created by {UserId}.")]
    private partial void LogOrganizationCreated(string organizationId, string userId);

    [LoggerMessage(EventId = 10002, Level = LogLevel.Information, Message = "Organization {OrganizationId} deleted by {UserId}.")]
    private partial void LogOrganizationDeleted(string organizationId, string userId);
}
