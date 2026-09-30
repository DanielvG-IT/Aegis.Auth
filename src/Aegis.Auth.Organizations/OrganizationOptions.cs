using Aegis.Auth.Entities;

namespace Aegis.Auth.Organizations;

public sealed class OrganizationOptions
{
    /// <summary>Whether a user may create organizations. Internal tools typically return false.</summary>
    public Func<User, Task<bool>> AllowUserToCreateOrganization { get; set; } = _ => Task.FromResult(true);

    /// <summary>Organizations a user can belong to.</summary>
    public int OrganizationLimit { get; set; } = 5;

    /// <summary>Members an organization can have.</summary>
    public int MembershipLimit { get; set; } = 100;

    /// <summary>Role given to the user who creates an organization.</summary>
    public string CreatorRole { get; set; } = OrganizationRoles.Owner;

    /// <summary>
    /// Roles by name. Defaults to owner, admin and member; add permissions (e.g. <c>project:create</c>)
    /// or roles here. A member can never grant or modify a role ranked higher than their own.
    /// </summary>
    public Dictionary<string, OrganizationRole> Roles { get; } = OrganizationRoles.CreateDefaults();

    /// <summary>Maps <c>POST /organization/members/add</c>. Off by default: adding members without an invitation is a server-side API.</summary>
    public bool MapAddMemberEndpoint { get; set; }
}

/// <summary>A role: its rank (higher outranks lower) and the <c>resource:action</c> permissions it grants.</summary>
public sealed class OrganizationRole(int rank, IEnumerable<string> permissions)
{
    public int Rank { get; } = rank;
    public HashSet<string> Permissions { get; } = new(permissions, StringComparer.Ordinal);
}

public static class OrganizationRoles
{
    public const string Owner = "owner";
    public const string Admin = "admin";
    public const string Member = "member";

    public static class Permissions
    {
        public const string OrganizationUpdate = "organization:update";
        public const string OrganizationDelete = "organization:delete";
        public const string MemberCreate = "member:create";
        public const string MemberUpdate = "member:update";
        public const string MemberDelete = "member:delete";
        public const string InvitationCreate = "invitation:create";
        public const string InvitationCancel = "invitation:cancel";
    }

    internal static Dictionary<string, OrganizationRole> CreateDefaults() => new(StringComparer.Ordinal)
    {
        [Owner] = new(300,
        [
            Permissions.OrganizationUpdate, Permissions.OrganizationDelete,
            Permissions.MemberCreate, Permissions.MemberUpdate, Permissions.MemberDelete,
            Permissions.InvitationCreate, Permissions.InvitationCancel,
        ]),
        [Admin] = new(200,
        [
            Permissions.OrganizationUpdate,
            Permissions.MemberCreate, Permissions.MemberUpdate, Permissions.MemberDelete,
            Permissions.InvitationCreate, Permissions.InvitationCancel,
        ]),
        [Member] = new(100, []),
    };

    internal static string[] Parse(string roles) =>
        roles.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

public static class OrganizationErrors
{
    public const string NotMember = "ORG_NOT_MEMBER";
    public const string Forbidden = "ORG_FORBIDDEN";
    public const string SlugTaken = "ORG_SLUG_TAKEN";
    public const string InvalidSlug = "ORG_INVALID_SLUG";
    public const string InvalidRequest = "ORG_INVALID_REQUEST";
    public const string CreationDisabled = "ORG_CREATION_DISABLED";
    public const string OrganizationLimitReached = "ORG_LIMIT_REACHED";
    public const string MembershipLimitReached = "ORG_MEMBERSHIP_LIMIT_REACHED";
    public const string LastOwner = "ORG_LAST_OWNER";
    public const string RoleNotFound = "ORG_ROLE_NOT_FOUND";
    public const string AlreadyMember = "ORG_ALREADY_MEMBER";
    public const string MemberNotFound = "ORG_MEMBER_NOT_FOUND";
    public const string NoActiveOrganization = "ORG_NO_ACTIVE_ORGANIZATION";
}
