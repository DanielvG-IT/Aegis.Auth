namespace Aegis.Auth.Organizations;

public sealed class Organization
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;

    /// <summary>Unique, lowercase and URL-safe.</summary>
    public string Slug { get; set; } = string.Empty;
    public string? Logo { get; set; }

    /// <summary>Consumer-defined JSON.</summary>
    public string? Metadata { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class Member
{
    public string Id { get; set; } = string.Empty;
    public string OrganizationId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;

    /// <summary>Comma-separated role names, e.g. <c>admin</c> or <c>member,billing</c>.</summary>
    public string Role { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}
