namespace Aegis.Auth.Sample.Entities;

public sealed class Project
{
  public string Id { get; set; } = string.Empty;
  public string OwnerUserId { get; set; } = string.Empty;
  public string Name { get; set; } = string.Empty;
  public string? Description { get; set; }
  public DateTime CreatedAt { get; set; }
  public DateTime UpdatedAt { get; set; }

  public ICollection<ProjectTask> Tasks { get; } = [];
}
