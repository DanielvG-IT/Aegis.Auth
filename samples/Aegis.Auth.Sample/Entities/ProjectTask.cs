namespace Aegis.Auth.Sample.Entities;

public sealed class ProjectTask
{
  public string Id { get; set; } = string.Empty;
  public string ProjectId { get; set; } = string.Empty;
  public string Title { get; set; } = string.Empty;
  public bool IsDone { get; set; }
  public DateTime CreatedAt { get; set; }
  public DateTime? CompletedAt { get; set; }

  public Project Project { get; set; } = null!;
}
