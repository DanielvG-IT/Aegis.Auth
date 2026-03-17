using Aegis.Auth.Entities;

namespace Aegis.Auth.Sample.Entities;

public sealed class AppUser : User
{
  public bool IsSpecial { get; set; }
}
