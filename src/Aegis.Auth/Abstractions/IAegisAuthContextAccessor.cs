using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Abstractions;

public interface IAegisAuthContextAccessor
{
  Task<AegisAuthContext?> GetCurrentAsync(HttpContext httpContext, CancellationToken cancellationToken = default);
}
