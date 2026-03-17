using Aegis.Auth.Http.Features.SignIn;
using Aegis.Auth.Http.Features.SignOut;
using Aegis.Auth.Http.Features.SignUp;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Http.Extensions;

public sealed class AegisAuthEndpointMapOptions
{
  public string BasePath { get; set; } = "/api/auth";
  public string TagName { get; set; } = "Aegis Auth";

  // Allow consumers to hide endpoints from the route table entirely.
  public bool MapSignOut { get; set; } = true;
  public bool MapEmailSignIn { get; set; } = true;
  public bool MapEmailSignUp { get; set; } = true;

  // true: derive defaults from AegisAuthOptions feature flags.
  // false: map strictly by Map* toggles above.
  public bool RespectConfiguration { get; set; } = true;
}

public static class AegisAuthEndpointRouteBuilderExtensions
{
  public static IEndpointRouteBuilder MapAegisAuthEndpoints(
    this IEndpointRouteBuilder endpoints,
    Action<AegisAuthEndpointMapOptions>? configure = null)
  {
    ArgumentNullException.ThrowIfNull(endpoints);

    var mapOptions = new AegisAuthEndpointMapOptions { RespectConfiguration = true };
    configure?.Invoke(mapOptions);

    AegisAuthOptions authOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<AegisAuthOptions>>().Value;
    RouteGroupBuilder group = endpoints.MapGroup(mapOptions.BasePath).WithTags(mapOptions.TagName);

    if (mapOptions.MapSignOut)
    {
      group.MapSignOut();
    }

    var canMapEmail = mapOptions.MapEmailSignIn || mapOptions.MapEmailSignUp;
    if (canMapEmail)
    {
      if (mapOptions.RespectConfiguration && authOptions.EmailAndPassword.Enabled is false)
      {
        return endpoints;
      }

      if (mapOptions.MapEmailSignIn)
      {
        group.MapSignInEmail();
      }

      var canMapEmailSignUp = mapOptions.MapEmailSignUp;
      if (mapOptions.RespectConfiguration)
      {
        canMapEmailSignUp = canMapEmailSignUp && authOptions.EmailAndPassword.DisableSignUp is false;
      }

      if (canMapEmailSignUp)
      {
        group.MapSignUpEmail();
      }
    }

    return endpoints;
  }
}