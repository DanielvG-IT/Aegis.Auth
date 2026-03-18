using Aegis.Auth.Extensions;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Aegis.Auth.Abstractions;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class AegisAuthorizeAttribute : Attribute, IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.HttpContext.RequestServices.GetService(typeof(IAegisAuthContextAccessor)) is not IAegisAuthContextAccessor accessor)
        {
            context.Result = new StatusCodeResult(StatusCodes.Status500InternalServerError);
            return;
        }

        AegisAuthContext? authContext = await accessor.GetCurrentAsync(context.HttpContext, context.HttpContext.RequestAborted);
        if (authContext is null)
        {
            context.Result = new UnauthorizedObjectResult(new ProblemDetails
            {
                Status = StatusCodes.Status401Unauthorized,
                Title = "Unauthorized",
                Detail = "Authentication is required to access this resource.",
                Type = "https://httpstatuses.com/401",
                Instance = context.HttpContext.Request.Path,
            });
            return;
        }

        context.HttpContext.SetAegisAuthContext(authContext);
    }
}
