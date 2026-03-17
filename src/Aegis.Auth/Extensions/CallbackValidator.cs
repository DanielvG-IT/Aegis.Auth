using Aegis.Auth.Options;

namespace Aegis.Auth.Extensions;

public static class CallbackValidator
{
    public static string? Validate(string? callback, AegisAuthOptions options)
    {
        if (string.IsNullOrWhiteSpace(callback))
        {
            return null;
        }

        if (callback.StartsWith('/') && !callback.StartsWith("//"))
        {
            return callback;
        }

        if (!Uri.TryCreate(callback, UriKind.Absolute, out Uri? uri))
        {
            return null;
        }

        if (uri.Scheme is not ("http" or "https"))
        {
            return null;
        }

        if (options.TrustedOrigins is null || options.TrustedOrigins.Count == 0)
        {
            return null;
        }

        var origin = $"{uri.Scheme}://{uri.Authority}";
        return options.TrustedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase)
            ? callback
            : null;
    }
}
