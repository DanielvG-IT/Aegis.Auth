namespace Aegis.Auth.Options
{
    public sealed class OAuthOptions
    {
        public bool Enabled { get; set; } = true;
        public bool AutoCreateUser { get; set; } = true;
        public bool AutoLinkByEmail { get; set; } = false;
        public GoogleOAuthOptions Google { get; set; } = new();
        public GitHubOAuthOptions GitHub { get; set; } = new();
        public MicrosoftOAuthOptions Microsoft { get; set; } = new();
        public AppleOAuthOptions Apple { get; set; } = new();

        public void AddGoogle(string clientId, string clientSecret, Action<GoogleOAuthOptions>? configure = null)
            => ConfigureProvider(Google, clientId, clientSecret, configure);

        public void AddGitHub(string clientId, string clientSecret, Action<GitHubOAuthOptions>? configure = null)
            => ConfigureProvider(GitHub, clientId, clientSecret, configure);

        public void AddMicrosoft(string clientId, string clientSecret, Action<MicrosoftOAuthOptions>? configure = null)
            => ConfigureProvider(Microsoft, clientId, clientSecret, configure);

        public void AddApple(string clientId, string clientSecret, Action<AppleOAuthOptions>? configure = null)
            => ConfigureProvider(Apple, clientId, clientSecret, configure);

        private static void ConfigureProvider<TProviderOptions>(
            TProviderOptions provider,
            string clientId,
            string clientSecret,
            Action<TProviderOptions>? configure)
            where TProviderOptions : OAuthProviderOptions
        {
            provider.Enabled = true;
            provider.ClientId = clientId;
            provider.ClientSecret = clientSecret;
            configure?.Invoke(provider);
        }
    }

    public abstract class OAuthProviderOptions
    {
        public bool Enabled { get; set; }
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string CallbackPath { get; set; } = string.Empty;
        public string[] Scopes { get; set; } = [];
        public bool SaveTokens { get; set; } = true;
    }

    public sealed class GoogleOAuthOptions : OAuthProviderOptions
    {
        public GoogleOAuthOptions()
        {
            CallbackPath = "/signin-aegis-google";
            Scopes = ["openid", "profile", "email"];
        }
    }

    public sealed class GitHubOAuthOptions : OAuthProviderOptions
    {
        public GitHubOAuthOptions()
        {
            CallbackPath = "/signin-aegis-github";
            Scopes = ["read:user", "user:email"];
        }
    }

    public sealed class MicrosoftOAuthOptions : OAuthProviderOptions
    {
        public string TenantId { get; set; } = "common";

        public MicrosoftOAuthOptions()
        {
            CallbackPath = "/signin-aegis-microsoft";
            Scopes = ["openid", "profile", "email"];
        }
    }

    public sealed class AppleOAuthOptions : OAuthProviderOptions
    {
        public string ResponseMode { get; set; } = "form_post";

        public AppleOAuthOptions()
        {
            CallbackPath = "/signin-aegis-apple";
            Scopes = ["openid", "email", "name"];
        }
    }
}
