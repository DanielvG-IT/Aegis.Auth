namespace Aegis.Auth.Options
{
    public sealed class OAuthOptions
    {
        public bool Enabled { get; set; } = true;
        public bool AutoCreateUser { get; set; } = true;
        public bool AutoLinkByEmail { get; set; } = false;
        public GoogleOAuthOptions Google { get; set; } = new();

        public void AddGoogle(string clientId, string clientSecret, Action<GoogleOAuthOptions>? configure = null)
        {
            Google.Enabled = true;
            Google.ClientId = clientId;
            Google.ClientSecret = clientSecret;
            configure?.Invoke(Google);
        }
    }

    public sealed class GoogleOAuthOptions
    {
        public bool Enabled { get; set; }
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string CallbackPath { get; set; } = "/signin-aegis-google";
        public string[] Scopes { get; set; } = ["openid", "profile", "email"];
        public bool SaveTokens { get; set; } = true;
    }
}
