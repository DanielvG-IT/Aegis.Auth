namespace Aegis.Auth.Options
{
    public interface IAuthOptions
    {
        bool RequireEmailVerification { get; set; }
    }

    public sealed class AuthOptions : IAuthOptions
    {
        public bool RequireEmailVerification { get; set; } = true;
    }
}