namespace Aegis.Auth.Constants
{
  public static class AuthErrors
  {
    // General
    public const string FeatureDisabled = "FEATURE_DISABLED";
    public const string InternalError = "INTERNAL_ERROR";

    // Validation
    public const string InvalidInput = "INVALID_INPUT";
    public const string EmailRequired = "EMAIL_REQUIRED";
    public const string PasswordTooWeak = "PASSWORD_TOO_WEAK";

    // Logic
    public const string UserAlreadyExists = "USER_ALREADY_EXISTS";
    public const string InvalidCredentials = "INVALID_CREDENTIALS";
    public const string EmailNotVerified = "EMAIL_NOT_VERIFIED";

    // Provider
    public const string ProviderNotFound = "PROVIDER_NOT_FOUND";
  }
}