using System.Text.Json.Serialization;

namespace Aegis.Auth.Entities
{
    /// <summary>
    /// Represents a user
    /// </summary>
    public class User
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public bool EmailVerified { get; set; } = false;
        public string? Image { get; set; } = null;
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }

        /// <summary>
        /// Consecutive failed password sign-ins. Reset on success and when a lockout starts.
        /// </summary>
        public int FailedSignInCount { get; set; }

        /// <summary>
        /// Password sign-in is rejected until this time (UTC). <see cref="DateTime.MaxValue"/>
        /// means locked until explicitly unlocked.
        /// </summary>
        public DateTime? LockoutUntil { get; set; }

        // Relations — JsonIgnore prevents circular reference during cache serialization
        [JsonIgnore]
        public ICollection<Account> Accounts { get; } = [];
        [JsonIgnore]
        public ICollection<Session> Sessions { get; } = [];
        [JsonIgnore]
        public ICollection<AuthToken> AuthTokens { get; } = [];
    }
}
