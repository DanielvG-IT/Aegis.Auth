namespace Aegis.Auth.Models
{
    public class UserDto
    {
        public required string Id { get; init; }
        public string? Name { get; init; }
        public required string Email { get; init; }
        public bool EmailVerified { get; init; }
        public string? Image { get; init; }
        public DateTime CreatedAt { get; init; }
        public DateTime UpdatedAt { get; init; }
    }
}