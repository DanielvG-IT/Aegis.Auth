namespace Aegis.Auth.Models
{
    public class UserDto
    {
        public required string Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public bool IsEmailVerified { get; set; }
        public string? Image { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}