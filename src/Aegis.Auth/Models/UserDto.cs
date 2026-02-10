namespace Aegis.Auth.Models
{
    public class UserDto
    {
        public required string Id { get; set; }
        public string? Name { get; set; }
        public required string Email { get; set; }
        public bool IsEmailVerified { get; set; }
        public string? Image { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}