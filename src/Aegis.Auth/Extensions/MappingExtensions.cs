using Aegis.Auth.Entities;
using Aegis.Auth.Models;

namespace Aegis.Auth.Extensions
{
    public static class MappingExtensions
    {
        public static UserDto ToDto(this User user)
        {
            return new UserDto
            {
                Id = user.Id,
                Email = user.Email,
                Name = user.Name,
                IsEmailVerified = user.IsEmailVerified,
                Image = user.Image,
                CreatedAt = user.CreatedAt
            };
        }
    }
}