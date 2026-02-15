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
                EmailVerified = user.EmailVerified,
                Image = user.Image,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt
            };
        }

        public static SessionDto ToDto(this Session session)
        {
            return new SessionDto
            {
                Id = session.Id,
                UserAgent = session.UserAgent,
                ExpiresAt = session.ExpiresAt,
                IpAddress = session.IpAddress,
                CreatedAt = session.CreatedAt,
                UpdatedAt = session.UpdatedAt,
                Token = session.Token,
                UserId = session.UserId,
            };
        }
    }
}