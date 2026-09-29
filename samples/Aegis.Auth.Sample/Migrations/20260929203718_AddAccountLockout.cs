using System;

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aegis.Auth.Sample.Migrations
{
    /// <inheritdoc />
    public partial class AddAccountLockout : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "FailedSignInCount",
                table: "Aegis.Auth.Abstractions.IAuthDbContext.Users",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "LockoutUntil",
                table: "Aegis.Auth.Abstractions.IAuthDbContext.Users",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FailedSignInCount",
                table: "Aegis.Auth.Abstractions.IAuthDbContext.Users");

            migrationBuilder.DropColumn(
                name: "LockoutUntil",
                table: "Aegis.Auth.Abstractions.IAuthDbContext.Users");
        }
    }
}
