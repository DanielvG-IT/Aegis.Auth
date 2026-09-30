using System;

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aegis.Auth.Sample.Migrations
{
    /// <inheritdoc />
    public partial class AddAegisKeyValue : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AegisKeyValues",
                columns: table => new
                {
                    Key = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Value = table.Column<string>(type: "TEXT", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AegisKeyValues", x => x.Key);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AegisKeyValues_ExpiresAt",
                table: "AegisKeyValues",
                column: "ExpiresAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AegisKeyValues");
        }
    }
}
