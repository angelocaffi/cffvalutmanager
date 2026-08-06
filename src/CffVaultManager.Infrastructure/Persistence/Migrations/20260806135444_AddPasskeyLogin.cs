using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CffVaultManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPasskeyLogin : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "PrfWrappedDek",
                table: "WebAuthnCredentials",
                type: "varbinary(max)",
                nullable: true);

            migrationBuilder.AlterColumn<Guid>(
                name: "UserId",
                table: "WebAuthnCeremonies",
                type: "uniqueidentifier",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uniqueidentifier");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PrfWrappedDek",
                table: "WebAuthnCredentials");

            migrationBuilder.AlterColumn<Guid>(
                name: "UserId",
                table: "WebAuthnCeremonies",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                oldClrType: typeof(Guid),
                oldType: "uniqueidentifier",
                oldNullable: true);
        }
    }
}
