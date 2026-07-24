using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CffVaultManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddRecoveryKit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "RecoveryEncryptedDek",
                table: "Users",
                type: "varbinary(max)",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "RecoveryKeyHash",
                table: "Users",
                type: "varbinary(max)",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RecoveryKitGeneratedAt",
                table: "Users",
                type: "datetimeoffset",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RecoveryEncryptedDek",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "RecoveryKeyHash",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "RecoveryKitGeneratedAt",
                table: "Users");
        }
    }
}
