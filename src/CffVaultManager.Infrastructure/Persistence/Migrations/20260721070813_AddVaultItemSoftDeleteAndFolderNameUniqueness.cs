using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CffVaultManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddVaultItemSoftDeleteAndFolderNameUniqueness : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Folders_VaultId",
                table: "Folders");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "DeletedAt",
                table: "VaultItems",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsDeleted",
                table: "VaultItems",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateIndex(
                name: "IX_VaultItems_TenantId_VaultId_IsDeleted",
                table: "VaultItems",
                columns: new[] { "TenantId", "VaultId", "IsDeleted" });

            migrationBuilder.CreateIndex(
                name: "IX_Folders_VaultId_Name",
                table: "Folders",
                columns: new[] { "VaultId", "Name" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_VaultItems_TenantId_VaultId_IsDeleted",
                table: "VaultItems");

            migrationBuilder.DropIndex(
                name: "IX_Folders_VaultId_Name",
                table: "Folders");

            migrationBuilder.DropColumn(
                name: "DeletedAt",
                table: "VaultItems");

            migrationBuilder.DropColumn(
                name: "IsDeleted",
                table: "VaultItems");

            migrationBuilder.CreateIndex(
                name: "IX_Folders_VaultId",
                table: "Folders",
                column: "VaultId");
        }
    }
}
