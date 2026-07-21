using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CffVaultManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddVaultMembershipAndUserKeyPair : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "EncryptedPrivateKey",
                table: "Users",
                type: "varbinary(max)",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "PublicKey",
                table: "Users",
                type: "varbinary(max)",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "VaultMemberships",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    VaultId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Permission = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    WrappedVaultDek = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    EphemeralPublicKey = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    InvitedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    RevokedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VaultMemberships", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VaultMemberships_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_VaultMemberships_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_VaultMemberships_Vaults_VaultId",
                        column: x => x.VaultId,
                        principalTable: "Vaults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_VaultMemberships_TenantId_UserId",
                table: "VaultMemberships",
                columns: new[] { "TenantId", "UserId" });

            migrationBuilder.CreateIndex(
                name: "IX_VaultMemberships_TenantId_VaultId_UserId",
                table: "VaultMemberships",
                columns: new[] { "TenantId", "VaultId", "UserId" },
                unique: true,
                filter: "[RevokedAt] IS NULL");

            migrationBuilder.CreateIndex(
                name: "IX_VaultMemberships_UserId",
                table: "VaultMemberships",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultMemberships_VaultId",
                table: "VaultMemberships",
                column: "VaultId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "VaultMemberships");

            migrationBuilder.DropColumn(
                name: "EncryptedPrivateKey",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "PublicKey",
                table: "Users");
        }
    }
}
