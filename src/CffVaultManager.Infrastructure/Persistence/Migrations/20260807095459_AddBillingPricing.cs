using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CffVaultManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddBillingPricing : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "BillingPricing",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    StandardAnnualPrice = table.Column<decimal>(type: "decimal(10,2)", nullable: false),
                    DiscountedAnnualPrice = table.Column<decimal>(type: "decimal(10,2)", nullable: true),
                    DiscountExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    PromoMessage = table.Column<string>(type: "nvarchar(280)", maxLength: 280, nullable: true),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BillingPricing", x => x.Id);
                    table.ForeignKey(
                        name: "FK_BillingPricing_Users_UpdatedByUserId",
                        column: x => x.UpdatedByUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_BillingPricing_UpdatedByUserId",
                table: "BillingPricing",
                column: "UpdatedByUserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "BillingPricing");
        }
    }
}
