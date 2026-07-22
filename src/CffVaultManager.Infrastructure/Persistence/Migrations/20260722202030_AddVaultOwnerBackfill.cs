using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CffVaultManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddVaultOwnerBackfill : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Data-only: no schema change. VaultPermission gained a third value, Owner, which is
            // now required to invite/revoke a vault's own membership (see
            // docs/features/sharing-access-control.md). Promotes the oldest active membership of
            // every organization vault that does not already have an active Owner, so no
            // pre-existing vault is left with nobody able to manage its membership.
            migrationBuilder.Sql(
                """
                UPDATE vm
                SET Permission = 'Owner'
                FROM VaultMemberships vm
                INNER JOIN Vaults v ON v.Id = vm.VaultId
                WHERE v.IsOrganizationVault = 1
                  AND vm.RevokedAt IS NULL
                  AND vm.Id = (
                      SELECT TOP 1 vm2.Id
                      FROM VaultMemberships vm2
                      WHERE vm2.VaultId = vm.VaultId AND vm2.RevokedAt IS NULL
                      ORDER BY vm2.CreatedAt ASC
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM VaultMemberships vm3
                      WHERE vm3.VaultId = vm.VaultId AND vm3.RevokedAt IS NULL AND vm3.Permission = 'Owner'
                  );
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Deliberate no-op: there is no reliable way to distinguish a membership promoted by
            // this backfill from one that was already legitimately Owner (none existed before this
            // migration) or from a new Owner created after it — same style already used elsewhere
            // in this project for data-only migrations.
        }
    }
}
