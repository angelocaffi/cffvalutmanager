using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;

namespace CffVaultManager.Infrastructure.Tests;

/// <summary>Pure-entity coverage of the trial/paid-plan lifecycle on <see cref="Tenant"/> — no database involved (see docs/features/billing.md).</summary>
public sealed class TenantBillingTests
{
    private static Tenant NewTenant(DateTimeOffset createdAt) =>
        new(Guid.NewGuid(), "Acme", "acme", TenantStatus.Active, createdAt: createdAt);

    [Fact]
    public void NewTenant_TrialEndsAt_defaults_to_CreatedAt_plus_30_days()
    {
        var createdAt = DateTimeOffset.UtcNow;
        var tenant = NewTenant(createdAt);

        Assert.Equal(createdAt.AddDays(30), tenant.TrialEndsAt);
    }

    [Fact]
    public void IsReadOnly_false_while_trial_is_still_active_and_no_plan_exists()
    {
        var tenant = NewTenant(DateTimeOffset.UtcNow);

        Assert.False(tenant.IsReadOnly(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void IsReadOnly_true_once_trial_has_ended_with_no_payment()
    {
        var tenant = NewTenant(DateTimeOffset.UtcNow.AddDays(-31));

        Assert.True(tenant.IsReadOnly(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void IsReadOnly_false_once_a_payment_has_extended_the_plan_past_now()
    {
        var tenant = NewTenant(DateTimeOffset.UtcNow.AddDays(-31));
        var now = DateTimeOffset.UtcNow;

        tenant.ExtendPlan(now, TimeSpan.FromDays(365));

        Assert.False(tenant.IsReadOnly(now));
    }

    [Fact]
    public void IsReadOnly_true_again_once_the_paid_plan_itself_has_expired()
    {
        var tenant = NewTenant(DateTimeOffset.UtcNow.AddDays(-400));
        tenant.ExtendPlan(DateTimeOffset.UtcNow.AddDays(-400).AddDays(30), TimeSpan.FromDays(365));

        Assert.True(tenant.IsReadOnly(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void ExtendPlan_whenNoActivePlanYet_extendsFromNow_notFromTrialEnd()
    {
        var tenant = NewTenant(DateTimeOffset.UtcNow.AddDays(-60));
        var now = DateTimeOffset.UtcNow;

        tenant.ExtendPlan(now, TimeSpan.FromDays(365));

        Assert.Equal(now.AddDays(365), tenant.PlanExpiresAt);
    }

    [Fact]
    public void ExtendPlan_whenPaidEarly_addsToTheRemainingTime_insteadOfResettingFromNow()
    {
        var tenant = NewTenant(DateTimeOffset.UtcNow);
        var firstPayment = DateTimeOffset.UtcNow;
        tenant.ExtendPlan(firstPayment, TimeSpan.FromDays(365));
        var expectedAfterFirst = firstPayment.AddDays(365);

        // Pays again while comfortably still covered by the first payment.
        var secondPayment = firstPayment.AddDays(10);
        tenant.ExtendPlan(secondPayment, TimeSpan.FromDays(365));

        Assert.Equal(expectedAfterFirst.AddDays(365), tenant.PlanExpiresAt);
    }

    [Fact]
    public void ExtendPlan_whenPlanAlreadyExpired_extendsFromNow_notFromTheStaleExpiry()
    {
        var tenant = NewTenant(DateTimeOffset.UtcNow.AddDays(-400));
        var firstPayment = DateTimeOffset.UtcNow.AddDays(-400).AddDays(30);
        tenant.ExtendPlan(firstPayment, TimeSpan.FromDays(365));

        var now = DateTimeOffset.UtcNow;
        tenant.ExtendPlan(now, TimeSpan.FromDays(365));

        Assert.Equal(now.AddDays(365), tenant.PlanExpiresAt);
    }
}
