// Collapses the mobile navbar menu after a navigation — without this, Bootstrap leaves the
// hamburger menu open (its .collapse component has no notion of Blazor's client-side routing, so
// clicking a NavLink never closes it), which reads as broken on a phone: you tap "Vault", the menu
// should get out of the way, not stay covering the page.
export function collapseNavbar(id) {
    const el = document.getElementById(id);
    if (!el || typeof bootstrap === "undefined") {
        return;
    }

    const instance = bootstrap.Collapse.getOrCreateInstance(el, { toggle: false });
    instance.hide();
}
