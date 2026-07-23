// Reads/writes the dark-mode preference. The *initial* choice (stored preference, else
// prefers-color-scheme) is applied synchronously by an inline script in App.razor before Blazor
// even starts, so there is no flash-of-wrong-theme; this module only handles the interactive
// toggle afterwards, so it doesn't duplicate that startup logic.

const STORAGE_KEY = "cffvaultmanager-theme";

export function getCurrentTheme() {
    return document.documentElement.getAttribute("data-bs-theme") || "light";
}

export function setTheme(theme) {
    document.documentElement.setAttribute("data-bs-theme", theme);
    localStorage.setItem(STORAGE_KEY, theme);
}

// Blazor Web App's enhanced navigation re-fetches and merges the server-rendered <head>/<html>
// for every internal navigation — including a plain client-side NavigationManager.NavigateTo call
// (e.g. Shared/RedirectToLogin.razor, hit whenever an [Authorize] page is opened while logged out).
// That merge strips data-bs-theme, since it only ever exists as a client-applied attribute, never
// part of the server-rendered markup. Re-asserted after every navigation (see ThemeToggle.razor)
// so a mid-session redirect can't silently revert an explicit dark-mode choice back to light.
export function reapplyStoredTheme() {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark") {
        document.documentElement.setAttribute("data-bs-theme", stored);
    }
}
