// Loads the PayPal JS SDK ("Smart Buttons") on demand and renders a Buttons instance that calls
// back into .NET for order creation/capture — see docs/features/billing.md "Flusso Web.Client".
// Approval happens in an SDK-managed popup; there is no redirect/return_url to handle here.

let sdkLoadPromise = null;

function loadSdk(clientId, currency) {
    if (window.paypal) {
        return Promise.resolve();
    }

    if (sdkLoadPromise) {
        return sdkLoadPromise;
    }

    sdkLoadPromise = new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = `https://www.paypal.com/sdk/js?client-id=${encodeURIComponent(clientId)}&currency=${encodeURIComponent(currency)}&disable-funding=card,credit,paylater,venmo`;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error("Impossibile caricare l'SDK PayPal."));
        document.head.appendChild(script);
    });

    return sdkLoadPromise;
}

export async function renderButtons(containerId, clientId, currency, dotNetRef) {
    await loadSdk(clientId, currency);

    window.paypal.Buttons({
        createOrder: () => dotNetRef.invokeMethodAsync("CreateOrderAsync"),
        onApprove: (data) => dotNetRef.invokeMethodAsync("OnApprovedAsync", data.orderID),
        onError: (err) => dotNetRef.invokeMethodAsync("OnErrorAsync", err ? err.toString() : "Errore sconosciuto."),
    }).render(`#${containerId}`);
}
