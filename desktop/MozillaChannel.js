// Adapted from Vauth/FoxyVPN (MIT). See LICENSE.FoxyVPN.
(() => {
    if (window !== window.top || location.origin !== 'https://accounts.firefox.com') return;
    const received = new WeakSet();
    const forward = event => {
        if (received.has(event)) return;
        received.add(event);
        let envelope = event.detail;
        if (typeof envelope === 'string') {
            try { envelope = JSON.parse(envelope); } catch { return; }
        }
        if (envelope && envelope.message) window.chrome.webview.postMessage(envelope);
    };
    window.addEventListener('WebChannelMessageToChrome', forward);
    document.addEventListener('WebChannelMessageToChrome', forward);
    window.chrome.webview.addEventListener('message', event => {
        const detail = event.data;
        window.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail }));
        document.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail }));
    });
})();
