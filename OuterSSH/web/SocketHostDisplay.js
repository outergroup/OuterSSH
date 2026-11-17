(() => {
    if (window.__outersshSocketHostDisplayInstalled) {
        return;
    }
    window.__outersshSocketHostDisplayInstalled = true;

    const socketSuffix = ".unix.outerssh.localhost";
    const pipeSuffix = ".pipe.outerssh.localhost";
    const socketHostPattern = /(^|[^a-z0-9_.-])([a-z2-7]+(?:\.[a-z2-7]+)*\.(?:unix|pipe)\.outerssh\.localhost)(?=$|[^a-z0-9_.-])/gi;

    const documentHost = String(window.location.hostname || "").toLowerCase().replace(/\.+$/, "");
    if (!documentHost.endsWith(socketSuffix) && !documentHost.endsWith(pipeSuffix)) {
        return;
    }

    function decodedSocketPath(host) {
        const pipe = host.toLowerCase().endsWith(pipeSuffix);
        const labels = host.toLowerCase().slice(0, -(pipe ? pipeSuffix : socketSuffix).length).split(".");
        if (labels.some((label, index) => label.length > 50 || (index < labels.length - 1 && label.length !== 50))) {
            return null;
        }
        const encoded = labels.join("");
        const bytes = [];
        let bits = 0;
        let count = 0;
        for (const symbol of encoded) {
            bits = (bits << 5) | "abcdefghijklmnopqrstuvwxyz234567".indexOf(symbol);
            count += 5;
            if (count >= 8) {
                count -= 8;
                const byte = bits >> count;
                if (byte < 32 || byte === 127) return null;
                bytes.push(byte);
                bits &= (1 << count) - 1;
            }
        }
        if (bits !== 0 || Math.ceil(bytes.length * 8 / 5) !== encoded.length || bytes.length > 144) return null;
        let path;
        try {
            path = new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes));
        } catch {
            return null;
        }
        if (pipe) {
            return /^\\\\\.\\pipe\\[a-z0-9._-]+$/.test(path) && path.length <= 110 ? path : null;
        }
        return path.startsWith("/") ? path : null;
    }

    function restoredText(value) {
        return value.replace(socketHostPattern, (match, prefix, host) => {
            const path = decodedSocketPath(host);
            return path === null ? match : prefix + path;
        });
    }

    function restoreTextNode(node) {
        if (!node.nodeValue || !/outerssh\.localhost/i.test(node.nodeValue)) {
            return;
        }
        const tagName = node.parentElement ? node.parentElement.localName : null;
        if (tagName === null || tagName === "script" || tagName === "style" || tagName === "noscript" || tagName === "template") {
            return;
        }
        const restored = restoredText(node.nodeValue);
        if (restored !== node.nodeValue) {
            node.nodeValue = restored;
        }
    }

    function restoreText(root) {
        if (!root) {
            return;
        }
        if (root.nodeType === Node.TEXT_NODE) {
            restoreTextNode(root);
            return;
        }
        if (root.nodeType !== Node.ELEMENT_NODE
            && root.nodeType !== Node.DOCUMENT_NODE
            && root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE) {
            return;
        }
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        let node;
        while ((node = walker.nextNode())) {
            restoreTextNode(node);
        }
    }

    function install() {
        const target = document.documentElement || document.body;
        if (!target) {
            window.addEventListener("DOMContentLoaded", install, { once: true });
            return;
        }
        restoreText(target);
        new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                if (mutation.type === "characterData") {
                    restoreText(mutation.target);
                } else {
                    for (const node of mutation.addedNodes) {
                        restoreText(node);
                    }
                }
            }
        }).observe(target, { childList: true, characterData: true, subtree: true });
    }

    install();
})();
