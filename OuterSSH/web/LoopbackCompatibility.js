(() => {
    if (window.__outersshLoopbackCompatibilityInstalled) {
        return;
    }
    window.__outersshLoopbackCompatibilityInstalled = true;

    const tcpSuffix = ".tcp.outerssh.localhost";
    const socketSuffix = ".unix.outerssh.localhost";
    const pipeSuffix = ".pipe.outerssh.localhost";

    function normalizedHost(host) {
        return String(host || "")
            .replace(/^\[/, "")
            .replace(/\]$/, "")
            .toLowerCase()
            .replace(/\.+$/, "");
    }

    function isEligibleDocumentHost(host) {
        const normalized = normalizedHost(host);
        return normalized.endsWith(tcpSuffix)
            || normalized.endsWith(socketSuffix)
            || normalized.endsWith(pipeSuffix)
            || normalized === "localhost"
            || normalized === "127.0.0.1"
            || normalized.startsWith("127.")
            || normalized === "::1"
            || normalized === "0:0:0:0:0:0:0:1";
    }

    const loopbackIPv4Pattern = /^127(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$/;

    function encodedTCPHost(host) {
        const normalized = normalizedHost(host);
        if (normalized === "localhost" || loopbackIPv4Pattern.test(normalized)) {
            return normalized + tcpSuffix;
        }
        if (normalized === "::1" || normalized === "0:0:0:0:0:0:0:1") {
            return "ip6-localhost" + tcpSuffix;
        }
        return null;
    }

    const tcpURLPattern = /\b(http|ws):\/\/(localhost|ip6-localhost|127(?:\.[0-9]{1,3}){3})\.tcp\.outerssh\.localhost(?=[:/?#\s"'<>]|$)/gi;
    const socketHostPattern = /(^|[^a-z0-9_.-])([a-z2-7]+(?:\.[a-z2-7]+)*\.(?:unix|pipe)\.outerssh\.localhost)(?=$|[^a-z0-9_.-])/gi;

    function decodedTCPHost(label) {
        const normalized = label.toLowerCase();
        if (normalized === "ip6-localhost") {
            return "[::1]";
        }
        return normalized === "localhost" || loopbackIPv4Pattern.test(normalized) ? normalized : null;
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
        return value
            .replace(tcpURLPattern, (match, scheme, label) => {
                const host = decodedTCPHost(label);
                return host === null ? match : scheme + "://" + host;
            })
            .replace(socketHostPattern, (match, prefix, host) => {
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

    function installObserver() {
        const target = document.documentElement || document.body;
        if (!target) {
            window.addEventListener("DOMContentLoaded", installObserver, { once: true });
            return;
        }
        restoreText(target);
        rewriteURLAttributes(target);
        new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                if (mutation.type === "characterData") {
                    restoreText(mutation.target);
                } else {
                    for (const node of mutation.addedNodes) {
                        restoreText(node);
                        rewriteURLAttributes(node);
                    }
                }
            }
        }).observe(target, { childList: true, characterData: true, subtree: true });
    }

    function rewrittenURLValue(value) {
        const valueIsURL = value instanceof URL;
        const urlText = valueIsURL ? value.href : (typeof value === "string" ? value : null);
        if (urlText === null) {
            return value;
        }

        let url;
        try {
            url = new URL(urlText, document.baseURI);
        } catch {
            return value;
        }

        const protocol = url.protocol.toLowerCase();
        const host = protocol === "http:" || protocol === "ws:" ? encodedTCPHost(url.hostname) : null;
        if (host === null) {
            return value;
        }

        url.hostname = host;
        return valueIsURL ? new URL(url.href) : url.href;
    }

    const markupHost = "(localhost|127(?:\\.[0-9]{1,3}){3}|\\[(?:::1|0:0:0:0:0:0:0:1)\\]):([0-9]{1,5})";
    const markupURLPattern = new RegExp("((?:http|ws)://)" + markupHost, "gi");
    const markupRelativeURLPattern = new RegExp("(^|[\"'=(\\s])(//)" + markupHost, "gi");

    function rewrittenMarkupURL(match, prefix, host, port) {
        const encoded = Number(port) <= 65535 ? encodedTCPHost(host) : null;
        return encoded === null ? match : prefix + encoded + ":" + port;
    }

    function rewrittenMarkup(value) {
        if (typeof value !== "string") {
            return value;
        }
        return value
            .replace(markupURLPattern, rewrittenMarkupURL)
            .replace(markupRelativeURLPattern, (match, boundary, prefix, host, port) =>
                boundary + rewrittenMarkupURL(prefix + host + ":" + port, prefix, host, port));
    }

    function rewrittenSrcset(value) {
        return String(value).split(",").map((candidate) => {
            const match = /^(\s*)(\S+)([\s\S]*)$/.exec(candidate);
            return match ? match[1] + rewrittenURLValue(match[2]) + match[3] : candidate;
        }).join(",");
    }

    const urlAttributes = {
        a: ["href"], area: ["href"], base: ["href"], link: ["href"],
        audio: ["src"], embed: ["src"], frame: ["src"], iframe: ["src"], script: ["src"], track: ["src"],
        img: ["src", "srcset"], source: ["src", "srcset"], video: ["src", "poster"],
        input: ["src", "formaction"], button: ["formaction"], form: ["action"], object: ["data"],
    };
    const urlAttributeSelector = Object.entries(urlAttributes)
        .flatMap(([tag, names]) => names.map((name) => `${tag}[${name}]`)).join(",");
    const originalSetAttribute = typeof Element !== "undefined" ? Element.prototype.setAttribute : null;

    function rewrittenAttributeValue(element, name, value) {
        const normalized = String(name).toLowerCase();
        if (element.localName === "iframe" && normalized === "srcdoc") {
            return rewrittenMarkup(value);
        }
        const names = urlAttributes[element.localName];
        if (!names || !names.includes(normalized)) {
            return value;
        }
        return normalized === "srcset" ? rewrittenSrcset(value) : String(rewrittenURLValue(String(value)));
    }

    function rewriteURLAttributes(root) {
        if (!originalSetAttribute || !root || root.nodeType !== Node.ELEMENT_NODE) {
            return;
        }
        const elements = root.matches(urlAttributeSelector) ? [root] : [];
        elements.push(...root.querySelectorAll(urlAttributeSelector));
        for (const element of elements) {
            for (const name of urlAttributes[element.localName] || []) {
                const value = element.getAttribute(name);
                if (value === null) {
                    continue;
                }
                const rewritten = rewrittenAttributeValue(element, name, value);
                if (rewritten !== value) {
                    originalSetAttribute.call(element, name, rewritten);
                }
            }
        }
    }

    function wrapConstructor(name) {
        const Original = globalThis[name];
        if (typeof Original !== "function") {
            return;
        }
        const Wrapped = function(url, ...rest) {
            return Reflect.construct(Original, [rewrittenURLValue(url), ...rest], new.target || Original);
        };
        Wrapped.prototype = Original.prototype;
        Object.setPrototypeOf(Wrapped, Original);
        globalThis[name] = Wrapped;
    }

    function rewrittenRequestInput(input) {
        if (typeof Request !== "undefined" && input instanceof Request) {
            const rewritten = rewrittenURLValue(input.url);
            if (rewritten !== input.url) {
                const method = String(input.method || "GET").toUpperCase();
                if (method !== "GET" && method !== "HEAD") {
                    return input;
                }
                return new Request(rewritten, input);
            }
            return input;
        }
        return rewrittenURLValue(input);
    }

    if (!isEligibleDocumentHost(window.location.hostname)) {
        return;
    }

    if (typeof globalThis.Request !== "undefined") {
        const OriginalRequest = globalThis.Request;
        globalThis.Request = function(input, init) {
            const rewritten = input instanceof OriginalRequest ? input : rewrittenURLValue(input);
            return Reflect.construct(OriginalRequest, init === undefined ? [rewritten] : [rewritten, init], new.target || OriginalRequest);
        };
        globalThis.Request.prototype = OriginalRequest.prototype;
        Object.setPrototypeOf(globalThis.Request, OriginalRequest);
    }

    if (typeof globalThis.fetch === "function") {
        const originalFetch = globalThis.fetch;
        globalThis.fetch = function(input, init) {
            return originalFetch.call(this, rewrittenRequestInput(input), init);
        };
    }

    if (typeof XMLHttpRequest !== "undefined") {
        const originalOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...rest) {
            return originalOpen.call(this, method, rewrittenURLValue(url), ...rest);
        };
    }

    for (const name of ["WebSocket", "EventSource", "Worker", "SharedWorker"]) {
        wrapConstructor(name);
    }

    if (navigator && typeof navigator.sendBeacon === "function") {
        const originalSendBeacon = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function(url, data) {
            return originalSendBeacon(rewrittenURLValue(url), data);
        };
    }

    if (typeof window.open === "function") {
        const originalOpen = window.open;
        window.open = function(url, ...rest) {
            return originalOpen.call(this, url === undefined ? url : rewrittenURLValue(url), ...rest);
        };
    }

    if (typeof History !== "undefined") {
        for (const method of ["pushState", "replaceState"]) {
            const original = History.prototype[method];
            History.prototype[method] = function(state, title, ...url) {
                return original.call(this, state, title, ...url.map(rewrittenURLValue));
            };
        }
    }

    if (originalSetAttribute) {
        Element.prototype.setAttribute = function(name, value) {
            return originalSetAttribute.call(this, name, rewrittenAttributeValue(this, name, value));
        };
    }

    for (const [interfaceName, property] of [
        ["HTMLAnchorElement", "href"], ["HTMLAreaElement", "href"], ["HTMLBaseElement", "href"],
        ["HTMLLinkElement", "href"], ["HTMLMediaElement", "src"], ["HTMLEmbedElement", "src"],
        ["HTMLFrameElement", "src"], ["HTMLIFrameElement", "src"], ["HTMLScriptElement", "src"],
        ["HTMLTrackElement", "src"], ["HTMLImageElement", "src"], ["HTMLImageElement", "srcset"],
        ["HTMLSourceElement", "src"], ["HTMLSourceElement", "srcset"], ["HTMLVideoElement", "poster"],
        ["HTMLInputElement", "src"], ["HTMLInputElement", "formAction"], ["HTMLButtonElement", "formAction"],
        ["HTMLFormElement", "action"], ["HTMLObjectElement", "data"],
    ]) {
        const prototype = globalThis[interfaceName] && globalThis[interfaceName].prototype;
        const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, property);
        if (!descriptor || !descriptor.set || !descriptor.configurable) {
            continue;
        }
        const setter = descriptor.set;
        Object.defineProperty(prototype, property, {
            ...descriptor,
            set(value) {
                setter.call(this, property === "srcset" ? rewrittenSrcset(value) : rewrittenURLValue(value));
            },
        });
    }

    function wrapSetter(interfaceName, property, transform) {
        const prototype = globalThis[interfaceName] && globalThis[interfaceName].prototype;
        const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, property);
        if (!descriptor || !descriptor.set || !descriptor.configurable) {
            return;
        }
        const setter = descriptor.set;
        Object.defineProperty(prototype, property, {
            ...descriptor,
            set(value) {
                setter.call(this, transform(value));
            },
        });
    }

    function wrapMethod(target, name, transformArguments) {
        const original = target && target[name];
        if (typeof original !== "function") {
            return;
        }
        target[name] = function(...args) {
            return original.apply(this, transformArguments(args));
        };
    }

    for (const [interfaceName, property] of [
        ["Element", "innerHTML"], ["Element", "outerHTML"], ["ShadowRoot", "innerHTML"],
        ["HTMLIFrameElement", "srcdoc"],
    ]) {
        wrapSetter(interfaceName, property, rewrittenMarkup);
    }
    const markupArgument = (index) => (args) => args.map((arg, i) => i === index ? rewrittenMarkup(arg) : arg);
    const allMarkupArguments = (args) => args.map(rewrittenMarkup);
    const prototypeOf = (name) => globalThis[name] && globalThis[name].prototype;
    wrapMethod(prototypeOf("Element"), "insertAdjacentHTML", markupArgument(1));
    wrapMethod(prototypeOf("Element"), "setHTMLUnsafe", markupArgument(0));
    wrapMethod(prototypeOf("ShadowRoot"), "setHTMLUnsafe", markupArgument(0));
    wrapMethod(prototypeOf("Range"), "createContextualFragment", markupArgument(0));
    wrapMethod(prototypeOf("Document"), "write", allMarkupArguments);
    wrapMethod(prototypeOf("Document"), "writeln", allMarkupArguments);
    wrapMethod(globalThis.Document, "parseHTMLUnsafe", markupArgument(0));
    wrapMethod(prototypeOf("DOMParser"), "parseFromString", (args) =>
        /html/i.test(String(args[1])) ? markupArgument(0)(args) : args);

    installObserver();
})();
