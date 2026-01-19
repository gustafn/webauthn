/*
 * Client-side support for WebAuthn passkey authentication (login).
 *
 * Handles invocation of navigator.credentials.get() and submission
 * of the resulting assertion to the server-side verification endpoint.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

(function () {
    const boxes = document.querySelectorAll(".webauthn-login");
    if (!boxes.length) return;

    function isLinuxDesktop() {
        const ua = navigator.userAgent || "";
        console.log('ua', ua);
        return ua.includes("Linux") && !ua.includes("Android");
    }

    function effectiveAuthMode(box) {
        const mode = (box.dataset.authMode || "auto").trim(); // auto|passkey|identifier
        if (mode !== "auto") return mode;

        const { ident } = getIdentValue(box);
        return ident ? "identifier" : "passkey";
    }

    function findIdentInput() {
        // OpenACS login form fields
        return (
            document.querySelector('input[name="email"]') ||
                document.querySelector('input[name="username"]') ||
                document.querySelector('input[name="email_or_username"]') ||
                document.querySelector('#login') ||
                null
        );
    }

    function getIdentValue(box) {
        const hintIdent = (box.dataset.hintIdent || box.dataset.identifier || "").trim();
        const input = findIdentInput();
        const formIdent = input ? (input.value || "").trim() : "";
        const ident = formIdent || hintIdent;
        return { ident, input, formIdent, hintIdent };
    }

    function b64urlToUint8Array(b64url) {
        const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
        const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(b64);
        const arr = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
        return arr;
    }

    function bufToB64url(buf) {
        const u8 = new Uint8Array(buf);
        let s = '';
        for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
        return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    }

    boxes.forEach((box) => {
        const btn = box.querySelector(".webauthn-login-btn");
        const out = box.querySelector(".webauthn-login-out");
        if (!btn || !out) return;

        function report(err, msg) {
            console.log(msg);
            out.textContent = (typeof msg === "string") ? msg : JSON.stringify(msg, null, 2);
            out.style.color = (err == 1) ? 'red' : 'inherit';
            out.style.display = "";
        }

        async function fetchOptions(returnUrl) {
            const authMode = effectiveAuthMode(box);
            console.log("fetchOptions effective auth_mode", authMode);

            let url = "/webauthn/auth/options?return_url=" + encodeURIComponent(returnUrl || "/")
                + "&auth_mode=" + encodeURIComponent(authMode);

            if (authMode === "identifier") {
                const { ident } = getIdentValue(box);
                if (ident) url += "&identifier=" + encodeURIComponent(ident);
            }

            const res = await fetch(url, { headers: { "Accept": "application/json" } });

            // Read JSON regardless of status; endpoint returns JSON errors.
            let data;
            try {
                data = await res.json();
            } catch (e) {
                throw new Error("options fetch failed: non-JSON response (" + res.status + ")");
            }

            // Keep status available for diagnostics (optional)
            data._http_status = res.status;

            return data;
        }


        async function fetchOptionsWithMode(returnUrl, mode) {
            let url = "/webauthn/auth/options?return_url=" + encodeURIComponent(returnUrl || "/")
                + "&auth_mode=" + encodeURIComponent(mode);

            if (mode === "identifier") {
                const { ident } = getIdentValue(box); // can fall back to hint if field empty
                url += "&identifier=" + encodeURIComponent(ident || "");
            }

            const res = await fetch(url, { headers: { "Accept": "application/json" } });
            const data = await res.json();
            data._http_status = res.status;
            return data;
        }
        

        async function init() {
            if (!window.PublicKeyCredential || !navigator.credentials) return;

            const visMode = (box.dataset.mode || "generic").trim(); // generic|hinted
            let configuredAuthMode = (box.dataset.authMode || "auto").trim();
            console.log("configured auth mode", configuredAuthMode);

            const { ident, input } = getIdentValue(box);
            const hasIdent = ident.length > 0;
            const btn = box.querySelector(".webauthn-login-btn");

            console.log("visMode", visMode, "configuredAuthMode", configuredAuthMode, "hasIdent", hasIdent, "ident", ident);

            if (configuredAuthMode === "identifier") {
                box.style.display = hasIdent ? "" : "none";
                if (btn) {
                    btn.disabled = !hasIdent;
                    if (!hasIdent) {
                        // Show box if we want disabled button instead of hiding:
                        // box.style.display = "";
                    }
                }

                if (input && btn) {
                    input.addEventListener("input", () => {
                        const now = (input.value || "").trim();
                        const ok = now.length > 0;
                        btn.disabled = !ok;
                        box.style.display = ok ? "" : "none";
                    });
                }
                return;
            }

            // Passkey-first (discoverable)
            const hasHint =
                  localStorage.getItem("webauthn:registered") === "1" || localStorage.getItem("webauthn:used") === "1";
            if (visMode === "generic" && !hasHint) {
                box.style.display = "none";
                return;
            }
            box.style.display = "";
        }


        btn.addEventListener("click", async () => {
            const returnUrl = box.dataset.returnUrl || "/";
        });

        btn.addEventListener("click", async (e) => {
            e.preventDefault();
            let mode = null;
            
            try {
                btn.disabled = true;

                const configured = (box.dataset.authMode || "auto").trim();
                const { formIdent, input, ident } = getIdentValue(box); // ident = formIdent||hint
                
                // Decide effective mode for THIS click
                if (configured === "identifier" || configured === "passkey") {
                    mode = configured;
                } else {
                    mode = formIdent ? "identifier" : "passkey"; // auto
                } 
                
                report(0, "Fetching passkey login options...");
                const data = await fetchOptionsWithMode(box.dataset.returnUrl || "/", mode);
                console.log("auth/options response", data);

                // Handle JSON error payloads from /auth/options
                if (data && data.error) {

                    if (data.error === "missing-identifier") {
                        const { input } = getIdentValue(box);
                        input?.focus();
                    }
                    report(1, data.detail || data.error);
                    return; 
                }

                const state = data.state;
                const opts  = data.publicKey || data.options || data;
                if (!state) throw new Error("options response missing 'state'");

                opts.challenge = b64urlToUint8Array(opts.challenge);

                if (opts.allowCredentials) {
                    opts.allowCredentials = opts.allowCredentials.map(c => ({
                        ...c,
                        id: b64urlToUint8Array(c.id),
                    }));
                }

                console.log('force passkey-first failure', box.dataset.devForcePasskeyFail === "1", 'mode', mode );
                // ---- DEV: force passkey-first failure to test fallback ----
                if (box.dataset.devForcePasskeyFail === "1" && mode === "passkey") {
                    const err = new DOMException("Simulated passkey-first failure", "NotAllowedError");
                    throw err;
                }
                
                report(0, "Calling navigator.credentials.get()...");
                const assertion = await navigator.credentials.get({ publicKey: opts });
                if (!assertion) throw new Error("No assertion returned");

                const payload = {
                    id: assertion.id,
                    rawId: bufToB64url(assertion.rawId),
                    type: assertion.type,
                    response: {
                        clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
                        authenticatorData: bufToB64url(assertion.response.authenticatorData),
                        signature: bufToB64url(assertion.response.signature),
                        userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : null
                    }
                };

                report(0, "Posting assertion for verification...");
                const verifyRes = await fetch("/webauthn/auth/verify?state=" + encodeURIComponent(state), {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });

                const text = await verifyRes.text();
                let obj;
                try { obj = JSON.parse(text); } catch(e) { obj = { raw: text }; }
                report(0, obj);

                if (verifyRes.ok && obj && obj.ok && obj.return_url) {
                    out.style.display = "none";
                    localStorage.setItem("webauthn:used", "1");
                    window.location = obj.return_url;
                }
            } catch (err) {

                const name = err?.name || "";
                const msg  = err?.message || String(err);

                // Auto fallback: passkey-first failed and user has no identifier -> prompt to type it
                const configured = (box.dataset.authMode || "auto").trim();
                const { formIdent, input } = getIdentValue(box);
                
                if (configured === "auto" && mode === "passkey" && !formIdent
                    && (name === "NotAllowedError" || name === "AbortError")
                   ) {
                    report(1, "Enter your email/username to use a passkey on this device/browser.");
                    input?.focus();
                    return;
                }

                report(1, msg);
            } finally {
                btn.disabled = false;
            }
        });

        init();
    });
})();
