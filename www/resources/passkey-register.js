/*
 * Client-side support for WebAuthn passkey registration.
 *
 * Handles invocation of navigator.credentials.create() and submission
 * of the resulting attestation to the server-side verification endpoint.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

(function () {
  function b64urlToUint8Array(b64url) {
    const pad = '='.repeat((4 - (b64url.length % 4)) % 4);
    const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(b64);
    const arr = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    return arr;
  }

  function uint8ToB64url(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function bufToB64url(buf) {
    return uint8ToB64url(new Uint8Array(buf));
  }

  async function fetchOptions(returnUrl) {
    const url = "/webauthn/reg/options?return_url=" + encodeURIComponent(returnUrl || "/");
    const res = await fetch(url, { headers: { "Accept": "application/json" } });
    if (!res.ok) throw new Error("options fetch failed: " + res.status);
    return await res.json();
  }

  function initWidget(container) {
    const out = container.querySelector('.webauthn-register-out');
    const btn = container.querySelector('.webauthn-register-btn');

    if (!btn || !out) {
      // Nothing to wire up
      return;
    }

    const returnUrl = container.dataset.returnUrl || "/";

    function log(x) {
      out.textContent = (typeof x === 'string') ? x : JSON.stringify(x, null, 2);
    }

    btn.addEventListener('click', async () => {
      try {
        btn.disabled = true;

        log("Fetching registration options...");
        const data = await fetchOptions(returnUrl);

        const state = data.state;
        const opts  = data.publicKey || data.options || data;
        if (!state) throw new Error("options response missing 'state'");
        if (!opts || !opts.challenge || !opts.user) throw new Error("options response missing required fields");

        // Convert base64url strings to ArrayBuffer-compatible fields
        opts.challenge = b64urlToUint8Array(opts.challenge);

        // WebAuthn expects user.id as BufferSource.
        // If server already sends base64url, change this conversion accordingly.
        opts.user.id = new TextEncoder().encode(String(opts.user.id));

        if (opts.excludeCredentials) {
          opts.excludeCredentials = opts.excludeCredentials.map(c => ({
            ...c,
            id: b64urlToUint8Array(c.id),
          }));
        }

        log("Calling navigator.credentials.create()...");
        const cred = await navigator.credentials.create({ publicKey: opts });
        if (!cred) throw new Error("No credential returned");

        const payload = {
          id: cred.id,
          rawId: bufToB64url(cred.rawId),
          type: cred.type,
          response: {
            clientDataJSON: bufToB64url(cred.response.clientDataJSON),
            attestationObject: bufToB64url(cred.response.attestationObject),
          }
        };

        log("Posting attestation for verification...");
        const verifyRes = await fetch("/webauthn/reg/verify?state=" + encodeURIComponent(state), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        const text = await verifyRes.text();
        let obj;
        try { obj = JSON.parse(text); } catch (e) { obj = { raw: text }; }

        log(obj);

        if (verifyRes.ok && obj && obj.ok) {
          localStorage.setItem("webauthn:registered", "1");
          if (obj.return_url) {
            window.location = obj.return_url;
          } else {
            // No return_url, refresh so the UI can reflect "registered"
            window.location.reload();
          }
        }
      } catch (e) {
        if (e && e.name === "InvalidStateError") {
          log(
              "A passkey already exists on this device/browser for this account.\n\n" +
                  "You can manage (rename/delete) your passkeys in your account settings, " +
                  "or register another passkey using a different device or security key."
          );
          return;
        }
        log(String(e));
      } finally {
        btn.disabled = false;
      }
    });
  }

  function initAll() {
    document.querySelectorAll('.webauthn-register').forEach(initWidget);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAll);
  } else {
    initAll();
  }
})();
