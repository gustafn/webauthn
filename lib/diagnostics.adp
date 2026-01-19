<!--
  ADP page for passkey diagnistics

  SPDX-License-Identifier: MPL-2.0
-->

<property name="doc(title)">@page_title;literal@</property>
<master>
<h2>@page_title;noquote@</h2>

<p>
This page checks basic WebAuthn capabilities and runs two interactive tests.
Nothing happens automatically; each test requires a button click (user gesture).
</p>

<style>
  .webauthn-diag { max-width: 72rem; }

  .webauthn-diag .wd-row { display:flex; gap:1rem; align-items:flex-start; margin:.4rem 0; }
  .webauthn-diag .wd-k   { width: 16rem; font-weight: 600; }
  .webauthn-diag .wd-v   { flex: 1; white-space: pre-wrap; }

  .webauthn-diag .wd-box { border: 1px solid #ddd; border-radius: .5rem; padding: .75rem; margin: 1rem 0; }
  .webauthn-diag .wd-out { padding:.5rem; border:1px solid #eee; border-radius:.4rem; margin-top:.5rem; white-space: pre-wrap; }

  .webauthn-diag .wd-ok  { color: #0a7; }
  .webauthn-diag .wd-bad { color: #c00; }
</style>


<div class="wd-row"><div class="k">Diagnostics ID</div><div class="v">@diag_id;noquote@</div></div>


<div class="webauthn-diag">

  <div class="wd-box" id="capBox">
    <h3>Capabilities</h3>
    <div class="wd-row"><div class="wd-k">Secure context</div><div class="wd-v" id="c_secure"></div></div>
    <div class="wd-row"><div class="wd-k">PublicKeyCredential</div><div class="wd-v" id="c_pkc"></div></div>
    <div class="wd-row"><div class="wd-k">navigator.credentials</div><div class="wd-v" id="c_creds"></div></div>
    <div class="wd-row"><div class="wd-k">UV platform authenticator</div><div class="wd-v" id="c_uvpaa"></div></div>
    <div class="wd-row"><div class="wd-k">Conditional mediation</div><div class="wd-v" id="c_cma"></div></div>
    <div class="wd-row"><div class="wd-k">User agent</div><div class="wd-v" id="c_ua"></div></div>
    <div class="wd-row"><div class="wd-k">UA platform (UA-CH)</div><div class="wd-v" id="c_uach"></div></div>
    <hr>
    <h3>User Activities</h3>    
    <div class="wd-row"><div class="wd-k">Passkey registered</div><div class="wd-v" id="c_kreg"></div></div>
    <div class="wd-row"><div class="wd-k">Passkey used</div><div class="wd-v" id="c_kuse"></div></div>
    <hr>

    <button class="btn btn-outline-secondary" id="copyBtn" type="button">Copy report</button>
    <div class="wd-out" id="copyOut" style="display:none"></div>    
    <button class="btn btn-outline-secondary" id="sendBtn" type="button">Send report to server log</button>
    <div class="wd-out" id="sendOut" style="display:none"></div>
  </div>

  <div class="wd-box">
    <h3>Test 1: Passkey-first (discoverable)</h3>
    <p>
      Calls <code>/webauthn/auth/options</code> with <code>auth_mode=passkey</code> and runs <code>navigator.credentials.get()</code>.
    </p>
    <button class="btn btn-outline-secondary" id="testPasskeyBtn" type="button">Run passkey-first test</button>
    <div class="wd-out" id="outPasskey"></div>
  </div>

  <div class="wd-box">
    <h3>Test 2: Identifier-first</h3>
    <p>
      Provide email/username; calls <code>/webauthn/auth/options</code> with <code>auth_mode=identifier</code>.
    </p>
    <div class="wd-row">
      <div class="wd-k">Identifier</div>
      <div class="wd-v">
        <input id="identInput" type="text" placeholder="email/username" size="34">
        <button class="btn btn-outline-secondary" id="testIdentBtn" type="button">Run identifier-first test</button>
      </div>
    </div>
    <div class="wd-out" id="outIdent"></div>
  </div>

</div>

<script nonce="@::__csp_nonce@">
(function() {
  const DIAG_ID = "@diag_id;noquote@";
  const returnUrl = "@return_url;noquote@";
  const kreg = localStorage.getItem("webauthn:registered") === "1";
  const kuse = localStorage.getItem("webauthn:used") === "1";

  const cap = {
    secureContext: window.isSecureContext === true,
    hasPublicKeyCredential: !!window.PublicKeyCredential,
    hasNavigatorCredentials: !!(navigator && navigator.credentials),
    uap: navigator.userAgent || "",
    uachPlatform: null,
    uvpaa: null,
    cma: null,
  };

  async function buildDiagReport() {
    return {
      diag_id: "@diag_id;noquote@",
      when: new Date().toISOString(),
      url: location.href,
      secureContext: window.isSecureContext === true,
      hasPublicKeyCredential: !!window.PublicKeyCredential,
      hasNavigatorCredentials: !!(navigator && navigator.credentials),
      uvpaa: cap.uvpaa,
      conditionalMediation: cap.cma,
      userAgent: navigator.userAgent || "",
      uaCHPlatform: (navigator.userAgentData && navigator.userAgentData.platform) ? navigator.userAgentData.platform : null,
      keyRegistered: kreg,
      keyUsed: kuse,
    };
  }
  
  document.getElementById("sendBtn").addEventListener("click", async () => {
    const out = document.getElementById("sendOut");
    out.style.display = "";
    out.style.color = "inherit";
    out.textContent = "Sending diagnostics report...";
  
    try {
      const payload = await buildDiagReport();
      const res = await fetch("/webauthn/diagnostics", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        credentials: "same-origin",
      });
      if (!res.ok) {
        // strict error contract: {error, detail}
        let data = {};
        try { data = await res.json(); } catch (_) {}
        out.style.color = "red";
        out.textContent = data.detail || ("Send failed: HTTP " + res.status);
        return;
      }
      out.style.color = "inherit";
      out.textContent = "Sent diagnostics report (logged server-side). Please mention diag_id: " + DIAG_ID;
    } catch (e) {
      out.style.color = "red";
      out.textContent = "Send failed: " + (e?.message || String(e));
    }
  });
    
  function setLine(id, ok, text) {
    const el = document.getElementById(id);
    el.textContent = text;
    el.className = ok ? "ed-v wd-ok" : "ed-v wd-bad";
  }

  async function probeAsyncCaps() {
    // isUserVerifyingPlatformAuthenticatorAvailable
    try {
      if (window.PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable) {
        cap.uvpaa = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      }
    } catch (e) {
      cap.uvpaa = { error: e?.name || "error", detail: e?.message || String(e) };
    }

    // isConditionalMediationAvailable (optional)
    try {
      if (window.PublicKeyCredential?.isConditionalMediationAvailable) {
        cap.cma = await PublicKeyCredential.isConditionalMediationAvailable();
      }
    } catch (e) {
      cap.cma = { error: e?.name || "error", detail: e?.message || String(e) };
    }

    // UA-CH
    try {
      cap.uachPlatform = navigator.userAgentData?.platform || null;
    } catch (e) {
      cap.uachPlatform = null;
    }
  }

  function renderCaps() {
    setLine("c_secure", cap.secureContext, String(cap.secureContext));
    setLine("c_pkc", cap.hasPublicKeyCredential, String(cap.hasPublicKeyCredential));
    setLine("c_creds", cap.hasNavigatorCredentials, String(cap.hasNavigatorCredentials));
    setLine("c_uvpaa", cap.uvpaa === true, cap.uvpaa === null ? "(not available)" : JSON.stringify(cap.uvpaa));
    setLine("c_cma", cap.cma === true, cap.cma === null ? "(not available)" : JSON.stringify(cap.cma));

    setLine("c_kreg", kreg, kreg);
    setLine("c_kuse", kuse, kuse);

    document.getElementById("c_ua").textContent = cap.uap;
    document.getElementById("c_uach").textContent = cap.uachPlatform || "(not available)";
  }

  function report(outEl, isErr, msg) {
    outEl.style.display = "";
    outEl.style.color = isErr ? "red" : "inherit";
    outEl.textContent = (typeof msg === "string") ? msg : JSON.stringify(msg, null, 2);
  }

  function b64urlToUint8Array(s) {
    // base64url -> Uint8Array
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = s.length % 4;
    if (pad) s += "=".repeat(4 - pad);
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    return b64;
  }

  async function fetchOptions(authMode, identifier) {
    let url = "/webauthn/auth/options?return_url=" + encodeURIComponent(returnUrl || "/") +
              "&auth_mode=" + encodeURIComponent(authMode);

    if (authMode === "identifier") {
      url += "&identifier=" + encodeURIComponent(identifier || "");
    }

    const res = await fetch(url, { headers: { "Accept": "application/json" } });
    const data = await res.json().catch(() => ({}));
    data._http_status = res.status;
    return data;
  }

  async function runGet(outEl, authMode, identifier) {
    if (!cap.hasPublicKeyCredential || !cap.hasNavigatorCredentials) {
      report(outEl, 1, "WebAuthn APIs not available in this browser.");
      return;
    }
    if (!cap.secureContext) {
      report(outEl, 1, "Not a secure context (WebAuthn requires HTTPS).");
      return;
    }

    report(outEl, 0, "Fetching options...");
    const data = await fetchOptions(authMode, identifier);

    if (data && data.error) {
      // strict contract: {error, detail}
      report(outEl, 1, data.detail || data.error);
      return;
    }

    const state = data.state;
    const opts  = data.publicKey || data.options || data;
    if (!state) {
      report(outEl, 1, { error: "missing-state", detail: "options response missing 'state'", raw: data });
      return;
    }
    
    async function sendDiag(obj) {
      try {
        await fetch("/webauthn/diagnostics", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(obj),
          credentials: "same-origin",
        });
      } catch (_) {}
    }
    
    try {
      opts.challenge = b64urlToUint8Array(opts.challenge);
      if (opts.allowCredentials) {
        opts.allowCredentials = opts.allowCredentials.map(c => ({
          ...c,
          id: b64urlToUint8Array(c.id),
        }));
      }

      report(outEl, 0, "Calling navigator.credentials.get()...");
      const assertion = await navigator.credentials.get({ publicKey: opts });
      if (!assertion) {
        report(outEl, 1, "No assertion returned");
        return;
      }

      // We stop here; this is a diagnostics page.
      // (Optionally you could POST to /webauthn/auth/verify as well, but this already tells
      // whether the authenticator flow is invoked successfully.)
      report(outEl, 0, {
        ok: true,
        gotAssertion: true,
        id: assertion.id,
        type: assertion.type,
      });
      sendDiag({ diag_id: "@diag_id;noquote@", event: "test", mode: authMode, result: "ok", when: new Date().toISOString() });

    } catch (e) {
      report(outEl, 1, {
        error: e?.name || "error",
        detail: e?.message || String(e),
      });

      sendDiag({
        diag_id: "@diag_id;noquote@",
        event: "test",
        mode: authMode,
        result: "error",
        when: new Date().toISOString(),
        err: { name: e?.name || "error", detail: e?.message || String(e) }
      });
    }
  }

  // Wire buttons
  document.getElementById("testPasskeyBtn").addEventListener("click", () => {
    runGet(document.getElementById("outPasskey"), "passkey", "");
  });

  document.getElementById("testIdentBtn").addEventListener("click", () => {
    const ident = (document.getElementById("identInput").value || "").trim();
    runGet(document.getElementById("outIdent"), "identifier", ident);
  });

  // Copy report
  document.getElementById("copyBtn").addEventListener("click", async () => {
    const reportObj = {
      when: new Date().toISOString(),
      url: location.href,
      secureContext: cap.secureContext,
      hasPublicKeyCredential: cap.hasPublicKeyCredential,
      hasNavigatorCredentials: cap.hasNavigatorCredentials,
      uvpaa: cap.uvpaa,
      conditionalMediation: cap.cma,
      userAgent: cap.uap,
      uaCHPlatform: cap.uachPlatform,
      keyRegistered: kreg,
      keyUsed: kuse,
    };
    const text = JSON.stringify(reportObj, null, 2);
    try {
      await navigator.clipboard.writeText(text);
      document.getElementById("copyOut").style.display = "";
      document.getElementById("copyOut").textContent = "Copied report to clipboard.";
    } catch (e) {
      document.getElementById("copyOut").style.display = "";
      document.getElementById("copyOut").textContent = "Clipboard write failed. Here is the report:\n\n" + text;
    }
  });

  // init
  probeAsyncCaps().then(() => {
    renderCaps();
  });

})();
</script>
