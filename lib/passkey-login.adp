<!--
  Passkey UI fragment for login button via passkey

  SPDX-License-Identifier: MPL-2.0
-->

<div class="webauthn-login"
     data-mode="@passkey.mode@"          
     data-auth-mode="@passkey.auth_mode@"
     data-label="@passkey.label@"
     data-identifier="@passkey.hint_ident@"
     data-dev-force-passkey-fail="@passkey.devForcePasskeyFail@"
     data-return-url="@return_url;noquote@">

  <adp:button class="btn btn-default webauthn-login-btn"
      title="#webauthn.login_btn_title#" aria-label="#webauthn.login_btn_title#">
      @passkey.label@
  </adp:button>

  <div class="webauthn-login-out" style="color:red; white-space: pre-wrap;"></div>
</div>
<script nonce="@::__csp_nonce@" src="/resources/webauthn/passkey-login.js?v=@js_v;literal@"></script>  
