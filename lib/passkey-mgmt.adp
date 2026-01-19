<!--
  Passkey UI fragment for passkey management

  SPDX-License-Identifier: MPL-2.0
-->

      <div class="portlet-wrapper">
          <div class="portlet-header">
            <div class="portlet-title">
              <h1>#webauthn.passkey_mgmt_heading#</h1>
            </div>
          </div>

          <div class="portlet webauthn-register"  data-return-url="@return_url;noquote@">
            <if @webauthn_registered;literal@ true>
              <p style="margin-bottom: 0.5em;">
                #webauthn.passkey_mgmt_registered#
              </p>

              <table class="table table-striped">
                <thead>
                  <tr>
                    <th>Created at</th>
                    <th></th>
                    <th>Last used</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody class="align-middle">
                  <multiple name="passkeys">
                    <tr>
                      <td>@passkeys.label@</td>
                      <td>@passkeys.created_at_pretty@</td>
                      <td>@passkeys.last_used_at_pretty@</td>
                      <td style="text-align:right;">
                        <form method="post" action="/webauthn/reg/delete">
                          <input type="hidden" name="credential_id" value="@passkeys.credential_id@">
                          <input type="hidden" name="return_url" value="@return_url@">
                          <button type="submit" class="btn webauthn-delete-btn">
                             <adp:icon name="trash" title="#webauthn.passkey_delete_title#">
                           </button>
                        </form>
                      </td>
                    </tr>
                  </multiple>
                </tbody>
              </table>

              <p>
                <adp:button class="btn btn-default webauthn-register-btn"
                    title="#webauthn.passkey_reg_additional_title#"
                    aria-label="#webauthn.passkey_reg_additional_title#">
                  #webauthn.passkey_reg_additional_label#
                </adp:button>&puncsp;
                <adp:button class="btn btn-default webauthn-diag-btn"
                        title="#webauthn.diagnose_btn_title#"
                        aria-label="#webauthn.diagnose_btn_title#"
                        data-diag-url="/webauthn/diagnostics">
                  #webauthn.diagnose_btn_label#
                </adp:button>
              </p>
            </if>
            <else>
              <p">#webauthn.passkey_mgmt_text#</p>
              <p>
                <adp:button class="btn btn-default webauthn-register-btn"
                    title="#webauthn.passkey_reg_first_title#"
                    aria-label="#webauthn.passkey_reg_first_title#">
                  #webauthn.passkey_reg_first_label#
                </adp:button>&puncsp;
                <adp:button class="btn btn-default webauthn-diag-btn"
                        title="#webauthn.diagnose_btn_title#"
                        aria-label="#webauthn.diagnose_btn_title#"
                        data-diag-url="/webauthn/diagnostics">
                  #webauthn.diagnose_btn_label#
                </button>
              </p>
            </else>
            <div style="white-space: pre-wrap;" class="webauthn-register-out"></div>
            
            <script nonce="@::__csp_nonce@">
              window.webauthnRegisterConfig = {
                return_url: "@return_url;noquote@"
              };
              (function () {
                const btn = document.querySelector(".webauthn-diag-btn");
                if (!btn) return;
                btn.addEventListener("click", function () {
                  const url = btn.dataset.diagUrl || "/webauthn/diagnostics";
                  window.location.assign(url);
                });
              })();
            </script>
            <script nonce="@::__csp_nonce@" src="/resources/webauthn/passkey-register.js"></script>
          </div>
        </div>

