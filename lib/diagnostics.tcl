# SPDX-License-Identifier: MPL-2.0

ad_page_contract {
    WebAuthn / Passkey diagnostics page.
} {
    {return_url "/"}
}

set page_title "WebAuthn / Passkey diagnostics"
set context [list $page_title]


set diag_id [::xo::oauth::nonce]
set ip      [ns_conn peeraddr]
set ua      [ns_set get [ns_conn headers] User-Agent]
set host    [ns_set get [ns_conn headers] host]
set proto   [ns_conn proto]

ns_log notice "WEBAUTHN-DIAG GET diag_id=$diag_id ip=$ip proto=$proto host={$host} ua={$ua}"

