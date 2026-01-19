# SPDX-License-Identifier: MPL-2.0

ad_include_contract {
    Passkey login button

    @author Gustaf Neumann
} {
    return_url:localurl   
}

set passkey(devForcePasskeyFail) 0
#set passkey(devForcePasskeyFail) 1
set passkey(auth_mode)  "auto"
# dev override (TODO: remove me, this is just for testing)
#set passkey(auth_mode) "identifier"

set passkey(label)      "Sign in with passkey"
set passkey(title)      "Sign in with a pre-registered passkey instead of a password"
set passkey(hint_ident) ""
set passkey(mode)       "generic"

set untrusted_user_id   [ad_conn untrusted_user_id]
if {$untrusted_user_id != 0} {
    acs_user::get -user_id $untrusted_user_id -array u
    if {[auth::UseEmailForLoginP]} {
        set passkey(hint_ident) $u(email)
    } else {
        set passkey(hint_ident) $u(username)
    }
    set passkey(mode) "hinted"
}
# use mtime as version id
set js_v [file mtime $::acs::rootdir/packages/webauthn/www/resources/passkey-login.js]

