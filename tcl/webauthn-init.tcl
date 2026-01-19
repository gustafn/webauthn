# SPDX-License-Identifier: MPL-2.0

if {[info commands ::ns_cbor] eq ""} {
    ns_log warning "webauthn: package is enabled, but NaviServer needs to be upgraded to include required crypto support."
} else {
    set rpid [parameter::get_from_package_key \
                  -package_key webauthn \
                  -parameter RpID \
                  -default [ns_info server]]
    set rpid [string tolower $rpid]

    if {![::webauthn::validRpIdP $rpid]} {
        if {[parameter::get_from_package_key -package_key webauthn -parameter RpID] eq ""} {
            switch -glob -- $rpid {
                openacs* -
                oacs* {
                    ns_log warning "webauthn: RpID not configured; derived '$rpid' (from ns_info server) is invalid. " \
                        "Falling back to 'localhost' for development. Configure parameter webauthn::RpID for production."                
                    set rpid localhost
                }
                default {
                    error "webauthn: derived rpID '$rpid' is not a valid rpID"
                }
            }
        } else {
            error "webauthn: provided rpID '$rpid' is not a valid rpID"
        }
    }

    ns_log notice webauthn: configuring WebAuthn passkey (server '[ns_info server]') with Relying Party ID (rpID): '$rpid'

    ::webauthn::WebAuthn create webauthn::passkey \
        -rp_id $rpid \
        -debug
    
}
