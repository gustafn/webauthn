# SPDX-License-Identifier: MPL-2.0

ad_include_contract {
    Passkey management

    @author Gustaf Neumann
} {
    user_id:object_type(user)
    return_url:localurl
}

#
# When webauthn is enabled, we have as well xooauth and xotcl-core
# installed.
#
ns_log notice DEBUG passkey-migmt for user_id $user_id
    
# List credentials for this user
db_multirow -extend {created_at_pretty last_used_at_pretty} passkeys get_passkeys {
    select credential_id,
    label,
    created_at,
    last_used_at
    from webauthn_credentials
    where user_id = :user_id
    order by created_at desc
} {
    ns_log notice DEBUG found entry with label $label credential_id $credential_id
    set passkey(diag_title) "If passkey sign-in does not work: run diagnostics and send the report!"
    set created_at_pretty   [lc_time_fmt $created_at "%Y-%m-%d %H:%M"]
    set last_used_at_pretty [expr {$last_used_at eq ""
                                   ? "-"
                                   : [lc_time_fmt $last_used_at "%Y-%m-%d %H:%M"]}]
}

set webauthn_registered [expr {[template::multirow size passkeys] > 0}]
