# SPDX-License-Identifier: MPL-2.0

#----------------------------------------------------------------------
# GET /webauthn/reg/options
#----------------------------------------------------------------------

ns_register_proc GET /webauthn/reg/options {

    set auth_obj [webauthn::json_contract {
        Provide WebAuthn registration options for adding a new passkey.

        Returns PublicKeyCredentialCreationOptions for
        navigator.credentials.create() for the currently logged-in user.
        A short-lived server-side registration state is created and keyed
        by a nonce ("state") to be used by the subsequent verification step.

        @param return_url Local URL to redirect to after successful registration
                          (default: /pvt/).
        @param exclude    If true, include excludeCredentials to prevent
                          re-registering existing credentials (default: 0).
    } {
        {return_url:localurl "/pvt/"}
        {exclude:boolean 0}
    }]

    auth::require_login

    set state      [::xo::oauth::nonce]
    set rpId       [$auth_obj cget -rp_id]
    set origin     [$auth_obj origin]

    set user_id  [ad_conn user_id]
    set username [party::email -party_id $user_id]
    if {$username eq ""} { set username "user-$user_id" }

    set key       "webauthn:reg:$state"
    set challenge [$auth_obj new_challenge 32]

    ns_log notice DEBUG reg/options registers rpId $rpId origin $origin

    [$auth_obj store] set $key [dict create \
                                    challenge  $challenge \
                                    rpId       $rpId \
                                    origin     $origin \
                                    return_url $return_url \
                                    user_id    $user_id \
                                    ts         [ns_time] \
                                   ]
    #
    # Optional sanity checks for “known-safe” values (cheap insurance)
    #
    #nsf::is integer  $user_id
    #nsf::is wordchar $rpId
    #nsf::is wordchar $challenge
    #nsf::is wordchar $state
    #if {![regexp {^[A-Za-z0-9_-]+=*$} $challenge]} {
    #    # accept base64url/base64-ish (your current challenge seems safe ASCII)
    #    error "challenge contains unexpected characters"
    #}

    #
    # Escape user-controlled strings
    #
    set j_username [webauthn::JQ $username]

    #
    # excludeCredentials JSON array items
    #
    set exclude_json_items {}
    if {$exclude} {
        ::xo::dc foreach get_creds {
            select credential_id
            from webauthn_credentials
            where user_id = :user_id and rp_id = :rpId
        } {
            # credential_id is base64url (still escape defensively)
            #nsf::is wordchar $credential_id
            lappend exclude_json_items [subst {{"type":"public-key","id":"$credential_id"}}]
        }
    }
    set exclude_json "\[[join $exclude_json_items ,]\]"

    #
    # Build JSON response (template)
    #
    set json [subst -nocommands [ns_trim -delimiter | {{
        | "state":"$state",
        | "publicKey":{
            |    "rp":{"id":"$rpId","name":"$rpId"},
            |    "user":{"id":"$user_id","name":"$j_username","displayName":"$j_username"},
            |    "challenge":"$challenge",
            |    "pubKeyCredParams":[{"type":"public-key","alg":-7}],
            |    "timeout":60000,
            |    "attestation":"none",
            |    "authenticatorSelection":{"residentKey":"preferred","userVerification":"preferred"},
            |    "excludeCredentials":$exclude_json
            |  }
        | }
    }]]
    ns_log notice DEBUG reg/options JSON=$json
    ns_log notice DEBUG stored-dict=[dict create \
                                                challenge  $challenge \
                                                rpId       $rpId \
                                                origin     $origin \
                                                return_url $return_url \
                                                user_id    $user_id \
                                                ts         [ns_time] \
                                               ]

    ns_return 200 application/json $json
}


#----------------------------------------------------------------------
# GET /webauthn/reg/verify
#----------------------------------------------------------------------

ns_register_proc POST /webauthn/reg/verify {
    set auth_obj [webauthn::json_contract {
        Verify a WebAuthn registration response and persist the new credential.

        This endpoint completes passkey registration for the currently logged-in user.
        It consumes the pending registration state referenced by "state"
        (created by /webauthn/reg/options). If the state is missing or expired, verification fails.

        @param state Opaque registration state/nonce returned by /webauthn/reg/options.
    } {
        state:token,notnull
    }]

    auth::require_login

    set rpId  [$auth_obj cget -rp_id]
    set key   "webauthn:reg:$state"
    ns_log notice "DEBUG KEYS LOOKUP: $key (/webauthn/reg/verify)"

    if {[catch { set st [[$auth_obj store] get $key] }]} {
        return [$auth_obj return_err "expired-registration" "no pending registration (expired?)"]
    }

    set body [ns_conn content]
    if {[catch { set req [util::json2dict $body] } err]} {
        return [$auth_obj return_err "invalid-json" "$err"]
    }

    try {
        set r [$auth_obj reg attestation_verify -st $st -req $req]

        ns_log notice "DEBUG reg attestation_verify receives st {$st} req {$req}"

        set credential_id [dict get $r credential_id]
        set user_id       [dict get $r user_id]
        set public_key    [dict get $r public_key]
        set sign_count    [dict get $r sign_count]
        set return_url    [dict get $r return_url]
        set origin        [dict get $r origin]
        set user_agent    [ns_set get [ns_conn headers] user-agent]

        switch -glob -- $user_agent {
            *iPhone*    { set platform "iPhone" }
            *iPad*      { set platform "iPad" }
            *Android*   { set platform "Android" }
            *Macintosh* { set platform "Mac" }
            *Windows*   { set platform "Windows" }
            *Linux*     { set platform "Linux" }
            default     { set platform "Browser" }
        }
        switch -glob -- $user_agent {
            *EdgiOS/*  -
            *Edg/*     { set browser Edge }
            *OPR/*     -
            *OPiOS/*   -
            *Opera*    { set browser Opera }
            *FxiOS/*   -
            *Firefox/* { set browser Firefox }
            *CriOS/*   -
            *Chrome/*  -
            *Chromium* { set browser Chrome }
            *Safari/*  { set browser Safari }
            default    { set browser Browser }
        }
        set label "$platform · $browser"

        ::xo::dc dml delete_old_credentials {
            delete from webauthn_credentials
            where user_id = :user_id
            and rp_id   = :rpId
            and label   = :label
        }
        ::xo::dc dml insert_credentials {
            insert into webauthn_credentials (credential_id, user_id,
                                              rp_id, origin,
                                              public_key, sign_count,
                                              user_agent, label)
            values (:credential_id, :user_id,
                    :rpId, :origin,
                    :public_key, :sign_count,
                    :user_agent, :label)
        }

        [$auth_obj store] unset $key
        ns_return 200 application/json [subst -nocommands {{"ok":true,"return_url":"$return_url"}}]

    } trap validation {errorMsg dict} {
        set errorCode [lindex [dict get $dict -errorcode] 1]
        return [$auth_obj return_err $errorCode $errorMsg]

    } on error {errorMsg} {
        ns_log error "webauthn reg verify internal error: $errorMsg"
        return [$auth_obj return_err -status 500 "internal_error" "Internal Error"]
        return
    }

}

#----------------------------------------------------------------------
# GET /webauthn/reg/delete
#----------------------------------------------------------------------

ns_register_proc POST /webauthn/reg/delete {

    webauthn::json_contract {
        Delete a registered WebAuthn credential (passkey) of the
        currently logged-in user.

        The credential is deleted only if it belongs to the current user.
        Requests for unknown or foreign credentials are handled silently
        and result in no change.

        @param credential_id Opaque credential identifier to delete.
        @param return_url    Local URL to redirect to after completion (default: /pvt/).
    } {
        credential_id:token,notnull
        {return_url:localurl "/pvt/"}
    }

    auth::require_login
    set user_id [ad_conn user_id]

    # Ensure the credential belongs to this user (and delete)
    set deleted_p 0
    db_transaction {
        set owner_p [db_string cred_owner_check {
            select 1
            from webauthn_credentials
            where user_id = :user_id
            and credential_id = :credential_id
        } -default 0]

        if {$owner_p} {
            db_dml delete_cred {
                delete from webauthn_credentials
                where user_id = :user_id
                and credential_id = :credential_id
            }
            set deleted_p 1
        }
    }
    ns_log notice /webauthn/reg/delete credential_id $credential_id deleted_p $deleted_p
    if {$deleted_p} {
        ad_returnredirect  -message "Passkey deleted." $return_url
    } else {
        # Credential not found / not owned by user
        # Keep it quiet and just go back.
        ad_returnredirect $return_url
    }
}

#----------------------------------------------------------------------
# GET /webauthn/auth/options
#----------------------------------------------------------------------

ns_register_proc GET /webauthn/auth/options {

    set auth_obj [webauthn::json_contract {
        Provide WebAuthn assertion options for passkey sign-in.

        Returns PublicKeyCredentialRequestOptions for
        navigator.credentials.get().

        auth_mode behavior:
        - auto: identifier → identifier mode, otherwise passkey mode
        - passkey: discovery / account chooser (no allowCredentials)
        - identifier: restrict options to credentials of resolved account

        @param return_url Local URL to redirect to after successful login.
        @param identifier Email or username used in identifier-based login.
        @param auth_mode  One of auto|passkey|identifier (default: auto).
    } {
        {return_url:localurl "/"}
        {identifier:trim ""}
        {auth_mode:oneof(auto|passkey|identifier) "auto"}
    }]

    ns_log notice "DEBUG /webauthn/auth/options" return_url $return_url identifier $identifier auth_mode $auth_mode
    set state     [::xo::oauth::nonce]
    set rpId      [$auth_obj cget -rp_id]
    set origin    [$auth_obj origin]

    set challenge [$auth_obj new_challenge 32]

    #
    # Optional sanity checks for “known-safe” values (cheap insurance)
    #
    nsf::is graph $rpId
    nsf::is wordchar $challenge
    nsf::is wordchar $state

    # Store ceremony state (will include intended identity if known)
    set key "webauthn:auth:$state"
    set st [dict create \
                challenge   $challenge \
                rpId        $rpId \
                origin      $origin \
                return_url  $return_url \
                ts          [ns_time] \
               ]

    set user_id ""
    set allow_credentials {}

    if {$auth_mode eq "identifier"} {

        if {$identifier eq ""} {
            return [$auth_obj return_err "missing-identifier" "Please enter your email/username first."]
        }

        if {[auth::UseEmailForLoginP]} {
            set user_id [party::get_by_email -email $identifier]
        } else {
            set user_id [acs_user::get_by_username -username $identifier]
        }

        if {$user_id eq ""} {
            return [$auth_obj return_err -status 404 "unknown-user" "No such user."]
        }

        dict set st identifier $identifier
        dict set st user_id $user_id

        # Collect credentials for this user and rpId
        ::xo::dc foreach get_creds {
            select credential_id
            from webauthn_credentials
            where user_id = :user_id
            and rp_id   = :rpId
        } {
            lappend allow_credentials \
                [subst -nocommands {{"type":"public-key","id":"$credential_id"}}]
        }
        if {[llength $allow_credentials] == 0} {
            return [$auth_obj return_err -status 404 "no-passkey" "No passkey registered for this account."]
        }
        ns_log notice "DEBUG identifier-first resolved" identifier $identifier user_id $user_id ncreds [llength $allow_credentials]
    }
    [$auth_obj store] set $key $st

    ns_log notice "DEBUG allow_credentials" $allow_credentials

    set allow_json ""
    if {[llength $allow_credentials] > 0} {
        set allow_json ,\"allowCredentials\":\[[join $allow_credentials ,]\]
    }
    set json [subst -nocommands [ns_trim -delimiter | {{
        | "state":"$state",
        | "publicKey":{
            |    "challenge":"$challenge",
            |    "timeout":60000,
            |    "rpId":"$rpId",
            |    "userVerification":"preferred"$allow_json
            | }
    }}]]

    ns_log notice /webauthn/auth/options returns $json
    ns_return 200 application/json $json
}

#----------------------------------------------------------------------
# GET /webauthn/auth/verify
#----------------------------------------------------------------------

ns_register_proc POST /webauthn/auth/verify {

    set auth_obj [webauthn::json_contract {
        Verify a WebAuthn assertion response and complete passkey login.

        This endpoint completes authentication using the pending state referenced
        by "state" (created by /webauthn/auth/options). If the state is missing or
        expired, verification fails.

        @param state Opaque authentication state/nonce returned by /webauthn/auth/options.
    } {
        state:token,notnull
    }]

    set key "webauthn:auth:$state"
    try {
        set st [[$auth_obj store] get $key]
    } on error {errorMsg} {
        return [$auth_obj return_err "no pending authentication (expired?)" ""]
    }

    #
    # Process body of the POST request
    #
    set body [ns_getcontent -as_file false]
    if {$body eq ""} {
        return [$auth_obj return_err "empty request body" ""]
    }

    try {
        set req [util::json2dict $body]
    } on error {errorMsg} {
        ns_log notice "JSON parse error: $errorMsg; body='$body'"
        return [$auth_obj return_err "invalid json" $errorMsg]
    }

    #
    # heck assertions and validity of the signature
    #
    try {
        ns_log notice "DEBUG reg auth/verify st {$st} req {$req}"
        $auth_obj auth assertion_verify -st $st -req $req
    } trap validation {errorMsg dict} {
        set errorCode [lindex [dict get $dict -errorcode] 1]
        return [$auth_obj return_err $errorCode $errorMsg]
    } on error {errorMsg} {
        ns_log error "webauthn verify internal error: $errorMsg"
        return [$auth_obj return_err -status 500 "internal_error" "Internal Error"]
    } on ok {user_id} {
    }

    ns_log notice "webauthn: can login with user_id $user_id"
    ad_user_login -external_registry $auth_obj $user_id

    set return_url [dict get $st return_url]

    # consume the ceremony state
    [$auth_obj store] unset $key


    ns_return 200 application/json [subst {{"ok":true, "return_url":"$return_url"}}]
}

#----------------------------------------------------------------------
# GET /webauthn/reg
#----------------------------------------------------------------------
#ns_register_proc GET /webauthn/reg {
#    set html [ad_parse_template \
#                  [template::themed_template "/packages/webauthn/lib/passkey-register"]]
#    ns_return 200 text/html [ns_adp_parse $html]
#}

#----------------------------------------------------------------------
# GET /webauthn/login
#----------------------------------------------------------------------
#ns_register_proc GET /webauthn/login {
#    set html [ad_parse_template \
#                  [template::themed_template "/packages/webauthn/lib/login-handler"]]
#    ns_return 200 text/html [ns_adp_parse $html]
#}


#----------------------------------------------------------------------
# GET /webauthn/diagnostics
#----------------------------------------------------------------------
ns_register_proc GET /webauthn/diagnostics {
    set html [ad_parse_template \
                  [template::themed_template "/packages/webauthn/lib/diagnostics"]]
    ns_return 200 text/html [ns_adp_parse $html]
}


#----------------------------------------------------------------------
# GET /webauthn/auth/verify
#----------------------------------------------------------------------
#
# POST: receive client-side report and log it
#
ns_register_proc POST /webauthn/diagnostics {

    set auth_obj [webauthn::json_contract {
        Receive a client-side diagnostics payload for troubleshooting WebAuthn.

        The request body must be a JSON object. The payload is logged (single-line)
        under WEBAUTHN-DIAG together with basic request metadata (ip/host/ref/ua).
        This endpoint is intended for short-term debugging aid, not telemetry.

        The optional diag_id is a client-generated identifier included in the JSON
        payload and extracted for easier log correlation.
    } {}]

    # Read body (expect JSON)
    set body [ns_conn content]
    if {$body eq ""} {
        return [$auth_obj return_err "missing-body" "Empty request body."]
    }

    # Prevent log spam (adjust as desired)
    if {[string length $body] > 8192} {
        return [$auth_obj return_err -status 413 "too-large" "Diagnostics payload too large."]
    }

    # Basic JSON sanity check:
    # - We do not strictly need to parse, but we ensure it "looks like" JSON object
    set trimmed [string trim $body]
    if {![string match {\{*} $trimmed] || ![string match {*\}} $trimmed]} {
        return [$auth_obj return_err "bad-json" "Expected a JSON object."]
    }

    # Make it single-line for easier grepping
    regsub -all {[\r\n\t]+} $trimmed { } oneline

    set ip   [ns_conn peeraddr]
    set ua   [ns_set get [ns_conn headers] User-Agent]
    set host [ns_set get [ns_conn headers] host]
    set ref  [ns_set iget [ns_conn headers] referer]  ;# OpenACS uses iget, but sets are CI in NS5 anyway

    set diag_id ""
    if {[regexp {\"diag_id\"\s*:\s*\"([A-Za-z0-9]+)\"} $oneline _ diag_id]} {
        # ok
    }
    ns_log notice "WEBAUTHN-DIAG POST diag_id=$diag_id ip=$ip host={$host} ref={$ref} ua={$ua} payload={$oneline}"

    ns_return 204 text/plain ""
}
