# SPDX-License-Identifier: MPL-2.0

::xo::library doc {
    Support for WebAuthn/FIDO2
}

# we need at least rest-procs, maybe  authorize-procs
::xo::library require -package xooauth rest-procs

#
# Make sure, we have the data model defined
#
#  credential_id: base64url
#  public_key:    whatever used verifier stores (COSE/JWK/PEM)

::xo::db::require table webauthn_credentials [subst {
    credential_id {varchar(512) primary key}
    user_id       {integer not null references users(user_id) on delete cascade}
    rp_id         {[::xo::dc map_datatype text] not null}
    origin        {[::xo::dc map_datatype text] not null}
    public_key    {[::xo::dc map_datatype text] not null}
    sign_count    {bigint not null default 0}
    created_at    {timestamptz not null default now()}
    last_used_at  {timestamptz}
    label         {[::xo::dc map_datatype text] not null}
    user_agent    {[::xo::dc map_datatype text] not null}
}]
::xo::db::require index -table webauthn_credentials -col credential_id -unique true

namespace eval webauthn {
    nx::Class create ::webauthn::WebAuthn -superclasses ::xo::REST {
        #
        #  rp_id:   The WebAuthn Relying Party ID (domain), e.g. 'openacs.org'
        #           or 'login.example.com'; Must be a registrable domain /
        #           host that matches the site origin rules.
        #
        #  after_successful_login_url: Where to redirect after login if no
        #           return_url exists in state.
        #
        #  login_failure_url: Where to send users on failure if you don’t
        #           want to show debug output.
        #

        :property {rp_id:required}
        :property {after_successful_login_url /pvt/}
        :property {login_failure_url /}

        :property {pretty_name "Passkey"}
        :property {debug:switch false}
        :property {storageObj ::xo::WebAuthnStore::Cache}

        :method init {} {
            set :store ${:storageObj}
        }

        :public method return_err {{-status 400} error detail} {
            #
            # Return a JSON error response on the current connection.
            #
            # @param status HTTP status code to use for the response (default: 400).
            # @param error   Short, stable error code (machine-readable).
            # @param detail  Human-readable error message suitable for display/logging.
            #
            ns_return $status application/json \
                [ns_json value -type object [list \
                                                 error string $error \
                                                 detail string $detail]]
        }

        :public method logout {} {
            #
            # Compatibility function with other external_registry objects
            #

            # The following command leads to an infinite loop.
            #
            #ad_user_logout

            # TODO: for now, this is a NOOP
            ns_log warning "[current] logout was called, but is not implemented"
        }

        :public method login_url {{-return_url /}} {
            #
            # Compatibility function with other external_registry objects
            #
            return [export_vars -base /register {return_url}]
        }


        :public method name {} {
            #
            # compatibility with xo::Authorize
            #
            return [expr {[info exists :pretty_name] ? ${:pretty_name} : [namespace tail [self]]}]
        }

        :public method origin {} {
            # Returns the "origin" field provided to the attestation.

            # In general, "ns_conn location" would be the right
            # thing. However, inside a container, it reports the
            # internal port.
            set proto [expr {[ad_conn behind_secure_proxy_p] ? "https" : [ns_conn proto]}]

            # Case-insensitive headers in NaviServer 5; ns_parsehostport validates.
            set hp [ns_parsehostport [ns_set get [ns_conn headers] Host]]

            set origin "${proto}://[dict get $hp host]"

            if {[dict exists $hp port]} {
                set port [dict get $hp port]
                if {($proto eq "http"  && $port != 80)
                    || ($proto eq "https" && $port != 443)} {
                    append origin ":$port"
                }
            }
            return $origin
        }

        :public method new_challenge {{nbytes 32}} {
            #
            # Generate a new cryptographically strong random challenge.
            #
            # The challenge is generated using ns_crypto::randombytes and
            # returned as a base64url-encoded string suitable for use in
            # WebAuthn request/creation options.
            #
            # @param nbytes Number of random bytes to generate before encoding
            #               (default: 32).
            #
            return [ns_crypto::randombytes -encoding base64url $nbytes]
        }

        :method state_key {purpose state} {
            return "webauthn:${purpose}:${state}"
        }

        :public method store {} {
            #
            # Return the backing store used for pending WebAuthn state.
            #
            return ${:store}
        }

        :method assert_rpidhash {-rpIdHash -rpId {-context ""}} {
            set got_hex [binary encode hex $rpIdHash]
            set exp_hex [ns_crypto::md string -digest sha256 -encoding hex $rpId]

            if {$got_hex ne $exp_hex} {
                if {$context ne ""} {
                    throw {validation rpid-mismatch} \
                        "$context for different rpid. Should be for: $rpId"
                } else {
                    throw {validation rpid-mismatch} "rpIdHash mismatch"
                }
            }
        }

        :method assert_clientdata_json {-clientData_raw -expected_type -expected_challenge -expected_origin} {
            #
            # clientDataJSON is bytes (as received). We decode and validate:
            #  - type
            #  - challenge
            #  - origin
            #
            set clientData_json [ns_base64urldecode -- $clientData_raw]
            if {$clientData_json eq ""} {
                throw {validation missing-clientdata} "invalid clientDataJSON"
            }
            set cd [ns_json parse $clientData_json]

            if {![dict exists $cd type]} {
                throw {validation bad-clientdata-json} "clientDataJSON missing 'type'"
            }
            if {![dict exists $cd challenge]} {
                throw {validation bad-clientdata-json} "clientDataJSON missing 'challenge'"
            }
            if {![dict exists $cd origin]} {
                throw {validation bad-clientdata-json} "clientDataJSON missing 'origin'"
            }

            set type      [dict get $cd type]
            set challenge [dict get $cd challenge]
            set origin    [dict get $cd origin]

            if {$type ne $expected_type} {
                throw {validation wrong-type} "unexpected clientDataJSON type '$type' (expected '$expected_type')"
            }
            if {$challenge ne $expected_challenge} {
                throw {validation challenge-mismatch} "challenge mismatch"
            }
            if {$origin ne $expected_origin} {
                throw {validation origin-mismatch} "origin mismatch (expected $expected_origin received $origin)"
            }

            return $clientData_json
        }

        :public method "reg attestation_verify" {-st -req} {
            #
            # Verify a WebAuthn registration response (attestation) against stored state.
            #
            # This method validates the incoming credential creation response from
            # navigator.credentials.create() for the current registration ceremony.
            # It checks required fields, verifies the clientDataJSON (type, challenge,
            # origin), decodes and parses the attestationObject (CBOR), and extracts
            # credential data (credential ID and public key) for subsequent storage.
            #
            # @param st  Registration state dict as created by /webauthn/reg/options
            #            (challenge, origin, return_url, user_id, ...).
            # @param req Parsed client response dict containing "response" fields,
            #            including clientDataJSON and attestationObject.

            set return_url        [dict get $st return_url]
            set user_id           [dict get $st user_id]

            if {![dict exists $req response clientDataJSON]
                || ![dict exists $req response attestationObject]} {
                throw {validation fields-missing} "missing required fields"
            }

            # ---- clientDataJSON
            :assert_clientdata_json \
                -clientData_raw      [dict get $req response clientDataJSON] \
                -expected_type       "webauthn.create" \
                -expected_challenge  [dict get $st challenge] \
                -expected_origin     [dict get $st origin]

            # ---- attestationObject (CBOR) -> authData -> credId + COSE_Key
            set attObj_b64u [dict get $req response attestationObject]
            set attObj_bin [ns_base64urldecode -binary -- $attObj_b64u]

            try {
                set ao [ns_cbor parse -binary -encoding binary $attObj_bin]
            } on error {e} {
                throw {validation attobj-cbor} "bad attestationObject CBOR: $e"
            }

            if {![dict exists $ao fmt] || ![dict exists $ao authData]} {
                throw {validation attobj-invalid} "attestationObject missing fmt/authData"
            }

            set fmt [dict get $ao fmt]
            if {$fmt ne "none"} {
                ns_log notice "registration attestation fmt=$fmt"
            }

            set authData [dict get $ao authData]
            if {[string length $authData] < 55} {
                throw {validation authdata-invalid} "authData too short"
            }

            set rpIdHash [string range $authData 0 31]
            :assert_rpidhash -rpIdHash $rpIdHash -rpId ${:rp_id} -context "attestation"

            binary scan [string range $authData 32 32] cu flags
            if {($flags & 0x40) == 0} {
                throw {validation attesteddata-missing} "no attested credential data"
            }

            binary scan [string range $authData 33 36] Iu signCount

            # fixed offsets from WebAuthn authData layout
            set aaguid [string range $authData 37 37+15]
            binary scan [string range $authData 53 53+1] S credIdLen

            if {$credIdLen <= 0 || (55+$credIdLen) > [string length $authData]} {
                throw {validation credidlen-invalid} "credentialId length out of range"
            }

            set credId  [string range $authData 55 54+$credIdLen]
            set coseKey [string range $authData 55+$credIdLen end]

            try {
                set cose [ns_cbor parse -binary -encoding binary $coseKey]
            } on error {e} {
                throw {validation cose-cbor} "bad COSE_Key CBOR: $e"
            }
            ns_log notice "DEBUG reg attestation_verify: COSE key parsed: $cose"

            if {![dict exists $cose 1] || ![dict exists $cose 3]} {
                throw {validation key-invalid} "COSE key missing kty/alg"
            }
            set kty [dict get $cose 1]
            set alg [dict get $cose 3]

            switch -exact -- "${kty}/${alg}" {
                "1/-8" {
                    # OKP / EdDSA
                    if {![dict exists $cose -1] || ![dict exists $cose -2]} {
                        throw {validation key-invalid} "OKP COSE key missing curve/public key"
                    }

                    switch -- [dict get $cose -1] {
                        6 - 7 {
                            # Ed25519 / Ed448
                        }
                        4 - 5 {
                            throw {validation curve-unsupported} \
                                "OKP curve is for key agreement, not signatures"
                        }
                        default {
                            throw {validation curve-unsupported} \
                                "unsupported OKP curve \"[dict get $cose -1]\""
                        }
                    }
                }
                "2/-7" {
                    # EC2 / ES256
                    if {![dict exists $cose -1] || [dict get $cose -1] != 1} {
                        throw {validation curve-unsupported} "unsupported COSE crv (expected 1 P-256)"
                    }
                }
                "3/-257" {
                    # RSA / RS256
                    if {![dict exists $cose -1] || ![dict exists $cose -2]} {
                        throw {validation key-invalid} "RSA COSE key missing modulus/exponent"
                    }
                }
                default {
                    throw {validation alg-unsupported} \
                        "unsupported COSE key type / algorithm ($kty/$alg)"
                }
            }

            # Build DB values
            set credential_id [ns_base64urlencode -binary -- $credId]

            set public_key [dict create \
                                format cose \
                                fmt $fmt \
                                aaguid_b64u [ns_base64urlencode -binary -- $aaguid] \
                                kty [dict get $cose 1] \
                                alg [dict get $cose 3] \
                                cose_b64u [ns_base64urlencode -binary -- $coseKey] \
                                sign_count $signCount \
                                rp_id ${:rp_id}]

            if {[dict exists $cose -1]} {
                dict set public_key crv [dict get $cose -1]
            }

            return [dict create \
                        user_id $user_id \
                        return_url $return_url \
                        credential_id $credential_id \
                        public_key $public_key \
                        origin [dict get $st origin] \
                        sign_count $signCount]
        }

        :public method "auth issue_options" {{-return_url "/"}} {
            #
            # Issue WebAuthn assertion options for starting a passkey login ceremony.
            #
            # Generates a fresh state nonce and challenge, stores the pending
            # authentication ceremony state in the configured store (keyed by state),
            # and returns a dict containing:
            #  - state:   the nonce to be echoed back to /webauthn/auth/verify
            #  - options: PublicKeyCredentialRequestOptions for navigator.credentials.get()
            #
            # @param return_url Local URL to redirect to after successful login
            #                   (default: "/").
            #

            set state     [::xo::oauth::nonce]
            set challenge [:new_challenge 32]

            # Store ceremony state
            set key [:state_key auth $state]
            ${:store} set $key [dict create \
                                    challenge $challenge \
                                    rpId ${:rp_id} \
                                    return_url $return_url \
                                    origin [:origin] \
                                    ts [ns_time] \
                                   ]
            # Return dict the handler can serialize
            return [dict create \
                        state $state \
                        options [dict create \
                                     challenge $challenge \
                                     timeout 60000 \
                                     rpId ${:rp_id} \
                                     userVerification preferred \
                                    ] \
                       ]
        }

        :method cose_public_key_pem {-cose} {
            #
            # Convert a COSE_Key into a PEM-encoded public key.
            #
            # Supports the WebAuthn-relevant COSE key types:
            #
            #  - EC2 (kty=2): Elliptic Curve keys (e.g., ES256 / P-256)
            #  - RSA (kty=3): RSA keys (e.g., RS256)
            #  - OKP (kty=1): Octet Key Pair keys, including:
            #        * Ed25519 / Ed448 (signature)
            #        * X25519 / X448   (key agreement)
            #
            # Note: This method performs key *conversion only*. It does not enforce
            # algorithm or usage constraints. Callers (e.g., assertion verification)
            # must ensure that the selected key type and curve are appropriate for
            # the intended operation (e.g., signature vs. key agreement).
            #
            # @param cose Parsed COSE_Key dict.
            # @return PEM string of public key
            #

            if {![dict exists $cose 1]} {
                throw {validation key-invalid} "COSE key missing kty"
            }

            set kty [dict get $cose 1]

            switch -- $kty {
                1 {
                    #
                    # OKP
                    #
                    if {![dict exists $cose -1] || ![dict exists $cose -2]} {
                        throw {validation key-invalid} "OKP COSE key missing crv/x"
                    }

                    set crv [dict get $cose -1]
                    set crvMap {
                        6 Ed25519
                        7 Ed448
                        4 X25519
                        5 X448
                    }

                    if {![dict exists $crvMap $crv]} {
                        throw {validation curve-unsupported} \
                            "unsupported COSE OKP curve \"$crv\""
                    }

                    set name [dict get $crvMap $crv]
                    set x [dict get $cose -2]

                    return [ns_crypto::key import \
                                -name OKP \
                                -params [dict create crv $name x $x]]
                }
                2 {
                    #
                    # EC2
                    #
                    if {![dict exists $cose -1]} {
                        throw {validation key-invalid} "EC COSE key missing curve"
                    }
                    if {![dict exists $cose -2] || ![dict exists $cose -3]} {
                        throw {validation key-invalid} "EC COSE key missing x/y coordinates"
                    }

                    set crv [dict get $cose -1]
                    set curveMap {
                        1 prime256v1
                        2 secp384r1
                        3 secp521r1
                        8 secp256k1
                    }
                    if {![dict exists $curveMap $crv]} {
                        throw {validation curve-unsupported} \
                            "unsupported COSE EC curve \"$crv\""
                    }

                    set group [dict get $curveMap $crv]
                    set x [dict get $cose -2]
                    set y [dict get $cose -3]

                    return [ns_crypto::key import \
                                -name EC \
                                -params [dict create group $group x $x y $y]]
                }

                3 {
                    #
                    # RSA
                    #
                    if {![dict exists $cose -1] || ![dict exists $cose -2]} {
                        throw {validation key-invalid} \
                            "RSA COSE key missing modulus/exponent"
                    }

                    set n [dict get $cose -1]
                    set e [dict get $cose -2]

                    return [ns_crypto::key import \
                                -name RSA \
                                -params [dict create n $n e $e]]
                }

                default {
                    throw {validation keytype-unsupported} \
                        "unsupported COSE kty \"$kty\""
                }
            }
        }

        :method verify_es256_assertion {-cose -sig -signedData} {
            #
            # Verify a WebAuthn assertion signature for an ES256 credential.
            #
            # Expects an EC2 / P-256 COSE key and verifies the signature
            # over signedData using ECDSA with SHA-256.
            #
            # @param cose       Parsed COSE_Key dict.
            # @param sig        Signature returned by the authenticator.
            # @param signedData Binary signed data (authenticatorData || hash(clientDataJSON)).
            #

            if {![dict exists $cose 1] || [dict get $cose 1] != 2} {
                throw {validation keytype-unsupported} "unsupported COSE kty (expected 2 EC2)"
            }
            if {![dict exists $cose 3] || [dict get $cose 3] != -7} {
                throw {validation alg-unsupported} "unsupported COSE alg (expected -7 ES256)"
            }
            if {![dict exists $cose -1] || [dict get $cose -1] != 1} {
                throw {validation curve-unsupported} "unsupported COSE crv (expected 1 P-256)"
            }

            if {[string length $sig] == 64} {
                throw {validation signature-format} "unexpected raw 64-byte signature; expected DER"
            }

            set pubpem [:cose_public_key_pem -cose $cose]

            set ok [ns_crypto::md string \
                        -digest sha256 \
                        -binary \
                        -encoding binary \
                        -verify $pubpem \
                        -signature $sig \
                        -- $signedData]

            if {!$ok} {
                throw {validation signature-invalid} "signature verification failed"
            }
        }

        :method verify_rs256_assertion {-cose -sig -signedData} {
            #
            # Verify a WebAuthn assertion signature for an RS256 credential.
            #
            # The expected COSE key type is RSA (kty=3) with alg=-257
            # (RS256), carrying modulus and exponent parameters.
            #
            # @param cose       Parsed COSE_Key dict.
            # @param sig        Signature returned by the authenticator.
            # @param signedData Binary signed data (authenticatorData || hash(clientDataJSON)).
            #

            if {![dict exists $cose 1] || [dict get $cose 1] != 3} {
                throw {validation keytype-unsupported} "unsupported COSE kty (expected 3 RSA)"
            }
            if {![dict exists $cose 3] || [dict get $cose 3] != -257} {
                throw {validation alg-unsupported} "unsupported COSE alg (expected -257 RS256)"
            }

            set pubpem [:cose_public_key_pem -cose $cose]

            set ok [ns_crypto::md string \
                        -digest sha256 \
                        -binary \
                        -encoding binary \
                        -verify $pubpem \
                        -signature $sig \
                        -- $signedData]

            if {!$ok} {
                throw {validation signature-invalid} "signature verification failed"
            }
        }

        :public method verify_okp_signature_assertion {-cose -sig -signedData} {
            #
            # Verify a WebAuthn assertion signature for an OKP signature key.
            #
            # Expects an OKP COSE key (kty=1, alg=-8) using a signature-capable
            # OKP curve such as Ed25519 or Ed448. X25519 and X448 are valid
            # OKP agreement curves, but cannot verify WebAuthn assertions.
            #
            # @param cose       Parsed COSE_Key dict.
            # @param sig        Signature returned by the authenticator.
            # @param signedData Binary signed data.
            #

            if {![dict exists $cose 1] || [dict get $cose 1] != 1} {
                throw {validation keytype-unsupported} \
                    "unsupported COSE kty (expected 1 OKP)"
            }
            if {![dict exists $cose 3] || [dict get $cose 3] != -8} {
                throw {validation alg-unsupported} \
                    "unsupported COSE alg (expected -8 EdDSA)"
            }
            if {![dict exists $cose -1] || ![dict exists $cose -2]} {
                throw {validation key-invalid} \
                    "OKP COSE key missing curve/public key"
            }

            switch -- [dict get $cose -1] {
                6 - 7 {
                    # Ed25519 / Ed448
                }
                4 - 5 {
                    throw {validation curve-unsupported} \
                        "OKP curve is for key agreement, not signatures"
                }
                default {
                    throw {validation curve-unsupported} \
                        "unsupported OKP curve \"[dict get $cose -1]\""
                }
            }

            set pubpem [:cose_public_key_pem -cose $cose]

            set ok [ns_crypto::signature verify \
                        -binary \
                        -pem $pubpem \
                        -signature $sig \
                        -- $signedData]

            if {!$ok} {
                throw {validation signature-invalid} \
                    "signature verification failed"
            }
        }

        :public method "auth assertion_verify" {-st -req} {
            #
            # Verify a WebAuthn authentication response (assertion) against stored state.
            #
            # This method validates the incoming assertion from navigator.credentials.get().
            # It checks required fields, maps the presented credential ID to a stored
            # credential (user_id + public key), and verifies the assertion using the
            # pending authentication state (challenge, rpId, origin, etc.).
            #
            # If the credential is unknown, an error is raised. When the state contains
            # a user_id (identifier-first flow), the error message is phrased as
            # "no passkey for this account"; otherwise it is treated as an unknown
            # credential in discovery mode.
            #
            # @param st  Authentication state dict as created by /webauthn/auth/options
            #            or auth issue_options (challenge, rpId, origin, return_url, ...).
            # @param req Parsed client response dict containing the assertion fields,
            #            including id, clientDataJSON, authenticatorData, and signature.
            #

            set return_url        [dict get $st return_url]
            set expectedRpId      [dict get $st rpId]

            ns_log notice DEBUG: auth/assertion_verify st '$st' req '$req'
            if {![dict exists $req id]
                || ![dict exists $req response clientDataJSON]
                || ![dict exists $req response authenticatorData]
                || ![dict exists $req response signature]} {
                throw {validation fields-missing} "missing required fields"
            }

            # Map credential -> user
            set credential_id [dict get $req id]  ;# base64url in WebAuthn JSON

            if {![::xo::dc 0or1row get_cred {
                select user_id, public_key, sign_count as old_sign_count
                from webauthn_credentials
                where credential_id = :credential_id
            }]} {
                if {[dict exists $st user_id]} {
                    throw {validation no-passkey} "No passkey registered for this account (or it was removed)."
                }
                throw {validation credential-unknown} "unknown credential"
            }

            if {[dict exists $st user_id] && $user_id != [dict get $st user_id]} {
                ns_log notice "webauthn: mismatch" selected_user [dict get $st user_id] \
                    credential_user $user_id credential_id $credential_id
                throw {validation credential-user-mismatch} "Passkey does not match the selected account"

            }

            # ---- clientDataJSON
            set clientData_json \
                [:assert_clientdata_json \
                     -clientData_raw     [dict get $req response clientDataJSON] \
                     -expected_type      "webauthn.get" \
                     -expected_challenge [dict get $st challenge] \
                     -expected_origin    [dict get $st origin]]

            # ---- authenticatorData basic checks (rpIdHash, flags, signCount)
            set authData_b64u [dict get $req response authenticatorData]
            set sig_b64u      [dict get $req response signature]

            set authData [ns_base64urldecode -binary -- $authData_b64u]
            set sig      [ns_base64urldecode -binary -- $sig_b64u]

            if {[string length $authData] < 37} {
                throw {validation authenicator-invalid} "authenticatorData too short"
            }

            set rpIdHash [string range $authData 0 31]
            :assert_rpidhash -rpIdHash $rpIdHash -rpId $expectedRpId

            binary scan [string range $authData 32 32] cu flags
            if {($flags & 0x01) == 0} {
                throw {validation user-data-missing} "user not present"
            }

            binary scan [string range $authData 33 36] Iu new_sign_count

            # ---- signature verification
            # verify signature using stored COSE key in $public_key

            # clientData_json is the *decoded* JSON string of clientDataJSON
            # Hash must be over the exact bytes that were base64url-decoded.
            set clientHash [ns_crypto::md string -digest sha256 -binary -encoding binary -- $clientData_json]

            # signedData = authenticatorData || clientHash
            set signedData "${authData}${clientHash}"

            # public_key is a Tcl dict string (from DB)
            if {![dict exists $public_key cose_b64u]} {
                throw {validation key-invalid} "stored public key missing cose_b64u"
            }
            set coseKey_bin [ns_base64urldecode -binary -- [dict get $public_key cose_b64u]]
            set cose [ns_cbor parse -binary -encoding binary $coseKey_bin]

            ns_log notice "assertion_verify: COSE key parsed: $cose"

            if {![dict exists $cose 1] || ![dict exists $cose 3]} {
                throw {validation key-invalid} "COSE key missing kty/alg"
            }

            set kty [dict get $cose 1]
            set alg [dict get $cose 3]

            switch -exact -- "${kty}/${alg}" {
                "1/-8" {
                    :verify_okp_signature_assertion \
                        -cose $cose \
                        -sig $sig \
                        -signedData $signedData
                }
                "2/-7" {
                    :verify_es256_assertion \
                        -cose $cose \
                        -sig $sig \
                        -signedData $signedData
                }
                "3/-257" {
                    :verify_rs256_assertion \
                        -cose $cose \
                        -sig $sig \
                        -signedData $signedData
                }
                default {
                    throw {validation alg-unsupported} \
                        "unsupported COSE key type / algorithm ($kty/$alg)"
                }
            }


            ns_log notice DEBUG: update credential_id  $credential_id old_sign_count $old_sign_count new_sign_count $new_sign_count

            db_dml update_last_used {
                update webauthn_credentials
                set last_used_at = now(),
                sign_count       = :new_sign_count
                where credential_id = :credential_id
            }

            return $user_id
        }

        :method lookup_user_id {-credential_id} {
            set user_id [db_string _ {
                select user_id from webauthn_credentials
                where credential_id = :credential_id
            } -default 0]
            return $user_id
        }
    }


    ad_proc -public json_contract {docstring query_specs} {

        Helper for JSON endpoints with page-contract-like parameter validation.

        This procedure validates and normalizes request parameters according to
        'query_specs#, using OpenACS page-contract filters via
        'ad_page_contract_filter_invoke'.  Parsed values are exported into the
        caller’s scope (via 'uplevel') so the endpoint can use them as normal
        Tcl variables.

        On validation failure, this procedure does not generate HTML complaint
        output.  Instead, it returns a JSON error (HTTP 400) using
        [$auth_obj return_err], taking the first complaint message from
        'ad_complaints_get_list', and aborts the script via 'ad_script_abort'.

        @param docstring   Human-readable endpoint documentation (currently unused
                                                                  by this helper; included to mirror 'ad_page_contract'
                                                                  call style and for future diagnostics/logging).
        @param query_specs List of parameter specifications, like in
        'ad_page_contract'

        @return The configured WebAuthn auth object (currently '::webauthn::passkey')

    } {
        set auth_obj ::webauthn::passkey
        if {![nsf::is object $auth_obj]} {
            ns_return 500 application/json {{"error":"passkey auth object not configured"}}
            ad_script_abort
            return
        }
        if {[llength $query_specs] > 0} {
            #ns_log notice "DEBUG: specs <[string trim $query_specs]>"

            # "ns_getform" triggers auto-parsing, which sets also the
            # cached JSON value
            set formData [ns_getform]

            #ns_log notice "DEBUG: have JSON body [info exists ::_ns_json_body]"
            set provided [expr {[info exists ::_ns_json_body]
                                ? [ns_parsequery [ns_conn query]]
                                : $formData}]
            #ns_log notice "DEBUG: query <[ns_conn query]>"
            #ns_log notice "DEBUG: provided [ns_set format $provided]"

            foreach p $query_specs {
                #ns_log notice "DEBUG: processing query spec <$p>"
                unset -nocomplain default
                if {[llength $p] == 2} {
                    lassign $p spec default
                } else {
                    lassign $p spec
                }
                #ns_log notice "DEBUG: processing query spec <$p> info exists default [info exists default]"

                lassign [split $spec :] name filters
                #ns_log notice "DEBUG: ns_set find $provided $name -> [ns_set find $provided $name]"

                if {[ns_set find $provided $name] != -1} {
                    set value [ns_set get $provided $name]
                    foreach filter [split $filters ,] {
                        set r 1
                        if {$filter eq "trim"} {
                            set value [string trim $value]
                        } elseif {$filter eq "notnull"} {
                        } elseif {[regexp {^(.+)[\(](.+)[\)]} $filter . filter_name filter_args]} {
                            set r [ad_page_contract_filter_invoke $filter_name $name value [list [split $filter_args |]]]
                        } else {
                            set r [ad_page_contract_filter_invoke $filter $name value]
                        }
                        ns_log notice DEBUG ad_page_contract_filter_invoke $filter $name value -> $r // $value
                        if {$r == 0} {
                            $auth_obj return_err -status 400 "invalid-argument" "Query parameter: [lindex [ad_complaints_get_list] 0]"
                            ad_script_abort
                        }
                    }
                } else {
                    set value $default
                }
                if {$value eq "" && "notnull" in [split $filters ,]} {
                    ad_complain -key $formal_name:notnull [_ acs-tcl.lt_You_must_specify_some]
                    $auth_obj return_err -status 400 "invalid-argument" "Query parameter: [lindex [ad_complaints_get_list] 0]"
                    ad_script_abort
                }

                ns_log notice DEBUG FINAL set $name $value
                uplevel [list set $name $value]
            }
        }
        return $auth_obj
    }



    ad_proc -private validRpIdP {rpid} {

        Validate the provided rpid (Relying Party ID)

        @return boolean value
    } {
        if {$rpid eq "localhost"} { return 1 }

        # must contain at least a dot (heuristic for registrable domain)
        if {[string first "." $rpid] < 0} { return 0 }

        # only hostname chars (no underscore, no port/scheme/path)
        if {![regexp {^[a-z0-9.-]+$} $rpid]} { return 0 }

        # no leading/trailing dot, no empty labels
        if {[string match .* $rpid] || [string match *. $rpid]} { return 0 }
        if {[string first ".." $rpid] >= 0} { return 0 }

        # optional: reject labels starting/ending with '-'
        foreach label [split $rpid "."] {
            if {$label eq ""} { return 0 }
            if {[string match -* $label] || [string match *- $label]} { return 0 }
        }

        return 1
    }

}

::xo::library source_dependent

#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 2
#    indent-tabs-mode: nil
# End
