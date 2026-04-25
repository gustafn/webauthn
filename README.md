# OpenACS WebAuthn / Passkeys

This package adds WebAuthn (passkey) authentication support to OpenACS running on NaviServer.

It provides:

* Login flows for passkeys (passkey-first, identifier-first, and auto mode)
* JSON endpoints for WebAuthn registration/authentication ceremonies
* Support for multiple credential types (ES256, RS256, EdDSA)
* Optional diagnostics endpoint for troubleshooting browser/device capabilities

## Endpoints (overview)

* `GET /webauthn/auth/options`
  Returns WebAuthn assertion options for `navigator.credentials.get()`.

Additional endpoints are provided for registration/authentication flows as part of
the package’s API surface.


## Endpoints

The package provides JSON-based endpoints implementing the WebAuthn
registration (attestation) and authentication (assertion) ceremonies.

### Registration (passkey creation)

* `GET /webauthn/reg/options`
  Returns PublicKeyCredentialCreationOptions for
  `navigator.credentials.create()`.

* `POST /webauthn/reg/verify`
  Verifies the attestation response and stores the credential.

---

### Authentication (passkey login)

* `GET /webauthn/auth/options`
  Returns PublicKeyCredentialRequestOptions for
  `navigator.credentials.get()`.

* `POST /webauthn/auth/verify`
  Verifies the assertion response and authenticates the user.

---

### Diagnostics

* `POST /webauthn/diagnostics`
  Receives browser capability diagnostics and logs them server-side
  for troubleshooting.

---

* All POST endpoints expect JSON request bodies.
* Responses are JSON except where redirects are used (e.g. after
  credential deletion).
* Request options (`/options`) are per-request and must not be cached.


## Development notes

* JSON endpoints validate inputs using `webauthn::json_contract` (similar in spirit
  to `ad_page_contract`, but returning JSON errors instead of HTML complaints).
* JSON parsing and generation uses native NaviServer functionality (`ns_json`,
  `ns_getjson`), replacing ad-hoc JSON handling.
* WebAuthn request options are per-request and must not be cached.
* COSE keys are stored in a generic form and converted on demand for verification.

## Cryptographic capabilities

This version supports multiple WebAuthn credential types:

* **ES256 (ECDSA / P-256)**
  Default and most widely supported algorithm.

* **RS256 (RSA)**
  Supported for compatibility with authenticators requiring RSA.

* **EdDSA (Ed25519 / Ed448)**
  Supported via OKP (Octet Key Pair) handling and native signature APIs.

Supported COSE key types:

* `kty=2` (EC2) → ES256
* `kty=3` (RSA) → RS256
* `kty=1` (OKP) → EdDSA (Ed25519, Ed448)

Notes:

* OKP agreement curves (`X25519`, `X448`) are supported by NaviServer,
  but are **not valid for WebAuthn signatures** and are rejected during verification.
* Signature verification is dispatched dynamically based on COSE `kty` and `alg`.

## Requirements

This package requires recent versions of both NaviServer and OpenACS.

### NaviServer

A recent NaviServer version with the following features enabled is required:

* **JSON support (`ns_json`)**
  Used for parsing and generating JSON in all endpoints.

* **CBOR support (RFC 8949)**
  Used for decoding WebAuthn attestation objects and authenticator data.

* **Extended cryptographic support (`ns_crypto`)**, including:

  * EC key handling (P-256, etc.)
  * RSA key handling
  * OKP key handling (Ed25519, Ed448, X25519, X448)
  * Signature verification for ECDSA, RSA, and EdDSA
  * COSE / WebAuthn–compatible key import

* **OpenSSL with modern crypto support**
  Required for EC, RSA, and EdDSA primitives.

In practice, this means a **current NaviServer 5.x build** with
`ns_json`, `ns_cbor`, and enhanced `ns_crypto` functionality enabled.

### OpenACS

* **OpenACS HEAD**
  Use the newest available version from the `HEAD` branch.
  The recent version of `acs-subsite` is needed for inclusion of
  the WebAuthn UI elements. Otherwise, branch `acs-5-10` should be sufficient.

Older OpenACS releases are not supported, as this package relies on
recent authentication infrastructure, filter behavior, and JSON-based
endpoint patterns.

## License

SPDX-License-Identifier: MPL-2.0

Copyright (c) 2026 Gustaf Neumann

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at
[https://mozilla.org/MPL/2.0/](https://mozilla.org/MPL/2.0/).

