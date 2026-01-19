# OpenACS WebAuthn / Passkeys

This package adds WebAuthn (passkey) authentication support to OpenACS running on
NaviServer.

It provides:
- Login flows for passkeys (passkey-first, identifier-first, and auto mode)
- JSON endpoints for WebAuthn registration/authentication ceremonies
- Optional diagnostics endpoint for troubleshooting browser/device capabilities

## Endpoints (overview)

- `GET /webauthn/auth/options`  
  Returns WebAuthn assertion options for `navigator.credentials.get()`.

Additional endpoints are provided for registration/authentication flows as part of
the package’s API surface.

## Development notes

- JSON endpoints validate inputs using `webauthn::json_contract` (similar in spirit
  to `ad_page_contract`, but returning JSON errors instead of HTML complaints).
- WebAuthn request options are per-request and must not be cached.

## Requirements

This package requires recent versions of both NaviServer and OpenACS.

### NaviServer

A recent NaviServer version with the following features enabled is required:

- **CBOR support (RFC 8949)**  
  Used for decoding WebAuthn attestation objects and authenticator data.

- **Extended cryptographic support for EC keys**, including:
  - Importing and creating elliptic-curve keys from affine coordinates
  - COSE / WebAuthn–compatible key handling
  - ECDSA verification suitable for ES256 credentials

- **OpenSSL with modern EC support**  
  NaviServer must be built against a recent OpenSSL version providing
  contemporary elliptic-curve primitives required by WebAuthn.

In practice, this means a **current NaviServer 5.x build** with
`ns_cbor` and enhanced `ns_crypto` functionality enabled.

### OpenACS

- **OpenACS 5.10.x (oacs-5-10 branch)**  
  Use the newest available version from the `oacs-5-10` branch.

Older OpenACS releases are not supported, as this package relies on
recent authentication infrastructure, filter behavior, and JSON-based
endpoint patterns.


## License

SPDX-License-Identifier: MPL-2.0

Copyright (c) 2026 Gustaf Neumann

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at
https://mozilla.org/MPL/2.0/.
