
<property name="context">{/doc/webauthn/ {OpenACS WebAuthn / Passkeys}} {OpenACS WebAuthn / Passkeys}</property>
<property name="doc(title)">OpenACS WebAuthn / Passkeys</property>
<master>
<style>
div.sect2 > div.itemizedlist > ul.itemizedlist > li.listitem {margin-top: 16px;}
div.sect3 > div.itemizedlist > ul.itemizedlist > li.listitem {margin-top: 6px;}
</style>              
<include src="/packages/acs-core-docs/lib/navheader"
			leftLink="" leftLabel=""
			title=""
			rightLink="" rightLabel="">
		    <div class="sect1">
<div class="titlepage">
<div><div><h2 class="title" style="clear: both">
<a name="webauthn-design" id="webauthn-design"></a>OpenACS WebAuthn / Passkeys</h2></div></div><hr>
</div><p>This package adds WebAuthn (passkey) authentication support to
OpenACS running on NaviServer.</p><div class="itemizedlist"><ul class="itemizedlist" style="list-style-type: disc;">
<li class="listitem"><p>Login flows for passkeys (passkey-first, identifier-first, and
auto mode)</p></li><li class="listitem"><p>JSON endpoints for WebAuthn registration/authentication
ceremonies</p></li><li class="listitem"><p>Optional diagnostics endpoint for troubleshooting browser/device
capabilities</p></li>
</ul></div><div class="sect2">
<div class="titlepage"><div><div><h3 class="title">
<a name="webauthn-design-endpoints" id="webauthn-design-endpoints"></a>Endpoints</h3></div></div></div><div class="itemizedlist"><ul class="itemizedlist" style="list-style-type: disc;"><li class="listitem"><p>
<code class="literal">GET /webauthn/auth/options</code>: Returns
WebAuthn assertion options for <code class="literal">navigator.credentials.get()</code>.</p></li></ul></div><p>Additional endpoints are provided for
registration/authentication flows as part of the
package&rdquo;™s API surface.</p>
</div><div class="sect2">
<div class="titlepage"><div><div><h3 class="title">
<a name="webauthn-design-development-notes" id="webauthn-design-development-notes"></a>Development Notes</h3></div></div></div><div class="itemizedlist"><ul class="itemizedlist" style="list-style-type: disc;">
<li class="listitem"><p>JSON endpoints validate inputs using <code class="literal">webauthn::json_contract</code> (similar in spirit to
<code class="literal">ad_page_contract</code>, but returning JSON
errors instead of HTML complaints).</p></li><li class="listitem"><p>WebAuthn request options are per-request and must not be
cached.</p></li>
</ul></div>
</div><div class="sect2">
<div class="titlepage"><div><div><h3 class="title">
<a name="webauthn-configuration" id="webauthn-configuration"></a>Configuration</h3></div></div></div><p>The WebAuthn relying party identifier (RP ID) can be configured
via the NaviServer configuration file. The RP ID must match the
effective host name used to access the site (for example,
<code class="literal">localhost</code> versus <code class="literal">127.0.0.1</code>), otherwise browsers will reject
WebAuthn operations.</p><p>To set the RP ID explicitly, add the following stanza:</p><pre class="programlisting">
ns_section ns/server/$server/acs/webauthn {
    ns_param RpID "YOUR-RPID"
}
</pre><p>If <code class="literal">RpID</code> is not specified, the
package first tries to use the configured server name (<code class="literal">[ns_info server]</code>). This value is typically correct
in Docker-based configurations and in standard installations
derived from the sample <code class="literal">openacs-config.tcl</code>. When the server name is not
appropriate for use as an RP ID, the package falls back to
<code class="literal">localhost</code>.</p>
</div><div class="sect3">
<div class="titlepage"><div><div><h4 class="title">
<a name="webauthn-configuration-pitfalls" id="webauthn-configuration-pitfalls"></a>Common Pitfalls</h4></div></div></div><p>A frequent source of WebAuthn failures during development is a
mismatch between the configured RP ID and the host name used to
access the site. Browsers enforce strict origin and RP ID checks
and will reject requests that do not match.</p><div class="itemizedlist"><ul class="itemizedlist" style="list-style-type: disc;">
<li class="listitem"><p>Accessing the site via <code class="literal">https://127.0.0.1</code> while the RP ID is <code class="literal">localhost</code> (or vice versa). In this case, browsers
typically fail with a <code class="literal">SecurityError</code>
such as &ldquo;The operation is
insecure.&rdquo;</p></li><li class="listitem"><p>Using an IP address as RP ID while accessing the site via a host
name, or changing the effective host name without updating the RP
ID.</p></li>
</ul></div><p>For local development, it is recommended to consistently use
<code class="literal">https://localhost</code> and either rely on
the default RP ID resolution or explicitly configure <code class="literal">RpID</code> to <code class="literal">localhost</code>.</p>
</div><div class="sect2">
<div class="titlepage"><div><div><h3 class="title">
<a name="webauthn-design-requirements" id="webauthn-design-requirements"></a>Requirements</h3></div></div></div><p>This package requires recent versions of both NaviServer and
OpenACS.</p><div class="sect3">
<div class="titlepage"><div><div><h4 class="title">
<a name="webauthn-design-requirements-naviserver" id="webauthn-design-requirements-naviserver"></a>NaviServer</h4></div></div></div><p>A recent NaviServer version with the following features enabled
is required:</p><div class="itemizedlist"><ul class="itemizedlist" style="list-style-type: disc;">
<li class="listitem"><p>
<span class="strong"><strong>CBOR support (RFC
8949)</strong></span>: Used for decoding WebAuthn attestation
objects and authenticator data.</p></li><li class="listitem">
<p>
<span class="strong"><strong>Extended cryptographic support for
EC keys</strong></span>, including:</p><div class="itemizedlist"><ul class="itemizedlist" style="list-style-type: circle;">
<li class="listitem"><p>Importing and creating elliptic-curve keys from affine
coordinates</p></li><li class="listitem"><p>COSE / WebAuthn-compatible key handling</p></li><li class="listitem"><p>ECDSA verification suitable for ES256 credentials</p></li>
</ul></div>
</li><li class="listitem"><p>
<span class="strong"><strong>OpenSSL with modern EC
support</strong></span>: NaviServer must be built against a recent
OpenSSL version providing contemporary elliptic-curve primitives
required by WebAuthn.</p></li>
</ul></div><p>In practice, this means a current NaviServer 5.x build with
<code class="literal">ns_cbor</code> and enhanced <code class="literal">ns_crypto</code> functionality enabled.</p>
</div><div class="sect3">
<div class="titlepage"><div><div><h4 class="title">
<a name="webauthn-design-requirements-openacs" id="webauthn-design-requirements-openacs"></a>OpenACS</h4></div></div></div><p>
<span class="strong"><strong>OpenACS HEAD</strong></span>: Use
the newest available version from the HEAD branch. The recent
version of <code class="literal">acs-subsite</code> is needed for
inclusion of the WebAuthn UI elements. Otherwise, branch
<code class="literal">acs-5-10</code> should be sufficient.</p><p>Older OpenACS releases are not supported, as this package relies
on recent authentication infrastructure, filter behavior, and
JSON-based endpoint patterns.</p>
</div>
</div><div class="sect2">
<div class="titlepage"><div><div><h3 class="title">
<a name="webauthn-design-license" id="webauthn-design-license"></a>License</h3></div></div></div><p>SPDX-License-Identifier: MPL-2.0</p><p>Copyright (c) 2026 Gustaf Neumann</p><p>This Source Code Form is subject to the terms of the Mozilla
Public License, v. 2.0. If a copy of the MPL was not distributed
with this file, You can obtain one at <a class="ulink" href="https://mozilla.org/MPL/2.0/" target="_top">https://mozilla.org/MPL/2.0/</a>.</p>
</div>
</div>
<include src="/packages/acs-core-docs/lib/navfooter"
			leftLink="" leftLabel="" leftTitle=""
			rightLink="" rightLabel="" rightTitle=""
			homeLink="" homeLabel="" 
			upLink="" upLabel=""> 
		    