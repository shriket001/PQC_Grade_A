"""Standalone end-to-end verification of the Windows SAML tempfile fix.

Drives a REAL SP-initiated SSO round-trip against BoxyHQ Mock SAML
(https://mocksaml.com) through the patched `Pysaml2SamlClient`:

  1. `login_redirect` builds an unsigned AuthnRequest (HTTP-Redirect binding).
  2. We GET the IdP SSO URL with that SAMLRequest. Mock SAML redirects to its
     mock login page `/saml/login?id=<loginId>&audience=...&acsUrl=...&relayState=...`.
  3. We POST Mock SAML's complete-login API `POST /api/saml/auth` with JSON
     `{email, id, audience, acsUrl, relayState}` — it returns an HTML
     auto-submit form carrying the signed SAMLResponse (Destination = our ACS,
     but Mock SAML hands the form back to *us*, the requester — it does NOT
     POST to localhost itself).
  4. We extract the base64 SAMLResponse and run `process_response` — the exact
     code path that was failing: pysaml2 extracts the IdP signing cert via
     `make_temp` (an open NamedTemporaryFile) and shells out to xmlsec.exe to
     verify the signature. On Windows pre-fix, O_TEMPORARY blocked xmlsec from
     opening that cert file -> "failed to load public key". With the
     delete=False shim, xmlsec reads it fine.

Exits 0 only if the signature validates and a profile email is returned.

Run from backend/:  .venv/Scripts/python.exe verify_saml_roundtrip.py
"""
from __future__ import annotations

import base64
import os
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET

import urllib3

from src.services.saml_client import Pysaml2SamlClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = r"E:/VAYUNX/Chat_Application/Grade_A"
IDP_METADATA = os.path.join(BASE, "docker/certs/saml-idp/mocksaml-idp-metadata.xml")
SP_CERT = os.path.join(BASE, "docker/certs/saml-sp/sp.crt")
SP_KEY = os.path.join(BASE, "docker/certs/saml-sp/sp.key")
XMLSEC = os.path.join(BASE, "tools/xmlsec-win64/bin/xmlsec.exe")

ENTITY_ID = "https://localhost:8000/api/v1/auth/saml/metadata"
ACS_URL = "https://localhost:8000/api/v1/auth/saml/samltest/acs"


def _input_value(html: str, name: str) -> str | None:
    m = re.search(
        r'<input[^>]+name="%s"[^>]*value="([^"]*)"' % re.escape(name),
        html,
        re.IGNORECASE,
    )
    if not m:
        m = re.search(
            r'<input[^>]+value="([^"]*)"[^>]+name="%s"' % re.escape(name),
            html,
            re.IGNORECASE,
        )
    return m.group(1) if m else None


def main() -> int:
    import requests  # noqa: PLC0415

    print("[1] constructing Pysaml2SamlClient (loads IdP metadata, wires xmlsec_binary)...")
    client = Pysaml2SamlClient(
        entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        sp_cert_file=SP_CERT,
        sp_key_file=SP_KEY,
        idp_metadata_path=IDP_METADATA,
        xmlsec_binary=XMLSEC,
    )
    print("    ok - client built")

    print("[2] login_redirect() -> AuthnRequest (HTTP-Redirect)...")
    relay_state = "verify-roundtrip"
    redirect_url, request_id = client.login_redirect(relay_state)
    print(f"    request_id={request_id}")

    s = requests.Session()
    s.verify = False

    print("[3] GET IdP SSO URL -> mock login page...")
    r = s.get(redirect_url, allow_redirects=True, timeout=30)
    print(f"    final url={r.url}")
    if r.status_code != 200:
        print(f"    !! status {r.status_code}")
        return 2
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.url).query))
    login_id = qs.get("id")
    audience = qs.get("audience", ENTITY_ID)
    acs = qs.get("acsUrl", ACS_URL)
    relay = qs.get("relayState", relay_state)
    if not login_id:
        print("    !! no id in mock login url; cannot complete login")
        return 3
    print(f"    login_id={login_id} audience={audience} acsUrl={acs}")

    print("[4] POST /api/saml/auth (complete mock login)...")
    auth_url = "https://mocksaml.com/api/saml/auth"
    payload = {
        "email": "jackson@example.com",
        "id": login_id,
        "audience": audience,
        "acsUrl": acs,
        "providerName": "vayunx-dev-sp",
        "relayState": relay,
    }
    r2 = s.post(auth_url, json=payload, timeout=30)
    print(f"    status={r2.status_code}")
    if r2.status_code != 200:
        print("    !! body:", r2.text[:400])
        return 4
    resp_html = r2.text

    print("[5] extract SAMLResponse from auto-submit form...")
    saml_response_b64 = _input_value(resp_html, "SAMLResponse")
    if not saml_response_b64:
        print("    !! no SAMLResponse; first 500 chars:")
        print(resp_html[:500])
        return 5
    print(f"    got SAMLResponse (b64 len={len(saml_response_b64)})")

    try:
        decoded = ET.fromstring(base64.b64decode(saml_response_b64))
        ns = {"s": "urn:oasis:names:tc:SAML:2.0:assertion"}
        iss = decoded.find(".//s:Issuer", ns)
        print(f"    decoded issuer={iss.text if iss is not None else '?'}")
    except Exception as e:
        print(f"    (decode preview failed: {e})")

    print("[6] process_response() - the failing path (xmlsec verifies signature)...")
    try:
        profile = client.process_response(saml_response_b64, request_id)
    except Exception as err:
        print(f"    !! FAILED: {type(err).__name__}: {err}")
        import traceback
        traceback.print_exc()
        return 6
    print("    OK - verified profile:")
    print(f"       issuer  = {profile.issuer}")
    print(f"       subject = {profile.subject}")
    print(f"       email   = {profile.email}")
    print(f"       name    = {profile.name}")
    print("\nSUCCESS: SAML signature verified on Windows - the tempfile fix works.")
    return 0


if __name__ == "__main__":
    sys.exit(main())