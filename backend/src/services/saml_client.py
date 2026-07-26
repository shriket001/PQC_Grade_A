"""SAML Relying-Party (Service Provider) client interface (FR-011 inbound
direction) + a pysaml2-based concrete implementation.

Same DIP pattern as `oidc_client.py` — a plain external-collaborator
interface (not the crypto isolation boundary in `crypto/interfaces.py`),
kept separate so `SamlService` is fully testable with a fake, no real IdP or
XML signature verification needed in tests.

Unlike OIDC's `email_verified` boolean (which exists because an OAuth
provider's account email isn't necessarily verified), SAML has no equivalent
claim — the entire trust model here is the IdP's cryptographic signature over
the assertion. Once `Pysaml2SamlClient` has verified that signature
(`want_assertions_signed=True` in the SP config), every attribute in the
assertion is, by construction, information the configured IdP vouches for —
so profiles from this client always set `email_verified=True`.
"""

import os
import sys
import tempfile
from abc import ABC, abstractmethod
from typing import Any, cast

from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import entity_descriptor

from src.services.external_identity_linker import ExternalProfile

# --- Windows compat: pysaml2 + native xmlsec temp-file access ---------------
# pysaml2's `xmlsec1` crypto backend shells out to the `xmlsec` CLI as a
# SEPARATE process, handing it temp-file paths for the cert PEMs it extracts
# (signing/verifying keys) and the `--output` canonicalized XML. It builds
# those temp files with `tempfile.NamedTemporaryFile(delete=True)` (its
# `delete_tmpfiles` default). On Linux that's fine — Unix file sharing lets
# another process open a file even while a handle to it is open. On Windows,
# `NamedTemporaryFile(delete=True)` opens the file with `O_TEMPORARY`, which
# FORBIDS any other process from opening it — so `xmlsec.exe` can't read the
# cert (`xmlSecCryptoAppKeyLoadEx failed ... failed to load public key`) and
# can't write `--output` (a child open raises `PermissionError [Errno 13]`).
# The SAML flow therefore dies at assertion verification on every Windows dev
# machine, while passing on Linux/CI (where the SAML tests also use a fake
# client, so they never exercise this). Fix: on Windows only, swap pysaml2's
# `NamedTemporaryFile` for a `delete=False` wrapper that still deletes the
# file on close/exit/GC (preserving pysaml2's cleanup), but allows the xmlsec
# subprocess to read/write the file while the Python handle is open. The
# Docker/Linux production path is left untouched.
if sys.platform == "win32":
    import saml2.sigver as _saml2_sigver

    class _WinNamedTemporaryFile:
        """`tempfile.NamedTemporaryFile` stand-in for pysaml2 on Windows.
        Behaves like `NamedTemporaryFile(delete=False)` (so a separate
        `xmlsec.exe` process can read/write the file) but deletes the file on
        `close()` / context-manager exit / GC, so temp files don't leak.
        Proxies the handful of file methods pysaml2 actually uses
        (`write`/`read`/`seek`/`tell`/`flush`)."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            # Always delete=False — the whole point is cross-process access.
            kwargs["delete"] = False
            self._ntf = tempfile.NamedTemporaryFile(*args, **kwargs)
            self.name = self._ntf.name
            self._closed = False

        def write(self, b: bytes) -> int:
            return self._ntf.write(b)

        def read(self, *args: Any, **kwargs: Any) -> bytes:
            return cast(bytes, self._ntf.read(*args, **kwargs))

        def seek(self, *args: Any, **kwargs: Any) -> int:
            return self._ntf.seek(*args, **kwargs)

        def tell(self) -> int:
            return self._ntf.tell()

        def flush(self) -> None:
            self._ntf.flush()

        def close(self) -> None:
            if self._closed:
                return
            self._closed = True
            try:
                self._ntf.close()
            finally:
                try:
                    os.remove(self.name)
                except OSError:
                    pass

        def __enter__(self) -> "_WinNamedTemporaryFile":
            return self

        def __exit__(self, *exc: object) -> None:
            self.close()

        def __del__(self) -> None:
            try:
                self.close()
            except Exception:
                pass

    # `make_temp` and `_run_xmlsec` both resolve `NamedTemporaryFile` as a
    # module global at call time, so reassigning it here is picked up by both.
    _saml2_sigver.NamedTemporaryFile = _WinNamedTemporaryFile

# Common attribute names IdPs use for email/display-name — tried in order.
# samltest.id (and most SimpleSAMLphp-based test IdPs) send the friendly
# names; the bare OID urns are the SAML2 core-attribute fallback some
# enterprise IdPs (e.g. ADFS/Shibboleth) send instead.
_EMAIL_ATTRIBUTE_KEYS = (
    "email",
    "mail",
    "emailAddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
)
# Single-attribute display names. If none of these is present we compose
# first+last below (many IdPs — Mock SAML, ADFS, Azure AD — never send a
# `displayName`, only `firstName`/`lastName` or `givenName`/`surname`).
_NAME_ATTRIBUTE_KEYS = (
    "displayName",
    "displayname",
    "cn",
    "urn:oid:2.16.840.1.113730.3.1.241",
)
_FIRST_NAME_ATTRIBUTE_KEYS = (
    "firstName",
    "firstname",
    "givenName",
    "givenname",
    "urn:oid:2.5.4.42",
)
_LAST_NAME_ATTRIBUTE_KEYS = ("lastName", "lastname", "surname", "sn", "urn:oid:2.5.4.4")


class SamlExchangeError(Exception):
    """The SAML response/assertion couldn't be validated or didn't carry a
    usable email — bad/missing signature, expired, replayed, wrong audience,
    or no email attribute. `SamlService` maps this to `SamlAssertionRejectedError`."""


class SamlClient(ABC):
    @abstractmethod
    def login_redirect(self, relay_state: str) -> tuple[str, str]:
        """Returns (redirect_url, request_id). `request_id` must be handed
        back to `process_response` to bind the response to this specific
        request (replay/unsolicited-response defense)."""
        ...

    @abstractmethod
    def process_response(self, saml_response_b64: str, request_id: str) -> ExternalProfile:
        """Validates a POSTed `SAMLResponse` and returns the verified profile."""
        ...

    @abstractmethod
    def metadata_xml(self) -> str:
        """This SP's own metadata XML, to hand to the IdP when registering
        it (e.g. uploading to samltest.id) — never used during login itself,
        only by the `/auth/saml/{idp}/metadata` endpoint."""
        ...


def _first_attribute(identity: dict[str, list[str]], *keys: str) -> str | None:
    for key in keys:
        values = identity.get(key)
        if values:
            return values[0]
    return None


class Pysaml2SamlClient(SamlClient):
    def __init__(
        self,
        *,
        entity_id: str,
        acs_url: str,
        sp_cert_file: str,
        sp_key_file: str,
        idp_metadata_path: str,
        idp_entity_id: str | None = None,
        xmlsec_binary: str | None = None,
    ) -> None:
        settings: dict[str, object] = {
            "entityid": entity_id,
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [(acs_url, BINDING_HTTP_POST)],
                    },
                    # SP-initiated only — every response must match a request
                    # WE issued (see `request_id`/outstanding binding below).
                    "allow_unsolicited": False,
                    "authn_requests_signed": False,
                    "want_assertions_signed": True,
                    "want_response_signed": False,
                },
            },
            "metadata": {"local": [idp_metadata_path]},
            "key_file": sp_key_file,
            "cert_file": sp_cert_file,
            # Surface attributes whose names aren't in any registered
            # attribute-converter map. pysaml2 ships converters keyed by
            # `attrname-format` (unspecified/basic/uri/...) each with a pre-baked
            # set of *known* attribute names (the SAML2 core OIDs etc.); with
            # this False (the default) any attribute an IdP sends under a name
            # not in one of those maps (e.g. Mock SAML's bare
            # `email`/`firstName`/`lastName`, or a real enterprise IdP's custom
            # claim names) is silently DROPPED from `get_identity()`, so we'd
            # never see an email. This flag only affects which attributes appear
            # in the parsed identity dict — it does NOT touch signature
            # verification (already enforced by `want_assertions_signed`), so it
            # doesn't widen trust, only prevents data loss for attributes we'd
            # otherwise look up by name anyway.
            "allow_unknown_attributes": True,
        }
        # pysaml2 shells out to the native `xmlsec1` CLI for every XML
        # sign/verify — it's a system binary, not a pip dependency, so we let
        # the operator point at it via `SAML_XMLSEC_BINARY_PATH` rather than
        # relying on it being on PATH (it isn't on a stock Windows machine).
        if xmlsec_binary:
            settings["xmlsec_binary"] = xmlsec_binary
        self._config = SPConfig()
        self._config.load(settings)

        if idp_entity_id is None:
            # Auto-detect: fine as long as the metadata file describes
            # exactly one IdP (the common case — a single downloaded
            # samltest.id/enterprise-IdP metadata file). An explicit
            # `idp_entity_id` is required if it ever describes more than one.
            known = list(self._config.metadata.identity_providers())
            if len(known) != 1:
                raise ValueError(
                    f"idp_entity_id must be specified explicitly: the configured "
                    f"metadata describes {len(known)} IdP(s), not exactly one"
                )
            idp_entity_id = known[0]
        self._idp_entity_id = idp_entity_id

    def metadata_xml(self) -> str:
        descriptor = entity_descriptor(self._config)
        return str(descriptor.to_string().decode("utf-8"))

    def login_redirect(self, relay_state: str) -> tuple[str, str]:
        client = Saml2Client(config=self._config)
        request_id, http_args = client.prepare_for_authenticate(
            entityid=self._idp_entity_id, relay_state=relay_state
        )
        redirect_url = dict(http_args["headers"])["Location"]
        return redirect_url, request_id

    def process_response(self, saml_response_b64: str, request_id: str) -> ExternalProfile:
        client = Saml2Client(config=self._config)
        try:
            authn_response = client.parse_authn_request_response(
                saml_response_b64,
                BINDING_HTTP_POST,
                outstanding={request_id: self._idp_entity_id},
            )
        except Exception as err:  # pysaml2 raises several distinct exception
            # types for a bad signature/expiry/audience/replay — all of them
            # mean the same thing to this caller: reject the assertion.
            raise SamlExchangeError("failed to validate the SAML response") from err

        if authn_response is None:
            raise SamlExchangeError("SAML response failed validation")

        subject = authn_response.get_subject()
        name_id = subject.text if subject is not None else None
        if not name_id:
            raise SamlExchangeError("SAML assertion did not include a NameID")

        identity = authn_response.get_identity() or {}
        email = _first_attribute(identity, *_EMAIL_ATTRIBUTE_KEYS)
        if not email:
            raise SamlExchangeError("SAML assertion did not include an email attribute")
        name = _first_attribute(identity, *_NAME_ATTRIBUTE_KEYS)
        if not name:
            # No single display-name attribute — compose first + last (Mock
            # SAML, ADFS, Azure AD all send them split rather than pre-joined).
            first = _first_attribute(identity, *_FIRST_NAME_ATTRIBUTE_KEYS)
            last = _first_attribute(identity, *_LAST_NAME_ATTRIBUTE_KEYS)
            name = " ".join(p for p in (first, last) if p) or None

        return ExternalProfile(
            issuer=authn_response.issuer(),
            subject=name_id,
            email=email,
            # See module docstring: the IdP's signature IS the verification.
            email_verified=True,
            name=name,
        )
