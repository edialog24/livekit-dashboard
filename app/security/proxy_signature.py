"""Verify the GAP-Signature that oauth2-proxy puts on every proxied request.

LOCAL ADDITION — not upstream. See app/security/basic_auth.py for the wider change.

The identity headers this app now trusts are only worth what the path to them is worth. The
NetworkPolicy already makes that path a single pod, but a header is still a header. oauth2-proxy's
--signature-key closes the gap: it HMACs every request it forwards with a key only it and this app
hold, so the identity it asserts cannot be invented by anything that reaches the port.

The algorithm is github.com/mbland/hmacauth, which oauth2-proxy vendors. Transcribed from its
source rather than from memory, because a first attempt from memory verified nothing:

    StringToSign = method + "\n"
                 + <value of each signed header, in order> + "\n"   (one line each, "" if absent)
                 + path [+ "?" + rawquery] [+ "#" + fragment] + "\n"

then the raw body is appended, HMAC'd with the key, and sent as "<algorithm> <std-base64(mac)>".
Note the trailing newline after the path — leaving it out is what made the first attempt fail.

The header list is oauth2-proxy's SignatureHeaders (pkg/upstream/http.go), in its order. Order and
spelling both matter: "X-Forwarded-Preferred-User", not "...-Username".
"""

import base64
import hashlib
import hmac
import logging
import os
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


# Exactly oauth2-proxy's SignatureHeaders, in order. Do not sort, do not add.
SIGNATURE_HEADERS: Tuple[str, ...] = (
    "Content-Length",
    "Content-Md5",
    "Content-Type",
    "Date",
    "Authorization",
    "X-Forwarded-User",
    "X-Forwarded-Email",
    "X-Forwarded-Preferred-User",
    "X-Forwarded-Access-Token",
    "Cookie",
    "Gap-Auth",
)

_ALGORITHMS = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def _configured() -> Optional[Tuple[str, bytes]]:
    """The key as configured, as (algorithm, key), or None when signing is not in use.

    Written the same way as the proxy's own flag: "algorithm:secret", e.g. "sha256:hunter2".
    """
    raw = os.environ.get("GAP_SIGNATURE_KEY", "").strip()
    if not raw:
        return None
    algorithm, _, secret = raw.partition(":")
    algorithm = algorithm.lower()
    if algorithm not in _ALGORITHMS or not secret:
        logger.error("GAP_SIGNATURE_KEY is not <algorithm>:<secret> with a known algorithm; ignoring it")
        return None
    return algorithm, secret.encode("utf-8")


def enforcing() -> bool:
    """True when a bad or missing signature should end the request.

    Off by default so a new key can be rolled out and confirmed against real traffic before it can
    lock anyone out. Turn it on with GAP_SIGNATURE_ENFORCE=true once /health reports a match.
    """
    return os.environ.get("GAP_SIGNATURE_ENFORCE", "false").lower() == "true"


def _string_to_sign(method: str, header_values: List[str], path_with_query: str) -> bytes:
    lines = [method]
    lines.extend(header_values)
    lines.append(path_with_query)
    # Every line is terminated, the last one included — hence the trailing empty string.
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def _header_values(headers, omit_content_length: bool) -> List[str]:
    values: List[str] = []
    for name in SIGNATURE_HEADERS:
        if omit_content_length and name == "Content-Length":
            # Go does not keep Content-Length in Request.Header — it lives in a struct field — so
            # hmacauth signs an empty line for it even when the request on the wire has one. This
            # only shows up on requests with a body, i.e. every control action in this app.
            values.append("")
            continue
        got = headers.getlist(name) if hasattr(headers, "getlist") else []
        values.append(",".join(got))
    return values


def verify(request, body: bytes = b"") -> Optional[bool]:
    """Check the request's GAP-Signature.

    Returns True when it matches, False when it does not or is missing, and None when signing is
    not configured at all — so a caller can tell "wrong" from "not asked for".
    """
    configured = _configured()
    if configured is None:
        return None
    algorithm, key = configured

    presented = request.headers.get("GAP-Signature", "")
    if not presented:
        logger.warning("Request carried no GAP-Signature; it did not come through oauth2-proxy")
        return False

    url = request.url
    path_with_query = url.path
    if url.query:
        path_with_query += "?" + url.query
    if url.fragment:
        path_with_query += "#" + url.fragment

    # Two candidates, differing only in how Content-Length is represented (see _header_values).
    # Both are HMACs under the same key, so accepting either costs nothing: an attacker still has
    # to hold the key. It just means one Go-versus-ASGI representation difference cannot reject a
    # legitimate request.
    for omit_content_length in (False, True):
        mac = hmac.new(
            key,
            _string_to_sign(request.method, _header_values(request.headers, omit_content_length), path_with_query),
            _ALGORITHMS[algorithm],
        )
        mac.update(body)
        expected = algorithm + " " + base64.b64encode(mac.digest()).decode("ascii")
        if hmac.compare_digest(presented, expected):
            return True

    logger.warning("GAP-Signature did not match for %s %s", request.method, url.path)
    return False
