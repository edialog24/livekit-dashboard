"""Authentication: the identity oauth2-proxy has already established.

Upstream checked an HTTP Basic pair from the environment here. We do not: this deployment sits
behind oauth2-proxy with GitHub, so by the time a request arrives the person is known, and a
shared password would only add a second, weaker thing to steal.

LOCAL CHANGE — when rebasing on upstream, this file is the whole patch. Everything else in the
tree is untouched; the 79 route definitions still say Depends(requires_admin) and still work.

The trust boundary this rests on:
  * the NetworkPolicy lets only the oauth2-proxy pod reach this container, so nothing else can
    present a header at all;
  * oauth2-proxy sets X-Forwarded-User / X-Forwarded-Email itself on every request, overwriting
    whatever the client sent, so the values cannot be chosen by the browser.
Both are required. Do not expose this service directly.
"""

import logging
from typing import Optional

from fastapi import HTTPException, Request, status

from app.security.proxy_signature import enforcing as signature_enforced
from app.security.proxy_signature import verify as verify_proxy_signature

logger = logging.getLogger(__name__)


# Set by oauth2-proxy with --pass-user-headers. Email first: it identifies a person across a
# GitHub rename, and it is what the audit log should carry.
_IDENTITY_HEADERS = ("X-Forwarded-Email", "X-Forwarded-User", "X-Forwarded-Preferred-Username")


def _identity(request: Request) -> Optional[str]:
    """Who the proxy says this is, or None if it said nothing."""
    for header in _IDENTITY_HEADERS:
        value = request.headers.get(header, "").strip()
        if value:
            return value
    return None


def requires_admin(request: Request) -> str:
    """Dependency for every route: there must be a signed-in person behind this request.

    Reaching the app without the header means the request did not come through the proxy, which
    should be impossible — so this answers 401 rather than guessing.
    """
    user = _identity(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authenticated user. This service must be reached through oauth2-proxy.",
        )

    # The headers say who; the signature says who is saying so. None means signing is not
    # configured, which is the upstream behaviour and leaves the NetworkPolicy as the only guard.
    signed = verify_proxy_signature(request)
    if signed is False:
        if signature_enforced():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Request signature missing or invalid.",
            )
        logger.warning("Unsigned request accepted for %s — GAP_SIGNATURE_ENFORCE is off", user)

    return user


def get_current_user(request: Request) -> Optional[str]:
    """The name to show in the page header and write to the audit log."""
    return _identity(request)
