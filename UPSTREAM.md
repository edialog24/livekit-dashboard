# This fork

A fork of [thinhdanggroup/livekit-dashboard](https://github.com/thinhdanggroup/livekit-dashboard)
(MIT), run by Youtello as the live view and control surface for our LiveKit SFU. Deployed from
`k8s/livekit-dashboard/` in **edialog24/telephonycluster**; the operational side is documented
there in `docs/LIVEKIT_DASHBOARD.md`.

Forked at `248b67c` — *"Fix settings page bugs and remove fabricated analytics data"*, 2 July 2026,
after a security review of the tree found no key exfiltration and nothing malicious.

## What we changed, and why

**Authentication.** Upstream gates all 79 routes with HTTP Basic against one shared
`ADMIN_USERNAME`/`ADMIN_PASSWORD`. A shared password cannot be revoked for one person, cannot say
who did what, and would have to be typed a second time after signing in with GitHub. This build
takes the identity oauth2-proxy has already established, and verifies the HMAC signature
oauth2-proxy puts on every request it forwards, so the identity cannot be forged by anything that
reaches the port.

That is deliberately a small patch — every route still says `Depends(requires_admin)`, untouched:

| file | change |
| --- | --- |
| `app/security/basic_auth.py` | replaced. `requires_admin` and `get_current_user` read `X-Forwarded-Email` / `X-Forwarded-User` and check the signature. |
| `app/security/proxy_signature.py` | new. Verifies `GAP-Signature` (github.com/mbland/hmacauth). |
| `app/main.py` | `/health` answers `OK signature:match` / `MISMATCH` when a signature is present, so the shared key can be checked without logging in. |
| `app/templates/base.html.j2`, `app/templates/homer/call.html.j2` | "Logout" points at `/oauth2/sign_out`, so it ends the session instead of doing nothing. |
| `app/templates/logout.html.j2` | copy no longer promises a browser password prompt. |
| `tests/` | the fixtures send the proxy's headers; `tests/test_security.py` covers identity, signing and enforcement. |

Two details in the signature algorithm are easy to get wrong and were both wrong on the first
attempt: there is a **trailing newline after the path**, and the signed header list contains
`X-Forwarded-Preferred-User`, not `...-Username`. `tests/test_security.py` pins both.

**Deployment requires two things of the operator, not of this code:** the app must be unreachable
except through oauth2-proxy (a NetworkPolicy does that), and oauth2-proxy must run with
`--signature-key`. Without the first, anything inside the namespace could present a header; without
the second, there is no signature to check. Never expose this service directly.

## Building

Nothing is built by hand. `.github/workflows/build.yml` runs the tests and publishes
`ghcr.io/edialog24/livekit-dashboard` on every merge to `main`:

| tag | use |
| --- | --- |
| `sha-<short>` | what a deployment pins — immutable and traceable |
| `main` | convenience only; never put it in a manifest |
| `v<x.y.z>` | on a `v*` git tag |

Deploying is then a one-line change to `k8s/livekit-dashboard/deployment.yaml` in telephonycluster,
reviewed like anything else. Pull requests build without pushing, so a broken image never reaches
`main`.

## Taking upstream changes

```bash
git remote add upstream https://github.com/thinhdanggroup/livekit-dashboard
git fetch upstream
git merge upstream/main
```

Conflicts should be confined to the files in the table above. `app/security/basic_auth.py` is ours
outright — keep our version. `app/main.py` and the templates are upstream files we edited, so take
theirs and re-apply our block.

Then let CI run: if `tests/test_security.py` still passes, the authentication change survived the
merge. After deploying, check `/health` still reports `signature:match` before anyone relies on it.

## Note on upstream's workflow directory

`.github/workflows/workflows/stale-issues.yml` is upstream's, one directory too deep — GitHub only
runs workflows directly under `.github/workflows/`, so it has never executed. Left as it is to keep
the diff from upstream small.
