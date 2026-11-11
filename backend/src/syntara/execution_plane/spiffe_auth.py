"""Lab proof: JWT-SVID authentication limited to the EP command ingress."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import jwt
from fastapi import HTTPException

from syntara.core.models.principal import service_principal_id

if TYPE_CHECKING:
    from fastapi import Request

    from syntara.core.config.base import Settings


def _verify_svid(authorization: str, settings: Settings) -> str:
    """Verify only against locally provisioned trust-domain keys."""
    expected = settings.ep_spiffe_id
    identity = urlsplit(expected or "")
    if identity.scheme != "spiffe" or not identity.netloc or not identity.path:
        raise ValueError
    if not settings.ep_spiffe_jwt_bundle_path:
        raise ValueError
    scheme, token = authorization.split(" ", 1)
    if scheme.lower() != "bearer" or not token:
        raise ValueError
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise ValueError
    # Read helper-managed bundles each time so issuer key rotation is visible.
    bundles = json.loads(Path(settings.ep_spiffe_jwt_bundle_path).read_text())
    bundle = json.loads(base64.b64decode(bundles[identity.netloc], validate=True))
    keys = [key for key in bundle["keys"] if key.get("kid") == header["kid"]]
    if len(keys) != 1:
        raise ValueError
    claims = jwt.decode(
        token,
        jwt.PyJWK.from_dict(keys[0], algorithm="RS256"),
        algorithms=["RS256"],
        audience=settings.ep_spiffe_jwt_audience,
        options={"require": ["exp", "sub", "aud"]},
    )
    if claims["sub"] != expected:
        raise ValueError
    return expected


def authenticate_callback(request: Request, settings: Settings) -> None:
    """Require the configured SPIFFE ID, with no fallback to the legacy CN."""
    try:
        expected = _verify_svid(request.headers.get("authorization", ""), settings)
    except (jwt.PyJWTError, ValueError, KeyError, TypeError, AttributeError, OSError):
        raise HTTPException(status_code=403, detail="Execution Plane SPIFFE identity required") from None
    request.state.ep_spiffe_id = expected
    request.state.ep_principal_id = service_principal_id(settings.ep_callback_service_cn)
    # Deliberately do not set is_cert_authenticated, which bypasses general RBAC.
