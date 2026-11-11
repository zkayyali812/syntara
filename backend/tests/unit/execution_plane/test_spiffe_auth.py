"""Reject untrusted JWT-SVIDs without granting global certificate privileges."""

import base64
import json
import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, Request

from syntara.execution_plane.spiffe_auth import authenticate_callback

ID = "spiffe://lab.example/syntara/ep-callback"
AUD = "syntara-ep-callback"


@pytest.fixture
def issuer(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="lab-key", use="sig", alg="RS256")
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"lab.example": base64.b64encode(json.dumps({"keys": [jwk]}).encode()).decode()}))
    settings = SimpleNamespace(
        ep_spiffe_id=ID,
        ep_spiffe_jwt_bundle_path=str(path),
        ep_spiffe_jwt_audience=AUD,
        ep_callback_service_cn="execution-plane.ao.svc",
    )
    return key, settings


def token(key, **overrides: object):
    claims = {"sub": ID, "aud": [AUD], "exp": int(time.time()) + 60}
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "lab-key"})


def request(value):
    return Request({"type": "http", "headers": [(b"authorization", ("Bearer " + value).encode())]})


def test_valid_svid_maps_identity_without_global_bypass(issuer):
    key, settings = issuer
    req = request(token(key))
    authenticate_callback(req, settings)
    assert req.state.ep_spiffe_id == ID
    assert req.state.ep_principal_id
    assert not getattr(req.state, "is_cert_authenticated", False)


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": "spiffe://lab.example/syntara/unrelated"},
        {"sub": "spiffe://other.example/syntara/ep-callback"},
        {"aud": ["wrong-audience"]},
        {"exp": int(time.time()) - 10},
        {"exp": None},
        {"sub": None},
        {"aud": None},
    ],
)
def test_claim_rejections(issuer, claims):
    key, settings = issuer
    with pytest.raises(HTTPException) as error:
        authenticate_callback(request(token(key, **claims)), settings)
    assert error.value.status_code == 403


def test_untrusted_key_is_denied_even_with_matching_kid(issuer):
    _, settings = issuer
    rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(HTTPException):
        authenticate_callback(request(token(rogue)), settings)


@pytest.mark.parametrize(
    "value", ["", "malformed", jwt.encode({"sub": ID}, "untrusted-identity-lab-test-key-32bytes", algorithm="HS256")]
)
def test_bad_token_does_not_fall_back_to_legacy_certificate(issuer, value):
    _, settings = issuer
    req = request(value)
    req.state.is_cert_authenticated = True
    req.state.cert_cn = settings.ep_callback_service_cn
    with pytest.raises(HTTPException):
        authenticate_callback(req, settings)


def test_missing_expiration_is_denied(issuer):
    key, settings = issuer
    value = jwt.encode({"sub": ID, "aud": [AUD]}, key, algorithm="RS256", headers={"kid": "lab-key"})
    with pytest.raises(HTTPException):
        authenticate_callback(request(value), settings)


def test_bundle_is_reloaded_and_missing_bundle_fails_closed(issuer):
    key, settings = issuer
    from pathlib import Path

    value = token(key)
    authenticate_callback(request(value), settings)
    Path(settings.ep_spiffe_jwt_bundle_path).write_text("{}")
    with pytest.raises(HTTPException):
        authenticate_callback(request(value), settings)
