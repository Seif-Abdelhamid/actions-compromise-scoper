"""Canary (fake) secrets for tests and the lab. Built at runtime so no token-shaped
literal sits in the repository for secret scanners to trip over."""

import base64
import json

CANARIES = {
    "AWS_ACCESS_KEY_ID": "AK" + "IA" + "CANARY" + "0" * 10,
    "GH_PAT": "gh" + "p_" + "CANARY" + "x" * 30,
    "NPM_TOKEN": "np" + "m_" + "CANARY" + "y" * 30,
    "DEPLOY_KEY": "-----BEGIN OPENSSH " + "PRIVATE KEY-----\\nCANARYONLY\\n-----END OPENSSH PRIVATE KEY-----",
    "PLAIN_SECRET": "canary-value-do-not-use",
}


def dump(secrets: dict[str, str]) -> str:
    """A representative dump: JSON-ish name -> {value, isSecret} (shape is a stand-in)."""
    return ",".join(f'"{k}":{{"value":{json.dumps(v)},"isSecret":true}}' for k, v in secrets.items())


def double_b64(text: str) -> str:
    return base64.b64encode(base64.b64encode(text.encode()).replace(b"\n", b"")).decode()
