"""Tiny, dependency-free token check for the REST API.

Kept out of :mod:`wifimonitor.rest_api` (which imports the scapy-backed
use-case layer) so the auth logic can be unit tested on its own.
"""

from __future__ import annotations

import hmac
import secrets
from pathlib import Path


def generate_token(nbytes: int = 24) -> str:
    """Return a random URL-safe token suitable for the API."""
    return secrets.token_urlsafe(nbytes)


def resolve_token(token_arg: str, token_file: str) -> str:
    """Pick the effective API token, preferring a token file over a bare argument.

    A token passed directly on the command line ends up in ``ps``/``/proc/<pid>/cmdline``
    and is readable by any local user; a file path is not. ``token_file`` wins when both
    are set so operators who follow the more secure path aren't silently overridden.
    """
    if token_file:
        return Path(token_file).read_text(encoding="utf-8").strip()
    return token_arg


def check_token(expected: str, authorization_header: str = "", query_token: str = "") -> bool:
    """Constant-time check of a request's credentials.

    When ``expected`` is empty the API is unauthenticated and every request is
    allowed. Otherwise the caller must present the token either as
    ``Authorization: Bearer <token>`` or as a ``?token=`` query parameter.
    """
    if not expected:
        return True
    provided = ""
    if authorization_header.startswith("Bearer "):
        provided = authorization_header[len("Bearer "):].strip()
    if not provided and query_token:
        provided = query_token
    return bool(provided) and hmac.compare_digest(provided, expected)
