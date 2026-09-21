"""Guardrail for PI-HTTP: a model-chosen URL about to be fetched.

Allowlist the host and block private/link-local/loopback ranges after DNS
resolution, so an allowlisted-looking hostname cannot rebind to internal
infrastructure (e.g. the cloud metadata endpoint) at request time.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeURLError(ValueError):
    """Raised when a model-chosen URL is not allowlisted or resolves privately."""


def validate_outbound_url(url: str, allowed_hosts: set[str]) -> str:
    """Validate a model-chosen URL before it is fetched.

    `allowed_hosts` is required (no default allowlist ships with this guard -
    choose one per call site). Raises UnsafeURLError if the scheme/host is
    invalid, the host is not allowlisted, or the host resolves to a private,
    link-local, or loopback address.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname is None:
        raise UnsafeURLError("invalid scheme or host")
    if parsed.hostname not in allowed_hosts:
        raise UnsafeURLError(f"host not allowed: {parsed.hostname}")
    for info in socket.getaddrinfo(parsed.hostname, None):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_link_local or ip.is_loopback:
            raise UnsafeURLError(f"resolves to a private address: {ip}")
    return url
