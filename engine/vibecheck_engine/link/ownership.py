"""Prove a site is yours before any owner-only checks run: a DNS TXT record or a file at
/.well-known/vibecheck.txt containing your token."""
from __future__ import annotations

import hashlib
import json
import urllib.request

from ..config import HOME


def token_for(host: str) -> str:
    HOME.mkdir(parents=True, exist_ok=True)
    seed_file = HOME / "owner-seed"
    if not seed_file.exists():
        import secrets
        seed_file.write_text(secrets.token_hex(16))
    return "vibecheck-" + hashlib.sha256((seed_file.read_text() + host).encode()).hexdigest()[:24]


def _txt_records(host: str) -> list[str]:
    # DNS-over-HTTPS (Cloudflare) because Python's stdlib can't query TXT records.
    req = urllib.request.Request(f"https://cloudflare-dns.com/dns-query?name={host}&type=TXT",
                                 headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return [a.get("data", "").strip('"') for a in json.loads(r.read()).get("Answer", [])]
    except (OSError, ValueError):
        return []


def verify(host: str, scheme: str = "https") -> dict:
    token = token_for(host)
    if token in _txt_records(host) or token in _txt_records(f"_vibecheck.{host}"):
        return {"verified": True, "method": "dns", "token": token}
    try:
        with urllib.request.urlopen(f"{scheme}://{host}/.well-known/vibecheck.txt", timeout=10) as r:
            if token in r.read(4096).decode("utf-8", errors="ignore"):
                return {"verified": True, "method": "well-known", "token": token}
    except OSError:
        pass
    return {
        "verified": False, "token": token,
        "how": f"Add a DNS TXT record on {host} (or _vibecheck.{host}) with the value {token}, "
               f"or serve it at {scheme}://{host}/.well-known/vibecheck.txt, then verify again.",
    }
