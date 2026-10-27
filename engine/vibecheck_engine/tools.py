"""Find or download the free scanner binaries (Opengrep, TruffleHog) at pinned versions."""
from __future__ import annotations

import hashlib
import io
import json
import platform
import shutil
import stat
import sys
import tarfile
import urllib.request
from pathlib import Path

from .config import BIN_DIR

OPENGREP_VERSION = "v1.33.0"
TRUFFLEHOG_VERSION = "v3.99.7"
# Opengrep ships cosign signatures but no checksums file, so we pin hashes we've checked.
OPENGREP_SHA256 = {
    "opengrep_windows_x86.exe": "9a9e90f187f73149f4d141f78241d18282538ce94d555d7515ca9cd70e8f22e9",
}

EXE = ".exe" if sys.platform == "win32" else ""


def _machine() -> str:
    m = platform.machine().lower()
    return "arm64" if m in ("arm64", "aarch64") else "x86"


def _opengrep_asset() -> str:
    arch = _machine()
    if sys.platform == "win32":
        return "opengrep_windows_x86.exe"
    if sys.platform == "darwin":
        return "opengrep_osx_arm64" if arch == "arm64" else "opengrep_osx_x86"
    return "opengrep_manylinux_aarch64" if arch == "arm64" else "opengrep_manylinux_x86"


def _trufflehog_asset() -> str:
    v = TRUFFLEHOG_VERSION.lstrip("v")
    os_name = {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")
    arch = "arm64" if _machine() == "arm64" else "amd64"
    return f"trufflehog_{v}_{os_name}_{arch}.tar.gz"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "vibecheck"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def _make_executable(p: Path) -> None:
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def find(name: str) -> Path | None:
    """Prefer our pinned copy, then whatever is on PATH."""
    local = BIN_DIR / f"{name}{EXE}"
    if local.exists():
        return local
    found = shutil.which(name)
    return Path(found) if found else None


def install_opengrep() -> dict:
    asset = _opengrep_asset()
    url = f"https://github.com/opengrep/opengrep/releases/download/{OPENGREP_VERSION}/{asset}"
    data = _get(url)
    digest = hashlib.sha256(data).hexdigest()
    pinned = OPENGREP_SHA256.get(asset)
    if pinned and pinned != digest:
        raise RuntimeError(f"Opengrep checksum mismatch for {asset}; refusing to install")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    dest = BIN_DIR / f"opengrep{EXE}"
    dest.write_bytes(data)
    _make_executable(dest)
    return {"tool": "opengrep", "version": OPENGREP_VERSION, "sha256": digest, "verified": "pinned-sha256" if pinned else "pinned-tag"}


def install_trufflehog() -> dict:
    asset = _trufflehog_asset()
    base = f"https://github.com/trufflesecurity/trufflehog/releases/download/{TRUFFLEHOG_VERSION}"
    data = _get(f"{base}/{asset}")
    digest = hashlib.sha256(data).hexdigest()
    sums = _get(f"{base}/trufflehog_{TRUFFLEHOG_VERSION.lstrip('v')}_checksums.txt").decode()
    expected = next((ln.split()[0] for ln in sums.splitlines() if ln.strip().endswith(asset)), None)
    if expected != digest:
        raise RuntimeError(f"TruffleHog checksum mismatch for {asset}; refusing to install")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        member = next(m for m in tf.getmembers() if Path(m.name).name == f"trufflehog{EXE}")
        dest = BIN_DIR / f"trufflehog{EXE}"
        dest.write_bytes(tf.extractfile(member).read())
    _make_executable(dest)
    return {"tool": "trufflehog", "version": TRUFFLEHOG_VERSION, "sha256": digest, "verified": "checksums.txt"}


def status() -> dict:
    return {name: str(find(name)) if find(name) else None for name in ("opengrep", "trufflehog", "git", "osv-scanner", "nuclei", "zap.sh")}


def ensure_all() -> list[dict]:
    out = []
    if not find("opengrep"):
        out.append(install_opengrep())
    if not find("trufflehog"):
        out.append(install_trufflehog())
    return out


if __name__ == "__main__":
    print(json.dumps(ensure_all() or status(), indent=2))
