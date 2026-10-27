"""Work out what a pasted link is."""
from __future__ import annotations

import re
from urllib.parse import urlparse

_REPO_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}


def classify(link: str) -> dict:
    link = link.strip()
    if re.match(r"^[\w.-]+/[\w.-]+$", link):  # owner/repo shorthand
        link = f"https://github.com/{link}"
    if not re.match(r"^https?://", link, re.I):
        link = "https://" + link
    u = urlparse(link)
    host = (u.hostname or "").lower().removeprefix("www.")
    parts = [p for p in u.path.split("/") if p]
    if host in _REPO_HOSTS and len(parts) >= 2:
        owner, repo = parts[0], parts[1].removesuffix(".git")
        ref = parts[3] if len(parts) >= 4 and parts[2] in ("tree", "blob") else None
        return {"kind": "repo", "host": host, "owner": owner, "repo": repo, "ref": ref,
                "clone_url": f"https://{host}/{owner}/{repo}.git", "url": link}
    if host:
        return {"kind": "website", "host": host, "url": f"{u.scheme}://{u.netloc}{u.path or '/'}"}
    raise ValueError("That doesn't look like a link. Paste a GitHub repo URL or a website address.")
