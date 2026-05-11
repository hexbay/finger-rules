#!/usr/bin/env python3
"""Build and optionally POST a compact finger-rules sync payload.

This script runs in the finger-rules repository from GitHub Actions. It scans
YAML rules, groups them by product key, gzips the payload, and can POST it to
Cloudmap's /hooks/finger-rules/sync endpoint.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import json
import os
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml


def word_to_key(value: str) -> str:
    return str(value).lower().replace(" ", "_").replace("-", "_")


def scan_rules(repo_dir: Path) -> dict[str, list[dict[str, Any]]]:
    apps: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in sorted(repo_dir.rglob("*.yaml")):
        if not path.is_file():
            continue
        relative_path = path.relative_to(repo_dir).as_posix()
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        except Exception as exc:
            print(f"skip invalid yaml {relative_path}: {exc}", file=sys.stderr)
            continue
        if not isinstance(data, list):
            continue

        file_vendor = relative_path.split("/", 1)[0].split(".", 1)[0]
        for item in data:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            rule = dict(item)
            rule["file_vendor"] = file_vendor
            apps[word_to_key(rule["name"])].append(rule)
    return dict(apps)


def build_payload(repo_dir: Path, commit_sha: str) -> dict[str, Any]:
    apps = scan_rules(repo_dir)
    return {
        "commit_sha": commit_sha,
        "apps": apps,
        "stats": {
            "apps": len(apps),
            "rules": sum(len(items) for items in apps.values()),
        },
    }


def post_payload(url: str, payload_bytes: bytes, secret: str | None) -> None:
    headers = {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
    }
    if secret:
        digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
        headers["X-Hub-Signature-256"] = f"sha256={digest}"

    request = urllib.request.Request(url, data=payload_bytes, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read().decode("utf-8", errors="replace")
        print(f"cloudmap response status={response.status} body={body}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", default=".")
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--output", default="finger-rules-payload.json.gz")
    parser.add_argument("--post-url", default=os.environ.get("CLOUDMAP_FINGER_RULES_SYNC_URL", ""))
    parser.add_argument("--secret", default=os.environ.get("CLOUDMAP_FINGER_RULES_WEBHOOK_SECRET", ""))
    args = parser.parse_args()

    payload = build_payload(Path(args.repo_dir).resolve(), args.commit_sha)
    payload_bytes = gzip.compress(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    Path(args.output).write_bytes(payload_bytes)
    print(f"payload written: {args.output} bytes={len(payload_bytes)} stats={payload['stats']}")

    if args.post_url:
        post_payload(args.post_url, payload_bytes, args.secret)


if __name__ == "__main__":
    main()
