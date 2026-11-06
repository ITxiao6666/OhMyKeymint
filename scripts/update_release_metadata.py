#!/usr/bin/env python3
"""Write KernelSU update metadata as UTF-8 bytes on every host platform."""

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-json", required=True, type=Path)
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    release = json.loads(args.release_json.read_text(encoding="utf-8"))
    version = release["tag_name"]
    notes = release.get("body") or ""
    if not isinstance(version, str) or not version or not isinstance(notes, str):
        raise ValueError("Release tag and notes must be strings")
    if args.version_code <= 0:
        raise ValueError("Version code must be positive")
    assets = [
        asset for asset in release["assets"]
        if "release" in asset["name"] and asset["name"].endswith(".zip")
        and asset.get("state") == "uploaded"
    ]
    if len(assets) != 1:
        raise ValueError("Expected exactly one uploaded release ZIP")
    update = {
        "version": version,
        "versionCode": args.version_code,
        "zipUrl": assets[0]["browser_download_url"],
        "changelog": "https://raw.githubusercontent.com/ITxiao6666/OhMyKeymint/changelog/changelog.md",
    }
    # Explicit bytes avoid Windows locale encoding and newline conversion. Never
    # pipe non-ASCII metadata through subprocess text mode without UTF-8 encoding.
    normalized_notes = notes.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
    encoded_notes = normalized_notes.encode("utf-8")
    encoded_update = (json.dumps(update, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "changelog.md").write_bytes(encoded_notes)
    (args.output_dir / "update.json").write_bytes(encoded_update)


if __name__ == "__main__":
    main()
