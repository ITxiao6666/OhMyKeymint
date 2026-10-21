#!/usr/bin/env python3
"""Build and stage the Rust Soter Binder daemon using the configured Cargo NDK.

Output contract: target/soterta-svc/<abi>/{debug,release}/soterta-svc
The Android linker and API level come from .cargo/config.toml, shared with OMK.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ABI_TO_TARGET = {
    "arm64-v8a": "aarch64-linux-android",
    "x86_64": "x86_64-linux-android",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abi", choices=sorted(ABI_TO_TARGET), default="arm64-v8a")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    target = ABI_TO_TARGET[args.abi]
    profile = "debug" if args.debug else "release"
    command = ["cargo", "build", "--locked", "--target", target,
               "-p", "soter-ta", "--bin", "soterta-svc"]
    if not args.debug:
        command.append("--release")
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=REPO_ROOT, check=True)
    source = REPO_ROOT / "target" / target / profile / "soterta-svc"
    output = REPO_ROOT / "target" / "soterta-svc" / args.abi / profile / "soterta-svc"
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, output)
    print(f"wrote {output} ({output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
