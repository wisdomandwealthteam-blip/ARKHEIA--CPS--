"""ARKHEIA DVE — key generation CLI.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

  python -m arkheia_receipt.keygen [--out-dir DIR] [--from-seed HEX]

Writes DIR/.env.arkheia-signing (0600) and DIR/arkheia-public-keys.json.
Refuses to overwrite. Output is identical to node/scripts/keygen.mjs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .keys import generate_seed_hex, signing_key_from_seed_hex


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="arkheia_receipt.keygen")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--from-seed")
    a = ap.parse_args(argv)
    seed = a.from_seed or generate_seed_hex()
    key = signing_key_from_seed_hex(seed)
    out = Path(a.out_dir)
    env_path, ring_path = out / ".env.arkheia-signing", out / "arkheia-public-keys.json"
    for p in (env_path, ring_path):
        if p.exists():
            print(f"refusing to overwrite {p}", file=sys.stderr)
            return 1
    out.mkdir(parents=True, exist_ok=True)
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(f"ARKHEIA_SIGNING_SEED_HEX={seed}\nARKHEIA_SIGNING_PUBLIC_KEY_ID={key.public_key_id}\n")
    ring = {"keys": [{"public_key_id": key.public_key_id, "algorithm": "Ed25519", "public_key_hex": key.public_key_hex, "status": "active"}]}
    ring_path.write_text(json.dumps(ring, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"public_key_id": key.public_key_id, "public_key_hex": key.public_key_hex, "env_file": str(env_path), "keyring": str(ring_path)}, indent=2))
    print("Store the seed in your secret manager. Never commit .env.arkheia-signing.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
