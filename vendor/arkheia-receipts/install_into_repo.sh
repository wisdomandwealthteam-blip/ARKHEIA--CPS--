#!/usr/bin/env bash
# ARKHEIA DVE — vendor the receipt toolkit into a target repository.
# Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
#
# Usage: bash install_into_repo.sh <python|node|rust> <path/to/repo> <engine_id>
#
#   python  ARKHEIA--CPS--bckend-1, ARKHEIA--CPS--, ARKHEIA-CPS-GATEWAY-, CUSTOS, supreme_kernel
#   node    MusicGuard (JS), SECURUS (TS)
#   rust    Single-loop-harness-
#
# Copies the toolkit to <repo>/vendor/arkheia-receipts, wires the dependency,
# writes .env.arkheia.example, and git-ignores the signing seed. Idempotent.

set -euo pipefail
LANG_KIND="${1:?python|node|rust}"
REPO="$(cd "${2:?path to repo}" && pwd)"
ENGINE_ID="${3:?engine_id, e.g. custos}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$REPO/vendor/arkheia-receipts"

case "$ENGINE_ID" in
  clearcheck|musicguard|governancecheck|provenancecheck|settlementcheck|riskcheck)
    echo "engine_id '$ENGINE_ID' is a wrapper name; engines and wrappers must stay separate" >&2; exit 1;;
esac
[[ "$ENGINE_ID" =~ ^[a-z][a-z0-9_-]{1,63}$ ]] || { echo "invalid engine_id '$ENGINE_ID'" >&2; exit 1; }

mkdir -p "$DEST"
tar -C "$SRC" --exclude='.venv-verify' --exclude='node_modules' --exclude='target' --exclude='__pycache__' \
    --exclude='*.egg-info' --exclude='.pytest_cache' -cf - . | tar -C "$DEST" -xf -
echo "vendored toolkit -> vendor/arkheia-receipts"

cat > "$REPO/.env.arkheia.example" <<EOF
# ARKHEIA DVE receipt signing — copy to .env.arkheia-signing (git-ignored) or set as Codespaces/Actions secrets.
ARKHEIA_ENGINE_ID=$ENGINE_ID
# Build commit of this engine; CI can leave unset to fall back to GITHUB_SHA.
ARKHEIA_ENGINE_COMMIT_SHA=
# memory | jsonl:<dir> | bps:<base_url>   (bps fails closed until the adapter is wired)
ARKHEIA_LEDGER=jsonl:./var/arkheia-ledger
# Generate: python -m arkheia_receipt.keygen --out-dir ./secrets  (or: node vendor/arkheia-receipts/node/scripts/keygen.mjs)
ARKHEIA_SIGNING_SEED_HEX=
ARKHEIA_SIGNING_PUBLIC_KEY_ID=
# Gateway only: published keyring of trusted engine keys
ARKHEIA_TRUSTED_KEYS_FILE=./arkheia-public-keys.json
EOF

touch "$REPO/.gitignore"
for line in ".env.arkheia-signing" "secrets/" "var/arkheia-ledger/" "vendor/arkheia-receipts/.venv-verify/"; do
  grep -qxF "$line" "$REPO/.gitignore" || echo "$line" >> "$REPO/.gitignore"
done

case "$LANG_KIND" in
  python)
    REQ="$REPO/requirements.txt"; touch "$REQ"
    grep -qxF -- "-e ./vendor/arkheia-receipts/python" "$REQ" || echo "-e ./vendor/arkheia-receipts/python" >> "$REQ"
    grep -qE '^cryptography' "$REQ" || echo "cryptography>=41" >> "$REQ"
    grep -qE '^pytest' "$REQ" || echo "pytest>=7" >> "$REQ"
    echo "added to requirements.txt; run: pip install -r requirements.txt";;
  node)
    (cd "$REPO" && npm install --save ./vendor/arkheia-receipts/node)
    echo "added @arkheia/receipt (file: dependency) to package.json";;
  rust)
    (cd "$REPO" && cargo add arkheia-receipt --path vendor/arkheia-receipts/rust/arkheia-receipt)
    (cd "$REPO" && cargo generate-lockfile)
    echo "added arkheia-receipt path dependency; Cargo.lock regenerated — commit it (repo uses cargo test --locked)";;
  *) echo "unknown kind '$LANG_KIND'" >&2; exit 1;;
esac

echo "done. verify: bash vendor/arkheia-receipts/verify_all.sh"
