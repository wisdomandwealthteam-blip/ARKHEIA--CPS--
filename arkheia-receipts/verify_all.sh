#!/usr/bin/env bash
# ARKHEIA DVE receipt toolkit — full verification (GitHub Codespaces / CI).
# Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.
#
# Usage:  bash verify_all.sh            # from the toolkit root (or vendor/arkheia-receipts)
# Needs:  node >= 22.12, python3 >= 3.10 (+ venv), cargo (network for crates on first run)
# Exit code is non-zero if ANY stage fails. Nothing is skipped silently.
# Air-gapped runners: ARKHEIA_VERIFY_OFFLINE=1 reuses system site-packages (cryptography,
# pytest, jsonschema must be preinstalled); ARKHEIA_TS_TYPEROOTS=<dir containing @types>.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
declare -a RESULTS=()
FAILED=0

stage() {  # stage "name" cmd...
  local name="$1"; shift
  printf '\n\033[1m==> %s\033[0m\n' "$name"
  if "$@"; then RESULTS+=("PASS  $name"); else RESULTS+=("FAIL  $name"); FAILED=1; fi
}

schema_copies() {
  local ref; ref="$(sha256sum schema/arkheia-receipt-schema-v1.json | cut -d' ' -f1)"
  local ok=0
  for f in node/schema/arkheia-receipt-schema-v1.json \
           python/arkheia_receipt/schema/arkheia-receipt-schema-v1.json \
           rust/arkheia-receipt/schema/arkheia-receipt-schema-v1.json; do
    local h; h="$(sha256sum "$f" | cut -d' ' -f1)"
    if [[ "$h" == "$ref" ]]; then echo "  ok   $f"; else echo "  DRIFT $f"; ok=1; fi
  done
  cmp -s test-vectors/vectors.json rust/arkheia-receipt/tests/data/vectors.json \
    && echo "  ok   rust/arkheia-receipt/tests/data/vectors.json" \
    || { echo "  DRIFT rust/arkheia-receipt/tests/data/vectors.json"; ok=1; }
  python3 -c "import json,sys; json.load(open('schema/arkheia-receipt-schema-v1.json'))" || ok=1
  return $ok
}

node_version() {
  node -e 'const [a,b]=process.versions.node.split(".").map(Number); if(a<22||(a===22&&b<12)){console.error("node >= 22.12 required, have "+process.versions.node);process.exit(1)} console.log("  node "+process.versions.node)'
}

vectors_deterministic() {
  local tmp; tmp="$(mktemp)"
  (cd node && node scripts/gen-vectors.mjs "$tmp" >/dev/null) || return 1
  if cmp -s "$tmp" test-vectors/vectors.json; then echo "  regenerated vectors are byte-identical"; rm -f "$tmp"; return 0; fi
  echo "  regenerated vectors DIFFER from committed test-vectors/vectors.json"; rm -f "$tmp"; return 1
}

node_tests() { (cd node && node --test test/*.test.mjs); }

ts_types() {
  local TSC=""
  if command -v tsc >/dev/null 2>&1; then TSC="tsc"; elif [[ -x node_modules/.bin/tsc ]]; then TSC="node_modules/.bin/tsc"; else TSC="npx --yes -p typescript@5 -p @types/node@22 tsc"; fi
  local TR=(); [[ -n "${ARKHEIA_TS_TYPEROOTS:-}" ]] && TR=(--typeRoots "$ARKHEIA_TS_TYPEROOTS")
  (cd node && $TSC --noEmit --strict --module nodenext --moduleResolution nodenext --target es2022 "${TR[@]}" --types node test/types/usage.ts)
}

python_tests() {
  local VENV="$ROOT/.venv-verify"
  if [[ "${ARKHEIA_VERIFY_OFFLINE:-0}" == "1" ]]; then
    [[ -d "$VENV" ]] || python3 -m venv --system-site-packages "$VENV" || return 1
    "$VENV/bin/python" -m pip install --quiet --no-deps --no-build-isolation -e python || return 1
  else
    [[ -d "$VENV" ]] || python3 -m venv "$VENV" || return 1
    "$VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1
    "$VENV/bin/python" -m pip install --quiet -e "python[dev]" || return 1
  fi
  (cd python && "$VENV/bin/python" -m pytest -q -rs)
}

rust_tests() {
  if ! command -v cargo >/dev/null 2>&1; then echo "  cargo not found (install: curl https://sh.rustup.rs -sSf | sh -s -- -y)"; return 1; fi
  (cd rust/arkheia-receipt && cargo test --quiet)
}

gateway_smoke() {
  local VENV="$ROOT/.venv-verify" PORT="${ARKHEIA_SMOKE_PORT:-18080}" ring; ring="$(mktemp)"
  python3 -c "import json; json.dump(json.load(open('test-vectors/vectors.json'))['keyring'], open('$ring','w'))"
  (cd python && ARKHEIA_TRUSTED_KEYS_FILE="$ring" PORT="$PORT" "$VENV/bin/python" -m arkheia_receipt.gateway >/dev/null 2>&1) &
  local pid=$!
  for _ in $(seq 1 50); do curl -fs "http://127.0.0.1:$PORT/v1/public-keys" >/dev/null 2>&1 && break; sleep 0.1; done
  local good bad keys rc=0
  good="$(python3 -c "import json; print(json.dumps(json.load(open('test-vectors/vectors.json'))['chain'][2]['receipt']))" \
    | curl -fs -X POST -H 'Content-Type: application/json' --data-binary @- "http://127.0.0.1:$PORT/v1/verify-receipt")"
  bad="$(python3 -c "import json; print(json.dumps(json.load(open('test-vectors/vectors.json'))['negative'][0]['receipt']))" \
    | curl -fs -X POST -H 'Content-Type: application/json' --data-binary @- "http://127.0.0.1:$PORT/v1/verify-receipt")"
  keys="$(curl -fs "http://127.0.0.1:$PORT/v1/public-keys")"
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -f "$ring"
  echo "  valid    -> $good"
  echo "  tampered -> $bad"
  [[ "$good" == *'"valid":true'* && "$good" == *'"signer":"ed25519:21fe31dfa154a261"'* ]] || rc=1
  [[ "$bad" == *'"valid":false'* && "$bad" == *'"error_code":"SIGNATURE_INVALID"'* ]] || rc=1
  [[ "$keys" == *'d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'* ]] || rc=1
  return $rc
}

stage "Schema copies + vectors identical across languages" schema_copies
stage "Node.js >= 22.12"                                    node_version
stage "Vector generator is deterministic"                   vectors_deterministic
stage "Node test suite (node --test)"                       node_tests
stage "TypeScript declarations (tsc --strict)"              ts_types
stage "Python test suite (pytest)"                          python_tests
stage "Rust test suite (cargo test)"                        rust_tests
stage "Live /v1/verify-receipt smoke test (HTTP)"           gateway_smoke

printf '\n\033[1m==> Summary\033[0m\n'
printf '  %s\n' "${RESULTS[@]}"
if [[ $FAILED -ne 0 ]]; then printf '\n\033[31mVERIFICATION FAILED\033[0m\n'; exit 1; fi
printf '\n\033[32mALL ARKHEIA DVE RECEIPT CHECKS PASSED\033[0m\n'
