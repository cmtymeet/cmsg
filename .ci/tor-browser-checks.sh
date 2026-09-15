#!/usr/bin/env bash
set -euo pipefail
rustc --version
cargo --version
python3 --version
case "$TOR_STAGE" in client|streams|service) ;; *) exit 2 ;; esac
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA/tor-$TOR_STAGE"
mkdir -p "$artifact_dir"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
ln -s "$TORJS_SOURCE_ARCHIVE" "$scratch/tor-js.tar"
ln -s "$ARTI_SOURCE_ARCHIVE" "$scratch/arti.tar"
printf '%s\n' "$TORJS_SOURCE_SHA256" > "$scratch/tor-js.tar.sha256"
printf '%s\n' "$ARTI_SOURCE_SHA256" > "$scratch/arti.tar.sha256"
python3 browser/upstream/apply.py --from-archives \
  "$scratch/tor-js.tar" "$scratch/arti.tar" "$scratch/source" "$TOR_STAGE" \
  | tee "$artifact_dir/source-application.json"
if test -n "${OPENSSL_INCLUDE_DIR:-}"; then
  test -d "$OPENSSL_INCLUDE_DIR/openssl"
  test -d "$OPENSSL_LIB_DIR"
  export OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR
  export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
torjs_manifest="$scratch/source/tor-js/Cargo.toml"
arti_manifest="$scratch/source/arti/Cargo.toml"
# Convert the pinned upstream graph to the explicit patched path dependencies.
# Capture this resolution before validation; later promotion must retain it.
cargo update --manifest-path "$torjs_manifest" --workspace
cp "$scratch/source/tor-js/Cargo.lock" "$artifact_dir/tor-js-Cargo.lock"
date -u +%FT%TZ > "$artifact_dir/dependency-resolution-time.txt"
result=0
timeout 1800 cargo check --locked --manifest-path "$torjs_manifest" \
  -p tor-js --target wasm32-unknown-unknown || result=$?
if test "$TOR_STAGE" = service; then
  cargo update --manifest-path "$arti_manifest" --workspace
  cp "$scratch/source/arti/Cargo.lock" "$artifact_dir/arti-Cargo.lock"
  timeout 1800 cargo test --locked --manifest-path "$arti_manifest" \
    -p tor-persist --features state-dir state_dir_wasm_tests -- --test-threads=2 || result=$?
fi
(cd "$artifact_dir" && sha256sum source-application.json *Cargo.lock > SHA256SUMS)
printf 'Patched upstream validation status: %s\n' "$result"
exit "$result"
