#!/usr/bin/env bash
set -euo pipefail
rustc --version
cargo --version
node --version
for tool in wasm-bindgen wasm-bindgen-test-runner chromium chromium-browser google-chrome chromedriver firefox geckodriver; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'Browser prerequisite %s: present\n' "$tool"
  else
    printf 'Browser prerequisite %s: unavailable\n' "$tool"
  fi
done
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA"
mkdir -p "$artifact_dir"
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  cargo update --workspace
  date -u +%FT%TZ > "$artifact_dir/dependency-resolution-time.txt"
fi
cp Cargo.lock "$artifact_dir/Cargo.lock"
result=0
timeout 1200 cargo test --locked --all-targets -- --test-threads=2 || result=$?
wasm_libdir="$(rustc --print target-libdir --target wasm32-unknown-unknown)"
if test -d "$wasm_libdir"; then
  timeout 1200 cargo check --locked --target wasm32-unknown-unknown --lib || result=$?
else
  printf 'Browser target standard library unavailable; browser validation incomplete\n'
  result=1
fi
cp browser/package-lock.json "$artifact_dir/browser-package-lock.json"
cargo fmt --all
tar --create --file "$artifact_dir/formatted-source.tar" src/*.rs tests/*.rs tests/common/mod.rs examples/*.rs
(cd "$artifact_dir" && sha256sum Cargo.lock browser-package-lock.json formatted-source.tar > SHA256SUMS)
printf 'Validation status: %s\n' "$result"
exit "$result"
