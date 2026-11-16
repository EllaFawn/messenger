#!/bin/sh
# Rebuilds wasm/ from rust/, inside a container so no Rust toolchain is
# needed on the host.
#
# The output is committed, and CI runs this script and fails if the result
# differs from what is committed. Everything that affects the bytes is pinned:
# the Rust image (by digest), the crates (Cargo.lock), the wasm-bindgen tool
# (version and checksum) and the CPU architecture the compiler runs on.
set -eu
cd "$(dirname "$0")"

RUST_IMAGE="rust:1.100-slim@sha256:e9d95b74296f7126a83ae3d041aeaba1ff4c478f13abc5cc034fcf7c131c3d4a"
WASM_BINDGEN_VERSION="0.2.130"
WASM_BINDGEN_SHA256="9687f3bb551b9f66f37ed32a40d7913a00f7962db653054e56857bc306c3227f"

tools=".tools"
archive="$tools/wasm-bindgen-$WASM_BINDGEN_VERSION.tar.gz"
mkdir -p "$tools"
if [ ! -f "$archive" ]; then
  curl --fail --silent --show-error --location --output "$archive.part" \
    "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/$WASM_BINDGEN_VERSION/wasm-bindgen-$WASM_BINDGEN_VERSION-x86_64-unknown-linux-musl.tar.gz"
  mv "$archive.part" "$archive"
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$archive" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$archive" | cut -d' ' -f1)
fi
if [ "$actual" != "$WASM_BINDGEN_SHA256" ]; then
  echo "wasm-bindgen download does not match its pinned checksum; refusing to use it" >&2
  rm -f "$archive"
  exit 1
fi

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

# linux/amd64 on every machine, so an Apple Silicon laptop and CI produce the same bytes.
docker run --rm --platform linux/amd64 \
  -v "$PWD/rust":/src:ro \
  -v "$PWD/$archive":/wasm-bindgen.tar.gz:ro \
  -v "$out":/out \
  -e RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
  "$RUST_IMAGE" sh -euc '
    cp -r /src /build && cd /build
    rustup target add wasm32-unknown-unknown >/dev/null 2>&1
    cargo build --locked --release --target wasm32-unknown-unknown
    tar -xzf /wasm-bindgen.tar.gz -C /tmp
    /tmp/wasm-bindgen-*/wasm-bindgen --target web --out-dir /out \
      target/wasm32-unknown-unknown/release/messager_ratchet.wasm
    chmod -R a+rwX /out
  '

rm -rf wasm
mkdir wasm
cp "$out"/messager_ratchet.js "$out"/messager_ratchet.d.ts \
   "$out"/messager_ratchet_bg.wasm "$out"/messager_ratchet_bg.wasm.d.ts wasm/
echo "built wasm/:"
ls -l wasm
