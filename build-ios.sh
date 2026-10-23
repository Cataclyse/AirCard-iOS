#!/bin/bash
# build-ios.sh
# Builds the Rust FFI static library for iOS and packages AirliftFFI.xcframework.
# Run any time rust-core/ changes, then regenerate with `xcodegen generate`.
set -Eeuo pipefail
trap 'build_status=$?; printf "ERROR: build-ios.sh line %s (exit %s)\n" "$LINENO" "$build_status" >&2; exit "$build_status"' ERR

echo "==> Starting iOS Rust build"

export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode-beta.app/Contents/Developer}"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-18.0}"

# Make Rust tools visible without executing an external shell startup file.
export PATH="$HOME/.cargo/bin:$PATH"

for build_tool in rustup cargo xcodebuild; do
  if ! command -v "$build_tool" >/dev/null 2>&1; then
    printf "ERROR: required build tool not found: %s\n" "$build_tool" >&2
    exit 127
  fi
done
printf "==> Xcode developer directory: %s\n" "$DEVELOPER_DIR"

# Remap $HOME so absolute source paths don't appear in the binary's log output
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${HOME}=/build"
export CFLAGS="${CFLAGS:-} -ffile-prefix-map=${HOME}=/build"
export TARGET_CFLAGS="${TARGET_CFLAGS:-} -ffile-prefix-map=${HOME}=/build"

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT/rust-core"

echo "==> Installing iOS targets (if needed)"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim

echo "==> Building Rust static libs (release)"
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim

cd "$ROOT"
echo "==> Repackaging AirliftFFI.xcframework"
rm -rf "$ROOT/AirliftFFI.xcframework"
xcodebuild -create-xcframework \
  -library rust-core/target/aarch64-apple-ios/release/libairlift_ffi.a \
  -headers rust-core/include \
  -library rust-core/target/aarch64-apple-ios-sim/release/libairlift_ffi.a \
  -headers rust-core/include \
  -output "$ROOT/AirliftFFI.xcframework"

echo "==> Done."
echo "    Regenerate the Xcode project with: xcodegen generate"
