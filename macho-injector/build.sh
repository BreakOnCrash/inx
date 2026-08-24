#!/usr/bin/env bash
# Build PE-map injector + payload.dylib (iphoneos arm64).
set -euo pipefail
cd "$(dirname "$0")"
OUT=.build
rm -rf "$OUT"
mkdir -p "$OUT"

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
CC="$(xcrun --sdk iphoneos -f clang)"
MIN_IOS="${MIN_IOS:-14.0}"
ARCHS=(arm64)

COMMON=(
  -isysroot "$SDK"
  -miphoneos-version-min="$MIN_IOS"
  -O2
  -fPIC
)

echo "==> payload.dylib (PE-safe: _last + import _dlsym only)"
PAYLOAD_SLICES=()
for arch in "${ARCHS[@]}"; do
  slice="$OUT/payload.$arch.dylib"
  "$CC" -arch "$arch" "${COMMON[@]}" \
    -fno-builtin -fvisibility=hidden \
    -shared -o "$slice" payload.c \
    -Wl,-exported_symbol,_last \
    -Wl,-dead_strip \
    -Wl,-fixup_chains \
    -install_name "@rpath/payload.dylib"
  PAYLOAD_SLICES+=("$slice")
done
lipo -create -output "$OUT/payload.dylib" "${PAYLOAD_SLICES[@]}"
ldid -S "$OUT/payload.dylib"
echo "   undefined (expect _dlsym):"
nm -u "$OUT/payload.arm64.dylib" 2>/dev/null || nm -u "$OUT/payload.dylib" | head

echo "==> injector"
INJ_SLICES=()
for arch in "${ARCHS[@]}"; do
  slice="$OUT/injector.$arch"
  "$CC" -arch "$arch" "${COMMON[@]}" -o "$slice" injector.c
  INJ_SLICES+=("$slice")
done
lipo -create -output "$OUT/injector" "${INJ_SLICES[@]}"
ldid -Sentitlements.plist "$OUT/injector"

cp -f "$OUT/injector" ./injector
cp -f "$OUT/payload.dylib" ./payload.dylib

echo
echo "Built (iphoneos ${ARCHS[*]}):"
lipo -info injector payload.dylib
nm -gU .build/payload.arm64.dylib 2>/dev/null || nm -gU payload.dylib | head
ls -lh injector payload.dylib
echo
echo "On device:"
echo "  ./injector SpringBoard payload.dylib"
echo "  ./injector securityd /var/jb/usr/lib/payload.dylib"
echo "Marker: /tmp/inject_demo_ok"
