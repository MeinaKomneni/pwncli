#!/bin/bash
# Patch a binary to use a specific glibc version from kpwn pkgs
# Usage: ./patch.sh <binary> <glibc_version>
# Example: ./patch.sh vuln 2.35-0ubuntu3

BINARY=$1
GLIBC_VER=$2
PKGS_DIR="$HOME/.config/kpwn/pkgs"

if [ -z "$BINARY" ] || [ -z "$GLIBC_VER" ]; then
    echo "Usage: $0 <binary> <glibc_version>"
    exit 1
fi

LIBC_DIR="$PKGS_DIR/$GLIBC_VER/amd64/libc6_${GLIBC_VER}_amd64/lib/x86_64-linux-gnu"
LIBC="$LIBC_DIR/libc.so.6"
LD="$LIBC_DIR/ld-linux-x86-64.so.2"

if [ ! -f "$LIBC" ]; then
    echo "libc not found: $LIBC"
    exit 1
fi

if [ ! -f "$LD" ]; then
    LD="$PKGS_DIR/$GLIBC_VER/amd64/libc6_${GLIBC_VER}_amd64/lib64/ld-linux-x86-64.so.2"
fi

if [ ! -f "$LD" ]; then
    echo "ld not found"
    exit 1
fi

OUTPUT="${BINARY}_${GLIBC_VER}"
cp "$BINARY" "$OUTPUT"
patchelf --set-interpreter "$LD" --set-rpath "$LIBC_DIR" "$OUTPUT"
echo "Patched: $OUTPUT (libc: $LIBC)"
