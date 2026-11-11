#!/bin/sh
set -eu
export LC_ALL=C
umask 077

# Fallback when Docker is stopped: verify the saved image archive and execute
# only its parser script under the host Bash. This is not a container runtime
# test and does not start the gateway, change networking, or use real keys.
TEST_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$TEST_DIR/../.." && pwd)
ARCHIVE="$REPO_DIR/release/server/velum-gateway-3.0.2-amd64-20260814-e937905a.tar"
ARCHIVE_SHA=a6cdea3c3ec27dbf34dd6a2cfe65dfc5a11500ad2d7b97778f7fd378fb6e894a
PARSER_LAYER=28c2bd40f6ff7c6d5fb1823c6bd18797c444e77840cd5f87f59d4e89d056adef
TEMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TEMP_ROOT"' EXIT HUP INT TERM

printf '%s  %s\n' "$ARCHIVE_SHA" "$ARCHIVE" | sha256sum --check --status
tar -xOf "$ARCHIVE" "blobs/sha256/$PARSER_LAYER" > "$TEMP_ROOT/parser.layer"
printf '%s  %s\n' "$PARSER_LAYER" "$TEMP_ROOT/parser.layer" | sha256sum --check --status
tar -xzOf "$TEMP_ROOT/parser.layer" usr/local/bin/awg-quick > "$TEMP_ROOT/awg-quick"
chmod 0700 "$TEMP_ROOT/awg-quick"
sha256sum "$TEMP_ROOT/awg-quick"
AWG_QUICK="$TEMP_ROOT/awg-quick" dash "$TEST_DIR/awg-quick-strip-tests.sh"
