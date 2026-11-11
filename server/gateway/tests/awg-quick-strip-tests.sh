#!/bin/sh
set -eu
export LC_ALL=C
umask 077

# Parser-only regression. Use the pinned gateway image or the exact upstream
# linux.bash installed as AWG_QUICK. This test never calls up/down/setconf and
# needs no network, NET_ADMIN, TUN device, or real private keys.
TEST_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
GATEWAY_DIR=$(CDPATH= cd -- "$TEST_DIR/.." && pwd)
AWG_QUICK=${AWG_QUICK:-awg-quick}
TEMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TEMP_ROOT"' EXIT HUP INT TERM

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

write_synthetic_config() {
  printf '%s\n' \
    '[Interface]' \
    'PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
    'Address = 10.77.0.1/24' \
    'ListenPort = 42016' \
    'DNS = 172.30.77.3' \
    'S1 = 12' \
    'S2 = 12' \
    'S3 = 12' \
    'S4 = 12' \
    '[Peer]' \
    'PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=' \
    'AllowedIPs = 10.77.0.3/32' > "$1"
}

for operation in add revoke; do
  # Exercise the same reservation template that the transaction uses rather
  # than a separately duplicated example that could drift from production.
  template=$(sed -n 's/^CANDIDATE=$(mktemp "\$BASE\/config\/\([^"]*\)").*/\1/p' "$GATEWAY_DIR/$operation-peer.sh")
  test -n "$template" || fail "$operation candidate reservation template missing"
  candidate=$(mktemp "$TEMP_ROOT/$template")
  write_synthetic_config "$candidate"
  "$AWG_QUICK" strip "$candidate" > "$TEMP_ROOT/stripped" 2> "$TEMP_ROOT/error" || fail "$operation candidate rejected by awg-quick"
  grep -Fxq 'S4 = 12' "$TEMP_ROOT/stripped" || fail 'AWG fields were not preserved'
  grep -Fxq 'AllowedIPs = 10.77.0.3/32' "$TEMP_ROOT/stripped" || fail 'peer mapping was not preserved'
  if grep -Eq '^(Address|DNS) = ' "$TEMP_ROOT/stripped"; then
    fail 'awg-quick additions were not stripped'
  fi
done

for filename in .velum0.peer.123.candidate .velum0.revoke.123.candidate sixteenlettersxx.conf; do
  write_synthetic_config "$TEMP_ROOT/$filename"
  if "$AWG_QUICK" strip "$TEMP_ROOT/$filename" > "$TEMP_ROOT/stripped" 2> "$TEMP_ROOT/error"; then
    fail 'awg-quick accepted a historical or oversized candidate filename'
  fi
  grep -Fq 'valid interface name, followed by .conf' "$TEMP_ROOT/error" || fail 'unexpected parser rejection'
done

echo 'real awg-quick strip tests: PASS (2 transaction templates, 3 invalid names)'
