#!/bin/sh
set -eu
export LC_ALL=C

# Network-free lifecycle model: ALL ip/iptables/ip6tables/awg commands resolve to
# the fake executable below. Production script is copied with only filesystem
# fixture paths and the TUN character-device check substituted for this test.
TEST_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
SOURCE="$TEST_DIR/../entrypoint.sh"
TEMP_ROOT=$(mktemp -d)
ORIGINAL_PATH=$PATH
trap 'rm -rf "$TEMP_ROOT"' EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "$TEMP_ROOT/bin"
cat > "$TEMP_ROOT/bin/network-mock" <<'MOCK'
#!/bin/sh
set -eu
. "$MOCK_STATE"
command=${0##*/}
COUNT=$((COUNT + 1))
printf '%s %s %s\n' "$COUNT" "$command" "$*" >> "$MOCK_LOG"
save_and_check() {
  if test "$UP" = 1 && test "$GUARD" = 0; then
    if test "$POLICY" != DROP || test "$RULES" != 18 || test "$FORWARD" != 1 || test "$RETURN" != 1 || test "$NAT" != 1; then
      echo "unrestricted IPv4 forwarding at command $COUNT" >> "$MOCK_UNSAFE"
    fi
    if test "$POLICY6" != DROP || test "$GUARD6" -eq 0; then
      echo "unrestricted IPv6 forwarding at command $COUNT" >> "$MOCK_UNSAFE"
    fi
  fi
  {
    printf 'COUNT=%s\nUP=%s\nPRESENT=%s\nGUARD=%s\nGUARD6=%s\n' "$COUNT" "$UP" "$PRESENT" "$GUARD" "$GUARD6"
    printf 'POLICY=%s\nPOLICY6=%s\nRULES=%s\nCHAIN=%s\n' "$POLICY" "$POLICY6" "$RULES" "$CHAIN"
    printf 'FORWARD=%s\nRETURN=%s\nNAT=%s\nCOMMIT_AT=%s\n' "$FORWARD" "$RETURN" "$NAT" "$COMMIT_AT"
  } > "$MOCK_STATE"
}
trap save_and_check EXIT

if test "$COUNT" = "${MOCK_FAIL_AT:-0}"; then
  # Model a partially successful interface start, not only a clean early error.
  if test "$command $*" = "awg-quick up $MOCK_CONFIG"; then PRESENT=1; UP=1; fi
  echo "injected failure at $COUNT" >> "$MOCK_LOG"
  exit 1
fi
case "$command" in
  iptables|ip6tables)
    test "$1 $2" = '-w 5' || exit 2
    shift 2
    if test "$command" = ip6tables; then
      case "$*" in
        '-I FORWARD 1 -j DROP') GUARD6=$((GUARD6 + 1)) ;;
        '-P FORWARD DROP') POLICY6=DROP ;;
        *) exit 2 ;;
      esac
      exit 0
    fi
    case "$*" in
      '-I FORWARD 1 -m comment --comment velum-lifecycle-block -j DROP')
        if test "$COMMIT_AT" -gt 0 && test "${MOCK_CLEANUP_GUARD_FAILURE:-0}" = 1; then exit 1; fi
        GUARD=$((GUARD + 1)) ;;
      '-P FORWARD DROP') POLICY=DROP ;;
      '-F FORWARD') GUARD=0; FORWARD=0; RETURN=0 ;;
      '-A FORWARD -m comment --comment velum-lifecycle-block -j DROP') GUARD=$((GUARD + 1)) ;;
      '-N VELUM-FWD') test "$CHAIN" = 0 || exit 1; CHAIN=1; RULES=0 ;;
      '-F VELUM-FWD') test "$CHAIN" = 1 || exit 1; RULES=0 ;;
      '-A VELUM-FWD '*) test "$CHAIN" = 1 || exit 1; RULES=$((RULES + 1)) ;;
      '-A FORWARD -i velum0 -j VELUM-FWD') FORWARD=1 ;;
      '-A FORWARD -o velum0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT') RETURN=1 ;;
      '-t nat -C POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE') test "$NAT" = 1 ;;
      '-t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE') NAT=1 ;;
      '-D FORWARD -m comment --comment velum-lifecycle-block -j DROP')
        test "$GUARD" = 1 || exit 2
        GUARD=0; COMMIT_AT=$COUNT ;;
      *) echo "unexpected iptables: $*" >&2; exit 2 ;;
    esac
    ;;
  ip)
    case "$*" in
      'link show dev velum0') test "$PRESENT" = 1 ;;
      'link set dev velum0 down')
        test "${MOCK_LINK_DOWN_FAILURE:-0}" != 1 || exit 1
        UP=0 ;;
      *) exit 2 ;;
    esac
    ;;
  awg-quick)
    case "$1" in
      up) test "$PRESENT" = 0 || exit 1; PRESENT=1; UP=1 ;;
      down) test "${MOCK_DOWN_FAILURE:-0}" != 1 || exit 1; PRESENT=0; UP=0 ;;
      *) exit 2 ;;
    esac
    ;;
  awg)
    test "$*" = 'show velum0' || exit 2
    case "${MOCK_END:-exit}" in
      TERM|INT|HUP) kill -"$MOCK_END" "$PPID" ;;
      exit) : ;;
      *) exit 2 ;;
    esac
    exit 1
    ;;
  *) exit 2 ;;
esac
MOCK
chmod 0755 "$TEMP_ROOT/bin/network-mock"
for command in iptables ip6tables ip awg-quick awg; do
  cp "$TEMP_ROOT/bin/network-mock" "$TEMP_ROOT/bin/$command"
done

setup_case() {
  CASE_DIR="$TEMP_ROOT/$1"
  mkdir -p "$CASE_DIR"
  MOCK_STATE="$CASE_DIR/state"
  MOCK_LOG="$CASE_DIR/commands"
  MOCK_UNSAFE="$CASE_DIR/unsafe"
  MOCK_CONFIG="$CASE_DIR/velum0.conf"
  printf '[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.77.0.1/24\nListenPort = 42016\n' > "$MOCK_CONFIG"
  : > "$CASE_DIR/tun"
  cat > "$MOCK_STATE" <<'STATE'
COUNT=0
UP=0
PRESENT=0
GUARD=0
GUARD6=0
POLICY=ACCEPT
POLICY6=ACCEPT
RULES=0
CHAIN=0
FORWARD=0
RETURN=0
NAT=0
COMMIT_AT=0
STATE
  sed -e "s|^CONFIG=.*|CONFIG='$MOCK_CONFIG'|" \
    -e "s|test -c /dev/net/tun|test -f '$CASE_DIR/tun'|" \
    -e "s|/run/amneziawg|$CASE_DIR/run/amneziawg|g" "$SOURCE" > "$CASE_DIR/entrypoint.sh"
  PATH="$TEMP_ROOT/bin:$ORIGINAL_PATH"
  export MOCK_STATE MOCK_LOG MOCK_UNSAFE MOCK_CONFIG PATH
  export VELUM_EGRESS_INTERFACE=eth0
  unset VELUM_RESOLVER_IP
  unset MOCK_FAIL_AT MOCK_END MOCK_CLEANUP_GUARD_FAILURE MOCK_LINK_DOWN_FAILURE MOCK_DOWN_FAILURE
}

run_case() {
  if sh "$CASE_DIR/entrypoint.sh" > "$CASE_DIR/stdout" 2> "$CASE_DIR/stderr"; then STATUS=0; else STATUS=$?; fi
  test "$STATUS" != 0 || fail 'gateway model unexpectedly reported a clean normal exit'
  test ! -e "$MOCK_UNSAFE" || { cat "$MOCK_UNSAFE" >&2; fail 'unrestricted forwarding window'; }
  . "$MOCK_STATE"
  test "$UP" = 0 || test "$GUARD" -gt 0 || fail 'teardown left an unblocked live interface'
}

setup_case normal
run_case
test "$COMMIT_AT" -gt 0 || fail 'normal startup did not commit'
STARTUP_COMMANDS=$COMMIT_AT
test "$POLICY" = DROP && test "$POLICY6" = DROP || fail 'teardown removed default DROP'
test "$GUARD" -gt 0 && test "$GUARD6" -gt 0 || fail 'teardown removed guards'
test "$RULES" = 18 || fail 'teardown deleted stable filter rules'
for destination in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
  grep -Fq -- "-A VELUM-FWD -d $destination -j DROP" "$MOCK_LOG" || fail "missing restriction $destination"
done

failure=1
while test "$failure" -le "$STARTUP_COMMANDS"; do
  setup_case "failure-$failure"
  MOCK_FAIL_AT=$failure
  export MOCK_FAIL_AT
  run_case
  grep -Fq "injected failure at $failure" "$MOCK_LOG" || fail 'failure injection was not reached'
  failure=$((failure + 1))
done

for signal in HUP INT TERM; do
  setup_case "signal-$signal"
  MOCK_END=$signal
  export MOCK_END
  run_case
  case "$signal" in HUP) expected=129 ;; INT) expected=130 ;; TERM) expected=143 ;; esac
  test "$STATUS" = "$expected" || fail "wrong exit status for $signal: $STATUS"
  test "$UP" = 0 && test "$GUARD" -gt 0 || fail "unsafe cleanup on $signal"
done

setup_case restart
run_case
# Model a stale live interface with the restrictions retained by prior shutdown.
printf 'UP=1\nPRESENT=1\nCOUNT=0\nCOMMIT_AT=0\n' >> "$MOCK_STATE"
run_case
test "$COMMIT_AT" -gt 0 && test "$UP" = 0 || fail 'retained namespace restart failed'

setup_case cleanup-guard-error
MOCK_CLEANUP_GUARD_FAILURE=1
export MOCK_CLEANUP_GUARD_FAILURE
run_case
test "$UP" = 0 || fail 'guard error did not force interface down'

setup_case teardown-failure
MOCK_LINK_DOWN_FAILURE=1
MOCK_DOWN_FAILURE=1
export MOCK_LINK_DOWN_FAILURE MOCK_DOWN_FAILURE
run_case
test "$UP" = 1 && test "$GUARD" -gt 0 || fail 'teardown failure did not retain barrier'
test "$RULES" = 18 && test "$POLICY6" = DROP || fail 'teardown failure removed restrictions'

setup_case missing-config
rm "$MOCK_CONFIG"
run_case
test "$COMMIT_AT" = 0 && test "$GUARD" -gt 0 || fail 'invalid configuration was not fail-closed'

setup_case isolated-native-resolver
export VELUM_RESOLVER_IP=172.30.78.3
run_case
test "$COMMIT_AT" -gt 0 || fail 'isolated resolver startup did not commit'
grep -Fq -- '-A VELUM-FWD -d 172.30.78.3 -p udp --dport 53 -j ACCEPT' "$MOCK_LOG" || fail 'isolated resolver UDP rule missing'
grep -Fq -- '-A VELUM-FWD -d 172.30.78.3 -p tcp --dport 53 -j ACCEPT' "$MOCK_LOG" || fail 'isolated resolver TCP rule missing'

setup_case unexpected-resolver
export VELUM_RESOLVER_IP=1.1.1.1
run_case
test "$STATUS" = 78 && test "$COMMIT_AT" = 0 && test "$GUARD" -gt 0 || fail 'unexpected resolver was not fail-closed'

printf 'gateway lifecycle mock tests: PASS (%s startup fault points + normal, 3 signals, restart, 2 cleanup faults, missing config, isolated resolver, rejected resolver)\n' "$STARTUP_COMMANDS"
