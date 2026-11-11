#!/bin/sh
set -eu
export LC_ALL=C

TEST_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
GATEWAY_DIR=$(CDPATH= cd -- "$TEST_DIR/.." && pwd)
SOURCE_SCRIPT="$GATEWAY_DIR/revoke-peer.sh"
SOURCE_ADD_SCRIPT="$GATEWAY_DIR/add-peer.sh"
TARGET_KEY='AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='
OTHER_KEY='AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='
PRIVATE_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
TEMP_ROOT=$(mktemp -d)
ORIGINAL_PATH=$PATH
trap 'rm -rf "$TEMP_ROOT"' EXIT HUP INT TERM

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_file_contains() {
  grep -Fq "$2" "$1" || fail "$1 does not contain expected text"
}

assert_file_not_contains() {
  if grep -Fq "$2" "$1"; then
    fail "$1 contains forbidden text"
  fi
}

write_config() {
  destination=$1
  target_extra=${2:-}
  other_address=${3:-10.77.0.9/32}
  {
    printf '%s\n' '[Interface]'
    printf 'PrivateKey = %s\n' "$PRIVATE_KEY"
    printf '%s\n\n' 'ListenPort = 42016'
    printf '%s\n' '[Peer]'
    printf 'PublicKey = %s\n' "$OTHER_KEY"
    printf 'AllowedIPs = %s\n\n' "$other_address"
    printf '%s\n' '[Peer]'
    printf 'PublicKey = %s\n' "$TARGET_KEY"
    printf '%s\n' 'AllowedIPs = 10.77.0.3/32'
    test -z "$target_extra" || printf '%s\n' "$target_extra"
  } > "$destination"
  chmod 0600 "$destination"
}

write_runtime() {
  destination=$1
  other_address=${2:-10.77.0.9/32}
  {
    printf '%s|%s|%s|%s|%s\n' "$OTHER_KEY" "$other_address" '(none)' '(none)' 'off'
    printf '%s|%s|%s|%s|%s\n' "$TARGET_KEY" '10.77.0.3/32' '(none)' '(none)' 'off'
  } > "$destination"
  chmod 0600 "$destination"
}

make_fake_commands() {
  fake_bin=$1
  mkdir -p "$fake_bin"
  printf '%s\n' '#!/bin/sh' 'test "${1:-}" = -u && { echo 0; exit 0; }' 'exit 1' > "$fake_bin/id"
  chmod 0755 "$fake_bin/id"
  printf '%s\n' '#!/bin/sh' 'test "${1:-}" = -f && test "$#" -eq 2' > "$fake_bin/sync"
  chmod 0755 "$fake_bin/sync"
  cat > "$fake_bin/awg" <<'EOF'
#!/bin/sh
set -eu
case "$*" in
  'show velum0 preshared-keys') awk -F '|' '{ print $1 "\t" $3 }' "$MOCK_RUNTIME" ;;
  'show velum0 persistent-keepalive') awk -F '|' '{ print $1 "\t" $5 }' "$MOCK_RUNTIME" ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 "$fake_bin/awg"
  cat > "$fake_bin/stat" <<'EOF'
#!/bin/sh
set -eu
test "${1:-}" = -c || exit 2
format=$2
path=$3
case "$format" in
  %u) echo 0 ;;
  %h) echo 1 ;;
  %a)
    case "$path" in
      */peer-staging|*/config) echo 700 ;;
      *) echo 600 ;;
    esac
    ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 "$fake_bin/stat"
  cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu

runtime=${MOCK_RUNTIME:?}
target=${MOCK_TARGET_KEY:?}

runtime_has_target() {
  awk -F '|' -v target="$target" '$1 == target { found=1 } END { exit !found }' "$runtime"
}

case "${1:-}" in
  inspect)
    template=$3
    name=$4
    case "$template|$name" in
      *Health.Status*'|velum-gateway')
        if { test "${MOCK_FAIL_POST_REMOVE:-0}" = 1 && ! runtime_has_target; } || { test "${MOCK_FAIL_POST_ADD:-0}" = 1 && runtime_has_target; }; then
          echo unhealthy
        else
          echo healthy
        fi
        ;;
      *State.Running*'|amnezia-awg2') echo true ;;
      *State.StartedAt*'|amnezia-awg2') echo '2026-08-14T00:00:00Z' ;;
      *Id*'|amnezia-awg2') echo 'sha256:amnezia-unchanged' ;;
      *) exit 2 ;;
    esac
    exit 0
    ;;
  exec)
    container=$2
    shift 2
    if test "$container" = amnezia-awg2; then
      test "$*" = 'awg show awg0'
      exit 0
    fi
    test "$container" = velum-gateway || exit 2
    if test "${1:-}" = sh && test "${2:-}" = -eu && test "${3:-}" = -c; then
      exec "$@"
    fi
    case "$*" in
      'awg show velum0 peers') awk -F '|' '{ print $1 }' "$runtime" ;;
      'awg show velum0') : ;;
      'awg show velum0 allowed-ips') awk -F '|' '{ print $1 "\t" $2 }' "$runtime" ;;
      'awg show velum0 preshared-keys') awk -F '|' '{ print $1 "\t" $3 }' "$runtime" ;;
      'awg show velum0 persistent-keepalive') awk -F '|' '{ print $1 "\t" $5 }' "$runtime" ;;
      awg-quick\ strip\ /config/*)
        file=${3#/config/}
        # Mirror the real parser's filename gate; the historical candidate
        # names passed a mere existence check but awg-quick rejected them.
        printf '%s\n' "$file" | grep -Eq '^[a-zA-Z0-9_=+.-]{1,15}\.conf$' || exit 1
        test -s "$MOCK_BASE/config/$file"
        ;;
      awg\ set\ velum0\ peer\ *\ remove)
        key=$5
        test "${MOCK_FAIL_REMOVE:-0}" != 1 || exit 1
        temporary="$runtime.tmp"
        awk -F '|' -v key="$key" '$1 != key' "$runtime" > "$temporary"
        mv -f "$temporary" "$runtime"
        ;;
      awg\ set\ velum0\ peer\ *\ allowed-ips\ *)
        key=$5
        address=$7
        if test "${MOCK_FAIL_RESTORE:-0}" = 1 && ! runtime_has_target; then
          exit 1
        fi
        temporary="$runtime.tmp"
        awk -F '|' -v key="$key" '$1 != key' "$runtime" > "$temporary"
        printf '%s|%s|%s|%s|%s\n' "$key" "$address" '(none)' '(none)' 'off' >> "$temporary"
        mv -f "$temporary" "$runtime"
        ;;
      *) echo "unexpected docker exec: $*" >&2; exit 2 ;;
    esac
    ;;
  *) echo "unexpected docker command: $*" >&2; exit 2 ;;
esac
EOF
  chmod 0755 "$fake_bin/docker"
}

setup_case() {
  case_name=$1
  source_script=${2:-$SOURCE_SCRIPT}
  CASE_DIR="$TEMP_ROOT/$case_name"
  TEST_BASE="$CASE_DIR/opt/velum"
  TEST_SCRIPT="$CASE_DIR/revoke-peer.sh"
  MOCK_RUNTIME="$CASE_DIR/runtime.tsv"
  mkdir -p "$TEST_BASE/config" "$TEST_BASE/audit" "$TEST_BASE/peer-staging" "$CASE_DIR/fake-bin"
  chmod 0700 "$TEST_BASE/config" "$TEST_BASE/audit" "$TEST_BASE/peer-staging"
  sed "s|^BASE=/opt/velum$|BASE='$TEST_BASE'|" "$source_script" > "$TEST_SCRIPT"
  chmod 0755 "$TEST_SCRIPT"
  printf '%s\n' 'LOCK_DIR="$BASE/.mutation.lock"' > "$TEST_BASE/upgrade.sh"
  printf '%s\n' 'LOCK_DIR="$BASE/.mutation.lock"' > "$TEST_BASE/add-peer.sh"
  chmod 0700 "$TEST_BASE/upgrade.sh" "$TEST_BASE/add-peer.sh"
  printf '%s\n' "$TARGET_KEY" > "$TEST_BASE/peer-staging/public.key"
  printf '%s\n' '10.77.0.3/32' > "$TEST_BASE/peer-staging/address"
  chmod 0600 "$TEST_BASE/peer-staging/public.key" "$TEST_BASE/peer-staging/address"
  write_runtime "$MOCK_RUNTIME"
  make_fake_commands "$CASE_DIR/fake-bin"
  export CASE_DIR TEST_BASE TEST_SCRIPT MOCK_RUNTIME
  export MOCK_BASE="$TEST_BASE" MOCK_TARGET_KEY="$TARGET_KEY"
  PATH="$CASE_DIR/fake-bin:$ORIGINAL_PATH"
  export PATH
  unset MOCK_FAIL_POST_REMOVE MOCK_FAIL_POST_ADD MOCK_FAIL_RESTORE MOCK_FAIL_REMOVE
}

run_script() {
  if "$TEST_SCRIPT" > "$CASE_DIR/stdout" 2> "$CASE_DIR/stderr"; then
    RUN_STATUS=0
  else
    RUN_STATUS=$?
  fi
  export RUN_STATUS
}

test_success_removes_only_exact_peer() {
  setup_case success
  write_config "$TEST_BASE/config/velum0.conf"
  run_script
  if test "$RUN_STATUS" -ne 0; then
    sed 's/^/revoke stderr: /' "$CASE_DIR/stderr" >&2
    fail "successful revoke exited $RUN_STATUS"
  fi
  assert_file_not_contains "$TEST_BASE/config/velum0.conf" "$TARGET_KEY"
  assert_file_contains "$TEST_BASE/config/velum0.conf" "$OTHER_KEY"
  assert_file_not_contains "$MOCK_RUNTIME" "$TARGET_KEY"
  assert_file_contains "$MOCK_RUNTIME" "$OTHER_KEY"
  test ! -e "$TEST_BASE/peer-staging" || fail 'successful revoke kept staging'
  test ! -e "$TEST_BASE/.mutation.lock" || fail 'successful revoke kept mutation lock'
  test ! -e "$TEST_BASE/.upgrade.lock" || fail 'successful revoke kept legacy lock'
  assert_file_contains "$CASE_DIR/stdout" 'VELUM_PEER_REVOKED 10.77.0.3/32'
}

test_extra_directive_is_rejected_before_mutation() {
  setup_case extra-directive
  write_config "$TEST_BASE/config/velum0.conf" 'PersistentKeepalive = 25'
  before_config=$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')
  before_runtime=$(sha256sum "$MOCK_RUNTIME" | awk '{print $1}')
  run_script
  test "$RUN_STATUS" -ne 0 || fail 'extra directive was accepted'
  test "$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')" = "$before_config" || fail 'config changed on preflight rejection'
  test "$(sha256sum "$MOCK_RUNTIME" | awk '{print $1}')" = "$before_runtime" || fail 'runtime changed on preflight rejection'
  test -d "$TEST_BASE/peer-staging" || fail 'failed revoke removed staging'
  test ! -e "$TEST_BASE/.mutation.lock" || fail 'preflight rejection retained lock'
  test ! -e "$TEST_BASE/.upgrade.lock" || fail 'preflight rejection retained legacy lock'
}

test_ambiguous_address_is_rejected() {
  setup_case ambiguous-address
  write_config "$TEST_BASE/config/velum0.conf" '' '10.77.0.3/32'
  before_config=$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')
  run_script
  test "$RUN_STATUS" -ne 0 || fail 'ambiguous address was accepted'
  test "$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')" = "$before_config" || fail 'ambiguous config changed'
  assert_file_contains "$MOCK_RUNTIME" "$TARGET_KEY"
  test ! -e "$TEST_BASE/.mutation.lock" || fail 'ambiguity rejection retained lock'
  test ! -e "$TEST_BASE/.upgrade.lock" || fail 'ambiguity rejection retained legacy lock'
}

test_broad_persistent_address_is_rejected() {
  setup_case broad-persistent-address
  write_config "$TEST_BASE/config/velum0.conf" '' '10.77.0.0/24'
  before_config=$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')
  before_runtime=$(sha256sum "$MOCK_RUNTIME" | awk '{print $1}')
  run_script
  test "$RUN_STATUS" -ne 0 || fail 'broader persistent AllowedIP was accepted'
  test "$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')" = "$before_config" || fail 'broad persistent config changed'
  test "$(sha256sum "$MOCK_RUNTIME" | awk '{print $1}')" = "$before_runtime" || fail 'runtime changed on broad persistent rejection'
  test ! -e "$TEST_BASE/.mutation.lock" || fail 'broad persistent rejection retained mutation lock'
  test ! -e "$TEST_BASE/.upgrade.lock" || fail 'broad persistent rejection retained legacy lock'
}

test_broad_runtime_address_is_rejected() {
  setup_case broad-runtime-address
  write_config "$TEST_BASE/config/velum0.conf"
  write_runtime "$MOCK_RUNTIME" '0.0.0.0/0'
  before_config=$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')
  before_runtime=$(sha256sum "$MOCK_RUNTIME" | awk '{print $1}')
  run_script
  test "$RUN_STATUS" -ne 0 || fail 'broader runtime AllowedIP was accepted'
  test "$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')" = "$before_config" || fail 'config changed on broad runtime rejection'
  test "$(sha256sum "$MOCK_RUNTIME" | awk '{print $1}')" = "$before_runtime" || fail 'broad runtime mapping changed'
  test ! -e "$TEST_BASE/.mutation.lock" || fail 'broad runtime rejection retained mutation lock'
  test ! -e "$TEST_BASE/.upgrade.lock" || fail 'broad runtime rejection retained legacy lock'
}

test_postcheck_failure_rolls_back_structurally() {
  setup_case verified-rollback
  write_config "$TEST_BASE/config/velum0.conf"
  before_config=$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')
  MOCK_FAIL_POST_REMOVE=1
  export MOCK_FAIL_POST_REMOVE
  run_script
  test "$RUN_STATUS" -ne 0 || fail 'forced postcheck failure reported success'
  test "$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')" = "$before_config" || fail 'verified rollback did not restore config'
  assert_file_contains "$MOCK_RUNTIME" "$TARGET_KEY"
  test -d "$TEST_BASE/peer-staging" || fail 'rolled-back revoke removed staging'
  test ! -e "$TEST_BASE/.mutation.lock" || fail 'verified rollback retained lock'
  test ! -e "$TEST_BASE/.upgrade.lock" || fail 'verified rollback retained legacy lock'
  assert_file_contains "$CASE_DIR/stderr" 'VELUM_PEER_REVOKE_ROLLED_BACK'
}

test_uncertain_rollback_retains_lock() {
  setup_case uncertain-rollback
  write_config "$TEST_BASE/config/velum0.conf"
  before_config=$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')
  MOCK_FAIL_POST_REMOVE=1
  MOCK_FAIL_RESTORE=1
  export MOCK_FAIL_POST_REMOVE MOCK_FAIL_RESTORE
  run_script
  test "$RUN_STATUS" -ne 0 || fail 'uncertain rollback reported success'
  test "$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')" = "$before_config" || fail 'uncertain rollback did not restore persistent config'
  assert_file_not_contains "$MOCK_RUNTIME" "$TARGET_KEY"
  test -d "$TEST_BASE/.mutation.lock" || fail 'uncertain rollback released mutation lock'
  test -d "$TEST_BASE/.upgrade.lock" || fail 'uncertain rollback released legacy lock'
  assert_file_contains "$CASE_DIR/stderr" 'VELUM_PEER_REVOKE_UNCERTAIN'
}

test_mock_rejects_historical_candidate_filenames() {
  setup_case historical-candidate-names
  for file in .velum0.peer.123.candidate .velum0.revoke.123.candidate 'sixteenlettersxx.conf'; do
    printf 'synthetic\n' > "$TEST_BASE/config/$file"
    if docker exec velum-gateway awg-quick strip "/config/$file"; then
      fail 'mock accepted a filename rejected by the real parser'
    fi
  done
}

test_add_uses_valid_candidate_without_replacing_existing_file() {
  setup_case add-success "$SOURCE_ADD_SCRIPT"
  write_config "$TEST_BASE/config/velum0.conf"
  # Starting point contains only the existing peer.
  awk -v key="$TARGET_KEY" 'BEGIN { RS="\\[Peer\\]" } index($0, key) == 0 { printf "%s%s", NR == 1 ? "" : "[Peer]", $0 }' \
    "$TEST_BASE/config/velum0.conf" > "$CASE_DIR/add.conf"
  mv "$CASE_DIR/add.conf" "$TEST_BASE/config/velum0.conf"
  awk -F '|' -v key="$TARGET_KEY" '$1 != key' "$MOCK_RUNTIME" > "$CASE_DIR/add.runtime"
  mv "$CASE_DIR/add.runtime" "$MOCK_RUNTIME"
  printf 'unrelated-stale-candidate\n' > "$TEST_BASE/config/vaddFIXED1.conf"
  run_script
  if test "$RUN_STATUS" -ne 0; then
    sed 's/^/add stderr: /' "$CASE_DIR/stderr" >&2
    fail "successful add exited $RUN_STATUS"
  fi
  assert_file_contains "$TEST_BASE/config/velum0.conf" "$TARGET_KEY"
  assert_file_contains "$TEST_BASE/config/velum0.conf" "$OTHER_KEY"
  assert_file_contains "$MOCK_RUNTIME" "$TARGET_KEY"
  assert_file_contains "$MOCK_RUNTIME" "$OTHER_KEY"
  test "$(cat "$TEST_BASE/config/vaddFIXED1.conf")" = unrelated-stale-candidate || fail 'add replaced unrelated candidate'
  test ! -e "$TEST_BASE/peer-staging" || fail 'successful add kept staging'
  test ! -e "$TEST_BASE/.mutation.lock" || fail 'successful add kept mutation lock'
  test ! -e "$TEST_BASE/.upgrade.lock" || fail 'successful add kept legacy lock'
  assert_file_contains "$CASE_DIR/stdout" 'VELUM_PEER_ADDED 10.77.0.3/32'
}

test_mktemp_failure_preserves_config_and_existing_candidate() {
  for operation in add revoke; do
    if test "$operation" = add; then source_script=$SOURCE_ADD_SCRIPT; else source_script=$SOURCE_SCRIPT; fi
    setup_case "mktemp-failure-$operation" "$source_script"
    write_config "$TEST_BASE/config/velum0.conf"
    if test "$operation" = add; then
      awk -v key="$TARGET_KEY" 'BEGIN { RS="\\[Peer\\]" } index($0, key) == 0 { printf "%s%s", NR == 1 ? "" : "[Peer]", $0 }' \
        "$TEST_BASE/config/velum0.conf" > "$CASE_DIR/add.conf"
      mv "$CASE_DIR/add.conf" "$TEST_BASE/config/velum0.conf"
      awk -F '|' -v key="$TARGET_KEY" '$1 != key' "$MOCK_RUNTIME" > "$CASE_DIR/add.runtime"
      mv "$CASE_DIR/add.runtime" "$MOCK_RUNTIME"
    fi
    printf 'unrelated-stale-candidate\n' > "$TEST_BASE/config/vaddFIXED1.conf"
    printf '%s\n' '#!/bin/sh' 'exit 1' > "$CASE_DIR/fake-bin/mktemp"
    chmod 0755 "$CASE_DIR/fake-bin/mktemp"
    before_config=$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')
    before_runtime=$(sha256sum "$MOCK_RUNTIME" | awk '{print $1}')
    run_script
    test "$RUN_STATUS" -ne 0 || fail 'candidate reservation failure was accepted'
    test "$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')" = "$before_config" || fail 'config changed on reservation failure'
    test "$(sha256sum "$MOCK_RUNTIME" | awk '{print $1}')" = "$before_runtime" || fail 'runtime changed on reservation failure'
    test "$(cat "$TEST_BASE/config/vaddFIXED1.conf")" = unrelated-stale-candidate || fail 'reservation failure removed unrelated candidate'
    test ! -e "$TEST_BASE/.mutation.lock" || fail 'reservation failure retained mutation lock'
    test ! -e "$TEST_BASE/.upgrade.lock" || fail 'reservation failure retained legacy lock'
  done
}

setup_add_case() {
  setup_case "$1" "$SOURCE_ADD_SCRIPT"
  {
    printf '[Interface] # interface comment\nPrivateKey = %s\nListenPort = 42016\n\n' "$PRIVATE_KEY"
    printf '[Peer] # existing peer\nPublicKey = %s # identity\nAllowedIPs = 10.77.0.9/32 # route\n' "$OTHER_KEY"
  } > "$TEST_BASE/config/velum0.conf"
  chmod 0600 "$TEST_BASE/config/velum0.conf"
  printf '%s|10.77.0.9/32|(none)|(none)|off\n' "$OTHER_KEY" > "$MOCK_RUNTIME"
}

assert_mutation_rejected_unchanged() {
  before_config=$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')
  before_runtime=$(sha256sum "$MOCK_RUNTIME" | awk '{print $1}')
  run_script
  test "$RUN_STATUS" -ne 0 || fail 'invalid/colliding mutation was accepted'
  test "$(sha256sum "$TEST_BASE/config/velum0.conf" | awk '{print $1}')" = "$before_config" || fail 'rejected mutation changed persistent policy'
  test "$(sha256sum "$MOCK_RUNTIME" | awk '{print $1}')" = "$before_runtime" || fail 'rejected mutation changed runtime policy'
  test -d "$TEST_BASE/peer-staging" || fail 'rejected mutation removed staging'
  test ! -e "$TEST_BASE/.mutation.lock" || fail 'rejected mutation retained mutation lock'
  test ! -e "$TEST_BASE/.upgrade.lock" || fail 'rejected mutation retained legacy lock'
  assert_file_not_contains "$CASE_DIR/stderr" "$PRIVATE_KEY"
}

test_add_comments_accept_valid_policy() {
  setup_add_case add-comments
  run_script
  test "$RUN_STATUS" -eq 0 || fail 'valid commented peer policy was rejected'
  assert_file_contains "$MOCK_RUNTIME" "$TARGET_KEY"
  assert_file_contains "$TEST_BASE/config/velum0.conf" '# existing peer'
}

test_add_persistent_comments_with_runtime_drift() {
  for conflict in key exact broad multiple; do
    setup_add_case "add-comment-drift-$conflict"
    # The persistent peer is missing from runtime; runtime cannot save the check.
    : > "$MOCK_RUNTIME"
    case "$conflict" in
      key) sed "s|$OTHER_KEY|$TARGET_KEY|" "$TEST_BASE/config/velum0.conf" > "$CASE_DIR/changed" ;;
      exact) sed 's|10.77.0.9/32|10.77.0.3/32|' "$TEST_BASE/config/velum0.conf" > "$CASE_DIR/changed" ;;
      broad) sed 's|10.77.0.9/32|10.77.0.0/24|' "$TEST_BASE/config/velum0.conf" > "$CASE_DIR/changed" ;;
      multiple) sed 's|10.77.0.9/32|10.77.0.9/32, 10.77.0.2/31|' "$TEST_BASE/config/velum0.conf" > "$CASE_DIR/changed" ;;
    esac
    mv "$CASE_DIR/changed" "$TEST_BASE/config/velum0.conf"
    assert_mutation_rejected_unchanged
  done
}

test_add_ambiguous_persistent_policy_is_rejected() {
  for bad_policy in bad-prefix bad-ip leading-zero empty-token ipv6 semicolon missing-key missing-address duplicate-key duplicate-address unknown-field unknown-section malformed-line; do
    setup_add_case "add-invalid-$bad_policy"
    case "$bad_policy" in
      bad-prefix) expression='s|10.77.0.9/32|10.77.0.9/33|' ;;
      bad-ip) expression='s|10.77.0.9/32|10.77.0.999/32|' ;;
      leading-zero) expression='s|10.77.0.9/32|010.77.0.9/32|' ;;
      empty-token) expression='s|10.77.0.9/32|10.77.0.9/32,,10.77.0.10/32|' ;;
      ipv6) expression='s|10.77.0.9/32|::/0|' ;;
      semicolon) expression='s|10.77.0.9/32|10.77.0.9/32 ; ambiguous|' ;;
      missing-key) expression='/PublicKey/d' ;;
      missing-address) expression='/AllowedIPs/d' ;;
      duplicate-key) expression='/PublicKey/p' ;;
      duplicate-address) expression='/AllowedIPs/p' ;;
      unknown-field) expression='s|AllowedIPs|Allowed IPs|' ;;
      unknown-section) expression='s|\[Peer\]|[Unknown]|' ;;
      malformed-line) expression='s|AllowedIPs = |AllowedIPs |' ;;
    esac
    sed "$expression" "$TEST_BASE/config/velum0.conf" > "$CASE_DIR/changed"
    mv "$CASE_DIR/changed" "$TEST_BASE/config/velum0.conf"
    assert_mutation_rejected_unchanged
  done
}

test_add_runtime_only_overlap_and_invalid_policy() {
  for runtime_address in 0.0.0.0/0 10.77.0.2/31 10.77.0.9/99 unknown; do
    setup_add_case add-runtime-policy
    printf '%s|%s|(none)|(none)|off\n' "$OTHER_KEY" "$runtime_address" > "$MOCK_RUNTIME"
    assert_mutation_rejected_unchanged
  done
}

test_add_postcheck_failure_restores_exact_state() {
  setup_add_case add-postcheck-rollback
  MOCK_FAIL_POST_ADD=1
  export MOCK_FAIL_POST_ADD
  assert_mutation_rejected_unchanged
  assert_file_contains "$CASE_DIR/stderr" 'VELUM_PEER_ADD_ROLLED_BACK'
}

comment_first_peer_header() {
  awk '!seen && $0 == "[Peer]" { print "[Peer] # existing peer"; seen=1; next } { print }' \
    "$TEST_BASE/config/velum0.conf" > "$CASE_DIR/changed"
  mv "$CASE_DIR/changed" "$TEST_BASE/config/velum0.conf"
}

test_revoke_preserves_commented_other_peer() {
  setup_case revoke-commented-other
  write_config "$TEST_BASE/config/velum0.conf" '' '10.77.0.9/32 # existing route'
  comment_first_peer_header
  run_script
  if test "$RUN_STATUS" -ne 0; then
    sed 's/^/revoke stderr: /' "$CASE_DIR/stderr" >&2
    fail 'revoke rejected safe comments on another peer'
  fi
  assert_file_not_contains "$TEST_BASE/config/velum0.conf" "$TARGET_KEY"
  assert_file_contains "$TEST_BASE/config/velum0.conf" '[Peer] # existing peer'
  assert_file_contains "$TEST_BASE/config/velum0.conf" '10.77.0.9/32 # existing route'
}

test_revoke_comments_cannot_hide_identity_or_address() {
  for conflict in key exact broad invalid-cidr target-comment unknown-field; do
    setup_case "revoke-comment-$conflict"
    case "$conflict" in
      exact) write_config "$TEST_BASE/config/velum0.conf" '' '10.77.0.3/32 # existing route' ;;
      broad) write_config "$TEST_BASE/config/velum0.conf" '' '10.77.0.0/24 # existing route' ;;
      invalid-cidr) write_config "$TEST_BASE/config/velum0.conf" '' '10.77.0.9/99 # ambiguous route' ;;
      target-comment) write_config "$TEST_BASE/config/velum0.conf" '# target annotation must be reviewed' ;;
      *) write_config "$TEST_BASE/config/velum0.conf" ;;
    esac
    comment_first_peer_header
    if test "$conflict" = key; then
      sed "s|$OTHER_KEY|$TARGET_KEY # duplicate identity|" "$TEST_BASE/config/velum0.conf" > "$CASE_DIR/changed"
      mv "$CASE_DIR/changed" "$TEST_BASE/config/velum0.conf"
    elif test "$conflict" = unknown-field; then
      sed 's|AllowedIPs|Allowed IPs|' "$TEST_BASE/config/velum0.conf" > "$CASE_DIR/changed"
      mv "$CASE_DIR/changed" "$TEST_BASE/config/velum0.conf"
    fi
    assert_mutation_rejected_unchanged
  done
}

test_success_removes_only_exact_peer
test_extra_directive_is_rejected_before_mutation
test_ambiguous_address_is_rejected
test_broad_persistent_address_is_rejected
test_broad_runtime_address_is_rejected
test_postcheck_failure_rolls_back_structurally
test_uncertain_rollback_retains_lock
test_mock_rejects_historical_candidate_filenames
test_add_uses_valid_candidate_without_replacing_existing_file
test_mktemp_failure_preserves_config_and_existing_candidate
test_add_comments_accept_valid_policy
test_add_persistent_comments_with_runtime_drift
test_add_ambiguous_persistent_policy_is_rejected
test_add_runtime_only_overlap_and_invalid_policy
test_add_postcheck_failure_restores_exact_state
test_revoke_preserves_commented_other_peer
test_revoke_comments_cannot_hide_identity_or_address
echo 'peer mutation mock tests: PASS (41 cases)'
