#!/bin/sh
set -eu
export LC_ALL=C

# Add one peer to the fixed Velum gateway. Client private keys are generated
# client-side and never accepted by this script or stored on the VPS.
BASE=/opt/velum
CONFIG="$BASE/config/velum0.conf"
STAGE="$BASE/peer-staging"
PUBLIC_KEY_FILE="$STAGE/public.key"
ADDRESS_FILE="$STAGE/address"
LEGACY_LOCK_DIR="$BASE/.upgrade.lock"
LOCK_DIR="$BASE/.mutation.lock"
PHASE_FILE="$LOCK_DIR/phase"
INPUT_CHECK="$LOCK_DIR/input.check"
SUCCESS=0
LEGACY_LOCK_HELD=0
LOCK_HELD=0
RUNTIME_SNAPSHOTTED=0
RUNTIME_APPLIED=0
PERSISTED=0
BACKUP=
CANDIDATE=
PUBLIC_KEY=
DECODED_KEY=
CONFIG_BEFORE_SHA=
RUNTIME_PEERS_BEFORE_SORTED=
RUNTIME_ALLOWED_BEFORE_SORTED=
CURRENT_RUNTIME_PEERS=
CURRENT_RUNTIME_ALLOWED=

normalize_lines() {
  sed '/^[[:space:]]*$/d' | sort
}

allowed_tokens_contain_address() {
  target_cidr=$1
  awk -v target_cidr="$target_cidr" '
    function ip_number(ip, octets, count, i, value, result) {
      count=split(ip, octets, ".")
      if (count != 4) return -1
      result=0
      for (i=1; i<=4; i++) {
        if (octets[i] !~ /^(0|[1-9][0-9]*)$/) return -1
        value=octets[i] + 0
        if (value < 0 || value > 255) return -1
        result=(result * 256) + value
      }
      return result
    }
    function contains(cidr, target, fields, prefix, network, address, block, start) {
      if (split(cidr, fields, "/") != 2 || fields[2] !~ /^(0|[1-9][0-9]*)$/) { invalid=1; return 0 }
      prefix=fields[2] + 0
      if (prefix < 0 || prefix > 32) { invalid=1; return 0 }
      network=ip_number(fields[1]); address=ip_number(target)
      if (network < 0 || address < 0) { invalid=1; return 0 }
      block=2 ^ (32 - prefix)
      start=int(network / block) * block
      return address >= start && address < start + block
    }
    BEGIN { split(target_cidr, target_parts, "/"); target=target_parts[1] }
    NF && contains($0, target) { found=1 }
    END { if (invalid) exit 2; exit !found }
  '
}

read_runtime_snapshot() {
  CURRENT_RUNTIME_PEERS=$(docker exec velum-gateway awg show velum0 peers) || return 1
  CURRENT_RUNTIME_ALLOWED=$(docker exec velum-gateway awg show velum0 allowed-ips) || return 1
}

runtime_matches_before() {
  read_runtime_snapshot || return 1
  test "$(printf '%s\n' "$CURRENT_RUNTIME_PEERS" | normalize_lines)" = "$RUNTIME_PEERS_BEFORE_SORTED" || return 1
  test "$(printf '%s\n' "$CURRENT_RUNTIME_ALLOWED" | normalize_lines)" = "$RUNTIME_ALLOWED_BEFORE_SORTED"
}

input_has_canonical_framing() {
  input_file=$1
  input_value=$2
  printf '%s' "$input_value" > "$INPUT_CHECK"
  if cmp -s "$input_file" "$INPUT_CHECK"; then
    rm -f "$INPUT_CHECK"
    return 0
  fi
  printf '%s\n' "$input_value" > "$INPUT_CHECK"
  if cmp -s "$input_file" "$INPUT_CHECK"; then
    rm -f "$INPUT_CHECK"
    return 0
  fi
  printf '%s\r\n' "$input_value" > "$INPUT_CHECK"
  if cmp -s "$input_file" "$INPUT_CHECK"; then
    rm -f "$INPUT_CHECK"
    return 0
  fi
  rm -f "$INPUT_CHECK"
  return 1
}

write_phase() {
  phase=$1
  test "$LOCK_HELD" = 1 || return 1
  printf '%s\n' "$phase" > "$LOCK_DIR/.phase.new"
  chmod 0600 "$LOCK_DIR/.phase.new"
  mv -f "$LOCK_DIR/.phase.new" "$PHASE_FILE"
  sync -f "$PHASE_FILE"
}

release_locks() {
  if test "$LOCK_HELD" = 1; then
    rm -f "$PHASE_FILE" "$LOCK_DIR/.phase.new" "$INPUT_CHECK" "$DECODED_KEY" || return 1
    if test -n "$BACKUP"; then
      rm -f "$BACKUP" || return 1
    fi
    rmdir "$LOCK_DIR" || return 1
    LOCK_HELD=0
  fi
  if test "$LEGACY_LOCK_HELD" = 1; then
    rmdir "$LEGACY_LOCK_DIR" || return 1
    LEGACY_LOCK_HELD=0
  fi
}

rollback() {
  test "$SUCCESS" = 1 && return 0
  trap - EXIT
  trap '' HUP INT TERM
  ROLLBACK_OK=1

  if test "$RUNTIME_APPLIED" = 1 && test -n "$PUBLIC_KEY"; then
    docker exec velum-gateway awg set velum0 peer "$PUBLIC_KEY" remove >/dev/null 2>&1 || ROLLBACK_OK=0
  fi
  if test "$PERSISTED" = 1; then
    if test -n "$BACKUP" && test -f "$BACKUP" \
      && install -m 0600 "$BACKUP" "$BASE/config/.velum0.rollback" \
      && mv -f "$BASE/config/.velum0.rollback" "$CONFIG" \
      && sync -f "$CONFIG" \
      && test "$(sha256sum "$CONFIG" | awk '{print $1}')" = "$CONFIG_BEFORE_SHA"; then
      :
    else
      ROLLBACK_OK=0
    fi
  fi
  if test "$RUNTIME_SNAPSHOTTED" = 1 && { test "$RUNTIME_APPLIED" = 1 || test "$PERSISTED" = 1; }; then
    runtime_matches_before || ROLLBACK_OK=0
  fi
  if test -n "$CANDIDATE"; then
    rm -f "$CANDIDATE" || ROLLBACK_OK=0
  fi
  if test -n "$DECODED_KEY"; then
    rm -f "$DECODED_KEY" || ROLLBACK_OK=0
  fi

  if test "$ROLLBACK_OK" = 1; then
    if release_locks; then
      echo "VELUM_PEER_ADD_ROLLED_BACK" >&2
    else
      echo "Velum state was rolled back but mutation locks require manual review" >&2
    fi
  else
    write_phase rollback-failed >/dev/null 2>&1 || true
    if test "$RUNTIME_APPLIED" = 1 || test "$PERSISTED" = 1; then
      docker stop velum-gateway >/dev/null 2>&1 || true
    fi
    echo "Velum peer rollback could not be proven; gateway is stopped when possible and mutation locks remain" >&2
  fi
  return 0
}

handle_signal() {
  code=$1
  trap - EXIT
  trap '' HUP INT TERM
  rollback
  exit "$code"
}

trap rollback EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

test "$(id -u)" = 0 || { echo "Velum peer provisioning must run as root" >&2; exit 77; }
umask 077
if ! mkdir "$LEGACY_LOCK_DIR" 2>/dev/null; then
  echo "A legacy or active Velum upgrade lock requires manual review" >&2
  exit 73
fi
LEGACY_LOCK_HELD=1
chmod 0700 "$LEGACY_LOCK_DIR"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Another or interrupted Velum mutation requires manual review" >&2
  exit 73
fi
LOCK_HELD=1
chmod 0700 "$LOCK_DIR"
write_phase locked

test -d "$STAGE" && test "$(stat -c '%a' "$STAGE")" = 700 && test "$(stat -c '%u' "$STAGE")" = 0 || { echo "Velum peer staging must be root-only" >&2; exit 78; }
test "$(find "$STAGE" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = "$(printf 'address\npublic.key')" || { echo "Velum peer staging contains unexpected entries" >&2; exit 78; }
for file in "$PUBLIC_KEY_FILE" "$ADDRESS_FILE"; do
  test -f "$file" && test ! -L "$file" || { echo "Velum peer input is missing or is a symlink" >&2; exit 78; }
  test "$(stat -c '%a' "$file")" = 600 && test "$(stat -c '%u' "$file")" = 0 || { echo "Velum peer input must be root-owned mode 0600" >&2; exit 78; }
done
test -f "$CONFIG" && test ! -L "$CONFIG" \
  && test "$(stat -c '%a' "$CONFIG")" = 600 \
  && test "$(stat -c '%u' "$CONFIG")" = 0 || { echo "Velum server config must be a root-owned regular file with mode 0600" >&2; exit 78; }
test "$(docker inspect -f '{{.State.Health.Status}}' velum-gateway)" = healthy || { echo "Velum gateway is not healthy" >&2; exit 69; }
docker exec velum-gateway awg show velum0 >/dev/null 2>&1 || { echo "Velum interface is not queryable" >&2; exit 69; }
test "$(docker inspect -f '{{.State.Running}}' amnezia-awg2)" = true || { echo "Existing Amnezia is not running" >&2; exit 69; }
docker exec amnezia-awg2 awg show awg0 >/dev/null 2>&1 || { echo "Existing Amnezia interface is not queryable" >&2; exit 69; }

AMNEZIA_ID=$(docker inspect -f '{{.Id}}' amnezia-awg2)
AMNEZIA_STARTED=$(docker inspect -f '{{.State.StartedAt}}' amnezia-awg2)
PUBLIC_KEY=$(tr -d '\r\n' < "$PUBLIC_KEY_FILE")
test -n "$PUBLIC_KEY" && input_has_canonical_framing "$PUBLIC_KEY_FILE" "$PUBLIC_KEY" || { echo "Client public key has invalid framing" >&2; exit 78; }
DECODED_KEY="$LOCK_DIR/client-public.bin"
printf '%s' "$PUBLIC_KEY" | base64 -d > "$DECODED_KEY" 2>/dev/null || { echo "Client public key is not valid Base64" >&2; exit 78; }
test "$(wc -c < "$DECODED_KEY")" = 32 || { echo "Client public key must decode to 32 bytes" >&2; exit 78; }
test "$(base64 -w 0 < "$DECODED_KEY")" = "$PUBLIC_KEY" || { echo "Client public key must use canonical Base64" >&2; exit 78; }
rm -f "$DECODED_KEY"
DECODED_KEY=

ADDRESS=$(tr -d '\r\n' < "$ADDRESS_FILE")
input_has_canonical_framing "$ADDRESS_FILE" "$ADDRESS" || { echo "Client address has invalid framing" >&2; exit 78; }
printf '%s\n' "$ADDRESS" | grep -Eq '^10\.77\.0\.([2-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4])/32$' || { echo "Client address must be an allocatable 10.77.0.x/32" >&2; exit 78; }

# Parse identity and routing together, with the same inline comment boundary as
# AWG. Unknown syntax must not hide a peer from the collision checks below.
CONFIG_POLICY=$(awk '
  function trim(value) { sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); return value }
  function valid_key(value) {
    return length(value) == 44 && value ~ /^[A-Za-z0-9+\/]+=$/ && substr(value, 43, 1) ~ /^[AEIMQUYcgkosw048]$/
  }
  function finish_peer() { if (section == "peer" && (seen["publickey"] != 1 || seen["allowedips"] != 1)) bad=1 }
  {
    sub(/#.*/, "")
    line=trim($0)
    if (line == "") next
    if (line ~ /^\[/) {
      finish_peer()
      if (tolower(line) == "[interface]" && !interface_count && !peer_count) { section="interface"; interface_count++ }
      else if (tolower(line) == "[peer]" && interface_count == 1) { section="peer"; peer_count++ }
      else { bad=1; exit }
      for (item in seen) delete seen[item]
      next
    }
    at=index(line, "=")
    if (!at || section == "") { bad=1; exit }
    name=tolower(trim(substr(line, 1, at - 1))); value=trim(substr(line, at + 1))
    if (name !~ /^[a-z][a-z0-9]*$/ || value == "") { bad=1; exit }
    if (section == "interface") {
      if (name !~ /^(privatekey|listenport|fwmark|address|dns|mtu|jc|jmin|jmax|s[1-4]|h[1-4]|i[1-5]|headerprotectionkey)$/) { bad=1; exit }
      next
    }
    if (name !~ /^(publickey|presharedkey|allowedips|endpoint|persistentkeepalive)$/ || ++seen[name] != 1) { bad=1; exit }
    if (name == "publickey") {
      if (!valid_key(value) || known_keys[value]++) { bad=1; exit }
      print "key\t" value
    }
    if (name == "allowedips") {
      count=split(value, parts, ",")
      for (i=1; i<=count; i++) {
        cidr=trim(parts[i])
        if (cidr == "" || cidr ~ /[[:space:]]/) { bad=1; exit }
        print "cidr\t" cidr
      }
    }
  }
  END { finish_peer(); if (bad || interface_count != 1) exit 1 }
' "$CONFIG") || { echo "Velum persistent peer policy has unsupported or ambiguous syntax" >&2; exit 78; }
if printf '%s\n' "$CONFIG_POLICY" | awk -v key="$PUBLIC_KEY" '$1 == "key" && $2 == key { found=1 } END { exit !found }'; then
  echo "Client public key already exists" >&2
  exit 73
fi
CONFIG_ALLOWED_TOKENS=$(printf '%s\n' "$CONFIG_POLICY" | awk '$1 == "cidr" { print $2 }')

read_runtime_snapshot || { echo "Velum runtime peer state is not queryable" >&2; exit 69; }
RUNTIME_PEERS_BEFORE_SORTED=$(printf '%s\n' "$CURRENT_RUNTIME_PEERS" | normalize_lines)
RUNTIME_ALLOWED_BEFORE_SORTED=$(printf '%s\n' "$CURRENT_RUNTIME_ALLOWED" | normalize_lines)
RUNTIME_SNAPSHOTTED=1
PEERS_BEFORE=$(printf '%s\n' "$CURRENT_RUNTIME_PEERS" | awk 'NF { count++ } END { print count + 0 }')
if printf '%s\n' "$CURRENT_RUNTIME_PEERS" | grep -Fxq "$PUBLIC_KEY"; then
  echo "Client public key already exists at runtime" >&2
  exit 73
fi
RUNTIME_ALLOWED_TOKENS=$(printf '%s\n' "$CURRENT_RUNTIME_ALLOWED" | awk '
  NF {
    if (NF < 2 || length($1) != 44 || $1 !~ /^[A-Za-z0-9+\/]+=$/ || seen[$1]++) { bad=1; exit }
    if (NF == 2 && $2 == "(none)") next
    for (i=2; i<=NF; i++) {
      count=split($i, parts, ",")
      for (j=1; j<=count; j++) { if (parts[j] == "") { bad=1; exit }; print parts[j] }
    }
  }
  END { if (bad) exit 1 }
') || { echo "Velum runtime AllowedIPs have unsupported or ambiguous syntax" >&2; exit 69; }
if { printf '%s\n' "$CONFIG_ALLOWED_TOKENS"; printf '%s\n' "$RUNTIME_ALLOWED_TOKENS"; } | allowed_tokens_contain_address "$ADDRESS"; then
  echo "Client address overlaps an existing persistent or runtime AllowedIP" >&2
  exit 73
else
  overlap_status=$?
  test "$overlap_status" = 1 || { echo "Velum peer policy requires valid unambiguous IPv4 CIDRs" >&2; exit 78; }
fi

BACKUP="$LOCK_DIR/velum0.conf.before"
install -m 0600 "$CONFIG" "$BACKUP"
sync -f "$BACKUP"
CONFIG_BEFORE_SHA=$(sha256sum "$CONFIG" | awk '{print $1}')
# awg-quick derives an interface name from the filename: 1-15 allowed
# characters followed by .conf. Reserve a short name atomically so a stale
# candidate is never overwritten and concurrent mutations remain locked out.
CANDIDATE=$(mktemp "$BASE/config/vaddXXXXXX.conf") || { echo "Could not reserve a peer candidate" >&2; exit 73; }
install -m 0600 "$CONFIG" "$CANDIDATE"
printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n' "$PUBLIC_KEY" "$ADDRESS" >> "$CANDIDATE"
if grep -Eiq '^[[:space:]]*(PreUp|PostUp|PreDown|PostDown|SaveConfig|Table)[[:space:]]*=' "$CANDIDATE"; then
  echo "Candidate config contains forbidden directives" >&2
  exit 78
fi
docker exec velum-gateway awg-quick strip "/config/$(basename "$CANDIDATE")" >/dev/null 2>&1 || { echo "Candidate config was rejected" >&2; exit 78; }
CANDIDATE_SHA=$(sha256sum "$CANDIDATE" | awk '{print $1}')
sync -f "$CANDIDATE"
write_phase candidate-validated

# Commit the validated persistent policy before authorizing the peer at runtime.
# A hard process crash can therefore never leave a runtime-only authorization.
PERSISTED=1
mv -f "$CANDIDATE" "$CONFIG"
CANDIDATE=
sync -f "$CONFIG"
test "$(sha256sum "$CONFIG" | awk '{print $1}')" = "$CANDIDATE_SHA"
test "$(stat -c '%a' "$CONFIG")" = 600 && test "$(stat -c '%u' "$CONFIG")" = 0
write_phase persistent-committed

RUNTIME_APPLIED=1
docker exec velum-gateway awg set velum0 peer "$PUBLIC_KEY" allowed-ips "$ADDRESS" >/dev/null
read_runtime_snapshot || { echo "Velum runtime postcondition is not queryable" >&2; exit 69; }
test "$(printf '%s\n' "$CURRENT_RUNTIME_PEERS" | awk 'NF { count++ } END { print count + 0 }')" -eq $((PEERS_BEFORE + 1))
printf '%s\n' "$CURRENT_RUNTIME_PEERS" | grep -Fxq "$PUBLIC_KEY"
test "$(printf '%s\n' "$CURRENT_RUNTIME_PEERS" | awk -v key="$PUBLIC_KEY" 'NF && $0 != key' | normalize_lines)" = "$RUNTIME_PEERS_BEFORE_SORTED"
test "$(printf '%s\n' "$CURRENT_RUNTIME_ALLOWED" | awk -v key="$PUBLIC_KEY" 'NF && $1 != key' | normalize_lines)" = "$RUNTIME_ALLOWED_BEFORE_SORTED"
printf '%s\n' "$CURRENT_RUNTIME_ALLOWED" | awk -v key="$PUBLIC_KEY" -v address="$ADDRESS" '
  $1 == key { count++; if (NF == 2 && $2 == address) exact=1 }
  END { exit !(count == 1 && exact) }
'
write_phase runtime-applied

test "$(sha256sum "$CONFIG" | awk '{print $1}')" = "$CANDIDATE_SHA"
test "$(docker inspect -f '{{.State.Health.Status}}' velum-gateway)" = healthy
test "$(docker inspect -f '{{.Id}}' amnezia-awg2)" = "$AMNEZIA_ID"
test "$(docker inspect -f '{{.State.StartedAt}}' amnezia-awg2)" = "$AMNEZIA_STARTED"
docker exec amnezia-awg2 awg show awg0 >/dev/null 2>&1

write_phase committed
trap '' HUP INT TERM
SUCCESS=1
rm -f "$PUBLIC_KEY_FILE" "$ADDRESS_FILE" || echo "Velum peer staging requires manual cleanup" >&2
rmdir "$STAGE" || echo "Velum peer staging directory requires manual cleanup" >&2
release_locks || echo "Velum mutation locks require manual cleanup" >&2
trap - EXIT HUP INT TERM
echo "VELUM_PEER_ADDED $ADDRESS"
