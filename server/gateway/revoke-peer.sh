#!/bin/sh
set -eu
export LC_ALL=C

# Revoke exactly one simple Velum peer. The staged identity is public data, but
# it is still accepted only from the fixed root-only staging directory. This
# script never accepts a client private key and never changes Amnezia.
BASE=/opt/velum
CONFIG="$BASE/config/velum0.conf"
STAGE="$BASE/peer-staging"
PUBLIC_KEY_FILE="$STAGE/public.key"
ADDRESS_FILE="$STAGE/address"
LOCK_DIR="$BASE/.mutation.lock"
LEGACY_LOCK_DIR="$BASE/.upgrade.lock"
SUCCESS=0
LOCK_HELD=0
LEGACY_LOCK_HELD=0
BASELINE_READY=0
RUNTIME_MUTATION_STARTED=0
PERSIST_MUTATION_STARTED=0
BACKUP=
CANDIDATE=
DECODED_KEY=
RUNTIME_PEERS=
RUNTIME_ALLOWED=
RUNTIME_CURRENT=
RUNTIME_BASELINE=
RUNTIME_EXPECTED=
RUNTIME_PEER_KEYS=
RUNTIME_ALLOWED_KEYS=
RUNTIME_DUPLICATE_KEYS=
RUNTIME_ALLOWED_UNSORTED=
RUNTIME_PSK_CHECK=
RUNTIME_KEEPALIVE_CHECK=
PUBLIC_KEY=
ADDRESS=
ORIGINAL_CONFIG_SHA=
PEERS_BEFORE=0
RUNTIME_PEERS_BEFORE=0
AMNEZIA_ID=
AMNEZIA_STARTED=

release_locks() {
  if test "$LOCK_HELD" = 1; then
    rmdir "$LOCK_DIR" || return 1
    LOCK_HELD=0
  fi
  if test "$LEGACY_LOCK_HELD" = 1; then
    rmdir "$LEGACY_LOCK_DIR" || return 1
    LEGACY_LOCK_HELD=0
  fi
}

clean_lock_files() {
  cleanup_ok=1
  for temporary in \
    "$DECODED_KEY" "$RUNTIME_PEERS" "$RUNTIME_ALLOWED" "$RUNTIME_CURRENT" \
    "$RUNTIME_BASELINE" "$RUNTIME_EXPECTED" "$RUNTIME_PEER_KEYS" \
    "$RUNTIME_ALLOWED_KEYS" "$RUNTIME_DUPLICATE_KEYS" "$RUNTIME_ALLOWED_UNSORTED" \
    "$RUNTIME_PSK_CHECK" "$RUNTIME_KEEPALIVE_CHECK" "$BACKUP" "$CANDIDATE"; do
    test -z "$temporary" || rm -f "$temporary" || cleanup_ok=0
  done
  test "$cleanup_ok" = 1
}

file_sha256() {
  digest_line=$(sha256sum "$1") || return 1
  digest=${digest_line%% *}
  test "${#digest}" -eq 64 || return 1
  printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s\n' "$digest"
}

peer_section_count() {
  awk '
    {
      line=$0
      sub(/#.*/, "", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (tolower(line) == "[peer]") count++
    }
    END { print count + 0 }
  ' "$1"
}

# Emit the source config without the staged peer only when that peer is a
# unique, unannotated block containing exactly PublicKey and AllowedIPs. The
# staged address must not be mapped by any other persistent peer.
config_without_exact_peer() {
  awk -v target_key="$PUBLIC_KEY" -v target_address="$ADDRESS" '
    function trim(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      return value
    }
    function ipv4_number(ip, octets, count, i, value, result) {
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
    function cidr_contains(cidr, target, fields, prefix, network, address, block, start) {
      if (split(cidr, fields, "/") != 2 || fields[2] !~ /^(0|[1-9][0-9]*)$/) { ambiguous=1; return 0 }
      prefix=fields[2] + 0
      if (prefix < 0 || prefix > 32) { ambiguous=1; return 0 }
      network=ipv4_number(fields[1]); address=ipv4_number(target)
      if (network < 0 || address < 0) { ambiguous=1; return 0 }
      block=2 ^ (32 - prefix)
      start=int(network / block) * block
      return address >= start && address < start + block
    }
    function reset_peer(  i) {
      for (i in peer_line) delete peer_line[i]
      for (i in field_seen) delete field_seen[i]
      peer_line_count=0
      peer_header=""
    }
    function flush_peer(  i, raw, parsed, separator, key, value, part_count, parts, j,
                            directive_count, public_count, allowed_count, public_value,
                            allowed_value, public_hit, address_hit, annotation_count,
                            malformed, exact_simple) {
      if (!in_peer) return
      peer_total++
      directive_count=0
      public_count=0
      allowed_count=0
      public_value=""
      allowed_value=""
      public_hit=0
      address_hit=0
      annotation_count=(index(peer_header, "#") != 0)
      malformed=0
      for (i=1; i<=peer_line_count; i++) {
        raw=peer_line[i]
        parsed=trim(raw)
        if (parsed == "") continue
        if (substr(parsed, 1, 1) == "#") {
          annotation_count++
          continue
        }
        if (index(parsed, "#")) annotation_count++
        sub(/#.*/, "", parsed)
        parsed=trim(parsed)
        separator=index(parsed, "=")
        if (!separator) {
          malformed=1
          continue
        }
        key=tolower(trim(substr(parsed, 1, separator - 1)))
        value=trim(substr(parsed, separator + 1))
        directive_count++
        if (key !~ /^(publickey|presharedkey|allowedips|endpoint|persistentkeepalive)$/ || value == "" || ++field_seen[key] != 1) malformed=1
        if (key == "publickey") {
          public_count++
          public_value=value
          if (length(value) != 44 || value !~ /^[A-Za-z0-9+\/]+=$/ || substr(value, 43, 1) !~ /^[AEIMQUYcgkosw048]$/ || known_keys[value]++) malformed=1
          if (value == target_key) public_hit=1
        } else if (key == "allowedips") {
          allowed_count++
          allowed_value=value
          part_count=split(value, parts, ",")
          for (j=1; j<=part_count; j++) {
            if (cidr_contains(trim(parts[j]), target_ip)) address_hit=1
          }
        }
      }
      if (malformed || public_count != 1 || allowed_count != 1) ambiguous=1
      if (public_hit) public_blocks++
      if (address_hit) address_blocks++
      exact_simple = !malformed && annotation_count == 0 && directive_count == 2 && \
        public_count == 1 && allowed_count == 1 && public_value == target_key && \
        allowed_value == target_address
      if (exact_simple) {
        exact_blocks++
      } else {
        print peer_header
        for (i=1; i<=peer_line_count; i++) print peer_line[i]
      }
      reset_peer()
      in_peer=0
    }
    BEGIN { split(target_address, target_parts, "/"); target_ip=target_parts[1] }
    {
      section=trim($0)
      sub(/#.*/, "", section)
      section=trim(section)
      if (section ~ /^\[[^]]+\]$/) {
        flush_peer()
        if (tolower(section) == "[peer]" && interface_count == 1) {
          in_peer=1
          peer_header=$0
          next
        }
        if (tolower(section) != "[interface]" || interface_count || peer_total) ambiguous=1
        interface_count++
        print
        next
      }
      if (in_peer) {
        peer_line[++peer_line_count]=$0
      } else {
        if (section != "") {
          separator=index(section, "=")
          name=tolower(trim(substr(section, 1, separator - 1)))
          if (!interface_count || !separator || name !~ /^(privatekey|listenport|fwmark|address|dns|mtu|jc|jmin|jmax|s[1-4]|h[1-4]|i[1-5]|headerprotectionkey)$/) ambiguous=1
        }
        print
      }
    }
    END {
      flush_peer()
      if (ambiguous || interface_count != 1 || public_blocks != 1 || address_blocks != 1 || exact_blocks != 1) exit 42
    }
  ' "$1"
}

persistent_target_absent() {
  awk -v target_key="$PUBLIC_KEY" -v target_address="$ADDRESS" '
    function trim(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      return value
    }
    function ipv4_number(ip, octets, count, i, value, result) {
      count=split(ip, octets, ".")
      if (count != 4) return -1
      result=0
      for (i=1; i<=4; i++) {
        if (octets[i] !~ /^[0-9]+$/) return -1
        value=octets[i] + 0
        if (value < 0 || value > 255) return -1
        result=(result * 256) + value
      }
      return result
    }
    function cidr_contains(cidr, target, fields, prefix, network, address, block, start) {
      if (split(cidr, fields, "/") != 2 || fields[2] !~ /^[0-9]+$/) return 0
      prefix=fields[2] + 0
      if (prefix < 0 || prefix > 32) return 0
      network=ipv4_number(fields[1]); address=ipv4_number(target)
      if (network < 0 || address < 0) return 0
      block=2 ^ (32 - prefix)
      start=int(network / block) * block
      return address >= start && address < start + block
    }
    BEGIN { split(target_address, target_parts, "/"); target_ip=target_parts[1] }
    {
      line=trim($0)
      sub(/#.*/, "", line)
      line=trim(line)
      if (line ~ /^\[[^]]+\]$/) {
        in_peer=(tolower(line) == "[peer]")
        next
      }
      if (!in_peer || line == "" || substr(line, 1, 1) == "#" || substr(line, 1, 1) == ";") next
      separator=index(line, "=")
      if (!separator) next
      key=tolower(trim(substr(line, 1, separator - 1)))
      value=trim(substr(line, separator + 1))
      sub(/[[:space:]]*[#;].*$/, "", value)
      gsub(/[[:space:]]/, "", value)
      if (key == "publickey" && value == target_key) public_hits++
      if (key == "allowedips") {
        count=split(value, parts, ",")
        for (i=1; i<=count; i++) if (cidr_contains(parts[i], target_ip)) address_hits++
      }
    }
    END { exit !((public_hits + 0) == 0 && (address_hits + 0) == 0) }
  ' "$1"
}

capture_runtime_mapping() {
  destination=$1
  docker exec velum-gateway awg show velum0 peers > "$RUNTIME_PEERS" || return 1
  docker exec velum-gateway awg show velum0 allowed-ips > "$RUNTIME_ALLOWED" || return 1
  chmod 0600 "$RUNTIME_PEERS" "$RUNTIME_ALLOWED" || return 1
  sort "$RUNTIME_PEERS" > "$RUNTIME_PEER_KEYS" || return 1
  awk '
    {
      key=$1
      $1=""
      value=$0
      gsub(/[[:space:]]/, "", value)
      if (key == "" || value == "") invalid=1
      print key "|" value
    }
    END { if (invalid) exit 1 }
  ' "$RUNTIME_ALLOWED" > "$RUNTIME_ALLOWED_UNSORTED" || return 1
  sort "$RUNTIME_ALLOWED_UNSORTED" > "$destination" || return 1
  chmod 0600 "$destination" || return 1
  awk -F '|' '{ print $1 }' "$destination" > "$RUNTIME_ALLOWED_KEYS" || return 1
  test "$(wc -l < "$RUNTIME_PEER_KEYS")" -eq "$(wc -l < "$RUNTIME_ALLOWED_KEYS")" || return 1
  cmp -s "$RUNTIME_PEER_KEYS" "$RUNTIME_ALLOWED_KEYS" || return 1
  uniq -d "$RUNTIME_PEER_KEYS" > "$RUNTIME_DUPLICATE_KEYS" || return 1
  test ! -s "$RUNTIME_DUPLICATE_KEYS" || return 1
  rm -f "$RUNTIME_PEER_KEYS" "$RUNTIME_ALLOWED_KEYS" "$RUNTIME_DUPLICATE_KEYS" "$RUNTIME_ALLOWED_UNSORTED" || return 1
}

runtime_target_is_exact() {
  mapping=$1
  test "$(grep -Fxc "$PUBLIC_KEY|$ADDRESS" "$mapping" || true)" -eq 1 || return 1
  awk -F '|' -v target_key="$PUBLIC_KEY" -v target_address="$ADDRESS" '
    function ipv4_number(ip, octets, count, i, value, result) {
      count=split(ip, octets, ".")
      if (count != 4) return -1
      result=0
      for (i=1; i<=4; i++) {
        if (octets[i] !~ /^[0-9]+$/) return -1
        value=octets[i] + 0
        if (value < 0 || value > 255) return -1
        result=(result * 256) + value
      }
      return result
    }
    function cidr_contains(cidr, target, fields, prefix, network, address, block, start) {
      if (split(cidr, fields, "/") != 2 || fields[2] !~ /^[0-9]+$/) return 0
      prefix=fields[2] + 0
      if (prefix < 0 || prefix > 32) return 0
      network=ipv4_number(fields[1]); address=ipv4_number(target)
      if (network < 0 || address < 0) return 0
      block=2 ^ (32 - prefix)
      start=int(network / block) * block
      return address >= start && address < start + block
    }
    BEGIN { split(target_address, target_parts, "/"); target_ip=target_parts[1] }
    {
      key=$1
      value=$2
      if (key == target_key) {
        key_rows++
        if (value == target_address) exact_rows++
      }
      count=split(value, parts, ",")
      for (i=1; i<=count; i++) {
        if (cidr_contains(parts[i], target_ip)) address_rows++
      }
    }
    END { exit !(key_rows == 1 && exact_rows == 1 && address_rows == 1) }
  ' "$mapping" || return 1
  docker exec velum-gateway sh -eu -c '
    values=$(awg show velum0 "$2")
    printf "%s\n" "$values" | awk -v target_key="$1" -v expected="$3" '\''
      $1 == target_key { rows++; if ($2 != expected) invalid=1 }
      END { exit !(rows == 1 && !invalid) }
    '\''
    printf ok
  ' sh "$PUBLIC_KEY" preshared-keys '(none)' > "$RUNTIME_PSK_CHECK" || return 1
  docker exec velum-gateway sh -eu -c '
    values=$(awg show velum0 "$2")
    printf "%s\n" "$values" | awk -v target_key="$1" -v expected="$3" '\''
      $1 == target_key { rows++; if ($2 != expected) invalid=1 }
      END { exit !(rows == 1 && !invalid) }
    '\''
    printf ok
  ' sh "$PUBLIC_KEY" persistent-keepalive off > "$RUNTIME_KEEPALIVE_CHECK" || return 1
  chmod 0600 "$RUNTIME_PSK_CHECK" "$RUNTIME_KEEPALIVE_CHECK" || return 1
  test "$(cat "$RUNTIME_PSK_CHECK")" = ok || return 1
  test "$(cat "$RUNTIME_KEEPALIVE_CHECK")" = ok
}

runtime_target_absent() {
  mapping=$1
  awk -F '|' -v target_key="$PUBLIC_KEY" -v target_address="$ADDRESS" '
    function ipv4_number(ip, octets, count, i, value, result) {
      count=split(ip, octets, ".")
      if (count != 4) return -1
      result=0
      for (i=1; i<=4; i++) {
        if (octets[i] !~ /^[0-9]+$/) return -1
        value=octets[i] + 0
        if (value < 0 || value > 255) return -1
        result=(result * 256) + value
      }
      return result
    }
    function cidr_contains(cidr, target, fields, prefix, network, address, block, start) {
      if (split(cidr, fields, "/") != 2 || fields[2] !~ /^[0-9]+$/) return 0
      prefix=fields[2] + 0
      if (prefix < 0 || prefix > 32) return 0
      network=ipv4_number(fields[1]); address=ipv4_number(target)
      if (network < 0 || address < 0) return 0
      block=2 ^ (32 - prefix)
      start=int(network / block) * block
      return address >= start && address < start + block
    }
    BEGIN { split(target_address, target_parts, "/"); target_ip=target_parts[1] }
    {
      key=$1
      value=$2
      if (key == target_key) key_rows++
      count=split(value, parts, ",")
      for (i=1; i<=count; i++) if (cidr_contains(parts[i], target_ip)) address_rows++
    }
    END { exit !((key_rows + 0) == 0 && (address_rows + 0) == 0) }
  ' "$mapping"
}

amnezia_unchanged() {
  test -n "$AMNEZIA_ID" && test -n "$AMNEZIA_STARTED" || return 1
  test "$(docker inspect -f '{{.Id}}' amnezia-awg2)" = "$AMNEZIA_ID" || return 1
  test "$(docker inspect -f '{{.State.StartedAt}}' amnezia-awg2)" = "$AMNEZIA_STARTED" || return 1
  test "$(docker inspect -f '{{.State.Running}}' amnezia-awg2)" = true || return 1
  docker exec amnezia-awg2 awg show awg0 >/dev/null 2>&1
}

verify_structural_baseline() {
  test "$(file_sha256 "$CONFIG")" = "$ORIGINAL_CONFIG_SHA" || return 1
  test "$(peer_section_count "$CONFIG")" -eq "$PEERS_BEFORE" || return 1
  config_without_exact_peer "$CONFIG" >/dev/null || return 1
  capture_runtime_mapping "$RUNTIME_CURRENT" || return 1
  cmp -s "$RUNTIME_CURRENT" "$RUNTIME_BASELINE" || return 1
  test "$(wc -l < "$RUNTIME_CURRENT")" -eq "$RUNTIME_PEERS_BEFORE" || return 1
  runtime_target_is_exact "$RUNTIME_CURRENT" || return 1
  test "$(docker inspect -f '{{.State.Health.Status}}' velum-gateway)" = healthy || return 1
  amnezia_unchanged
}

rollback() {
  test "$SUCCESS" = 1 && return 0
  trap - EXIT
  trap '' HUP INT TERM
  rollback_ok=1

  if test "$PERSIST_MUTATION_STARTED" = 1; then
    if test -n "$BACKUP" && test -f "$BACKUP"; then
      if install -m 0600 "$BACKUP" "$BASE/config/.velum0.revoke-rollback"; then
        sync -f "$BASE/config/.velum0.revoke-rollback" || rollback_ok=0
        if test "$rollback_ok" = 1; then
          mv -f "$BASE/config/.velum0.revoke-rollback" "$CONFIG" || rollback_ok=0
        fi
        if test "$rollback_ok" = 1; then
          sync -f "$CONFIG" || rollback_ok=0
          sync -f "$BASE/config" || rollback_ok=0
        fi
      else
        rollback_ok=0
      fi
    else
      rollback_ok=0
    fi
  fi
  if test "$RUNTIME_MUTATION_STARTED" = 1; then
    docker exec velum-gateway awg set velum0 peer "$PUBLIC_KEY" allowed-ips "$ADDRESS" >/dev/null 2>&1 || rollback_ok=0
  fi
  if test "$BASELINE_READY" = 1; then
    verify_structural_baseline >/dev/null 2>&1 || rollback_ok=0
  fi

  if test "$rollback_ok" = 1; then
    clean_lock_files || rollback_ok=0
    if test "$rollback_ok" = 1; then
      release_locks || rollback_ok=0
    fi
  fi
  if test "$rollback_ok" = 1; then
    echo "VELUM_PEER_REVOKE_ROLLED_BACK" >&2
  else
    echo "VELUM_PEER_REVOKE_UNCERTAIN: mutation lock retained for manual review" >&2
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

test "$(id -u)" = 0 || { echo "Velum peer revocation must run as root" >&2; exit 77; }
umask 077
# Older upgrade scripts used a different lock and cannot safely coordinate with
# peer mutations. Deploy the common-lock upgrade/add scripts first, then ensure
# that no legacy operation remains before revocation is enabled.
for coordinator in "$BASE/upgrade.sh" "$BASE/add-peer.sh"; do
  test -f "$coordinator" && test ! -L "$coordinator" || { echo "Common-lock Velum coordinators must be deployed first" >&2; exit 73; }
  test "$(grep -Fxc 'LOCK_DIR="$BASE/.mutation.lock"' "$coordinator" || true)" -eq 1 || { echo "Velum coordinator does not use the common mutation lock" >&2; exit 73; }
done
if ! mkdir "$LEGACY_LOCK_DIR" 2>/dev/null; then
  echo "Legacy or interrupted Velum upgrade requires manual review" >&2
  exit 73
fi
LEGACY_LOCK_HELD=1
chmod 0700 "$LEGACY_LOCK_DIR"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Another or interrupted Velum peer operation requires manual review" >&2
  exit 73
fi
LOCK_HELD=1
chmod 0700 "$LOCK_DIR"

test -d "$STAGE" && test ! -L "$STAGE" || { echo "Velum peer staging is missing or unsafe" >&2; exit 78; }
test "$(stat -c '%a' "$STAGE")" = 700 && test "$(stat -c '%u' "$STAGE")" = 0 || { echo "Velum peer staging must be root-only" >&2; exit 78; }
test "$(find "$STAGE" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = "$(printf 'address\npublic.key')" || { echo "Velum peer staging contains unexpected entries" >&2; exit 78; }
for file in "$PUBLIC_KEY_FILE" "$ADDRESS_FILE"; do
  test -f "$file" && test ! -L "$file" || { echo "Velum peer input is missing or is a symlink" >&2; exit 78; }
  test "$(stat -c '%a' "$file")" = 600 && test "$(stat -c '%u' "$file")" = 0 && test "$(stat -c '%h' "$file")" = 1 || { echo "Velum peer input must be an unlinked root-owned mode 0600 file" >&2; exit 78; }
done
test -f "$CONFIG" && test ! -L "$CONFIG" && test "$(stat -c '%a' "$CONFIG")" = 600 && test "$(stat -c '%u' "$CONFIG")" = 0 && test "$(stat -c '%h' "$CONFIG")" = 1 || { echo "Velum server config must be an unlinked root-owned mode 0600 file" >&2; exit 78; }
test "$(stat -c '%u' "$BASE/config")" = 0 && test "$((0$(stat -c '%a' "$BASE/config") & 0022))" -eq 0 || { echo "Velum config directory must not be group/world writable" >&2; exit 78; }
test "$(docker inspect -f '{{.State.Health.Status}}' velum-gateway)" = healthy || { echo "Velum gateway is not healthy" >&2; exit 69; }
test "$(docker inspect -f '{{.State.Running}}' amnezia-awg2)" = true || { echo "Existing Amnezia is not running" >&2; exit 69; }
docker exec amnezia-awg2 awg show awg0 >/dev/null 2>&1 || { echo "Existing Amnezia interface is not queryable" >&2; exit 69; }

AMNEZIA_ID=$(docker inspect -f '{{.Id}}' amnezia-awg2)
AMNEZIA_STARTED=$(docker inspect -f '{{.State.StartedAt}}' amnezia-awg2)
PUBLIC_KEY=$(cat "$PUBLIC_KEY_FILE")
test -n "$PUBLIC_KEY" || { echo "Client public key has invalid framing" >&2; exit 78; }
if ! printf '%s' "$PUBLIC_KEY" | cmp -s - "$PUBLIC_KEY_FILE" && ! printf '%s\n' "$PUBLIC_KEY" | cmp -s - "$PUBLIC_KEY_FILE"; then
  echo "Client public key has invalid framing" >&2
  exit 78
fi
DECODED_KEY="$LOCK_DIR/client-public.bin"
printf '%s' "$PUBLIC_KEY" | base64 -d > "$DECODED_KEY" 2>/dev/null || { echo "Client public key is not valid Base64" >&2; exit 78; }
test "$(wc -c < "$DECODED_KEY")" = 32 || { echo "Client public key must decode to 32 bytes" >&2; exit 78; }
test "$(base64 -w 0 < "$DECODED_KEY")" = "$PUBLIC_KEY" || { echo "Client public key must use canonical Base64" >&2; exit 78; }
rm -f "$DECODED_KEY"
DECODED_KEY=

ADDRESS=$(cat "$ADDRESS_FILE")
if ! printf '%s' "$ADDRESS" | cmp -s - "$ADDRESS_FILE" && ! printf '%s\n' "$ADDRESS" | cmp -s - "$ADDRESS_FILE"; then
  echo "Client address has invalid framing" >&2
  exit 78
fi
printf '%s\n' "$ADDRESS" | grep -Eq '^10\.77\.0\.([2-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4])/32$' || { echo "Client address must be an allocatable 10.77.0.x/32" >&2; exit 78; }

PEERS_BEFORE=$(peer_section_count "$CONFIG")
test "$PEERS_BEFORE" -ge 1 || { echo "Persistent peer set is empty" >&2; exit 73; }
# Keep the basename compatible with awg-quick's 1-15 character interface
# names, and reserve it atomically without replacing a stale candidate.
CANDIDATE=$(mktemp "$BASE/config/vdelXXXXXX.conf") || { echo "Could not reserve a revoke candidate" >&2; exit 73; }
config_without_exact_peer "$CONFIG" > "$CANDIDATE" || { echo "Persistent peer mapping is ambiguous or not a simple exact peer" >&2; exit 73; }
chmod 0600 "$CANDIDATE"
sync -f "$CANDIDATE"
test "$(peer_section_count "$CANDIDATE")" -eq $((PEERS_BEFORE - 1)) || { echo "Candidate did not remove exactly one peer" >&2; exit 73; }
persistent_target_absent "$CANDIDATE" || { echo "Candidate still references the staged peer" >&2; exit 73; }
if grep -Eiq '^[[:space:]]*(PreUp|PostUp|PreDown|PostDown|SaveConfig|Table)[[:space:]]*=' "$CANDIDATE"; then
  echo "Candidate config contains forbidden directives" >&2
  exit 78
fi
docker exec velum-gateway awg-quick strip "/config/$(basename "$CANDIDATE")" >/dev/null 2>&1 || { echo "Candidate config was rejected" >&2; exit 78; }

RUNTIME_PEERS="$LOCK_DIR/runtime.peers"
RUNTIME_ALLOWED="$LOCK_DIR/runtime.allowed"
RUNTIME_CURRENT="$LOCK_DIR/runtime.current"
RUNTIME_BASELINE="$LOCK_DIR/runtime.baseline"
RUNTIME_EXPECTED="$LOCK_DIR/runtime.expected"
RUNTIME_PEER_KEYS="$LOCK_DIR/runtime.peer-keys.sorted"
RUNTIME_ALLOWED_KEYS="$LOCK_DIR/runtime.allowed-keys.sorted"
RUNTIME_DUPLICATE_KEYS="$LOCK_DIR/runtime.duplicate-keys"
RUNTIME_ALLOWED_UNSORTED="$LOCK_DIR/runtime.allowed.unsorted"
RUNTIME_PSK_CHECK="$LOCK_DIR/runtime.psk-check"
RUNTIME_KEEPALIVE_CHECK="$LOCK_DIR/runtime.keepalive-check"
capture_runtime_mapping "$RUNTIME_CURRENT"
install -m 0600 "$RUNTIME_CURRENT" "$RUNTIME_BASELINE"
sync -f "$RUNTIME_BASELINE"
RUNTIME_PEERS_BEFORE=$(wc -l < "$RUNTIME_BASELINE")
test "$RUNTIME_PEERS_BEFORE" -eq "$PEERS_BEFORE" || { echo "Persistent and runtime peer counts differ" >&2; exit 73; }
runtime_target_is_exact "$RUNTIME_BASELINE" || { echo "Runtime peer mapping is ambiguous or has non-restorable state" >&2; exit 73; }
awk -F '|' -v target_key="$PUBLIC_KEY" '$1 != target_key { print }' "$RUNTIME_BASELINE" > "$RUNTIME_EXPECTED"
chmod 0600 "$RUNTIME_EXPECTED"
sync -f "$RUNTIME_EXPECTED"
test "$(wc -l < "$RUNTIME_EXPECTED")" -eq $((RUNTIME_PEERS_BEFORE - 1)) || { echo "Expected runtime mapping did not remove exactly one peer" >&2; exit 73; }
runtime_target_absent "$RUNTIME_EXPECTED" || { echo "Expected runtime mapping still references the staged peer" >&2; exit 73; }

BACKUP="$LOCK_DIR/velum0.conf.before"
install -m 0600 "$CONFIG" "$BACKUP"
sync -f "$BACKUP"
ORIGINAL_CONFIG_SHA=$(file_sha256 "$CONFIG")
test "$(file_sha256 "$BACKUP")" = "$ORIGINAL_CONFIG_SHA"
BASELINE_READY=1

PERSIST_MUTATION_STARTED=1
mv -f "$CANDIDATE" "$CONFIG"
CANDIDATE=
sync -f "$CONFIG"
sync -f "$BASE/config"
test "$(stat -c '%a' "$CONFIG")" = 600 && test "$(stat -c '%u' "$CONFIG")" = 0 && test "$(stat -c '%h' "$CONFIG")" = 1
test "$(peer_section_count "$CONFIG")" -eq $((PEERS_BEFORE - 1))
persistent_target_absent "$CONFIG"
docker exec velum-gateway awg-quick strip "/config/$(basename "$CONFIG")" >/dev/null 2>&1

RUNTIME_MUTATION_STARTED=1
docker exec velum-gateway awg set velum0 peer "$PUBLIC_KEY" remove
capture_runtime_mapping "$RUNTIME_CURRENT"
cmp -s "$RUNTIME_CURRENT" "$RUNTIME_EXPECTED"
test "$(wc -l < "$RUNTIME_CURRENT")" -eq $((RUNTIME_PEERS_BEFORE - 1))
runtime_target_absent "$RUNTIME_CURRENT"

test "$(docker inspect -f '{{.State.Health.Status}}' velum-gateway)" = healthy
amnezia_unchanged

trap '' HUP INT TERM
SUCCESS=1
trap - EXIT
if ! rm -f "$PUBLIC_KEY_FILE" "$ADDRESS_FILE" || ! rmdir "$STAGE" || ! clean_lock_files || ! release_locks; then
  echo "VELUM_PEER_REVOKED_CLEANUP_UNCERTAIN: lock retained where possible" >&2
  exit 74
fi
trap - HUP INT TERM
echo "VELUM_PEER_REVOKED $ADDRESS"
