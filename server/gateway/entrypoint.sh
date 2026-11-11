#!/bin/sh
set -eu
export LC_ALL=C

INTERFACE=${VELUM_INTERFACE:-velum0}
case "$INTERFACE" in
  *[!a-zA-Z0-9_.-]*|'') echo "Invalid interface name" >&2; exit 78 ;;
esac
CONFIG="/config/${INTERFACE}.conf"
VPN_SUBNET=${VELUM_VPN_SUBNET:-10.77.0.0/24}
RESOLVER_IP=${VELUM_RESOLVER_IP:-172.30.77.3}

# This container owns its network namespace. Close forwarding before inspecting
# configuration or touching a possibly stale interface. An inserted first rule
# also blocks stale ACCEPT rules; the DROP policy survives later chain rebuilds.
block_forwarding() {
  iptables -w 5 -I FORWARD 1 -m comment --comment velum-lifecycle-block -j DROP || return 1
  iptables -w 5 -P FORWARD DROP || return 1
  ip6tables -w 5 -I FORWARD 1 -j DROP || return 1
  ip6tables -w 5 -P FORWARD DROP || return 1
}

cleanup() {
  trap - EXIT
  trap '' HUP INT TERM
  cleanup_failed=0
  block_forwarding || cleanup_failed=1
  if ip link show dev "$INTERFACE" >/dev/null 2>&1; then
    # Link-down is an additional safety boundary if awg-quick teardown fails.
    ip link set dev "$INTERFACE" down || cleanup_failed=1
    awg-quick down "$CONFIG" >/dev/null 2>&1 || cleanup_failed=1
  fi
  # Never remove the deny policy or the filtering chains during teardown.
  # A failed teardown therefore retains its restrictions until namespace exit.
  if test "$cleanup_failed" != 0; then
    echo "Velum teardown incomplete; forwarding restrictions were retained" >&2
  fi
  return 0
}

handle_signal() {
  code=$1
  cleanup
  exit "$code"
}
trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

block_forwarding || { echo "Cannot establish fail-closed forwarding policy" >&2; exit 70; }
test -r "$CONFIG" || { echo "Velum gateway configuration is missing" >&2; exit 78; }
test -c /dev/net/tun || { echo "/dev/net/tun is unavailable" >&2; exit 78; }
test "$VPN_SUBNET" = 10.77.0.0/24 || { echo "Unexpected VPN subnet" >&2; exit 78; }
case "$RESOLVER_IP" in
  172.30.77.3|172.30.78.3) ;;
  *) echo "Unexpected resolver address" >&2; exit 78 ;;
esac
if grep -Eiq '^[[:space:]]*(PreUp|PostUp|PreDown|PostDown|SaveConfig|Table)[[:space:]]*=' "$CONFIG"; then
  echo "Unsafe awg-quick directives are forbidden" >&2
  exit 78
fi
if ! awk '
  /^[[:space:]]*($|#|;)/ { next }
  index($0, "=") == 0 { next }
  {
    split($0, pair, "=")
    key = tolower(pair[1])
    gsub(/[[:space:]]/, "", key)
    value = pair[2]
    gsub(/[[:space:]]/, "", value)
    if (key == "headerprotectionkey") {
      header_count++
    }
    if (key ~ /^s[1-4]$/) {
      split(value, bounds, "-")
      count[key]++
      if (bounds[1] !~ /^[0-9]+$/ || bounds[1] + 0 < 12) invalid[key] = 1
    }
  }
  END {
    if (header_count == 0) exit 0
    if (header_count != 1) exit 1
    for (slot = 1; slot <= 4; slot++) {
      key = "s" slot
      if (count[key] != 1 || invalid[key]) exit 1
    }
  }
' "$CONFIG"; then
  echo "Header protection requires one S1-S4 directive with a minimum of 12" >&2
  exit 78
fi

# /run is mounted as tmpfs at container start, so directories created in the
# image layer are intentionally hidden. Recreate the private userspace socket
# directory after the mount exists.
umask 077
mkdir -p /run/amneziawg
chmod 0700 /run/amneziawg

case "${VELUM_EGRESS_INTERFACE:-auto}" in
  auto) EGRESS=$(ip -4 route show default | awk 'NR==1 { for (i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit } }') ;;
  *[!a-zA-Z0-9_.:-]*) echo "Invalid egress interface" >&2; exit 78 ;;
  *) EGRESS=$VELUM_EGRESS_INTERFACE ;;
esac
test -n "$EGRESS" || { echo "Default egress interface not found" >&2; exit 78; }

# A restart in a retained namespace may still have an interface and old rules.
# Stop that interface under the barrier, then build all rules with DROP default.
if ip link show dev "$INTERFACE" >/dev/null 2>&1; then
  ip link set dev "$INTERFACE" down
  awg-quick down "$CONFIG"
fi
iptables -w 5 -F FORWARD
iptables -w 5 -A FORWARD -m comment --comment velum-lifecycle-block -j DROP
iptables -w 5 -N VELUM-FWD 2>/dev/null || iptables -w 5 -F VELUM-FWD
iptables -w 5 -A VELUM-FWD -d "$RESOLVER_IP" -p udp --dport 53 -j ACCEPT
iptables -w 5 -A VELUM-FWD -d "$RESOLVER_IP" -p tcp --dport 53 -j ACCEPT
for destination in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
  iptables -w 5 -A VELUM-FWD -d "$destination" -j DROP
done
iptables -w 5 -A VELUM-FWD -o "$EGRESS" -j ACCEPT
iptables -w 5 -A VELUM-FWD -j DROP
iptables -w 5 -A FORWARD -i "$INTERFACE" -j VELUM-FWD
iptables -w 5 -A FORWARD -o "$INTERFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -w 5 -t nat -C POSTROUTING -s "$VPN_SUBNET" -o "$EGRESS" -j MASQUERADE 2>/dev/null || iptables -w 5 -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$EGRESS" -j MASQUERADE

# Enabling forwarding is the final commit: partial rule construction and even a
# partially successful interface startup remain behind the lifecycle barrier.
awg-quick up "$CONFIG"
iptables -w 5 -D FORWARD -m comment --comment velum-lifecycle-block -j DROP

while awg show "$INTERFACE" >/dev/null 2>&1; do sleep 5; done
exit 1
