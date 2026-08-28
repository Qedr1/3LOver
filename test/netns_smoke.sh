#!/usr/bin/env bash
# Функциональный smoke-тест l3overlay на двух netns.
# Доказывает: сборку, связность overlay в обе стороны, лог "peer unavailable"
# с корректным endpoint после ICMP-инжекции, итоговые счётчики дропов,
# отсутствие ошибок записи в TUN.
# Требования: root, iproute2, go, ping. Запуск: bash test/netns_smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d /tmp/l3ov-smoke.XXXXXX)"
BIN="$TMP/l3overlay"
NS1=smoke1; NS2=smoke2
P1=18555; P2=28555

log()  { echo "[smoke] $*"; }
fail() { echo "[smoke][FAIL] $*" >&2; exit 1; }

preclean() {
  set +e
  pkill -TERM -f "$BIN" 2>/dev/null
  ip netns del "$NS1" 2>/dev/null
  ip netns del "$NS2" 2>/dev/null
  set -e
}

cleanup() {
  set +e
  pkill -TERM -f "$BIN" 2>/dev/null
  sleep 0.3
  ip netns del "$NS1" 2>/dev/null
  ip netns del "$NS2" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || fail "нужен root"
command -v ip >/dev/null || fail "нужен iproute2"

# VNET_HDR=1 — прогон в режиме virtio vnet_hdr + TSO.
VNET_LINE=""
[ "${VNET_HDR:-0}" = "1" ] && VNET_LINE="vnet_hdr = true"

log "сборка $BIN"
(cd "$ROOT" && go build -o "$BIN" .)

preclean
ip netns add "$NS1"
ip netns add "$NS2"
ip link add veth-s1 mtu 9000 type veth peer name veth-s2 mtu 9000
ip link set veth-s1 netns "$NS1"
ip link set veth-s2 netns "$NS2"
ip netns exec "$NS1" ip addr add 172.31.0.1/30 dev veth-s1
ip netns exec "$NS2" ip addr add 172.31.0.2/30 dev veth-s2
ip netns exec "$NS1" ip link set veth-s1 up
ip netns exec "$NS2" ip link set veth-s2 up
ip netns exec "$NS1" ip link set lo up
ip netns exec "$NS2" ip link set lo up

cat >"$TMP/ns1.toml" <<EOF
[tun]
name = "tunA"
addr = "10.10.0.1/24"
link_mtu = 9000
add_route = true
mtu = 8972
$VNET_LINE
[transport]
listen = "172.31.0.1:$P1"
[map]
path = "$TMP/ns1-peers.toml"
[batch]
warmup = "200ms"
[log]
level = "info"
EOF
cat >"$TMP/ns2.toml" <<EOF
[tun]
name = "tunB"
addr = "10.10.0.2/24"
link_mtu = 9000
add_route = true
mtu = 8972
$VNET_LINE
[transport]
listen = "172.31.0.2:$P2"
[map]
path = "$TMP/ns2-peers.toml"
[batch]
warmup = "200ms"
[log]
level = "info"
EOF
cat >"$TMP/ns1-peers.toml" <<EOF
[peers]
"10.10.0.2" = "172.31.0.2:$P2"
EOF
cat >"$TMP/ns2-peers.toml" <<EOF
[peers]
"10.10.0.1" = "172.31.0.1:$P1"
EOF

ip netns exec "$NS1" "$BIN" -config "$TMP/ns1.toml" >"$TMP/ov1.log" 2>&1 &
ip netns exec "$NS2" "$BIN" -config "$TMP/ns2.toml" >"$TMP/ov2.log" 2>&1 &
sleep 2
pgrep -f "$BIN" >/dev/null || { cat "$TMP/ov1.log" "$TMP/ov2.log"; fail "сервис не стартовал"; }

log "ping 10.10.0.2 из $NS1"
ip netns exec "$NS1" ping -c 3 -W 1 10.10.0.2 >/dev/null || { cat "$TMP/ov1.log" "$TMP/ov2.log"; fail "ping direct"; }
log "ping 10.10.0.1 из $NS2"
ip netns exec "$NS2" ping -c 3 -W 1 10.10.0.1 >/dev/null || { cat "$TMP/ov1.log" "$TMP/ov2.log"; fail "ping reverse"; }

log "ICMP-инжекция: остановка $NS2, трафик из $NS1"
pkill -TERM -f "config $TMP/ns2.toml" || fail "не удалось остановить $NS2"
sleep 1
ip netns exec "$NS1" ping -c 3 -W 1 10.10.0.2 >/dev/null 2>&1 || true
sleep 1
grep -q "peer unavailable" "$TMP/ov1.log" || { cat "$TMP/ov1.log"; fail "нет peer unavailable после инжекции"; }
grep -q "172.31.0.2:$P2" "$TMP/ov1.log" || { cat "$TMP/ov1.log"; fail "peer unavailable без endpoint 172.31.0.2:$P2"; }

log "остановка $NS1, проверка итоговых логов"
pkill -TERM -f "config $TMP/ns1.toml" 2>/dev/null
sleep 1
! grep -q "tun write" "$TMP/ov1.log" || { cat "$TMP/ov1.log"; fail "ошибки tun write в ov1.log"; }
! grep -q "tun write" "$TMP/ov2.log" || { cat "$TMP/ov2.log"; fail "ошибки tun write в ov2.log"; }
grep -q "pipeline stats" "$TMP/ov1.log" || { cat "$TMP/ov1.log"; fail "нет pipeline stats в ov1.log"; }
grep -q "unknown_dst" "$TMP/ov1.log" || { cat "$TMP/ov1.log"; fail "нет счётчика unknown_dst в ov1.log"; }

log "OK: все проверки прошли"
