#!/usr/bin/env bash
# dockfence integration tests (PLAN §12) — run ON a Linux Docker host.
# Usage: sudo bash scripts/test.sh [--mode enforcing|monitor]
set -euo pipefail

MODE=${1:-}
COMPOSE="docker compose"
DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$DIR"

NET=dfwtest
# test containers must opt in with the SAME label key the firewall watches
TAG=$(grep -oP 'FW_LABEL: *\K\S+' compose.yaml 2>/dev/null || echo dockfence)
PASS=0; FAIL=0

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1  ($2)"; fi; }

# dockfence CLI helpers
FW=http://127.0.0.1:8420
TOKEN=$(grep -oP 'UI/API token: \K\S*' data/dockfence.log 2>/dev/null || true)
if [ -z "$TOKEN" ]; then TOKEN=$(docker compose logs dockfence 2>/dev/null | grep -oP 'UI/API token: \K\S*' | tail -1); fi
H="Authorization: Bearer $TOKEN"

api() { curl -sS -H "$H" "$@"; }

setup() {
  docker network create "$NET" >/dev/null 2>&1 || true
  if [ -n "$MODE" ]; then
    sed -i "s/FW_MODE: .*/FW_MODE: $MODE/" compose.yaml
  fi
  $COMPOSE up -d --build --quiet-build 2>/dev/null || $COMPOSE up -d --build
  sleep 3
  # test containers: two tagged, one untagged; restart policy so they
  # survive a docker daemon restart (step 6)
  docker rm -f dfw-web dfw-db dfw-curl >/dev/null 2>&1 || true
  docker run -d --restart unless-stopped --name dfw-web  --network "$NET" --label "$TAG=web"  nginx:alpine  >/dev/null
  docker run -d --restart unless-stopped --name dfw-db   --network "$NET" --label "$TAG=db"   busybox sleep infinity >/dev/null
  docker run -d --restart unless-stopped --name dfw-curl --network "$NET" busybox sleep infinity >/dev/null
  sleep 35  # > reconcile interval
}

# net helpers
run() { docker exec "$@"; }
setup
web_ip=$(docker inspect -f '{{.NetworkSettings.Networks.'"$NET"'.IPAddress}}' dfw-web)
db_ip=$(docker inspect -f '{{.NetworkSettings.Networks.'"$NET"'.IPAddress}}' dfw-db)

blocked_out() { ! run -u 0 dfw-db nc -w 2 -z "$1" "$2" >/dev/null 2>&1; }

say "1. untagged container is untouched (reaches the internet)"
check "untagged egress works" \
  "run dfw-curl ping -c1 -W2 8.8.8.8 >/dev/null"

say "2. tagged containers default-deny in and out (incl. container<->container)"
check "tagged egress blocked (db->web:80)"     "blocked_out $web_ip 80"
check "tagged ingress blocked (curl->web:80)"  "blocked_out $web_ip 80"
check "tagged direct DNS out blocked"          "blocked_out 8.8.8.8 53"
check "untagged->tagged:80 blocked (dual consent)" "blocked_out $web_ip 80"

say "3. adding a rule opens the flow; disabling closes it"
RULE=$(api -X POST "http://127.0.0.1:8420/api/containers/dfw-db/rules" \
  -H 'Content-Type: application/json' \
  -d "{\"direction\":\"out\",\"proto\":\"tcp\",\"port\":80,\"cidr\":\"$web_ip/32\",\"action\":\"accept\"}")
RID=$(echo "$RULE" | grep -oP '"id":\K[0-9]+')
check "rule accepted" "[ -n "$RID" ]"
sleep 2
check "egress to web:80 now allowed" "run dfw-db nc -w2 -z $web_ip 80"
api -X PATCH "http://127.0.0.1:8420/api/rules/$RID" -H 'Content-Type: application/json' -d '{"enabled":false}' >/dev/null
sleep 2
check "disabled rule closes the flow again" "blocked_out $web_ip 80"
api -X DELETE "http://127.0.0.1:8420/api/rules/$RID" >/dev/null

say "4. each blocked attempt produces exactly one log row"
BEFORE=$(api "http://127.0.0.1:8420/api/containers/dfw-db/logs?limit=1&offset=0" | grep -oP '"id":\K[0-9]+' | head -1 || echo 0)
run dfw-db nc -w1 -z 8.8.8.8 53 >/dev/null 2>&1 || true
sleep 3
AFTER=$(api "http://127.0.0.1:8420/api/containers/dfw-db/logs?limit=100" | grep -cE '"dst": *"8.8.8.8"')
check "blocked attempt logged" "[ "$AFTER" -ge 1 ]"

say "5. container recreation keeps its rules (policy binding)"
api -X POST "http://127.0.0.1:8420/api/containers/dfw-db/rules" -H 'Content-Type: application/json' \
  -d "{\"direction\":\"out\",\"proto\":\"tcp\",\"port\":1234,\"action\":\"accept\"}" >/dev/null
docker rm -f dfw-db >/dev/null
docker run -d --name dfw-db --network "$NET" --label "$TAG=db" busybox sleep infinity >/dev/null
sleep 35
check "rule follows policy after recreate" \
  "api http://127.0.0.1:8420/api/containers/dfw-db/rules | grep -qE '\"port\": *1234'"

say "6. docker restart: untagged unaffected, tagged still denied"
# OPT-IN: restarting the daemon disturbs every container on this host.
# Run with DFW_RESTART_DOCKER=1 only on a dedicated test host.
if [ "${DFW_RESTART_DOCKER:-0}" = "1" ] && command -v systemctl >/dev/null && systemctl is-active --quiet docker; then
  systemctl restart docker
  sleep 10
  $COMPOSE start 2>/dev/null || docker start dockfence >/dev/null 2>&1 || true
  sleep 10
  check "untagged still reaches internet" "run dfw-curl ping -c1 -W2 8.8.8.8 >/dev/null"
  check "tagged still default-deny" "blocked_out $web_ip 80"
else
  printf '  SKIP (set DFW_RESTART_DOCKER=1; restarts the docker daemon — dedicated test host only)\n'
fi

say "7. firewall container restart: rules persist (fail-closed)"
docker restart dockfence >/dev/null
sleep 8
check "tagged still default-deny after fw restart" "blocked_out $web_ip 80"

say "8. monitor mode passes traffic but logs everything"
if [ "${MODE:-}" = "monitor" ]; then
  check "monitor: tagged egress allowed" "run dfw-db nc -w2 -z $web_ip 80"
  check "monitor: still logged" "api 'http://127.0.0.1:8420/api/containers/dfw-db/logs?limit=5' | grep -q ."
else
  printf '  SKIP (run with --mode monitor)\n'
fi

say "9. docker's own firewall rules untouched"
# iptables-save embeds volatile policy counters and timestamps — compare rules only
RULES() { iptables-save | grep -vE '^#|^:' | sort; }
R1=$(RULES)
api -X POST http://127.0.0.1:8420/api/resync >/dev/null
sleep 1
R2=$(RULES)
check "iptables rules identical across resync" '[ "$R1" = "$R2" ]'

say "10. anti-exfiltration: egress filtering + deny-private-out ordering"
api -X POST "http://127.0.0.1:8420/api/containers/dfw-db/presets/web-out" >/dev/null
sleep 2
check "web-out: public egress 443 allowed"        "run dfw-db nc -w2 -z 1.1.1.1 443"
check "web-out: private dst allowed (broad rule)" "run dfw-db nc -w2 -z $web_ip 80"
api -X POST "http://127.0.0.1:8420/api/containers/dfw-db/presets/deny-private-out" >/dev/null
sleep 2
check "deny-private-out closes private dst despite broad allow" "blocked_out $web_ip 80"
check "public 443 still allowed after deny-private" "run dfw-db nc -w2 -z 1.1.1.1 443"
run dfw-db nc -w1 -z 10.99.99.99 445 >/dev/null 2>&1 || true
sleep 3
check "exfil attempt to private range logged (dir=out)" \
  "api 'http://127.0.0.1:8420/api/containers/dfw-db/logs?direction=out&limit=50' | grep -qE '\"dst\": *\"10.99.99.99\"'"
# cleanup so re-runs start clean (preset rules are removed identically)
api -X DELETE "http://127.0.0.1:8420/api/containers/dfw-db/presets/web-out" >/dev/null
api -X DELETE "http://127.0.0.1:8420/api/containers/dfw-db/presets/deny-private-out" >/dev/null
sleep 2
check "preset cleanup: egress closed again" "blocked_out 1.1.1.1 443"

say "summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
