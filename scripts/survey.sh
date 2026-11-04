#!/usr/bin/env bash
# dockfence environment survey — run ON the target Docker host.
# Usage: sudo bash scripts/survey.sh | tee docs/env-survey-$(hostname).txt
set -u

section() { printf '\n== %s ==\n' "$1"; }
run()    { "$@" 2>&1 || echo "(failed: $*)"; }

section "host"
uname -a
head -2 /etc/os-release

section "nftables"
run nft --version
run nft list tables

section "kernel modules"
run lsmod | grep -E 'nf_tables|nfnetlink_log|nf_log' | head -10

section "iptables backend (nf_tables = iptables-nft)"
run iptables -V

section "docker"
run docker version
run docker info | grep -iE 'server version|iptables|nftab|swarm|cgroup|network driver'

section "docker networks"
run docker network ls
run docker network inspect bridge --format '{{json .IPAM.Config}}'

section "docker-owned nft tables (native nftables backend?)"
run nft list tables | grep -i docker || echo "no docker-owned nft table visible (iptables backend or no docker)"

section "existing dockfence table"
run nft list table inet dockfence | head -5

section "nflog support"
run ls /proc/net/ 2>/dev/null | grep -i nflog || true
run cat /proc/net/netfilter/nfnetlink_log 2>/dev/null | head -3 || true

printf '\n== end ==\n'
