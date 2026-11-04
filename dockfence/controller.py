"""Controller: wires docker state + rules store into the nftables kernel
projection of the desired state. Full re-render + atomic apply on every change;
30 s reconcile loop corrects drift; failed applies keep the last good table."""

from __future__ import annotations

import threading
import time

from .config import Config
from .nft import NftApplier, NftError, TaggedContainer, render_table
from .store import Store
from .watcher import DockerWatcher


class Controller:
    def __init__(self, cfg: Config, store: Store, applier: NftApplier, watcher: DockerWatcher):
        self.cfg = cfg
        self.store = store
        self.applier = applier
        self.watcher = watcher
        self.lock = threading.RLock()
        self.status = {
            "last_apply_ts": None,
            "last_apply_ok": None,
            "last_error": None,
            "applies": 0,
            "apply_failures": 0,
            "tagged": 0,
        }
        self._stop = threading.Event()

    # -- helpers ---------------------------------------------------------
    def _tagged(self, containers: list[dict]) -> list[TaggedContainer]:
        out: list[TaggedContainer] = []
        for c in containers:
            if not c.get("opt_in") or c.get("self"):
                continue
            reason = self.watcher.unfilterable_reason(c)
            if reason:
                continue
            short = c["id"][:12]
            ips6 = [n["v6"] for n in c.get("networks", []) if n.get("v6")]
            if not self.cfg.ipv6:
                ips6 = []
            out.append(
                TaggedContainer(
                    id=c["id"],
                    short_id=short,
                    name=c["name"],
                    policy=c["policy"] or c["name"],
                    ips4=[ip for ip in c.get("ips", []) if ":" not in ip],
                    ips6=ips6,
                )
            )
        return out

    def _rules_by_policy(self) -> dict[str, list]:
        by_policy: dict[str, list] = {}
        for p in self.store.list_policies():
            by_policy[p["name"]] = self.store.list_rules(policy_id=p["id"])
        return by_policy

    def _dns_sets(self, rules_by_policy: dict[str, list]) -> dict[str, dict[str, list[str]]]:
        """Observed answer IPs for every hostname referenced by an enabled
        dns-rule — the elements of the per-rule kernel sets (nft.render_table)."""
        names = sorted({r.dns
                        for rules in rules_by_policy.values()
                        for r in rules if r.enabled and r.dns})
        return self.store.dns_ips(names) if names else {}

    # -- apply -------------------------------------------------------------
    def resync(self, reason: str = "resync") -> bool:
        """Rebuild the kernel table from docker + store. Returns True on success."""
        try:
            containers = self.watcher.refresh()
        except Exception as exc:  # noqa: BLE001  docker unreachable
            self._record_error(f"docker unreachable: {exc}")
            return False

        with self.lock:
            tagged = self._tagged(containers)
            seen_ids = set()
            for c in containers:
                policy_name = c.get("policy") or c["name"]
                policy_id = self.store.get_or_create_policy(policy_name) if c.get("opt_in") else None
                seen_ids.add(c["id"])
                self.store.upsert_container(
                    {
                        "id": c["id"],
                        "name": c["name"],
                        "policy_id": policy_id,
                        "ips": c.get("ips", []),
                        "networks": c.get("networks", []),
                        "state": c.get("state", ""),
                        "host_network": c.get("host_network", False),
                        "self": c.get("self", False),
                    }
                )
            self.store.mark_gone_except(seen_ids)

            mode = self.cfg.mode
            try:
                if mode == "disabled":
                    self.applier.delete_table()
                else:
                    by_policy = self._rules_by_policy()
                    rendered = render_table(
                        self.cfg, tagged, by_policy, mode,
                        logging=self.store.get_bool_setting("logging", False),
                        dns_log=self.store.get_bool_setting("dns_log", False),
                        dns_sets=self._dns_sets(by_policy),
                    )
                    self.applier.apply(rendered)
            except NftError as exc:
                self._record_error(f"nft apply failed ({reason}): {exc}")
                self.store.add_event("apply_error", f"{reason}: {exc}")
                return False

            self.status["last_apply_ts"] = time.time()
            self.status["last_apply_ok"] = True
            self.status["last_error"] = None
            self.status["tagged"] = len(tagged)
            self.status["applies"] += 1
            self.store.add_event("apply", f"{reason}: applied for {len(tagged)} tagged container(s)")
            return True

    def rules_changed(self) -> bool:
        """Re-render + apply after a rule/policy edit (container snapshot reused)."""
        with self.lock:
            tagged = self._tagged(self.watcher.snapshot())
            try:
                if self.cfg.mode == "disabled":
                    self.applier.delete_table()
                else:
                    by_policy = self._rules_by_policy()
                    rendered = render_table(
                        self.cfg, tagged, by_policy, self.cfg.mode,
                        logging=self.store.get_bool_setting("logging", False),
                        dns_log=self.store.get_bool_setting("dns_log", False),
                        dns_sets=self._dns_sets(by_policy),
                    )
                    self.applier.apply(rendered)
            except NftError as exc:
                self._record_error(f"nft apply failed (rules_changed): {exc}")
                self.store.add_event("apply_error", f"rules_changed: {exc}")
                return False
            self.status["last_apply_ts"] = time.time()
            self.status["last_apply_ok"] = True
            self.status["last_error"] = None
            self.status["tagged"] = len(tagged)
            self.status["applies"] += 1
            return True

    def _record_error(self, msg: str) -> None:
        self.status["last_apply_ok"] = False
        self.status["last_error"] = msg
        self.status["apply_failures"] += 1

    # -- events ---------------------------------------------------------
    def handle_event(self, ev: dict) -> None:
        etype = ev.get("Type")
        action = ev.get("Action", "")
        actor = (ev.get("Actor") or {}).get("ID", "")
        if etype == "container" and action in (
            "start", "die", "destroy", "restart", "rename", "create", "update", "stop", "kill"
        ):
            # re-inspect just this container, then re-apply
            self.watcher.refresh_one(actor)
            self.rules_changed()
            self.store.add_event("docker", f"container {action} → re-applied")
        elif etype == "network" and action in ("connect", "disconnect"):
            cid = ((ev.get("Actor") or {}).get("Attributes") or {}).get("container", "")
            if cid:
                self.watcher.refresh_one(cid)
                self.rules_changed()
                self.store.add_event("docker", f"network {action} → re-applied")

    # -- reconcile loop ---------------------------------------------------
    def run_reconcile(self) -> None:
        while not self._stop.is_set():
            if self._stop.wait(timeout=self.cfg.reconcile):
                break
            # drift correction: missed events, manual nft edits, missed IPs
            self.resync(reason="reconcile")

    def stop(self) -> None:
        self._stop.set()
