"""One hunt instance: fresh workspace → /hunt --fresh '<prompt>' → watch → stop at the first hit in its stop set."""
from __future__ import annotations

import json
import os
import platform
import shutil
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import Target, Vuln
from .cost import CostTracker
from .items import Item, scan_items
from .match import heuristic
from .material import materialize, remove_material

# judge(target, item_text, item_id, tier, verdict) -> {"verdict", "vuln", "reason", "cost_usd", …}
Judge = Callable[[Target, str, str, str, str], dict]


def iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


def now() -> float:
    return time.time()


def write_json(p: Path, data) -> None:
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str) + "\n")
    os.replace(tmp, p)


def fmt_dur(s: float | None) -> str:
    if s is None:
        return "—"
    s = int(s)
    h, r = divmod(s, 3600)
    m, sec = divmod(r, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{sec:02d}s"


# ---- workspace --------------------------------------------------------------------------------------
def build_workspace(target: Target, ws: Path, hackbot: Path, cache: Path, vault_name: str, log) -> None:
    """A fresh hackbot research workspace: .omp link, a new vault, the raw material and target.json only."""
    omp_dir = hackbot / ".omp"
    if not (omp_dir / "hooks").is_dir():
        raise RuntimeError(f"{hackbot} is not a redteam-hackbot clone (no .omp/hooks)")
    ws.mkdir(parents=True, exist_ok=False)
    (ws / ".omp").symlink_to(omp_dir)  # what `scripts/install.sh --link-only --workspace` does
    r = subprocess.run(
        [str(ws / ".omp/scripts/migrate-vault.sh"), "--name", vault_name],
        cwd=ws, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600,
    )
    (ws.parent / "setup.log").write_text(r.stdout + r.stderr)
    if r.returncode != 0 or not (ws / "vault").is_symlink():
        raise RuntimeError(f"migrate-vault.sh failed (rc={r.returncode}): {(r.stderr or r.stdout)[-800:]}")
    ctx = ws / "vault" / "context"
    ctx.mkdir(parents=True, exist_ok=True)
    materialize(target, cache, ctx, log=log)
    shutil.copy2(target.target_json_path, ctx / "target.json")
    for d in target.data.get("docs", []) or []:  # optional operator documents → vault/docs/
        src = (target.dir / d).resolve()
        dst = ws / "vault" / "docs" / src.name
        (shutil.copytree(src, dst, dirs_exist_ok=True) if src.is_dir() else shutil.copy2(src, dst))
    # No CONTEXT.md on purpose: /hunt then runs the full /recon pass first and hands off to the hunt.
    if (ctx / "CONTEXT.md").exists():
        raise RuntimeError("material placed a CONTEXT.md in vault/context/: /hunt would skip recon")


def hackbot_dashboard_url(ws: Path) -> str | None:
    """Where hackbot's own dashboard for this workspace is served (.omp/hooks/lib/dashboard.ts): the pinned
    PI_DASHBOARD_PORT omp inherits from the bench, else the port remembered for the workspace's real path in
    <tmpdir>/omp-dashboard-ports.json. None until hackbot has started one. Never reads the pairing token."""
    pinned = os.environ.get("PI_DASHBOARD_PORT", "")
    if pinned.isdigit() and int(pinned) > 0:
        return f"http://127.0.0.1:{int(pinned)}"
    try:
        ports = json.loads((Path(tempfile.gettempdir()) / "omp-dashboard-ports.json").read_text())
        port = ports.get(os.path.realpath(ws))
    except (OSError, ValueError, AttributeError):
        return None
    return f"http://127.0.0.1:{port}" if isinstance(port, int) and port > 0 else None


def read_hunt_state(ws: Path) -> dict | None:
    try:
        return json.loads((ws / "vault" / "sessions" / ".hunt.json").read_text())
    except (OSError, ValueError):
        return None


def parse_iso(s: str | None) -> float | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() if s else None
    except ValueError:
        return None


# ---- process / container cleanup -----------------------------------------------------------------
def kill_procs_in(ws: Path, log) -> int:
    """Linux: SIGTERM then SIGKILL every process whose cwd is inside the workspace (agent shells, PoCs)."""
    if platform.system() != "Linux":
        return 0
    root = str(ws.resolve())
    me = os.getpid()
    pids = []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit() or int(d.name) == me:
            continue
        try:
            cwd = os.readlink(d / "cwd")
        except OSError:
            continue
        if cwd == root or cwd.startswith(root + "/"):
            pids.append(int(d.name))
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in pids:
            try:
                os.kill(pid, sig)
            except OSError:
                pass
        if sig == signal.SIGTERM and pids:
            time.sleep(5)
    if pids:
        log(f"  killed {len(pids)} leftover process(es) in the workspace")
    return len(pids)


def docker_ids() -> set[str] | None:
    if not shutil.which("docker"):
        return None
    try:
        r = subprocess.run(["docker", "ps", "-aq", "--no-trunc"], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return None
    return set(r.stdout.split()) if r.returncode == 0 else None


# ---- one hunt instance ----------------------------------------------------------------------------
class HuntInstance:
    """One fresh hunt of `target`. Stops when a VALID item is judged to be any vuln in `stop_vulns`.

    Every vuln of the target it proves on the way is recorded (judge-confirmed), in or out of the stop set.
    """

    def __init__(self, bench: dict, run_dir: Path, run_id: str, target: Target, index: int,
                 stop_vulns: list[Vuln], prompt: str, budget: dict, launcher, judge: Judge | None,
                 log=print, omp: str = "omp"):
        self.b = bench
        self.target = target
        self.stop_ids = [v.id for v in stop_vulns]
        self.prompt = prompt
        self.budget = budget
        self.launcher = launcher
        self.judge = judge
        self.log = log
        self.omp = omp
        self.index = index
        self.id = f"{target.id}#{index:02d}"
        self.dir = run_dir / "instances" / f"{target.id}__{index:02d}"
        self.ws = self.dir / "workspace"
        self.sessdir = self.dir / "omp-sessions"
        short = "".join(ch for ch in target.id if ch.isalnum())[:16]
        self.name = f"hb-{run_id}-{short}-{index:02d}"
        self.vault_name = self.name.lower()
        self.det = target.detection(bench)
        self.cost = CostTracker(self.sessdir)
        self.timeline: list[dict] = []
        self.judged: dict[tuple, dict] = {}
        self.found: dict[str, dict] = {}       # vuln id → first proving item (judge-confirmed)
        self.keyword_hits: dict[str, dict] = {}  # vuln id → first item (any tier) matching its keywords
        self.items_seen: dict[str, str] = {}
        self.judge_cost = 0.0
        self.interrupted = False
        self.launched: float | None = None
        self.hunt_state: dict = {}
        self.recon_s: float | None = None
        self.item_counts: dict = {}
        self.started = now()

    def live(self, state: str, status: str | None = None) -> None:
        """Write live.json: what `hackbench serve` shows for this instance while it runs (and after)."""
        try:
            st = self.hunt_state
            L = self.launched
            write_json(self.dir / "live.json", {
                "instance": self.id, "target": self.target.id, "index": self.index, "stop_set": self.stop_ids,
                "state": state, "status": status, "updated_at": iso(now()), "started_at": iso(self.started),
                "launched_at": iso(L), "elapsed_s": round(now() - L, 1) if L else None,
                "phase": "recon" if st.get("phase") == "recon" else ("hunt" if st else None), "recon_s": self.recon_s,
                "iteration": st.get("iteration"), "hunt_dir": st.get("dir"),
                "budget": self.budget, "spent_usd": self.cost.total(), "judge_cost_usd": round(self.judge_cost, 6),
                "items": self.item_counts,
                "found": [{"vuln": v, "item": f["id"], "tier": f["tier"], "in_stop_set": v in self.stop_ids,
                           "time_to_find_s": round(f["ts"] - L, 1) if L else None,
                           "cost_to_find_usd": self.cost.total(until=f["ts"])}
                          for v, f in sorted(self.found.items(), key=lambda kv: kv[1]["ts"])],
                "keyword_hits": sorted(self.keyword_hits), "tmux_session": self.name, "workspace": str(self.ws),
                "hackbot_dashboard": hackbot_dashboard_url(self.ws) if st else None,
            })
        except Exception:  # noqa: BLE001  (a monitoring write must never break a hunt)
            pass

    def event(self, kind: str, **kw) -> None:
        e = {"t": iso(now()), "event": kind, **kw}
        self.timeline.append(e)
        with open(self.dir / "events.jsonl", "a") as f:
            f.write(json.dumps(e, default=str) + "\n")

    # -- detection ---------------------------------------------------------------------------------
    def _accepts(self, it: Item) -> bool:
        if it.tier not in self.det["accept_tiers"] or not it.valid:
            return False
        return it.confirmed or not self.det.get("require_confirmed")

    def evaluate(self, items: list[Item]) -> list[str]:
        """Process new/changed items; return the stop-set vuln ids proven so far."""
        for it in items:
            key = f"{it.tier}/{it.id}"
            if self.items_seen.get(key) != it.sha:
                if key not in self.items_seen:
                    self.event("item", id=it.id, tier=it.tier, verdict=it.verdict, title=it.title[:200])
                self.items_seen[key] = it.sha
            for v in self.target.vulns:
                if v.id not in self.keyword_hits and heuristic(v, it.text)["match"]:
                    self.keyword_hits[v.id] = {"item": it.id, "tier": it.tier, "ts": now()}
                    self.event("keyword_hit", vuln=v.id, id=it.id, tier=it.tier)
            if not self._accepts(it):
                continue
            jkey = (it.id, it.tier, it.verdict, it.confirmed)
            if jkey in self.judged:
                continue
            j = self.judged[jkey] = self._judge(it)
            for vid in j.get("vuln_ids", []):
                if vid in self.found:
                    continue
                at = max(self.launched or 0, min(now(), it.mtime))
                self.found[vid] = {**it.brief(), "vuln": vid, "ts": at, "judgement": j}
                self.event("found", vuln=vid, id=it.id, tier=it.tier, in_stop_set=vid in self.stop_ids)
                self.log(f"  {'FOUND' if vid in self.stop_ids else 'found (already known)'} {vid} via {it.id} "
                         f"({it.tier}) after {fmt_dur(at - (self.launched or at))}, ${self.cost.total(until=at):.2f}")
        return [v for v in self.stop_ids if v in self.found]

    def _judge(self, it: Item) -> dict:
        hv = [v.id for v in self.target.vulns if heuristic(v, it.text)["match"]]
        res: dict = {"keyword_vulns": hv}
        if self.judge:
            try:
                j = self.judge(self.target, it.text, it.id, it.tier, it.verdict)
            except Exception as e:  # noqa: BLE001
                j = {"verdict": "error", "reason": repr(e)}
            res["judge"] = j
            self.judge_cost += float(j.get("cost_usd") or 0)
            v = j.get("verdict")
            if v in ("match", "partial", "no_match"):
                counts = v == "match" or (v == "partial" and self.b["judge"].get("count_partial"))
                res["vuln_ids"] = list(j.get("vulns") or []) if counts else []
                res["decided_by"] = "judge"
            else:
                res["vuln_ids"] = hv
                res["decided_by"] = "keywords (judge failed)"
        else:
            res["vuln_ids"] = hv
            res["decided_by"] = "keywords"
        self.event("judged", id=it.id, tier=it.tier, vulns=res["vuln_ids"], decided_by=res["decided_by"],
                   verdict=(res.get("judge") or {}).get("verdict"), reason=(res.get("judge") or {}).get("reason"))
        return res

    # -- lifecycle -----------------------------------------------------------------------------------
    def run(self) -> dict:
        self.dir.mkdir(parents=True, exist_ok=True)
        res: dict = {
            "instance": self.id, "target": self.target.id, "index": self.index, "stop_set": self.stop_ids,
            "prompt": self.prompt, "budget": self.budget, "detection": self.det, "status": None, "error": None,
            "workspace": str(self.ws), "tmux_session": self.name,
        }
        t_setup = now()
        self.live("setup")
        try:
            build_workspace(self.target, self.ws, Path(self.b["hackbot"]), Path(self.b["cache_dir"]), self.vault_name, self.log)
        except Exception as e:  # noqa: BLE001
            res.update(status="setup_error", error=f"{type(e).__name__}: {e}")
            self.event("setup_error", error=res["error"])
            return self._finish(res)
        res["setup_s"] = round(now() - t_setup, 1)
        self.event("workspace_ready", setup_s=res["setup_s"])

        containers_before = docker_ids() if self.b["stop"].get("cleanup_containers") else None
        argv = [self.omp, "--session-dir", str(self.sessdir), *map(str, self.b["omp"].get("args") or [])]
        if self.b["omp"].get("pass_max_cost") and self.budget.get("max_cost_usd"):
            argv += ["--max-cost", str(self.budget["max_cost_usd"])]
        env = dict(os.environ, HACKBENCH_INSTANCE=self.id)
        try:
            self.launcher.start(self.name, self.ws, argv, env)
        except Exception as e:  # noqa: BLE001
            res.update(status="launch_error", error=f"{type(e).__name__}: {e}")
            self.event("launch_error", error=res["error"])
            return self._finish(res)
        self.event("omp_started", argv=argv)
        self.live("starting")

        try:
            status = self._drive(res)
        except KeyboardInterrupt:  # stop the hunt and record its spend before the bench exits
            status = "interrupted"
            self.interrupted = True
            self.event("interrupted")
        res["status"] = status
        end_ts = now()
        self.live("stopping", status)
        stop_info = self._stop(status)

        # ---- metrics ----
        L = self.launched
        res["launched_at"] = iso(L)
        res["ended_at"] = iso(end_ts)
        res["wall_s"] = round(end_ts - L, 1) if L else None
        res["stop_mode"] = stop_info["stop_mode"]
        res["leftover_procs_killed"] = stop_info.get("procs", 0)
        res["found"] = [
            {"vuln": vid, "in_stop_set": vid in self.stop_ids, "item": f["id"], "tier": f["tier"],
             "verdict": f["verdict"], "confirmed": f["confirmed"], "severity": f["severity"], "title": f["title"],
             "found_at": iso(f["ts"]), "time_to_find_s": round(f["ts"] - L, 1) if L else None,
             "cost_to_find_usd": self.cost.total(until=f["ts"]), "judgement": f["judgement"]}
            for vid, f in sorted(self.found.items(), key=lambda kv: kv[1]["ts"])
        ]
        res["keyword_hits"] = [
            {"vuln": vid, "item": h["item"], "tier": h["tier"], "at": iso(h["ts"]),
             "time_s": round(h["ts"] - L, 1) if L else None}
            for vid, h in sorted(self.keyword_hits.items(), key=lambda kv: kv[1]["ts"])
        ]
        res["cost"] = self.cost.summary()
        res["total_cost_usd"] = res["cost"]["cost_usd"]
        res["judge_cost_usd"] = round(self.judge_cost, 6)
        res["post_stop_cost_usd"] = round(res["total_cost_usd"] - stop_info["cost_at_stop"], 6)
        if res["post_stop_cost_usd"] > 0:
            self.event("warning", msg=f"spend continued after the stop: ${res['post_stop_cost_usd']:.2f}")
        st = read_hunt_state(self.ws) or {}
        sess = self.ws / st["dir"] if st.get("dir") else None
        res["hunt_session_dir"] = str(sess) if sess else None
        res["items"] = [it.brief() for it in scan_items(sess)] if sess and sess.exists() else []
        if containers_before is not None:
            new = sorted((docker_ids() or set()) - containers_before)
            if new:
                subprocess.run(["docker", "rm", "-f", *new], capture_output=True, timeout=300)
                self.event("containers_removed", count=len(new))
            res["containers_removed"] = len(new)
        return self._finish(res)

    def _drive(self, res: dict) -> str:
        lc = self.b["launcher"]
        poll = float(self.b["monitor"]["poll_s"])
        deadline = now() + float(lc["startup_wait_s"])  # let the TUI come up, then type the /hunt line
        while now() < deadline:
            if not self.launcher.alive(self.name) or self.launcher.pane_dead(self.name):
                (self.dir / "pane.txt").write_text(self.launcher.capture(self.name))
                res["error"] = "omp exited during startup (see pane.txt)"
                return "launch_error"
            time.sleep(1)
        cmd = self.b["hunt_command"].format(prompt=self.prompt)
        self.launcher.send_line(self.name, cmd)
        self.launched = launched = now()
        res["hunt_command"] = cmd
        self.event("hunt_command_sent")

        retried = False
        while read_hunt_state(self.ws) is None:  # /hunt writes .hunt.json (recon phase or hunt)
            if now() - launched > float(lc["start_timeout_s"]):
                (self.dir / "pane.txt").write_text(self.launcher.capture(self.name))
                res["error"] = "/hunt did not start (no vault/sessions/.hunt.json); see pane.txt for the refusal"
                return "launch_error"
            if not retried and now() - launched > 30:
                self.launcher.send_enter(self.name)  # a TUI that swallowed the first Enter
                retried = True
            if not self.launcher.alive(self.name):
                res["error"] = "omp exited before /hunt started"
                return "launch_error"
            time.sleep(2)

        max_s = float(self.budget.get("max_hours") or 0) * 3600
        max_cost = float(self.budget.get("max_cost_usd") or 0)
        recon_seen = hunt_seen = False
        stopped_since = None
        last_log = 0.0
        while True:
            t = now()
            st = read_hunt_state(self.ws) or {}
            if st.get("phase") == "recon" and not recon_seen:
                recon_seen = True
                self.event("recon_started")
            if st and st.get("phase") != "recon" and not hunt_seen:
                # The recon → hunt hand-off rewrites .hunt.json without `phase`, with the hunt's own `started`.
                hunt_seen = True
                hs = parse_iso(st.get("started")) or t
                res["recon_s"] = self.recon_s = round(max(0.0, hs - launched), 1) if recon_seen else 0.0
                self.event("hunt_started", started=st.get("started"), recon_s=res["recon_s"])
            self.cost.scan()
            spent = self.cost.total()
            self.hunt_state = st
            sess = self.ws / st["dir"] if st.get("dir") else None
            items = scan_items(sess) if sess and sess.exists() else []
            self.item_counts = {k: sum(1 for i in items if i.tier == k) for k in ("finding", "gadget", "lead", "rejected")}
            self.item_counts["valid"] = sum(1 for i in items if i.valid and i.tier in ("finding", "gadget"))
            hit = bool(items) and self.evaluate(items)
            self.live(st.get("phase") or "hunt")
            if hit:
                return "found"
            if t - last_log >= 600:
                last_log = t
                phase = "recon" if st.get("phase") == "recon" else f"hunt iter {st.get('iteration', '?')}"
                self.log(f"  … {fmt_dur(t - launched)} · {phase} · ${spent:.2f} · {len(self.items_seen)} items")
            if max_s and t - launched >= max_s:
                self.event("timeout")
                return "timeout"
            if max_cost and spent >= max_cost:
                self.event("budget_exhausted", spent=spent)
                return "budget_exhausted"
            if not self.launcher.alive(self.name) or self.launcher.pane_dead(self.name):
                (self.dir / "pane.txt").write_text(self.launcher.capture(self.name))
                self.event("omp_exited")
                return "omp_exited"
            if st.get("stopped"):
                stopped_since = stopped_since or t
                if t - max(self.cost.last_call_ts(), stopped_since) >= float(self.b["monitor"]["stopped_idle_s"]):
                    self.event("hunt_stopped", phase=st.get("phase"))
                    return "recon_failed" if st.get("phase") == "recon" else "hunt_stopped"
            time.sleep(poll)

    def _stop(self, status: str) -> dict:
        info: dict = {}
        sc = self.b["stop"]
        try:
            (self.dir / "pane.txt").write_text(self.launcher.capture(self.name))
        except Exception:  # noqa: BLE001
            pass
        st = read_hunt_state(self.ws) or {}
        sess = self.ws / st["dir"] if st.get("dir") else None
        if sess and sess.exists() and not (sess / "STOP").exists():
            (sess / "STOP").write_text(f"{iso(now())} hackbench: {status}\n")
        if sc.get("mode") == "graceful" and status not in ("omp_exited", "launch_error") and self.launcher.alive(self.name):
            deadline = now() + float(sc.get("graceful_timeout_s", 1800))
            while now() < deadline and self.launcher.alive(self.name):
                self.cost.scan()
                if (read_hunt_state(self.ws) or {}).get("stopped") and now() - self.cost.last_call_ts() > 120:
                    break
                time.sleep(15)
            info["stop_mode"] = "graceful"
        else:
            info["stop_mode"] = "kill"
        self.launcher.kill(self.name)
        self.cost.scan()
        info["cost_at_stop"] = self.cost.total()
        self.event("stopped", mode=info["stop_mode"])
        if sc.get("kill_workspace_procs"):
            info["procs"] = kill_procs_in(self.ws, self.log)
        q = float(sc.get("quiesce_s", 60))
        end = now() + q
        while now() < end:
            time.sleep(min(10, q))
            self.cost.scan()
        return info

    def _finish(self, res: dict) -> dict:
        res["timeline"] = self.timeline
        if self.ws.exists() and not self.b.get("keep_material", False):
            remove_material(self.target, self.ws / "vault" / "context")
            res["material_removed"] = True
        if not self.b.get("keep_workspaces", True) and self.ws.exists():
            keep = self.dir / "kept"
            for sub in ("vault/sessions", "reports", "vault/context/CONTEXT.md", "vault/context/recon"):
                src = self.ws / sub
                if src.exists():
                    dst = keep / sub
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    (shutil.copytree(src, dst, symlinks=True) if src.is_dir() else shutil.copy2(src, dst))
            shutil.rmtree(self.ws, ignore_errors=True)
            res["workspace"] = None
            res["kept"] = str(keep)
        write_json(self.dir / "result.json", res)
        self.live("ended", res.get("status"))
        return res


# ---- campaigns ------------------------------------------------------------------------------------
SCORE_EXCLUDED = ("setup_error", "launch_error", "interrupted")


def next_stop_ids(strategy: str, vuln_ids: list[str], done: list[dict], max_misses: int = 1,
                  max_instances: int = 0) -> list[str] | None:
    """The stop set of the next instance, or None when the target is done. Pure: ids and result dicts only.

    campaign: stop set = selected vulns no instance has proven yet; ends when all are found, after
      `max_misses` consecutive instances that prove nothing new, or after `max_instances` (0 = no cap).
    per-vuln: one instance per selected vuln, in order.
    Instances that ended in a setup/launch error or an interrupt do not count.
    """
    scored = [r for r in done if r.get("status") not in SCORE_EXCLUDED]
    if strategy == "per-vuln":
        tried = {tuple(r.get("stop_set") or []) for r in scored}
        return next(([v] for v in vuln_ids if (v,) not in tried), None)
    found = {f["vuln"] for r in scored for f in r.get("found", []) if f.get("in_stop_set")}
    remaining = [v for v in vuln_ids if v not in found]
    if not remaining or trailing_misses(done) >= max(1, int(max_misses or 1)):
        return None
    if max_instances and len(scored) >= int(max_instances):
        return None
    return remaining


def trailing_misses(done: list[dict]) -> int:
    """Consecutive scored instances, newest first, that proved nothing new."""
    misses = 0
    for r in reversed([r for r in done if r.get("status") not in SCORE_EXCLUDED]):
        if any(f.get("in_stop_set") for f in r.get("found", [])):
            break
        misses += 1
    return misses


def plan_next(target: Target, selected: list[Vuln], done: list[dict], bench: dict) -> tuple[list[Vuln], str, dict] | None:
    """The next instance for a target given its finished instances, or None when the target is done."""
    cfg = target.campaign(bench)
    ids = next_stop_ids(target.strategy, [v.id for v in selected], done,
                        int(cfg.get("max_misses") or 1), int(cfg.get("max_instances") or 0))
    if ids is None:
        return None
    vs = [v for v in selected if v.id in ids]
    if target.strategy == "per-vuln":
        return vs, vs[0].prompt, vs[0].budget(bench)
    return vs, target.prompt, target.budget(bench)
