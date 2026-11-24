"""`hackbench serve`: a read-only live dashboard over <work_root>/runs.

Security: hunts run on this host, and hackbot lets them reach loopback. The API returns ground truth (vuln
titles, judge reasons), so every /api/* call except /api/health needs a bearer token. The token is random,
lives only in this process's memory (never on disk, in argv or in the environment), and reaches the
operator only in the URL printed at start (`#token=…`: a fragment, so browsers never send it to a server).
The page itself holds no data. Nothing here writes to a run.
"""
from __future__ import annotations

import hmac
import json
import os
import platform
import re
import secrets
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from .report import build_summary, load_instances
from .runner import SCORE_EXCLUDED, next_stop_ids, parse_iso

PAGE = Path(__file__).resolve().parent / "dashboard" / "index.html"
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
STALE_S = 300  # a running instance whose live.json is older than this is shown as stale
EVENT_TAIL_BYTES = 128 * 1024


def _read_json(p: Path) -> dict | None:
    try:
        d = json.loads(p.read_text())
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except PermissionError:
        return True
    except (OSError, ValueError, TypeError):
        return False


def _age_s(iso_ts: str | None) -> float | None:
    t = parse_iso(iso_ts)
    return None if t is None else max(0.0, datetime.now(timezone.utc).timestamp() - t)


def run_state(run_dir: Path) -> dict:
    """Whether a bench process is driving this run now: running | done | interrupted | stopped | unknown."""
    st = _read_json(run_dir / "state.json") or {}
    state = st.get("state") or "unknown"
    if state == "running":
        same_host = st.get("host") in (None, platform.node())
        if same_host and not _pid_alive(st.get("pid")):
            state = "stopped"  # the bench process is gone without writing a final state (killed, crashed)
    return {**st, "state": state}


def _tail_events(path: Path, instance: str, limit: int = 200) -> list[dict]:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - EVENT_TAIL_BYTES))
            lines = f.read().splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        if isinstance(e, dict):
            e.pop("argv", None)
            e["instance"] = instance
            out.append(e)
    return out


def _live_as_result(lv: dict) -> dict:
    """A running instance's live.json in the shape build_summary() reads from result.json."""
    return {
        "instance": lv.get("instance"), "target": lv.get("target"), "index": lv.get("index", 0),
        "stop_set": lv.get("stop_set") or [], "status": "running", "found": lv.get("found") or [],
        "wall_s": lv.get("elapsed_s"), "recon_s": lv.get("recon_s"), "total_cost_usd": lv.get("spent_usd") or 0.0,
        "judge_cost_usd": lv.get("judge_cost_usd") or 0.0, "keyword_hits": [], "items": [],
    }


def run_snapshot(run_dir: Path) -> dict:
    """Everything the page shows for one run, computed from the files the bench writes."""
    meta = _read_json(run_dir / "run.json") or {}
    state = run_state(run_dir)
    finished = load_instances(run_dir)
    done_ids = {r.get("instance") for r in finished}
    lives, running = {}, []
    for p in sorted((run_dir / "instances").glob("*/live.json")):
        lv = _read_json(p)
        if not lv:
            continue
        lives[lv.get("instance")] = lv
        if lv.get("instance") not in done_ids and lv.get("state") != "ended":
            age = _age_s(lv.get("updated_at"))
            lv["stale"] = state["state"] != "running" or (age is not None and age > STALE_S)
            lv["age_s"] = None if age is None else round(age)
            running.append(lv)
    summary = build_summary(run_dir, finished + [_live_as_result(lv) for lv in running if not lv["stale"]])
    plan = meta.get("plan") or {}
    bench = meta.get("bench") or {}
    live_running = [lv for lv in running if not lv["stale"]]

    targets = []
    for tid, tp in plan.items():
        tinst = [r for r in finished if r.get("target") == tid]
        trun = [lv for lv in live_running if lv.get("target") == tid]
        camp = tp.get("campaign") or bench.get("campaign") or {}
        budget = tp.get("budget") or bench.get("budget") or {}
        nxt = next_stop_ids(tp.get("strategy", "campaign"), tp.get("vulns", []), tinst,
                            int(camp.get("max_misses") or 1), int(camp.get("max_instances") or 0))
        last = tinst[-1] if tinst else None
        if trun:
            status = "running"
        elif nxt is None:
            status = "done"
        elif last and last.get("status") in SCORE_EXCLUDED:
            status = "error"
        elif not tinst:
            status = "pending"
        else:
            status = "queued" if state["state"] == "running" else "incomplete"
        targets.append({
            "id": tid, "name": tp.get("name", tid), "strategy": tp.get("strategy", "campaign"), "status": status,
            "budget": budget, "campaign": camp, "next_stop_set": nxt,
            "active": {k: trun[0].get(k) for k in ("instance", "phase", "iteration", "elapsed_s", "spent_usd")} if trun else None,
            "cost_usd": round(sum(r.get("total_cost_usd") or 0 for r in tinst)
                              + sum(float(lv.get("spent_usd") or 0) for lv in trun), 4),
            "vulns": [r for r in summary["vuln_results"] if r["target"] == tid],
            "instances": [r for r in summary["instance_results"] if (r.get("instance") or "").startswith(tid + "#")],
        })
        for v in targets[-1]["vulns"]:
            v["hunting"] = (not v["found"]) and any(v["vuln"] in (lv.get("stop_set") or []) for lv in trun)

    events = []
    for d in sorted((run_dir / "instances").glob("*__*")):
        tid, _, idx = d.name.rpartition("__")  # instances/<target>__NN → <target>#NN
        events += _tail_events(d / "events.jsonl", f"{tid}#{idx}")
    events.sort(key=lambda e: e.get("t") or "", reverse=True)

    errors = sum(1 for r in finished if r.get("status") in ("setup_error", "launch_error", "omp_exited"))
    return {
        "run_id": meta.get("run_id") or run_dir.name,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "state": state,
        "meta": {k: meta.get(k) for k in ("started_at", "hackbot", "omp_version", "host", "selection", "bench_commit")},
        "judge": {k: (bench.get("judge") or {}).get(k) for k in ("enabled", "model", "thinking")},
        "overview": {
            "vulns": summary["vulns"], "found": summary["found"], "found_pct": summary["found_pct"],
            "targets": len(targets), "targets_done": sum(1 for t in targets if t["status"] == "done"),
            "targets_running": sum(1 for t in targets if t["status"] == "running"),
            "instances": len(finished) + len(live_running), "instances_running": len(live_running), "errors": errors,
            "hunt_cost_usd": summary["total_cost_usd"], "judge_cost_usd": summary["judge_cost_usd"],
            "wall_s": summary["total_wall_s"], "time_to_find_s": summary["time_to_find_s"],
            "cost_to_find_usd": summary["cost_to_find_usd"],
        },
        "targets": targets,
        "running": running,
        "events": events[:120],
    }


def list_runs(runs_dir: Path) -> list[dict]:
    out = []
    for d in sorted(runs_dir.glob("*"), reverse=True):
        if not (d.is_dir() and RUN_ID.match(d.name) and (d / "run.json").exists()):
            continue
        meta = _read_json(d / "run.json") or {}
        plan = meta.get("plan") or {}
        out.append({"run_id": d.name, "started_at": meta.get("started_at"), "state": run_state(d)["state"],
                    "targets": list(plan), "vulns": sum(len(p.get("vulns", [])) for p in plan.values())})
    out.sort(key=lambda r: r.get("started_at") or r["run_id"], reverse=True)
    return out


def make_handler(runs_dir: Path, token: str | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "hackbench"
        sys_version = ""

        def log_message(self, *a):  # quiet: the bench's own terminal stays readable
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                             "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; "
                             "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, code: int, data) -> None:
            self._send(code, json.dumps(data, default=str).encode(), "application/json; charset=utf-8")

        def _authed(self) -> bool:
            if token is None:
                return True
            got = self.headers.get("Authorization", "")
            return got.startswith("Bearer ") and hmac.compare_digest(got[7:].strip(), token)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            try:
                path = urlparse(self.path).path
                if path in ("/", "/index.html"):
                    return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
                if path == "/api/health":
                    return self._json(200, {"app": "hackbench", "auth": token is not None})
                if not path.startswith("/api/"):
                    return self._json(404, {"error": "not found"})
                if not self._authed():
                    return self._json(401, {"error": "token required: open the URL `hackbench serve` printed"})
                if path == "/api/runs":
                    return self._json(200, {"runs": list_runs(runs_dir), "runs_dir": str(runs_dir)})
                if path.startswith("/api/run/"):
                    rid = unquote(path[len("/api/run/"):])
                    d = runs_dir / rid
                    if not RUN_ID.match(rid) or not (d / "run.json").exists():
                        return self._json(404, {"error": "no such run"})
                    return self._json(200, run_snapshot(d))
                return self._json(404, {"error": "not found"})
            except Exception as e:  # noqa: BLE001  (a monitoring page must never take the server down)
                return self._json(500, {"error": f"{type(e).__name__}: {e}"})

        def do_POST(self):
            self._json(405, {"error": "read-only"})

        do_PUT = do_DELETE = do_PATCH = do_POST

    return Handler


def serve(runs_dir: Path, host: str = "127.0.0.1", port: int = 8765, auth: bool = True, log=print) -> None:
    token = secrets.token_hex(24) if auth else None
    httpd = ThreadingHTTPServer((host, port), make_handler(runs_dir, token))
    httpd.daemon_threads = True
    shown = "127.0.0.1" if host in ("0.0.0.0", "", "::") else host
    url = f"http://{shown}:{httpd.server_address[1]}/"
    log(f"hackbench dashboard over {runs_dir}")
    log(f"  open: {url}#token={token}" if token else f"  open: {url}   (no token: anyone who can reach it can read ground truth)")
    if host not in ("127.0.0.1", "localhost", "::1"):
        log(f"  warning: listening on {host}, not loopback")
    log(f"  from the Mac: ssh -L {httpd.server_address[1]}:127.0.0.1:{httpd.server_address[1]} <vm>, then open the URL above")
    log("  Ctrl-C to stop")
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
