"""hackbench command line."""
from __future__ import annotations

import argparse
import fcntl
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import REPO, deep_merge, host_arch, lint_target, load_bench, load_targets, resolve_selection
from .launcher import LaunchError, TmuxLauncher, hunt_host_status
from .match import OmpJudge
from .material import fetch
from .campaign import drive
from .report import render_md, summarize
from .runner import write_json


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def _sh(argv, cwd=None) -> str:
    try:
        return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def _bench(args) -> dict:
    b = load_bench(Path(args.config) if getattr(args, "config", None) else None)
    over: dict = {}
    if getattr(args, "launcher", None):
        over.setdefault("launcher", {})["mode"] = args.launcher
    if getattr(args, "max_hours", None) is not None:
        over.setdefault("budget", {})["max_hours"] = args.max_hours
    if getattr(args, "max_cost", None) is not None:
        over.setdefault("budget", {})["max_cost_usd"] = args.max_cost
    if getattr(args, "no_judge", False):
        over.setdefault("judge", {})["enabled"] = False
    if getattr(args, "stop", None):
        over.setdefault("stop", {})["mode"] = args.stop
    if getattr(args, "discard_workspaces", False):
        over["keep_workspaces"] = False
    b = deep_merge(b, over)
    b["_cli_budget"] = over.get("budget") or {}  # CLI budget beats target budgets too
    return b


def _budget(b: dict, budget: dict) -> dict:
    return deep_merge(budget, b.get("_cli_budget"))


def _selection(b: dict, args):
    """(selection, include, exclude) from bench.yaml `targets:` and -c / --exclude; exits 2 on a bad pattern."""
    try:
        return resolve_selection(b, load_targets(), getattr(args, "case", None), getattr(args, "exclude", None))
    except ValueError as e:
        print(f"error: {e}")
        raise SystemExit(2)


# ---- commands -------------------------------------------------------------------------------------
def cmd_list(args) -> int:
    b = _bench(args)
    selection, include, exclude = _selection(b, args)
    chosen = {v.case_id for _, vs in selection for v in vs}
    print(f"selection: include {include or ['*']}" + (f", exclude {exclude}" if exclude else "")
          + "   (bench.yaml targets:, -c, --exclude; * = analyzed)\n")
    for t in load_targets():
        bud = t.budget(b)
        print(f"{t.id}  —  {t.name}  [{t.strategy}; {bud['max_hours']}h / ${bud['max_cost_usd']} per instance]")
        if t.strategy == "campaign":
            print(f"  prompt: {t.prompt}")
        for v in t.vulns:
            print(f"  {'*' if v.case_id in chosen else ' '} {v.case_id}  {v.title}")
        for v in t.excluded:
            print(f"    ({v.case_id}  not scored: {'/'.join(v.os or [])} only, target is {t.os})")
    return 0


def cmd_lint(args) -> int:
    errs = [e for t in load_targets() for e in lint_target(t)]
    for e in errs:
        print(f"error: {e}")
    print("ok" if not errs else f"{len(errs)} problem(s)")
    return 1 if errs else 0


def cmd_fetch(args) -> int:
    b = _bench(args)
    for t, _ in _selection(b, args)[0]:
        log(f"{t.id} ({host_arch()})")
        fetch(t, Path(b["cache_dir"]), log=log)
    log("material cached")
    return 0


def cmd_check(args) -> int:
    b = _bench(args)
    ok = True

    def row(good: bool, what: str, detail: str = "") -> None:
        nonlocal ok
        ok &= good
        print(f"  {'ok  ' if good else 'FAIL'}  {what}{('  ' + detail) if detail else ''}")

    print("hackbench preflight")
    row(sys.version_info >= (3, 9), "python >= 3.9", platform.python_version())
    row(bool(shutil.which("omp")), "omp on PATH", _sh(["omp", "--version"]).splitlines()[0] if shutil.which("omp") else "")
    row(bool(shutil.which("tmux")), "tmux on PATH", _sh(["tmux", "-V"]))
    row(bool(shutil.which("git")), "git on PATH")
    hb = Path(b["hackbot"])
    row((hb / ".omp/hooks/pre/ralph.ts").exists(), "hackbot clone", f"{hb} @ {_sh(['git', '-C', str(hb), 'rev-parse', '--short', 'HEAD'])}")
    active, why = hunt_host_status()
    if platform.system() == "Linux":
        row(active or b["launcher"]["mode"] == "tmux", "hunt host (hackbot-hunt.service)", why)
    else:
        print(f"  info  hunt host: {why}; the private tmux launcher is used (HACKBOT_ALLOW_UNPROTECTED=1)")
    row(bool(shutil.which("docker")), "docker on PATH (PoC harnesses)")
    print(f"  info  host arch {host_arch()}")
    wr = Path(b["work_root"])
    row(REPO.resolve() not in [wr, *wr.parents], "work_root outside this repo", str(wr))
    probe_dir = wr if wr.exists() else wr.parent if wr.parent.exists() else Path.home()
    try:  # material like GitLab's terminfo holds names that differ only in case; they collapse on such a fs
        import tempfile
        with tempfile.TemporaryDirectory(dir=probe_dir) as td:
            (Path(td) / "CaseProbe").touch()
            ci = (Path(td) / "caseprobe").exists()
        row(not ci, "work_root filesystem is case-sensitive",
            "case-INSENSITIVE (e.g. a macOS / Parallels shared folder): some material files will collapse; put work_root on VM-local disk" if ci else "")
    except OSError as e:
        print(f"  info  could not probe work_root case sensitivity: {e}")
    free = shutil.disk_usage(probe_dir).free
    print(f"  info  free disk at work_root: {free / 2**30:.0f} GiB (GitLab CE: ~1.2 GiB cached + ~4.5 GiB per instance)")
    lint = [e for t in load_targets() for e in lint_target(t)]
    row(not lint, "target specs lint", f"{len(lint)} problem(s)" if lint else "")
    print("ready" if ok else "not ready")
    return 0 if ok else 1


def _run_meta(b: dict, run_id: str, plan: dict, include: list, exclude: list) -> dict:
    hb = Path(b["hackbot"])
    return {
        "run_id": run_id,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hackbench_version": __version__,
        "bench_commit": _sh(["git", "-C", str(REPO), "rev-parse", "HEAD"]),
        "hackbot": {"path": str(hb), "commit": _sh(["git", "-C", str(hb), "rev-parse", "HEAD"]),
                    "dirty": bool(_sh(["git", "-C", str(hb), "status", "--porcelain"]))},
        "omp_version": _sh(["omp", "--version"]).splitlines()[0] if shutil.which("omp") else None,
        "host": {"system": platform.system(), "release": platform.release(), "arch": host_arch(), "node": platform.node()},
        "bench": {k: v for k, v in b.items() if not k.startswith("_")},
        "selection": {"include": include, "exclude": exclude},
        "plan": plan,
    }


def cmd_run(args) -> int:
    b = _bench(args)
    selection, include, exclude = _selection(b, args)
    if not selection:
        print("no cases selected (bench.yaml targets: / -c / --exclude)")
        return 2
    errs = [e for t, _ in selection for e in lint_target(t)]
    if errs:
        for e in errs:
            print(f"error: {e}")
        return 2
    work = Path(b["work_root"])
    if REPO.resolve() in [work, *work.parents]:
        print(f"error: work_root {work} is inside this repo; the hunt's agents could read the ground truth")
        return 2
    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_dir = work / "runs" / run_id
    plan = {t.id: {"strategy": t.strategy, "vulns": [v.id for v in vs], "titles": {v.id: v.title for v in vs}}
            for t, vs in selection}

    if args.dry_run:
        print(f"run {run_id} → {run_dir}   (arch {host_arch()})")
        print(f"selection: include {include or ['*']}" + (f", exclude {exclude}" if exclude else ""))
        j = b["judge"]
        print(f"judge: {j['model']} (thinking {j.get('thinking') or 'default'})" if j["enabled"] else "judge: off (keywords decide)")
        for t, vs in selection:
            bud = _budget(b, t.budget(b))
            print(f"\n{t.id} [{t.strategy}, {t.os}] — {len(vs)} vuln(s): {', '.join(v.id for v in vs)}")
            if t.excluded:
                ex = ", ".join("%s (%s only)" % (v.id, "/".join(v.os or [])) for v in t.excluded)
                print(f"  not scored (other OS): {ex}")
            if t.strategy == "campaign":
                cmax = t.campaign(b)
                print(f"  fresh hunt instances, each stopping at the first not-yet-found vuln; ends when all are found or after "
                      f"{cmax['max_misses']} instance(s) without a new find. Per instance: {bud['max_hours']}h / ${bud['max_cost_usd']}")
                print(f"  {b['hunt_command'].format(prompt=t.prompt)}")
            else:
                for v in vs:
                    print(f"  {v.id}: {b['hunt_command'].format(prompt=v.prompt)}")
            for m in t.material():
                print(f"  material {m['kind']:7} → vault/context/{m['dest']}  {m.get('url') or m.get('path')}")
        return 0

    work.mkdir(parents=True, exist_ok=True)
    lock = open(work / ".hackbench.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(f"error: another hackbench run holds {work}/.hackbench.lock (one hunt at a time)")
        return 2
    try:
        launcher = TmuxLauncher.from_config(b["launcher"]["mode"], work)
    except LaunchError as e:
        print(f"error: {e}")
        return 2
    omp = shutil.which("omp") or "omp"
    judge = OmpJudge(launcher.oneshot, b["judge"]["model"], int(b["judge"]["timeout_s"]), omp,
                     thinking=b["judge"].get("thinking")) if b["judge"]["enabled"] else None

    run_dir.mkdir(parents=True, exist_ok=True)
    if (run_dir / "run.json").exists():
        meta = json.loads((run_dir / "run.json").read_text())
        for tid, tp in plan.items():  # a resume may add targets; it never drops planned ones
            meta.setdefault("plan", {}).setdefault(tid, tp)
        write_json(run_dir / "run.json", meta)
    else:
        write_json(run_dir / "run.json", _run_meta(b, run_id, plan, include, exclude))
        cfg = Path(b["hackbot"]) / ".omp" / "config.yml"
        if cfg.exists():
            shutil.copy2(cfg, run_dir / "hackbot-config.yml")
    log(f"run {run_id}: {sum(len(vs) for _, vs in selection)} vuln(s) in {len(selection)} target(s), "
        f"launcher {launcher.mode}, judge {'on' if judge else 'off'} → {run_dir}")

    rc = drive(b, run_dir, run_id, selection, launcher, judge, log=log, omp=omp, retry_errors=args.retry_errors)
    if rc:
        return rc
    s = summarize(run_dir)
    print()
    print(render_md(s))
    print(f"summary: {run_dir / 'summary.md'}")
    return 0


def cmd_report(args) -> int:
    b = _bench(args)
    run_dir = Path(args.run) if ("/" in args.run or Path(args.run).exists()) else Path(b["work_root"]) / "runs" / args.run
    if not run_dir.exists():
        print(f"no run at {run_dir}")
        return 2
    print(render_md(summarize(run_dir)))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hackbench", description="Benchmark redteam-hackbot (/hunt) on known-vulnerable targets.")
    p.add_argument("--config", help="bench config (default: bench.yaml in the repo)")
    sub = p.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list", help="list targets and their vulns; * marks what the selection analyzes")
    sub.add_parser("lint", help="check every target spec")
    f = sub.add_parser("fetch", help="download and verify target material (this host's arch) into the cache")
    c = sub.add_parser("check", help="preflight the host")
    c.add_argument("--launcher", choices=["auto", "hunt-host", "tmux"])
    r = sub.add_parser("run", help="run targets one hunt at a time")
    r.add_argument("--run-id", help="name of the run; reusing one resumes it")
    r.add_argument("--retry-errors", action="store_true", help="on resume, re-run an instance that ended in a setup/launch error or an interrupt")
    r.add_argument("--launcher", choices=["auto", "hunt-host", "tmux"])
    r.add_argument("--max-hours", type=float, help="override every instance's time budget")
    r.add_argument("--max-cost", type=float, help="override every instance's spend budget (USD)")
    r.add_argument("--stop", choices=["kill", "graceful"], help="how to end a hunt after a hit or a budget stop")
    r.add_argument("--no-judge", action="store_true", help="decide hits with the keyword matcher only")
    r.add_argument("--discard-workspaces", action="store_true", help="keep only sessions/, reports/ and recon/ of each instance")
    r.add_argument("--dry-run", action="store_true", help="print the plan and the /hunt lines, run nothing")
    for sp in (ls, f, r):
        sp.add_argument("-c", "--case", action="append",
                        help="target or target/vuln glob, e.g. 'codex-*' (repeatable); replaces bench.yaml targets.include")
        sp.add_argument("--exclude", action="append",
                        help="target or target/vuln glob to skip (repeatable); added to bench.yaml targets.exclude")
    rp = sub.add_parser("report", help="(re)build summary.md / summary.json for a run")
    rp.add_argument("run", help="run id or run directory")
    args = p.parse_args(argv)
    return {"list": cmd_list, "lint": cmd_lint, "fetch": cmd_fetch, "check": cmd_check, "run": cmd_run,
            "report": cmd_report}[args.cmd](args)
