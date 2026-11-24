"""Drive every selected target: one hunt instance at a time until each target's plan is exhausted."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .config import Target, Vuln, deep_merge
from .material import fetch
from .report import ERROR_STATUSES, load_instances, summarize
from .runner import HuntInstance, fmt_dur, plan_next


def drive(b: dict, run_dir: Path, run_id: str, selection: list[tuple[Target, list[Vuln]]], launcher, judge,
          log=print, omp: str = "omp", retry_errors: bool = False) -> int:
    """Returns 0 when every target ran to its end, 130 on interrupt, 2 on a material failure."""
    for t, vs in selection:
        retried = False
        while True:
            done = [r for r in load_instances(run_dir) if r.get("target") == t.id]
            last = done[-1] if done else None
            if last and last.get("status") in ERROR_STATUSES:
                if retry_errors and not retried:
                    retired = run_dir / "retired" / f"{t.id}__{last['index']:02d}-{datetime.now().strftime('%H%M%S')}"
                    retired.parent.mkdir(parents=True, exist_ok=True)
                    (run_dir / "instances" / f"{t.id}__{last['index']:02d}").rename(retired)
                    log(f"{t.id}: retrying instance {last['index']} ({last['status']}); old attempt in {retired}")
                    retried = True
                    continue
                log(f"{t.id}: stopped after {last['status']} in {last['instance']} ({last.get('error')}); "
                    f"fix it and resume with --run-id {run_id} --retry-errors")
                break
            nxt = plan_next(t, vs, done, b)
            if nxt is None:
                log(f"{t.id}: done")
                break
            stop_vulns, prompt, budget = nxt
            index = max((r.get("index", 0) for r in done), default=0) + 1
            log(f"{t.id} #{index:02d}: hunting for {', '.join(v.id for v in stop_vulns)}")
            try:
                fetch(t, Path(b["cache_dir"]), log=log)
            except Exception as e:  # noqa: BLE001
                log(f"  material unavailable: {e}")
                return 2
            inst = HuntInstance(b, run_dir, run_id, t, index, stop_vulns, prompt,
                                deep_merge(budget, b.get("_cli_budget")), launcher, judge, log=log, omp=omp)
            res = inst.run()
            hits = [f["vuln"] for f in res.get("found", []) if f["in_stop_set"]]
            log(f"{t.id} #{index:02d}: {res['status']}" + (f" — proved {', '.join(hits)}" if hits else "")
                + f" · {fmt_dur(res.get('wall_s'))} · ${res.get('total_cost_usd') or 0:.2f}"
                + (f" · {res['error']}" if res.get("error") else ""))
            summarize(run_dir)
            if inst.interrupted:
                log(f"interrupted: resume with --run-id {run_id} --retry-errors")
                return 130
    return 0
