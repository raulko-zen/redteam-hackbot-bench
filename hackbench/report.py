"""summary.json / summary.md for a run directory: per-vuln results derived from the hunt instances."""
from __future__ import annotations

import json
import statistics
from pathlib import Path

from .runner import fmt_dur, write_json

ERROR_STATUSES = ("setup_error", "launch_error", "interrupted")


def load_instances(run_dir: Path) -> list[dict]:
    out = []
    for p in sorted((run_dir / "instances").glob("*/result.json")):
        try:
            out.append(json.loads(p.read_text()))
        except ValueError:
            continue
    out.sort(key=lambda r: (r.get("target", ""), r.get("index", 0)))
    return out


def _stats(xs: list[float]) -> dict:
    if not xs:
        return {"n": 0}
    return {"n": len(xs), "mean": round(statistics.mean(xs), 2), "median": round(statistics.median(xs), 2),
            "min": round(min(xs), 2), "max": round(max(xs), 2)}


def vuln_results(plan: dict, instances: list[dict]) -> list[dict]:
    """One row per planned vuln: found by which instance, after how long and how much."""
    rows = []
    for tid, tplan in plan.items():
        insts = [r for r in instances if r.get("target") == tid]
        for vid in tplan["vulns"]:
            row = {"case": f"{tid}/{vid}", "target": tid, "vuln": vid, "title": tplan.get("titles", {}).get(vid),
                   "found": False}
            prior_wall = prior_cost = 0.0
            for r in insts:
                hit = next((f for f in r.get("found", []) if f["vuln"] == vid), None)
                if hit:
                    row.update(
                        found=True, instance=r["instance"], item=hit["item"], tier=hit["tier"],
                        confirmed=hit.get("confirmed"), severity=hit.get("severity"),
                        time_to_find_s=hit.get("time_to_find_s"), cost_to_find_usd=hit.get("cost_to_find_usd"),
                        campaign_time_s=round(prior_wall + (hit.get("time_to_find_s") or 0), 1),
                        campaign_cost_usd=round(prior_cost + (hit.get("cost_to_find_usd") or 0), 4),
                        decided_by=(hit.get("judgement") or {}).get("decided_by"),
                        recon_s=r.get("recon_s"),
                    )
                    break
                prior_wall += r.get("wall_s") or 0
                prior_cost += r.get("total_cost_usd") or 0
            kw = [(r, k) for r in insts for k in r.get("keyword_hits", []) if k["vuln"] == vid]
            if kw:
                r, k = kw[0]
                row["first_mention"] = {"instance": r["instance"], "item": k["item"], "tier": k["tier"], "time_s": k["time_s"]}
            rows.append(row)
    return rows


def build_summary(run_dir: Path, instances: list[dict] | None = None) -> dict:
    """The run's summary as data (no files written). `instances` defaults to the finished ones on disk."""
    meta = json.loads((run_dir / "run.json").read_text()) if (run_dir / "run.json").exists() else {}
    instances = load_instances(run_dir) if instances is None else instances
    plan = meta.get("plan") or {}
    rows = vuln_results(plan, instances)
    found = [r for r in rows if r["found"]]
    s = {
        "run_id": meta.get("run_id"),
        "started_at": meta.get("started_at"),
        "hackbot_commit": (meta.get("hackbot") or {}).get("commit"),
        "omp_version": meta.get("omp_version"),
        "arch": (meta.get("host") or {}).get("arch"),
        "vulns": len(rows),
        "found": len(found),
        "found_pct": round(100.0 * len(found) / len(rows), 1) if rows else None,
        "time_to_find_s": _stats([r["time_to_find_s"] for r in found if r.get("time_to_find_s") is not None]),
        "cost_to_find_usd": _stats([r["cost_to_find_usd"] for r in found if r.get("cost_to_find_usd") is not None]),
        "instances": len(instances),
        "total_cost_usd": round(sum(r.get("total_cost_usd") or 0 for r in instances), 4),
        "judge_cost_usd": round(sum(r.get("judge_cost_usd") or 0 for r in instances), 4),
        "total_wall_s": round(sum(r.get("wall_s") or 0 for r in instances), 1),
        "by_target": {},
        "vuln_results": rows,
        "instance_results": [
            {k: r.get(k) for k in ("instance", "status", "stop_set", "wall_s", "recon_s", "total_cost_usd",
                                   "post_stop_cost_usd", "error")}
            | {"found": [f["vuln"] for f in r.get("found", []) if f.get("in_stop_set", True)],
               "refound": [f["vuln"] for f in r.get("found", []) if not f.get("in_stop_set", True)],
               "other_valid_items": [i["id"] for i in r.get("items", [])
                                     if i["tier"] in ("finding", "gadget") and i["verdict"].upper().startswith("VALID")
                                     and i["id"] not in {f["item"] for f in r.get("found", [])}]}
            for r in instances
        ],
    }
    for tid in plan:
        trows = [r for r in rows if r["target"] == tid]
        tinst = [r for r in instances if r.get("target") == tid]
        s["by_target"][tid] = {"vulns": len(trows), "found": sum(r["found"] for r in trows), "instances": len(tinst),
                               "cost_usd": round(sum(r.get("total_cost_usd") or 0 for r in tinst), 4)}
    return s


def summarize(run_dir: Path) -> dict:
    """Build the summary and write summary.json / summary.md."""
    s = build_summary(run_dir)
    write_json(run_dir / "summary.json", s)
    (run_dir / "summary.md").write_text(render_md(s))
    return s


def _usd(x) -> str:
    return "—" if x is None else f"${x:,.2f}"


def render_md(s: dict) -> str:
    L = [f"# hackbench run {s['run_id']}", ""]
    L.append(f"- Started: {s['started_at']} · hackbot `{(s['hackbot_commit'] or '')[:12]}` · {s['omp_version']} · {s['arch']}")
    pct = "—" if s["found_pct"] is None else f"{s['found_pct']}%"
    L.append(f"- **Found: {s['found']}/{s['vulns']} vulns ({pct})** in {s['instances']} hunt instance(s)")
    t, c = s["time_to_find_s"], s["cost_to_find_usd"]
    if t.get("n"):
        L.append(f"- Time to find (within its instance): median {fmt_dur(t['median'])}, "
                 f"range {fmt_dur(t['min'])}–{fmt_dur(t['max'])}")
        L.append(f"- Cost to find (within its instance): median {_usd(c['median'])}, range {_usd(c['min'])}–{_usd(c['max'])}")
    L.append(f"- Total spend: {_usd(s['total_cost_usd'])} hunts + {_usd(s['judge_cost_usd'])} judge · wall {fmt_dur(s['total_wall_s'])}")
    L += ["", "## Vulns", "", "| Vuln | Found | Instance | Item | Time to find | Cost to find | Campaign time | Campaign cost | First mention |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in s["vuln_results"]:
        fm = r.get("first_mention")
        fm_s = f"{fm['instance'].split('#')[-1]}: {fm['item']} @ {fmt_dur(fm['time_s'])}" if fm else "—"
        if r["found"]:
            L.append(f"| {r['case']} | yes | {r['instance']} | {r['item']} ({r['tier']}) | {fmt_dur(r['time_to_find_s'])} | "
                     f"{_usd(r['cost_to_find_usd'])} | {fmt_dur(r['campaign_time_s'])} | {_usd(r['campaign_cost_usd'])} | {fm_s} |")
        else:
            L.append(f"| {r['case']} | **no** | — | — | — | — | — | — | {fm_s} |")
    L += ["", "## Hunt instances", "", "| Instance | Status | Proved | Recon | Wall | Cost | Other VALID items |",
          "|---|---|---|---|---|---|---|"]
    for r in s["instance_results"]:
        L.append(f"| {r['instance']} | {r['status']} | {', '.join(r['found']) or '—'} | {fmt_dur(r.get('recon_s'))} | "
                 f"{fmt_dur(r.get('wall_s'))} | {_usd(r.get('total_cost_usd'))} | {', '.join(r['other_valid_items']) or '—'} |")
    errs = [r for r in s["instance_results"] if r.get("error")]
    if errs:
        L += ["", "## Errors", ""] + [f"- {r['instance']}: {r['error']}" for r in errs]
    warn = [r for r in s["instance_results"] if (r.get("post_stop_cost_usd") or 0) > 0]
    if warn:
        L += ["", "## Spend after stop", ""] + [f"- {r['instance']}: {_usd(r['post_stop_cost_usd'])}" for r in warn]
    return "\n".join(L) + "\n"
