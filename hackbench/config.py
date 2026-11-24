"""Bench config (bench.yaml) and the target / vuln specs under targets/."""
from __future__ import annotations

import copy
import fnmatch
import json
import os
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    raise SystemExit("hackbench needs PyYAML (the hackbot installer adds it: apt python3-yaml / pip install pyyaml)")

REPO = Path(__file__).resolve().parent.parent
TARGETS_DIR = REPO / "targets"

DEFAULTS: dict = {
    "hackbot": "~/projects/redteam-hackbot",
    "work_root": "~/hackbench-work",
    "cache_dir": "~/.cache/hackbench",
    "hunt_command": "/hunt --fresh '{prompt}'",
    "launcher": {"mode": "auto", "startup_wait_s": 20, "start_timeout_s": 240},
    "omp": {"args": [], "pass_max_cost": True},
    "budget": {"max_hours": 12, "max_cost_usd": 300},
    "campaign": {"max_misses": 1, "max_instances": 0},
    "monitor": {"poll_s": 20, "stopped_idle_s": 600},
    "stop": {
        "mode": "kill",
        "graceful_timeout_s": 1800,
        "quiesce_s": 60,
        "kill_workspace_procs": True,
        "cleanup_containers": True,
    },
    "detection": {"accept_tiers": ["finding", "gadget"], "require_confirmed": False},
    "judge": {"enabled": True, "model": "sonnet", "timeout_s": 300, "count_partial": False},
    "keep_workspaces": True,
    "keep_material": False,
}

MATERIAL_KINDS = ("tarball", "file", "deb", "git", "local")
ARCHES = ("amd64", "arm64")
OSES = ("linux", "windows", "macos")


def host_arch() -> str:
    m = platform.machine().lower()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, m)


def deep_merge(base: dict, over: dict | None) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def expand(p: str | os.PathLike) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(str(p)))).resolve()


def load_bench(path: Path | None = None) -> dict:
    path = path or REPO / "bench.yaml"
    data = {}
    if path.exists():
        data = yaml.safe_load(path.read_text()) or {}
    cfg = deep_merge(DEFAULTS, data)
    if os.environ.get("HACKBENCH_HACKBOT"):
        cfg["hackbot"] = os.environ["HACKBENCH_HACKBOT"]
    if os.environ.get("HACKBENCH_WORK_ROOT"):
        cfg["work_root"] = os.environ["HACKBENCH_WORK_ROOT"]
    for k in ("hackbot", "work_root", "cache_dir"):
        cfg[k] = str(expand(cfg[k]))
    return cfg


def one_line(s) -> str:
    return " ".join(str(s or "").split())


@dataclass
class Target:
    id: str
    dir: Path
    data: dict
    vulns: list["Vuln"] = field(default_factory=list)
    excluded: list["Vuln"] = field(default_factory=list)  # known vulns that do not apply to this target's OS

    @property
    def name(self) -> str:
        return self.data.get("name", self.id)

    @property
    def os(self) -> str:
        """The OS the target's material is built for (vulns may declare `os: [...]` to scope themselves)."""
        return str(self.data.get("os", "linux")).lower()

    @property
    def strategy(self) -> str:
        """campaign: one hunt after another, each stops at the first not-yet-found vuln of the target.
        per-vuln: one hunt per vuln, each stops only at its own vuln (vulns may carry their own prompts)."""
        return self.data.get("strategy", "campaign")

    @property
    def prompt(self) -> str:
        return one_line(self.data.get("prompt"))

    def material(self, arch: str | None = None) -> list[dict]:
        """Material entries for this host's architecture (entries without `arch` apply everywhere)."""
        arch = arch or host_arch()
        return [m for m in self.data.get("material", []) if not m.get("arch") or m.get("arch") == arch]

    @property
    def target_json_path(self) -> Path:
        return self.dir / self.data.get("target_json", "target.json")

    def target_json(self) -> dict:
        return json.loads(self.target_json_path.read_text())

    def budget(self, bench: dict) -> dict:
        return deep_merge(bench["budget"], self.data.get("budget"))

    def detection(self, bench: dict) -> dict:
        return deep_merge(bench["detection"], self.data.get("detection"))

    def campaign(self, bench: dict) -> dict:
        return deep_merge(bench["campaign"], self.data.get("campaign"))


@dataclass
class Vuln:
    id: str
    path: Path
    data: dict
    target: Target

    @property
    def case_id(self) -> str:
        return f"{self.target.id}/{self.id}"

    @property
    def title(self) -> str:
        return self.data.get("title", self.id)

    @property
    def prompt(self) -> str:
        if self.target.strategy == "campaign":
            return self.target.prompt
        return one_line(self.data.get("prompt")) or self.target.prompt

    def budget(self, bench: dict) -> dict:
        b = self.target.budget(bench)
        return b if self.target.strategy == "campaign" else deep_merge(b, self.data.get("budget"))

    @property
    def os(self) -> list[str] | None:
        v = self.data.get("os")
        return None if v is None else [str(x).lower() for x in ([v] if isinstance(v, str) else v)]

    def applies_to(self, target: "Target") -> bool:
        return self.os is None or target.os in self.os


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)


def load_targets(root: Path = TARGETS_DIR) -> list[Target]:
    targets = []
    for spec in sorted(root.glob("*/target.yaml")):
        data = yaml.safe_load(spec.read_text()) or {}
        t = Target(id=str(data.get("id") or spec.parent.name), dir=spec.parent, data=data)
        seen = set()
        for g in data.get("vulns") or ["vulns/*.yaml"]:
            for vp in sorted(spec.parent.glob(g)):
                if vp in seen:
                    continue
                seen.add(vp)
                vd = yaml.safe_load(vp.read_text()) or {}
                v = Vuln(id=str(vd.get("id") or vp.stem), path=vp, data=vd, target=t)
                (t.vulns if v.applies_to(t) else t.excluded).append(v)
        targets.append(t)
    return targets


def select(targets: list[Target], patterns: list[str] | None) -> list[tuple[Target, list[Vuln]]]:
    """Targets with the vulns the patterns select (a target pattern selects all its vulns)."""
    out = []
    for t in targets:
        vs = [v for v in t.vulns if not patterns
              or any(fnmatch.fnmatch(v.case_id, p) or fnmatch.fnmatch(t.id, p) for p in patterns)]
        if vs:
            out.append((t, vs))
    return out


def lint_target(t: Target) -> list[str]:
    """Problems that would make a target unrunnable or its score meaningless."""
    errs: list[str] = []
    w = t.id
    mats = t.data.get("material", [])
    if not mats:
        errs.append(f"{w}: no material")
    for i, m in enumerate(mats):
        kind = m.get("kind")
        if kind not in MATERIAL_KINDS:
            errs.append(f"{w}: material[{i}] kind must be one of {', '.join(MATERIAL_KINDS)}")
        if m.get("arch") and m["arch"] not in ARCHES:
            errs.append(f"{w}: material[{i}] arch must be one of {', '.join(ARCHES)}")
        d = str(m.get("dest", ""))
        if not d or d.startswith(("/", "..")) or "/.." in d:
            errs.append(f"{w}: material[{i}] needs a relative dest under vault/context/")
        if kind in ("tarball", "file", "deb") and not re.fullmatch(r"[0-9a-f]{64}", str(m.get("sha256", ""))):
            errs.append(f"{w}: material[{i}] {kind} needs a sha256")
        if kind == "git" and not re.fullmatch(r"[0-9a-f]{40}", str(m.get("commit", ""))):
            errs.append(f"{w}: material[{i}] git needs a full 40-hex commit")
    arches = {m["arch"] for m in mats if m.get("arch")}
    for a in arches:
        if not t.material(a):
            errs.append(f"{w}: no material for {a}")
    try:
        tj = t.target_json()
    except Exception as e:  # noqa: BLE001
        errs.append(f"{w}: target.json unreadable: {e}")
        tj = {}
    roots = tj.get("artifactRoots") or []
    if not roots:
        errs.append(f"{w}: target.json artifactRoots is empty (/hunt refuses)")
    for k in ("readOnly", "appendOnly", "artifactRoots", "dependencyRoots"):
        for p in tj.get(k) or []:
            if not (p.startswith("vault/") or p == "third_party" or p.startswith("third_party/")):
                errs.append(f"{w}: target.json {k} entry {p!r} must be written as vault/… or third_party")
    for a in sorted(arches) or [None]:
        dests = {f"vault/context/{m.get('dest')}".rstrip("/") for m in t.material(a)}
        for r in roots:
            if not any(d == r or d.startswith(r + "/") or r.startswith(d + "/") for d in dests):
                errs.append(f"{w}: artifactRoot {r!r} is not filled by any material{f' for {a}' if a else ''}")
    if t.strategy not in ("campaign", "per-vuln"):
        errs.append(f"{w}: strategy must be campaign or per-vuln")
    if t.os not in OSES:
        errs.append(f"{w}: os must be one of {', '.join(OSES)}")
    for v in t.vulns + t.excluded:
        if v.os is not None and (not v.os or not set(v.os) <= set(OSES)):
            errs.append(f"{v.case_id}: os must list values from {', '.join(OSES)}")
    if not t.vulns:
        errs.append(f"{w}: no vulns apply to os {t.os}")
    ids = [v.id for v in t.vulns + t.excluded]
    if len(ids) != len(set(ids)):
        errs.append(f"{w}: duplicate vuln ids")
    if t.strategy == "campaign":
        if not t.prompt:
            errs.append(f"{w}: a campaign target needs a target-level prompt")
        for v in t.vulns:
            if v.data.get("prompt") or v.data.get("budget"):
                errs.append(f"{v.case_id}: prompt/budget belong to the target in a campaign (strategy: per-vuln to vary them)")
    for v in t.vulns:
        vw = v.case_id
        if not v.prompt:
            errs.append(f"{vw}: empty prompt")
        if "'" in v.prompt:
            errs.append(f"{vw}: prompt contains a single quote (the /hunt line wraps it in single quotes)")
        if not str(v.data.get("ground_truth", "")).strip():
            errs.append(f"{vw}: no ground_truth (the judge needs it)")
        groups = (v.data.get("match") or {}).get("all_of")
        if not groups or not all(isinstance(g, list) and g for g in groups):
            errs.append(f"{vw}: match.all_of must be a non-empty list of non-empty keyword lists")
    return errs
