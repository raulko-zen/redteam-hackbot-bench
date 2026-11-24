"""Spend of an omp run, read from its session files.

omp writes one JSONL file per session; subagent sessions (workers, validators, recon agents) are JSONL
files in a directory next to it. Every model call is recorded with its priced usage:

  {"type":"message", "message":{"role":"assistant", "usage":{..., "cost":{"total":…}}, "responseId":…}}
  {"type":"model_usage", "purpose":"title-fork", "usage":{..., "cost":{"total":…}}}   # auxiliary calls

The hunt runs with --session-dir pointing at a per-case directory, so everything under it is this case.
Files are read incrementally (only complete lines), so polling a multi-hour hunt stays cheap.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

TOKEN_KEYS = ("input", "output", "cacheRead", "cacheWrite")


@dataclass
class Call:
    ts: float          # epoch seconds
    cost: float        # USD
    model: str
    tokens: dict
    file: str
    purpose: str       # "turn" for assistant messages, else model_usage purpose


def _ts(entry: dict, msg: dict) -> float:
    v = entry.get("timestamp")
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    for v in (msg.get("completedAt"), msg.get("timestamp")):
        if isinstance(v, (int, float)):
            return v / 1000.0 if v > 1e11 else float(v)
    return 0.0


class CostTracker:
    def __init__(self, root: Path):
        self.root = Path(root)
        self._offsets: dict[Path, int] = {}
        self._seen: set = set()
        self.calls: list[Call] = []

    def scan(self) -> int:
        """Read new lines; return the number of new priced calls."""
        if not self.root.exists():
            return 0
        before = len(self.calls)
        for p in sorted(self.root.rglob("*.jsonl")):
            try:
                size = p.stat().st_size
            except OSError:
                continue
            off = self._offsets.get(p, 0)
            if size < off:  # truncated or replaced: start over (dedupe keys keep totals right)
                off = 0
            if size == off:
                continue
            with open(p, "rb") as f:
                f.seek(off)
                data = f.read(size - off)
            end = data.rfind(b"\n")
            if end < 0:
                continue
            self._offsets[p] = off + end + 1
            for line in data[: end + 1].splitlines():
                self._parse(p, line)
        return len(self.calls) - before

    def _parse(self, p: Path, line: bytes) -> None:
        try:
            e = json.loads(line)
        except ValueError:
            return
        if not isinstance(e, dict):
            return
        t = e.get("type")
        if t == "message":
            msg = e.get("message") or {}
            if msg.get("role") != "assistant":
                return
            usage = msg.get("usage") or {}
            key = ("r", msg.get("responseId")) if msg.get("responseId") else ("e", str(p), e.get("id"))
            model = f"{msg.get('provider', '?')}/{msg.get('model', '?')}"
            purpose = "turn"
        elif t == "model_usage":
            msg = {}
            usage = e.get("usage") or {}
            key = ("u", str(p), e.get("id"))
            model = f"{e.get('provider', '?')}/{e.get('model', '?')}"
            purpose = str(e.get("purpose") or "aux")
        else:
            return
        if key in self._seen:
            return
        self._seen.add(key)
        cost = float(((usage.get("cost") or {}).get("total")) or 0.0)
        tokens = {k: int(usage.get(k) or 0) for k in TOKEN_KEYS}
        self.calls.append(Call(_ts(e, msg), cost, model, tokens, str(p.relative_to(self.root)), purpose))

    # ---- aggregates -------------------------------------------------------------------------------
    def _sel(self, until: float | None):
        return self.calls if until is None else [c for c in self.calls if c.ts <= until]

    def total(self, until: float | None = None) -> float:
        return round(sum(c.cost for c in self._sel(until)), 6)

    def summary(self, until: float | None = None) -> dict:
        calls = self._sel(until)
        by_model: dict = defaultdict(lambda: {"calls": 0, "cost_usd": 0.0, **{k: 0 for k in TOKEN_KEYS}})
        for c in calls:
            m = by_model[c.model]
            m["calls"] += 1
            m["cost_usd"] += c.cost
            for k in TOKEN_KEYS:
                m[k] += c.tokens.get(k, 0)
        for m in by_model.values():
            m["cost_usd"] = round(m["cost_usd"], 6)
        files = {c.file for c in calls}
        return {
            "cost_usd": round(sum(c.cost for c in calls), 6),
            "calls": len(calls),
            "sessions": len(files),
            "tokens": {k: sum(c.tokens.get(k, 0) for c in calls) for k in TOKEN_KEYS},
            "by_model": dict(by_model),
        }

    def last_call_ts(self) -> float:
        return max((c.ts for c in self.calls), default=0.0)
