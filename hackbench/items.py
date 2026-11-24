"""Hackbot item files in a hunt session directory (vault/sessions/NN-<slug>/).

Tier is the directory (findings/ → finding, gadgets/ → gadget, leads/ → lead, leads/rejected/ → rejected).
Lines 1–6 of an item are the verdict header (VERDICT/SEVERITY/CONFIDENCE/REASONING/ISSUES/REQUIRED
EVIDENCE TO SUBMIT); a second, independent validation appends a "VALID (CONFIRMED)" log entry.
See redteam-hackbot docs/05-agents-and-item-lifecycle.md "Item file format".
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

TIER_DIRS = (("findings", "finding"), ("gadgets", "gadget"), ("leads", "lead"), ("leads/rejected", "rejected"))
ITEM_RE = re.compile(r"^(FIND|GAD|LEAD)-\d+.*\.md$")
HEADER_KEYS = ("VERDICT", "SEVERITY", "CONFIDENCE", "REASONING", "ISSUES", "REQUIRED EVIDENCE TO SUBMIT")


@dataclass
class Item:
    id: str
    tier: str
    path: Path
    text: str
    mtime: float
    sha: str
    header: dict = field(default_factory=dict)
    title: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        return self.header.get("VERDICT", "").strip()

    @property
    def valid(self) -> bool:
        return self.verdict.upper().startswith("VALID")

    @property
    def confirmed(self) -> bool:
        return "VALID (CONFIRMED)" in self.text

    @property
    def severity(self) -> str:
        return self.header.get("SEVERITY", "").strip()

    def brief(self) -> dict:
        return {
            "id": self.id,
            "tier": self.tier,
            "path": str(self.path),
            "verdict": self.verdict,
            "confirmed": self.confirmed,
            "severity": self.severity,
            "confidence": self.header.get("CONFIDENCE", "").strip(),
            "title": self.title,
            "objective": self.meta.get("Objective", ""),
        }


def parse_item(path: Path, tier: str) -> Item:
    raw = path.read_bytes()
    text = raw.decode("utf-8", "replace")
    st = path.stat()
    header: dict = {}
    key = None
    title = ""
    meta: dict = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Z][A-Z ]+):\s?(.*)$", line)
        if m and m.group(1) in HEADER_KEYS and not title:
            key = m.group(1)
            header[key] = m.group(2)
            continue
        if line.startswith("# ") and not title:
            title = line[2:].strip()
            key = None
            continue
        if key and line.startswith("- ") and not title:
            header[key] += " " + line[2:]
            continue
        mm = re.match(r"^- ([A-Z][A-Za-z-]+):\s*(.*)$", line)
        if title and mm and mm.group(1) not in meta:
            meta[mm.group(1)] = mm.group(2).strip()
    m = re.match(r"^((?:FIND|GAD|LEAD)-\d+)", path.name)
    return Item(
        id=m.group(1) if m else path.stem,
        tier=tier,
        path=path,
        text=text,
        mtime=st.st_mtime,
        sha=hashlib.sha256(raw).hexdigest(),
        header=header,
        title=title,
        meta=meta,
    )


def scan_items(session_dir: Path) -> list[Item]:
    out = []
    for sub, tier in TIER_DIRS:
        d = session_dir / sub
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            if p.is_file() and ITEM_RE.match(p.name):
                try:
                    out.append(parse_item(p, tier))
                except OSError:
                    continue  # moved mid-scan (promotion): picked up next poll
    return out
