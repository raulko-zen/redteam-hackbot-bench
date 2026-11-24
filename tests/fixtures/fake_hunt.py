"""Stands in for `omp` + `/hunt` in tests: waits for the typed /hunt line, then plays a hunt on disk.

usage: fake_hunt.py <workspace> <session-dir> <script>
  script: comma-separated steps after recon: find1 (VALID FIND for TOY-1), find2 (VALID FIND for TOY-2),
          lead (an unrelated lead), idle (do nothing more)
"""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ws, sessdir, script = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3].split(",")
sessdir.mkdir(parents=True, exist_ok=True)


def iso(t=None):
    return datetime.fromtimestamp(t or time.time(), timezone.utc).isoformat().replace("+00:00", "Z")


n = 0


def spend(path: Path, usd: float):
    global n
    n += 1
    path.parent.mkdir(parents=True, exist_ok=True)
    rid = f"{ws.parent.name}-r{n}"
    with open(path, "a") as f:
        f.write(json.dumps({"type": "message", "id": rid, "timestamp": iso(), "message": {
            "role": "assistant", "provider": "anthropic", "model": "claude-opus-5-5", "responseId": rid,
            "usage": {"input": 10, "output": 20, "cacheRead": 0, "cacheWrite": 0, "cost": {"total": usd}}}}) + "\n")


cmd_file = ws / ".fake-cmd"
while not cmd_file.exists():
    time.sleep(0.05)
cmd = cmd_file.read_text()
hunt_json = ws / "vault/sessions/.hunt.json"
main = sessdir / "2026-01-01T00-00-00-000Z_main.jsonl"

hunt_json.write_text(json.dumps({"owner": "x", "focus": cmd, "started": iso(), "iteration": 0, "phase": "recon", "fresh": True}))
spend(main, 1.0)  # recon
time.sleep(0.3)
(ws / "vault/context/CONTEXT.md").write_text("# Target context\n")
S = "vault/sessions/01-toy-hunt"
sd = ws / S
for d in ("leads", "gadgets", "findings"):
    (sd / d).mkdir(parents=True, exist_ok=True)
hunt_json.write_text(json.dumps({"owner": "x", "focus": cmd, "started": iso(), "iteration": 1, "dir": S, "fresh": True}))
spend(sessdir / "2026-01-01T00-00-00-000Z_main/Worker1.jsonl", 2.0)

HDR = "VERDICT: VALID\nSEVERITY: High\nCONFIDENCE: High\nREASONING: reproduced\nISSUES: none\nREQUIRED EVIDENCE TO SUBMIT: poc\n\n"
for step in script:
    time.sleep(0.4)
    if step == "lead":
        (sd / "leads/LEAD-009-noise.md").write_text("VERDICT: NEW\nSEVERITY: Low\n\n# LEAD-009 — something unrelated\n\n- Objective: none\n")
    elif step == "find1":
        (sd / "findings/FIND-001-strcpy.md").write_text(
            HDR + "# FIND-001 — attacker input to parse() overflows a stack buffer\n\n- Objective: met\n\n"
            "## Claim\nparse() in toy.c uses strcpy into char b[8]: stack overflow.\n")
    elif step == "find2":
        (sd / "gadgets/GAD-002-fmt.md").write_text(
            HDR + "# GAD-002 — printf(s) format string in parse()\n\n- Objective: step\n\n"
            "## Claim\nparse() passes attacker text to printf: format string write primitive.\n")
    spend(main, 1.0)
while True:  # an omp session stays open until the bench ends it
    time.sleep(1)
