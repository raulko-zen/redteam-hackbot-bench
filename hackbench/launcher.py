"""Run omp in a detached tmux pane and drive it like an operator.

hunt-host: redteam-hackbot's protected hunt host (scripts/protect-harness.sh install): hackbot-hunt.service runs
  a tmux server as you on $XDG_RUNTIME_DIR/hackbot.tmux, in a root-owned cgroup that systemd-oomd never picks.
  On Linux, /hunt refuses to run anywhere else (.omp/hooks/lib/protection.ts). We create *detached*
  sessions on that server, the same way `hackbot-hunt` does minus the attach, so omp and every agent it
  spawns live in the protected cgroup.
tmux: a private tmux server (development, macOS). Sets HACKBOT_ALLOW_UNPROTECTED=1.

The judge's one-shot omp calls run through the same server: an omp started outside the hunt host can leave a
worker daemon there, which makes the next /hunt refuse.
"""
from __future__ import annotations

import os
import platform
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

HUNT_UNIT = "hackbot-hunt.service"
SKIP_ENV = {
    "TMUX", "TMUX_PANE", "TERM", "SHLVL", "PWD", "OLDPWD", "_", "COLUMNS", "LINES", "INVOCATION_ID",
    "JOURNAL_STREAM", "MANAGERPID", "SYSTEMD_EXEC_PID", "PS1", "PS2", "PS4", "PROMPT_COMMAND",
}


class LaunchError(RuntimeError):
    pass


def hunt_host_status() -> tuple[bool, str]:
    if platform.system() != "Linux":
        return False, "not Linux"
    if not shutil.which("systemctl"):
        return False, "no systemctl"
    r = subprocess.run(["systemctl", "is-active", "--quiet", HUNT_UNIT])
    if r.returncode == 0:
        return True, "active"
    r2 = subprocess.run(["systemctl", "cat", HUNT_UNIT], capture_output=True)
    return False, "installed but not running (sudo systemctl start hackbot-hunt.service)" if r2.returncode == 0 else "not installed"


class TmuxLauncher:
    def __init__(self, socket: str, mode: str, tmux: str = "tmux"):
        self.socket = socket
        self.mode = mode  # "hunt-host" | "tmux"
        self.tmux = tmux

    @classmethod
    def from_config(cls, mode: str, work_root: Path) -> "TmuxLauncher":
        tmux = shutil.which("tmux")
        if not tmux:
            raise LaunchError("tmux is not installed")
        active, why = hunt_host_status()
        if mode == "auto":
            mode = "hunt-host" if active else "tmux"
            if platform.system() == "Linux" and not active:
                raise LaunchError(
                    f"the hackbot hunt host is {why}; /hunt refuses outside it on Linux. Install it with "
                    "`sudo scripts/protect-harness.sh install` in the hackbot clone, or pass --launcher tmux "
                    "to hunt unprotected (HACKBOT_ALLOW_UNPROTECTED=1)."
                )
        if mode == "hunt-host":
            if not active:
                raise LaunchError(f"the hackbot hunt host is {why}")
            rt = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
            return cls(f"{rt}/hackbot.tmux", "hunt-host", tmux)
        if mode == "tmux":
            # Keep the socket path short (sun_path is ~104 bytes on macOS).
            return cls(f"/tmp/hackbench-{os.getuid()}.tmux", "tmux", tmux)
        raise LaunchError(f"unknown launcher mode {mode!r}")

    # ---- tmux plumbing ----------------------------------------------------------------------------
    def _t(self, *args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
        # Output is always captured (capture is kept for callers' readability).
        try:
            r = subprocess.run([self.tmux, "-S", self.socket, *args], capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            r = subprocess.CompletedProcess(args, 124, "", "timed out after 60s")
        if check and r.returncode != 0:  # carry tmux's own reason into result.json
            raise LaunchError(f"tmux {args[0]} failed ({r.returncode}): {(r.stderr or r.stdout).strip()}")
        return r

    @staticmethod
    def _pane(name: str) -> str:
        # A pane target needs the colon: tmux (3.6) looks a bare "=name" up as a pane, not a session, and
        # send-keys then fails with "can't find pane" while display-message and capture-pane print nothing.
        return f"={name}:"

    def _env_args(self, env: dict) -> list[str]:
        out = []
        for k, v in env.items():
            if k in SKIP_ENV or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                continue
            out += ["-e", f"{k}={v}"]
        return out

    def start(self, name: str, cwd: Path, argv: list[str], env: dict) -> None:
        if self.alive(name):
            raise LaunchError(f"tmux session {name} already exists")
        env = dict(env)
        if self.mode == "tmux":
            env["HACKBOT_ALLOW_UNPROTECTED"] = "1"
        self._t("new-session", "-d", "-s", name, "-x", "240", "-y", "60", "-c", str(cwd),
                *self._env_args(env), "--", *argv)

    def alive(self, name: str) -> bool:
        r = self._t("has-session", "-t", f"={name}", check=False, capture=True)
        return r.returncode == 0

    def pane_dead(self, name: str) -> bool:
        r = self._t("display-message", "-p", "-t", self._pane(name), "#{pane_dead}", check=False, capture=True)
        return r.returncode != 0 or r.stdout.strip() == "1"

    def send_line(self, name: str, text: str) -> None:
        self._t("send-keys", "-t", self._pane(name), "-l", "--", text)
        time.sleep(1.0)
        self._t("send-keys", "-t", self._pane(name), "Enter")

    def send_enter(self, name: str) -> None:
        self._t("send-keys", "-t", self._pane(name), "Enter", check=False)

    def capture(self, name: str, lines: int = 3000) -> str:
        r = self._t("capture-pane", "-p", "-J", "-t", self._pane(name), "-S", f"-{lines}", check=False, capture=True)
        return r.stdout if r.returncode == 0 else ""

    def kill(self, name: str) -> None:
        self._t("kill-session", "-t", f"={name}", check=False, capture=True)

    def oneshot(self, name: str, cwd: Path, argv: list, out_path: Path, timeout_s: int) -> int | None:
        """Run argv to completion in its own detached session; stdout → out_path. None on timeout."""
        rc_path = out_path.with_suffix(".rc")
        sname = f"hb-{name}-{os.getpid()}"
        script = f"{shlex.join(argv)} </dev/null >{shlex.quote(str(out_path))} 2>&1; echo $? >{shlex.quote(str(rc_path))}"
        env = {k: v for k, v in os.environ.items()}
        if self.mode == "tmux":
            env["HACKBOT_ALLOW_UNPROTECTED"] = "1"
        self._t("new-session", "-d", "-s", sname, "-c", str(cwd), *self._env_args(env), "--", "sh", "-c", script)
        deadline = time.time() + timeout_s
        try:
            while time.time() < deadline:
                if rc_path.exists():
                    try:
                        return int(rc_path.read_text().strip() or "1")
                    except ValueError:
                        return 1
                time.sleep(2)
            return None
        finally:
            self.kill(sname)
