"""Target material: download once into the cache (sha256-verified), then lay it out in a workspace.

Kinds (each entry may carry `arch: amd64|arm64`; only the host's arch is used):
  tarball  url + sha256, extracted (strip_components) into vault/context/<dest>/
  file     url + sha256, placed as shipped into vault/context/<dest>/<name> (hardlinked from the cache when possible)
  deb      url + sha256, the package's data.tar extracted into vault/context/<dest>/ (the installed file tree;
           absolute symlinks are rebased inside dest, as if dest were /)
  git      url + 40-hex commit, checked out without .git into vault/context/<dest>/
  local    path inside the target dir, copied
"""
from __future__ import annotations

import hashlib
import io
import os
import posixpath
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

from .config import Target


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _basename(m: dict) -> str:
    return m.get("name") or PurePosixPath(m["url"].split("?")[0]).name or "material.bin"


def _cache_path(cache: Path, m: dict) -> Path:
    if m["kind"] in ("tarball", "file", "deb"):
        return cache / "files" / m["sha256"] / _basename(m)
    if m["kind"] == "git":
        return cache / "git" / m["commit"]
    raise ValueError(m["kind"])


def _download(url: str, sha: str, dst: Path, log) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dst.parent, suffix=".part")
    os.close(fd)
    try:
        log(f"  download {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "hackbench"})
        h = hashlib.sha256()
        n = 0
        with urllib.request.urlopen(req, timeout=600) as r, open(tmp, "wb") as f:
            total = int(r.headers.get("Content-Length") or 0)
            next_log = 1 << 28
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                h.update(chunk)
                n += len(chunk)
                if n >= next_log:
                    log(f"    {n >> 20} MiB" + (f" / {total >> 20} MiB" if total else ""))
                    next_log += 1 << 28
        if h.hexdigest() != sha:
            raise ValueError(f"sha256 mismatch for {url}: got {h.hexdigest()}, want {sha}")
        os.chmod(tmp, 0o444)  # cached material is hardlinked into workspaces: keep it immutable
        os.replace(tmp, dst)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def fetch(t: Target, cache: Path, log=print) -> None:
    """Download every remote material of a target (for this host's arch) into the cache; verify hashes."""
    for m in t.material():
        kind = m["kind"]
        if kind == "local":
            if not (t.dir / m["path"]).exists():
                raise FileNotFoundError(f"{t.id}: local material {m['path']} missing")
            continue
        dst = _cache_path(cache, m)
        if kind in ("tarball", "file", "deb"):
            if dst.exists():
                continue  # verified before it was moved into place; the file is read-only
            _download(m["url"], m["sha256"], dst, log)
        elif kind == "git":
            if dst.exists():
                continue
            log(f"  clone {m['url']} @ {m['commit']}")
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(tempfile.mkdtemp(dir=dst.parent, prefix=".clone-"))
            try:
                subprocess.run(["git", "init", "-q", str(tmp)], check=True)
                subprocess.run(["git", "-C", str(tmp), "fetch", "-q", "--depth", "1", m["url"], m["commit"]], check=True)
                subprocess.run(["git", "-C", str(tmp), "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"], check=True)
                got = subprocess.run(["git", "-C", str(tmp), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
                if got != m["commit"]:
                    raise ValueError(f"{t.id}: fetched {got}, want {m['commit']}")
                os.replace(tmp, dst)
            finally:
                if tmp.exists():
                    shutil.rmtree(tmp, ignore_errors=True)


# ---- extraction ---------------------------------------------------------------------------------------
def _inside(p: str) -> bool:
    n = posixpath.normpath(p)
    return not (n.startswith("/") or n == ".." or n.startswith("../"))


def _safe_member(mem: tarfile.TarInfo, strip: int, rebase_abs_links: bool) -> tarfile.TarInfo | None:
    """The member with `strip` leading components removed, or None when it could escape the destination."""
    parts = PurePosixPath(mem.name).parts[strip:]
    if not parts:
        return None
    rel = str(PurePosixPath(*parts))
    if not _inside(rel):
        return None
    if not (mem.isfile() or mem.isdir() or mem.issym() or mem.islnk()):
        return None  # no devices or fifos
    if mem.issym():
        link = mem.linkname
        if link.startswith("/") and rebase_abs_links:
            link = posixpath.relpath(link.lstrip("/") or ".", posixpath.dirname(rel) or ".")
        if not _inside(posixpath.join(posixpath.dirname(rel), link)):
            return None
        mem.linkname = link
    if mem.islnk():
        lparts = PurePosixPath(mem.linkname.lstrip("/")).parts[strip:]
        if not lparts or not _inside(str(PurePosixPath(*lparts))):
            return None
        mem.linkname = str(PurePosixPath(*lparts))
    mem.name = rel
    mem.mode = (mem.mode or 0o644) & 0o755 | (0o700 if mem.isdir() else 0o600)  # no setuid; owner can read/write
    mem.uid = mem.gid = 0
    mem.uname = mem.gname = ""
    return mem


def extract_tar_stream(fileobj, dest: Path, strip: int = 0, rebase_abs_links: bool = False) -> tuple[int, int]:
    """Extract a (possibly compressed) tar stream member by member. Returns (extracted, skipped)."""
    kw = {"filter": "fully_trusted"} if hasattr(tarfile, "fully_trusted_filter") else {}  # members are pre-checked
    ok = skipped = 0
    dest_real = os.path.realpath(dest)
    with tarfile.open(fileobj=fileobj, mode="r|*") as tf:
        for mem in tf:
            m = _safe_member(mem, strip, rebase_abs_links)
            if m is None:
                skipped += 1
                continue
            # never write through a symlink that leads out of dest
            parent = os.path.realpath(os.path.join(dest, posixpath.dirname(m.name)))
            if parent != dest_real and not parent.startswith(dest_real + os.sep):
                skipped += 1
                continue
            if m.islnk():
                # Hard links are made here: tarfile's fallback for a link it cannot make re-reads the target
                # member by seeking backwards, which a stream cannot do (it then desyncs every later member).
                src, dst = os.path.join(dest, m.linkname), os.path.join(dest, m.name)
                try:
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    if os.path.lexists(dst):
                        if os.path.lexists(src) and os.path.samestat(os.lstat(src), os.lstat(dst)):
                            ok += 1  # same file already (e.g. names that differ only in case, on a case-insensitive fs)
                            continue
                        os.unlink(dst)
                    try:
                        os.link(src, dst, follow_symlinks=False)
                    except OSError:
                        shutil.copy2(src, dst, follow_symlinks=False)
                    ok += 1
                except OSError:
                    skipped += 1
                continue
            try:
                tf.extract(m, dest, set_attrs=not m.issym(), **kw)
                ok += 1
            except (OSError, tarfile.TarError):
                skipped += 1
    return ok, skipped


class _Slice(io.RawIOBase):
    """A read-only window [start, start+size) of a file."""

    def __init__(self, f, start: int, size: int):
        self.f, self.left = f, size
        f.seek(start)

    def readable(self):
        return True

    def readinto(self, b):
        if self.left <= 0:
            return 0
        n = self.f.readinto(memoryview(b)[: min(len(b), self.left)])
        self.left -= n or 0
        return n


def deb_data_member(path: Path) -> tuple[str, int, int]:
    """(name, offset, size) of the data.tar.* member of a .deb (an `ar` archive)."""
    with open(path, "rb") as f:
        if f.read(8) != b"!<arch>\n":
            raise ValueError(f"{path} is not a .deb (ar) archive")
        off = 8
        while True:
            hdr = f.read(60)
            if len(hdr) < 60:
                break
            name = hdr[:16].decode().strip().rstrip("/")
            size = int(hdr[48:58].decode().strip())
            if name.startswith("data.tar"):
                return name, off + 60, size
            off += 60 + size + (size & 1)
            f.seek(off)
    raise ValueError(f"{path}: no data.tar member")


def extract_deb(path: Path, dest: Path) -> tuple[int, int]:
    name, off, size = deb_data_member(path)
    with open(path, "rb") as f:
        sl = io.BufferedReader(_Slice(f, off, size), 1 << 20)
        if name.endswith(".zst"):  # tarfile has no zstd before Python 3.14: decompress with the zstd CLI
            p = subprocess.Popen(["zstd", "-dc"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

            def feed():
                try:
                    shutil.copyfileobj(sl, p.stdin, 1 << 20)
                finally:
                    p.stdin.close()

            import threading
            th = threading.Thread(target=feed, daemon=True)
            th.start()
            res = extract_tar_stream(p.stdout, dest, 0, rebase_abs_links=True)
            th.join()
            p.wait()
            return res
        return extract_tar_stream(sl, dest, 0, rebase_abs_links=True)


def _place(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def materialize(t: Target, cache: Path, context_dir: Path, log=print) -> list[str]:
    """Lay out every material (for this host's arch) under vault/context/<dest>/. Returns the dests written."""
    out = []
    for m in t.material():
        dest = context_dir / m["dest"]
        dest.mkdir(parents=True, exist_ok=True)
        kind = m["kind"]
        src = None if kind == "local" else _cache_path(cache, m)
        if src is not None and not src.exists():
            raise FileNotFoundError(f"{src} not cached: run `hackbench fetch` first")
        if kind == "tarball":
            with open(src, "rb") as f:
                ok, sk = extract_tar_stream(f, dest, int(m.get("strip_components", 0)))
            log(f"  {m['dest']}: {ok} entries" + (f", {sk} skipped" if sk else ""))
        elif kind == "deb":
            log(f"  {m['dest']}: extracting {src.name} …")
            ok, sk = extract_deb(src, dest)
            log(f"  {m['dest']}: {ok} entries" + (f", {sk} skipped" if sk else ""))
        elif kind == "file":
            _place(src, dest / _basename(m))
        elif kind == "git":
            shutil.copytree(src, dest, dirs_exist_ok=True, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        elif kind == "local":
            s = (t.dir / m["path"]).resolve()
            if s.is_dir():
                shutil.copytree(s, dest, dirs_exist_ok=True, symlinks=True)
            else:
                shutil.copy2(s, dest / s.name)
        for rm in m.get("remove", []) or []:  # strip files that would leak the answer
            p = (dest / rm)
            if dest.resolve() in p.resolve().parents:
                if p.is_dir() and not p.is_symlink():
                    shutil.rmtree(p)
                elif p.exists() or p.is_symlink():
                    p.unlink()
        out.append(m["dest"])
    return out


def remove_material(t: Target, context_dir: Path) -> None:
    """Delete the material dests (reproducible from the cache) to free disk after a hunt."""
    for d in {PurePosixPath(m["dest"]).parts[0] for m in t.material()}:
        p = context_dir / d
        if p.exists():
            for root, dirs, _ in os.walk(p):  # extracted trees may contain read-only dirs
                for x in dirs:
                    try:
                        os.chmod(os.path.join(root, x), stat.S_IRWXU)
                    except OSError:
                        pass
            shutil.rmtree(p, ignore_errors=True)
