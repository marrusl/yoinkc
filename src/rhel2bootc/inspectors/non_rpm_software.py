"""Non-RPM Software inspector: /opt, /usr/local, pip/npm/gem. File-based scan. Optional deep strings scan."""

import re
from pathlib import Path
from typing import Optional

from ..executor import Executor
from ..schema import NonRpmSoftwareSection

VERSION_PATTERNS = [
    re.compile(rb"version\s*[=:]\s*[\"']?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I),
    re.compile(rb"v([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\s\-]"),
    re.compile(rb"([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$|\))"),
]


def _is_binary(executor: Optional[Executor], host_root: Path, path: Path) -> bool:
    if not executor:
        return False
    r = executor(["file", "-b", str(path)])
    if r.returncode != 0:
        return False
    out = r.stdout.lower()
    return "elf" in out or "executable" in out or "script" in out


def _strings_version(executor: Optional[Executor], path: Path, limit_kb: Optional[int] = None) -> Optional[str]:
    if not executor:
        return None
    if limit_kb:
        cmd = ["sh", "-c", f"head -c {limit_kb * 1024} {path!s} | strings"]
    else:
        cmd = ["strings", str(path)]
    r = executor(cmd)
    if r.returncode != 0:
        return None
    data = r.stdout.encode() if isinstance(r.stdout, str) else r.stdout
    for pat in VERSION_PATTERNS:
        m = pat.search(data)
        if m:
            return m.group(1).decode("utf-8", errors="replace").strip()
    return None


def _safe_iterdir(d: Path) -> list:
    try:
        return list(d.iterdir())
    except (PermissionError, OSError):
        return []


# Standard FHS directories under /usr/local that are always present and
# should only be reported if they contain actual user-installed content.
_FHS_DIRS = frozenset({
    "bin", "etc", "games", "include", "lib", "lib64", "libexec",
    "sbin", "share", "src", "man",
})


def _dir_has_content(d: Path) -> bool:
    """Return True if d contains at least one regular file (at any depth)."""
    try:
        for p in d.rglob("*"):
            if p.is_file():
                return True
    except (PermissionError, OSError):
        pass
    return False


def _scan_dirs(section: NonRpmSoftwareSection, host_root: Path, executor: Optional[Executor], deep: bool) -> None:
    """Scan /opt and /usr/local for non-RPM software directories."""
    for base in ("opt", "usr/local"):
        d = host_root / base
        if not d.exists():
            continue
        for entry in _safe_iterdir(d):
            if not entry.is_dir() or entry.name.startswith("."):
                continue
            if base == "usr/local" and entry.name in _FHS_DIRS and not _dir_has_content(entry):
                continue
            item: dict = {"path": str(entry.relative_to(host_root)), "name": entry.name, "confidence": "low", "method": "directory scan"}
            if executor:
                try:
                    for f in entry.rglob("*"):
                        if not f.is_file():
                            continue
                        if _is_binary(executor, host_root, f):
                            limit = None if deep else 4
                            ver = _strings_version(executor, f, limit_kb=limit)
                            if ver:
                                item["version"] = ver
                                item["method"] = "strings" if deep else "strings (first 4KB)"
                                item["confidence"] = "medium"
                                break
                except Exception:
                    pass
            section.items.append(item)


def _scan_pip(section: NonRpmSoftwareSection, host_root: Path, executor: Optional[Executor]) -> None:
    """Detect pip-installed packages by scanning dist-info directories."""
    for search_root in ("usr/lib/python3", "usr/lib64/python3", "usr/local/lib/python3"):
        base = host_root / search_root
        if not base.exists():
            continue
        try:
            for parent in base.iterdir():
                if not parent.is_dir():
                    continue
                site_packages = parent / "site-packages"
                if not site_packages.exists():
                    site_packages = parent
                for dist_info in site_packages.glob("*.dist-info"):
                    stem = dist_info.name.replace(".dist-info", "")
                    parts = stem.split("-")
                    name, version = stem, ""
                    for idx, part in enumerate(parts):
                        if part and part[0].isdigit():
                            name = "-".join(parts[:idx])
                            version = "-".join(parts[idx:])
                            break
                    section.items.append({
                        "path": str(dist_info.relative_to(host_root)),
                        "name": name,
                        "version": version,
                        "confidence": "high",
                        "method": "pip dist-info",
                    })
        except Exception:
            continue

    for venv_root in ("opt", "srv", "home"):
        d = host_root / venv_root
        if not d.exists():
            continue
        try:
            for req in d.rglob("requirements.txt"):
                if req.is_file():
                    try:
                        content = req.read_text()
                    except (PermissionError, OSError):
                        content = ""
                    section.items.append({
                        "path": str(req.relative_to(host_root)),
                        "name": "requirements.txt",
                        "confidence": "high",
                        "method": "pip requirements.txt",
                        "content": content,
                    })
        except Exception:
            continue


_LOCKFILE_NAMES = frozenset({
    "package.json", "package-lock.json", "yarn.lock",
    "Gemfile", "Gemfile.lock",
})


def _read_lockfile_dir(d: Path) -> dict:
    """Read lockfile-related files from a project directory.

    Returns {filename: content} for files relevant to reproducible installs.
    """
    result: dict = {}
    for name in _LOCKFILE_NAMES:
        f = d / name
        try:
            if f.is_file():
                result[name] = f.read_text()
        except (PermissionError, OSError):
            pass
    return result


def _scan_npm(section: NonRpmSoftwareSection, host_root: Path) -> None:
    """Detect npm projects by scanning for package-lock.json and yarn.lock."""
    for search_root in ("opt", "srv", "home", "usr/local"):
        d = host_root / search_root
        if not d.exists():
            continue
        try:
            for lock in d.rglob("package-lock.json"):
                if lock.is_file():
                    files = _read_lockfile_dir(lock.parent)
                    section.items.append({
                        "path": str(lock.parent.relative_to(host_root)),
                        "name": lock.parent.name,
                        "confidence": "high",
                        "method": "npm package-lock.json",
                        "files": files,
                    })
            for lock in d.rglob("yarn.lock"):
                if lock.is_file():
                    files = _read_lockfile_dir(lock.parent)
                    section.items.append({
                        "path": str(lock.parent.relative_to(host_root)),
                        "name": lock.parent.name,
                        "confidence": "high",
                        "method": "yarn.lock",
                        "files": files,
                    })
        except Exception:
            continue


def _scan_gem(section: NonRpmSoftwareSection, host_root: Path) -> None:
    """Detect Ruby gems by scanning for Gemfile.lock."""
    for search_root in ("opt", "srv", "home", "usr/local"):
        d = host_root / search_root
        if not d.exists():
            continue
        try:
            for lock in d.rglob("Gemfile.lock"):
                if lock.is_file():
                    files = _read_lockfile_dir(lock.parent)
                    section.items.append({
                        "path": str(lock.parent.relative_to(host_root)),
                        "name": lock.parent.name,
                        "confidence": "high",
                        "method": "gem Gemfile.lock",
                        "files": files,
                    })
        except Exception:
            continue


def run(
    host_root: Path,
    executor: Optional[Executor],
    deep_binary_scan: bool = False,
) -> NonRpmSoftwareSection:
    section = NonRpmSoftwareSection()
    host_root = Path(host_root)

    _scan_dirs(section, host_root, executor, deep_binary_scan)
    _scan_pip(section, host_root, executor)
    _scan_npm(section, host_root)
    _scan_gem(section, host_root)

    _CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}
    seen: dict = {}
    for item in section.items:
        path = item.get("path", "")
        rank = _CONFIDENCE_RANK.get(item.get("confidence", "low"), 0)
        if path not in seen or rank > seen[path][1]:
            seen[path] = (item, rank)
    section.items = [v[0] for v in seen.values()]

    return section
