"""
RPM inspector: package list, rpm -Va, repo files, dnf history removed.
Baseline is generated from comps XML (fetched or --comps-file); fallback is all-packages mode.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Optional, Set

_DEBUG = bool(os.environ.get("RHEL2BOOTC_DEBUG", ""))


def _debug(msg: str) -> None:
    if _DEBUG:
        print(f"[rhel2bootc] rpm: {msg}", file=sys.stderr)

from collections import defaultdict
from typing import Dict

from ..baseline import get_baseline_packages
from ..executor import Executor
from ..schema import (
    PackageEntry,
    PackageState,
    RepoFile,
    RpmSection,
    RpmVaEntry,
)


RPM_QA_QUERYFORMAT = r"%{EPOCH}:%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}"

# When the host root is a read-only bind mount, rpm --root fails because it
# can't create a lock file.  For read-only queries (-qa, --queryformat) we use
# --dbpath which only needs DB access.  For -Va (file verification) we still
# need --root but redirect the lock to a writable location.
_RPM_LOCK_DEFINE = ["--define", "_rpmlock_path /var/tmp/.rpm.lock"]


def _parse_nevr(nevra: str) -> Optional[PackageEntry]:
    """Parse a single NEVRA line from rpm -qa --queryformat.

    Format: epoch:name-version-release.arch
    Epoch is numeric or ``(none)`` when the package has no explicit epoch tag.
    """
    s = nevra.strip()
    if ":" not in s:
        return None
    epoch_part, rest = s.split(":", 1)
    if epoch_part.isdigit():
        epoch = epoch_part
    elif epoch_part == "(none)":
        epoch = "0"
    else:
        return None
    # rest = name-version-release.arch
    if "." not in rest:
        return None
    base, arch = rest.rsplit(".", 1)
    parts = base.split("-")
    if len(parts) < 3:
        return None
    release = parts[-1]
    version = parts[-2]
    name = "-".join(parts[:-2])
    return PackageEntry(
        name=name,
        epoch=epoch,
        version=version,
        release=release,
        arch=arch,
        state=PackageState.ADDED,
    )


def _parse_rpm_qa(stdout: str) -> List[PackageEntry]:
    packages = []
    failed = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        pkg = _parse_nevr(line)
        if pkg:
            packages.append(pkg)
        else:
            failed.append(line)
    if failed:
        _debug(f"NEVRA parse failures: {len(failed)} lines")
        for f in failed[:10]:
            _debug(f"  failed to parse: {f!r}")
    _debug(f"parsed {len(packages)} packages from rpm -qa "
           f"(first 5 names: {[p.name for p in packages[:5]]})")
    return packages


def _parse_rpm_va(stdout: str) -> List[RpmVaEntry]:
    """Parse rpm -Va output. Format: flags type path (e.g. S.5....T.  c /etc/foo)."""
    entries = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        # First 9 chars are flags (e.g. S.5....T.), then optional whitespace and type (c/d), then path
        if len(line) < 11:
            continue
        flags = line[:9].strip()
        rest = line[9:].lstrip()
        # Rest can be "c /path" or "/path"
        if rest.startswith("c ") or rest.startswith("d "):
            path = rest[2:].strip()
        else:
            path = rest.strip()
        if path:
            entries.append(RpmVaEntry(path=path, flags=flags, package=None))
    return entries


def _read_os_id_version(host_root: Path) -> tuple[str, str]:
    """Read ID and VERSION_ID from host os-release. Returns (id, version_id) or ('', '')."""
    os_release = host_root / "etc" / "os-release"
    if not os_release.exists():
        return "", ""
    id_val = ""
    version_id = ""
    for line in os_release.read_text().splitlines():
        if line.startswith("ID="):
            id_val = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("VERSION_ID="):
            version_id = line.split("=", 1)[1].strip().strip('"')
    return id_val, version_id


def _collect_repo_files(host_root: Path) -> List[RepoFile]:
    """Read repo files from host_root/etc/yum.repos.d and host_root/etc/dnf."""
    repo_files = []
    for subdir in ("etc/yum.repos.d", "etc/dnf"):
        d = host_root / subdir
        try:
            if not d.exists():
                continue
            entries = sorted(d.iterdir())
        except (PermissionError, OSError):
            continue
        for f in entries:
            if f.is_file() and (f.suffix in (".repo", ".conf") or subdir == "etc/dnf"):
                try:
                    content = f.read_text()
                except Exception:
                    content = ""
                repo_files.append(RepoFile(path=str(f.relative_to(host_root)), content=content))
    return repo_files


def _dnf_history_removed(executor: Executor, host_root: Path) -> List[str]:
    """Run dnf history and collect package names from Remove transactions."""
    # In real run: dnf history list --installroot /host, then for each Remove: dnf history info N
    result = executor(["dnf", "history", "list", "-q"], cwd=str(host_root))
    if result.returncode != 0:
        return []
    removed = []
    # Parse "     N | ... | Removed | M" and get transaction IDs for Removed
    for line in result.stdout.splitlines():
        parts = line.split("|")
        if len(parts) >= 4 and "Removed" in (parts[3].strip() if len(parts) > 3 else ""):
            try:
                tid = int(parts[0].strip())
            except ValueError:
                continue
            info_result = executor(["dnf", "history", "info", str(tid), "-q"], cwd=str(host_root))
            if info_result.returncode != 0:
                continue
            # Parse "Removed     pkg-name-ver-rel.arch"
            for iline in info_result.stdout.splitlines():
                if "Removed" in iline:
                    # Line like "    Removed     old-daemon-1.0-3.el9.x86_64"
                    pkg_part = iline.split("Removed", 1)[-1].strip().split()
                    if pkg_part:
                        # Take first word and strip version: old-daemon-1.0-3.el9.x86_64 -> old-daemon
                        nevra = pkg_part[0]
                        name = re.match(r"^([^-]+(?:-[^-]+)*?)-\d", nevra)
                        if name:
                            removed.append(name.group(1))
                        else:
                            removed.append(nevra.split("-")[0] if "-" in nevra else nevra)
    return removed


_DEP_SCRIPT = """\
import rpm, sys
mode = sys.argv[1]
if mode == 'P':
    tags = [rpm.RPMTAG_PROVIDENAME]
else:
    tags = [rpm.RPMTAG_REQUIRENAME, rpm.RPMTAG_RECOMMENDNAME]
ts = rpm.TransactionSet()
mi = ts.dbMatch()
for h in mi:
    name = h['name']
    for tag in tags:
        deps = h[tag]
        if deps:
            for dep in deps:
                if dep and not dep.startswith('rpmlib('):
                    sys.stdout.write(name + '\\t' + dep + '\\n')
"""


def _expand_baseline_deps(
    executor: Executor,
    host_root: Path,
    seed_names: Set[str],
    installed_names: Set[str],
) -> Set[str]:
    """Expand the comps baseline by following transitive RPM dependencies.

    Runs a small Python script via chroot that uses the host's own
    python3-rpm bindings to dump all provides and requires mappings.
    Falls back to rpm queryformat if the host lacks python3-rpm.
    """
    def _run_dep_script(tag_char: str) -> str:
        """Run the dep script; tag_char is 'P' for provides, 'R' for requires."""
        # rpm.RPMSENSE_* or dsFromHeader tag character
        cmd = [
            "chroot", str(host_root), "python3", "-c", _DEP_SCRIPT, tag_char,
        ]
        result = executor(cmd)
        lines = len(result.stdout.splitlines()) if result.stdout else 0
        _debug(f"dep-expand: python3 rpm {tag_char}: rc={result.returncode} lines={lines}")
        if result.returncode != 0:
            _debug(f"dep-expand: stderr: {result.stderr.strip()[:300]}")
        if result.returncode == 0 and lines > 0:
            return result.stdout
        return ""

    # Provides: capability → set of package names
    prov_stdout = _run_dep_script("P")
    if not prov_stdout:
        _debug("dep-expand: no provides data, skipping expansion")
        return seed_names

    cap_to_pkgs: Dict[str, Set[str]] = defaultdict(set)
    prov_count = 0
    for line in prov_stdout.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[0] in installed_names:
            cap_to_pkgs[parts[1]].add(parts[0])
            prov_count += 1

    _debug(f"dep-expand: {prov_count} provides for "
           f"{len(cap_to_pkgs)} unique capabilities")

    # Requires: package → set of capabilities
    req_stdout = _run_dep_script("R")
    if not req_stdout:
        _debug("dep-expand: no requires data, skipping expansion")
        return seed_names

    pkg_to_reqs: Dict[str, Set[str]] = defaultdict(set)
    req_count = 0
    for line in req_stdout.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[0] in installed_names:
            pkg_to_reqs[parts[0]].add(parts[1])
            req_count += 1

    _debug(f"dep-expand: {req_count} requires for "
           f"{len(pkg_to_reqs)} packages")

    # BFS from seed packages
    expanded = set(seed_names) & installed_names
    queue = list(expanded)
    while queue:
        pkg = queue.pop()
        for cap in pkg_to_reqs.get(pkg, ()):
            for provider in cap_to_pkgs.get(cap, ()):
                if provider not in expanded:
                    expanded.add(provider)
                    queue.append(provider)

    _debug(f"dep-expand: {len(seed_names)} comps names -> "
           f"{len(expanded)} after dependency resolution")
    return expanded


def run(
    host_root: Path,
    executor: Optional[Executor],
    tool_root: Optional[Path] = None,
    comps_file: Optional[Path] = None,
    profile_override: Optional[str] = None,
) -> RpmSection:
    """
    Run RPM inspection. Baseline is from comps XML (--comps-file or fetch from repos);
    if unavailable, no_baseline=True and all installed packages are treated as added.
    """
    host_root = Path(host_root)
    section = RpmSection()

    # 1) rpm -qa — use --dbpath to avoid lock-file issues on read-only mounts
    if executor is not None:
        dbpath = str(host_root / "var" / "lib" / "rpm")
        cmd_qa = ["rpm", "--dbpath", dbpath, "-qa", "--queryformat", RPM_QA_QUERYFORMAT + "\\n"]
        result_qa = executor(cmd_qa)
        if result_qa.returncode != 0:
            cmd_qa = ["rpm", "--root", str(host_root)] + _RPM_LOCK_DEFINE + ["-qa", "--queryformat", RPM_QA_QUERYFORMAT + "\\n"]
            result_qa = executor(cmd_qa)
        installed = _parse_rpm_qa(result_qa.stdout)
    else:
        installed = []

    # 2) Baseline from comps (or all-packages fallback)
    id_val, version_id = _read_os_id_version(host_root)
    baseline_names: Optional[Set[str]] = None
    section.no_baseline = False
    if id_val and version_id:
        baseline_set, _profile_used, no_baseline = get_baseline_packages(
            host_root, id_val, version_id, comps_file=comps_file,
            profile_override=profile_override,
        )
        if no_baseline:
            section.no_baseline = True
            baseline_names = set()
        else:
            baseline_names = baseline_set
    else:
        section.no_baseline = True
        baseline_names = set()

    if installed:
        installed_names = {p.name for p in installed}
        _debug(f"installed package count: {len(installed_names)}")
        if baseline_names is not None and not section.no_baseline:
            # Expand comps baseline with transitive RPM dependencies
            if executor is not None and baseline_names:
                baseline_names = _expand_baseline_deps(
                    executor, host_root, baseline_names, installed_names,
                )
            added_names = installed_names - baseline_names
            removed_names = baseline_names - installed_names
            matched_names = installed_names & baseline_names
            _debug(f"baseline has {len(baseline_names)} names, "
                   f"installed has {len(installed_names)} names")
            _debug(f"matched={len(matched_names)}, "
                   f"added (installed-baseline)={len(added_names)}, "
                   f"removed (baseline-installed)={len(removed_names)}")
            if removed_names:
                sample = sorted(removed_names)[:20]
                _debug(f"'removed' sample (baseline names not in installed): {sample}")
                for rname in sample:
                    close = [n for n in installed_names
                             if n.startswith(rname) or rname.startswith(n)]
                    if close:
                        _debug(f"  '{rname}' has close installed matches: {close[:5]}")
            section.baseline_package_names = sorted(baseline_names)
            for p in installed:
                if p.name in added_names:
                    p.state = PackageState.ADDED
                    section.packages_added.append(p)
            for name in removed_names:
                section.packages_removed.append(
                    PackageEntry(name=name, epoch="0", version="", release="", arch="noarch", state=PackageState.REMOVED)
                )
        else:
            # All-packages mode: everything is added
            section.baseline_package_names = None
            for p in installed:
                p.state = PackageState.ADDED
                section.packages_added.append(p)

    # 3) rpm -Va — needs --root for file verification; redirect lock to writable path
    if executor is not None:
        cmd_va = ["rpm", "-Va", "--nodeps", "--noscripts"]
        if str(host_root) != "/":
            cmd_va = ["rpm", "--root", str(host_root)] + _RPM_LOCK_DEFINE + ["-Va", "--nodeps", "--noscripts"]
        result_va = executor(cmd_va)
        section.rpm_va = _parse_rpm_va(result_va.stdout)
    else:
        section.rpm_va = []

    # 4) Repo files
    section.repo_files = _collect_repo_files(host_root)

    # 5) dnf history removed
    if executor is not None:
        section.dnf_history_removed = _dnf_history_removed(executor, host_root)
    else:
        section.dnf_history_removed = []

    return section
