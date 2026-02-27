"""
Inspectors produce structured data that is merged into the inspection snapshot.
Each inspector receives host_root and an executor; returns a section for the snapshot.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional, TypeVar

from ..executor import Executor, make_executor
from ..schema import InspectionSnapshot, OsRelease

T = TypeVar("T")


def _safe_run(name: str, fn: Callable[[], T], default: T, warnings: list) -> T:
    """Run an inspector; on PermissionError/OSError log a warning and return *default*."""
    try:
        return fn()
    except (PermissionError, OSError) as exc:
        warnings.append({
            "source": name,
            "message": f"{name} inspector: {exc}",
            "severity": "warning",
        })
        print(f"WARNING: {name} inspector skipped: {exc}", file=sys.stderr)
        return default

from .rpm import run as run_rpm
from .config import run as run_config
from .service import run as run_service
from .network import run as run_network
from .storage import run as run_storage
from .scheduled_tasks import run as run_scheduled_tasks
from .container import run as run_container
from .non_rpm_software import run as run_non_rpm_software
from .kernel_boot import run as run_kernel_boot
from .selinux import run as run_selinux
from .users_groups import run as run_users_groups


def _tool_root() -> Path:
    """Project root (where manifests/ lives)."""
    # From .../src/rhel2bootc/inspectors/__init__.py -> .../ (project root)
    return Path(__file__).resolve().parent.parent.parent.parent


def _read_os_release(host_root: Path) -> Optional[OsRelease]:
    p = host_root / "etc" / "os-release"
    if not p.exists():
        return None
    data = {}
    for line in p.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v.strip().strip('"')
    return OsRelease(
        name=data.get("NAME", ""),
        version_id=data.get("VERSION_ID", ""),
        version=data.get("VERSION", ""),
        id=data.get("ID", ""),
        id_like=data.get("ID_LIKE", ""),
        pretty_name=data.get("PRETTY_NAME", ""),
    )


def _validate_supported_host(os_release: Optional[OsRelease], tool_root: Path) -> Optional[str]:
    """Return error message if host is not supported, else None.

    Baselines are generated from comps at runtime; we support any RHEL 9.x and CentOS Stream 9.
    """
    if not os_release or not os_release.version_id:
        return None
    vid = os_release.version_id
    if os_release.id == "rhel":
        if not vid.startswith("9."):
            return (
                f"Host is running RHEL {vid}. This version of rhel2bootc only supports "
                "RHEL 9.x and CentOS Stream 9."
            )
    elif "centos" in os_release.id.lower():
        if vid != "9":
            return (
                f"Host is running CentOS {vid}. This version of rhel2bootc only supports "
                "CentOS Stream 9."
            )
    else:
        return None
    return None


def _profile_warning(host_root: Path) -> Optional[str]:
    """If install profile could not be determined, return warning message."""
    import os
    _dbg = bool(os.environ.get("RHEL2BOOTC_DEBUG", ""))
    for p in ("root/anaconda-ks.cfg", "root/original-ks.cfg"):
        full = host_root / p
        try:
            exists = full.exists()
            if _dbg:
                print(f"[rhel2bootc] _profile_warning: {full} exists={exists}", file=sys.stderr)
            if exists:
                return None
        except (PermissionError, OSError) as exc:
            if _dbg:
                print(f"[rhel2bootc] _profile_warning: {full} error: {exc}", file=sys.stderr)
            continue
    anaconda = host_root / "var/log/anaconda"
    try:
        a_exists = anaconda.exists()
        if _dbg:
            print(f"[rhel2bootc] _profile_warning: {anaconda} exists={a_exists}", file=sys.stderr)
        if a_exists and any(anaconda.iterdir()):
            return None
    except (PermissionError, OSError) as exc:
        if _dbg:
            print(f"[rhel2bootc] _profile_warning: {anaconda} error: {exc}", file=sys.stderr)
    return (
        "Could not determine original install profile. Using '@minimal' baseline. "
        "Some packages reported as 'added' may have been part of the original installation. "
        "Review the package list in the audit report and remove false positives."
    )


def run_all(
    host_root: Path,
    executor: Optional[Executor] = None,
    tool_root: Optional[Path] = None,
    config_diffs: bool = False,
    deep_binary_scan: bool = False,
    query_podman: bool = False,
    comps_file: Optional[Path] = None,
    profile_override: Optional[str] = None,
) -> InspectionSnapshot:
    """Run all inspectors and return a merged snapshot."""
    host_root = Path(host_root)
    if executor is None:
        executor = make_executor(str(host_root))
    if tool_root is None:
        tool_root = _tool_root()

    meta = {"host_root": str(host_root), "timestamp": datetime.utcnow().isoformat() + "Z"}
    hostname_path = host_root / "etc" / "hostname"
    try:
        if hostname_path.exists():
            meta["hostname"] = hostname_path.read_text().strip().splitlines()[0]
    except (PermissionError, OSError):
        pass
    os_release = _read_os_release(host_root)
    err = _validate_supported_host(os_release, tool_root)
    if err:
        raise ValueError(err)
    snapshot = InspectionSnapshot(
        meta=meta,
        os_release=os_release,
    )
    if not profile_override:
        profile_warn = _profile_warning(host_root)
        if profile_warn:
            snapshot.warnings.append({"source": "rpm", "message": profile_warn, "severity": "warning"})

    w = snapshot.warnings
    snapshot.rpm = _safe_run("rpm", lambda: run_rpm(host_root, executor, tool_root, comps_file=comps_file, profile_override=profile_override), None, w)
    if snapshot.rpm and snapshot.rpm.no_baseline:
        w.append({
            "source": "rpm",
            "message": (
                "Could not fetch comps XML from configured repositories. "
                "No baseline available — all installed packages will be included in the Containerfile. "
                "To reduce image size, provide a comps file via --comps-file or manually trim the package list."
            ),
            "severity": "warning",
        })
    snapshot.config = _safe_run("config", lambda: run_config(host_root, executor, rpm_section=snapshot.rpm, rpm_owned_paths_override=None, config_diffs=config_diffs), None, w)
    snapshot.services = _safe_run("service", lambda: run_service(host_root, executor, tool_root), None, w)
    snapshot.network = _safe_run("network", lambda: run_network(host_root, executor), None, w)
    snapshot.storage = _safe_run("storage", lambda: run_storage(host_root, executor), None, w)
    snapshot.scheduled_tasks = _safe_run("scheduled_tasks", lambda: run_scheduled_tasks(host_root, executor), None, w)
    snapshot.containers = _safe_run("containers", lambda: run_container(host_root, executor, query_podman=query_podman), None, w)
    snapshot.non_rpm_software = _safe_run("non_rpm_software", lambda: run_non_rpm_software(host_root, executor, deep_binary_scan=deep_binary_scan), None, w)
    snapshot.kernel_boot = _safe_run("kernel_boot", lambda: run_kernel_boot(host_root, executor), None, w)
    snapshot.selinux = _safe_run("selinux", lambda: run_selinux(host_root, executor), None, w)
    snapshot.users_groups = _safe_run("users_groups", lambda: run_users_groups(host_root, executor), None, w)

    return snapshot
