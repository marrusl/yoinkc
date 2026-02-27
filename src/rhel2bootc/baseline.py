"""
Baseline generation by querying the target bootc base image.

Detects the host OS from /etc/os-release, maps to the corresponding bootc
base image, and runs ``podman run --rm <image> rpm -qa --queryformat '%{NAME}\n'``
to get the concrete package list.  The diff against host packages produces
exactly the ``dnf install`` list the Containerfile needs.
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_DEBUG = bool(os.environ.get("RHEL2BOOTC_DEBUG", ""))


def _debug(msg: str) -> None:
    if _DEBUG:
        print(f"[rhel2bootc] baseline: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# OS → base image mapping
# ---------------------------------------------------------------------------

_IMAGE_MAP: Dict[str, str] = {
    "rhel-9": "registry.redhat.io/rhel9/rhel-bootc",
    "centos-9": "quay.io/centos-bootc/centos-bootc",
}


def select_base_image(os_id: str, version_id: str) -> Optional[str]:
    """Map host OS identity to the bootc base image reference.

    Returns a fully-qualified image:tag string, or None if unmapped.
    """
    os_id = os_id.lower()
    major = version_id.split(".")[0] if version_id else ""

    if os_id == "rhel" and major == "9":
        return f"registry.redhat.io/rhel9/rhel-bootc:{version_id}"
    if "centos" in os_id and major == "9":
        return "quay.io/centos-bootc/centos-bootc:stream9"

    _debug(f"no base image mapping for os_id={os_id} version_id={version_id}")
    return None


# ---------------------------------------------------------------------------
# Query the base image for its package list
# ---------------------------------------------------------------------------

def query_base_image_packages(
    executor,
    base_image: str,
) -> Optional[Set[str]]:
    """Run ``podman run --rm <base_image> rpm -qa --queryformat '%{NAME}\\n'``.

    Returns the set of package names in the base image, or None on failure.
    """
    cmd = [
        "podman", "run", "--rm", base_image,
        "rpm", "-qa", "--queryformat", r"%{NAME}\n",
    ]
    _debug(f"querying base image: {' '.join(cmd)}")
    result = executor(cmd)
    if result.returncode != 0:
        _debug(f"podman run failed (rc={result.returncode}): "
               f"{result.stderr.strip()[:300]}")
        return None
    names: Set[str] = set()
    for line in result.stdout.splitlines():
        name = line.strip()
        if name:
            names.add(name)
    _debug(f"base image has {len(names)} packages")
    return names


# ---------------------------------------------------------------------------
# Query the base image for systemd preset files
# ---------------------------------------------------------------------------

def query_base_image_presets(
    executor,
    base_image: str,
) -> Optional[str]:
    """Dump all systemd preset content from the base image.

    Returns the concatenated text of all ``/usr/lib/systemd/system-preset/*.preset``
    files, or None on failure.
    """
    cmd = [
        "podman", "run", "--rm", base_image,
        "bash", "-c", "cat /usr/lib/systemd/system-preset/*.preset 2>/dev/null || true",
    ]
    _debug(f"querying base image presets: {' '.join(cmd)}")
    result = executor(cmd)
    if result.returncode != 0:
        _debug(f"preset query failed (rc={result.returncode}): "
               f"{result.stderr.strip()[:200]}")
        return None
    text = result.stdout.strip()
    if not text:
        _debug("base image returned no preset data")
        return None
    lines = text.splitlines()
    _debug(f"base image presets: {len(lines)} lines")
    return result.stdout


# ---------------------------------------------------------------------------
# Load a pre-built package list file (--baseline-packages)
# ---------------------------------------------------------------------------

def load_baseline_packages_file(path: Path) -> Optional[Set[str]]:
    """Read a newline-separated package name list from *path*."""
    path = Path(path)
    if not path.exists():
        _debug(f"baseline packages file not found: {path}")
        return None
    try:
        text = path.read_text()
    except (PermissionError, OSError) as exc:
        _debug(f"cannot read baseline packages file: {exc}")
        return None
    names = {line.strip() for line in text.splitlines() if line.strip()}
    _debug(f"loaded {len(names)} baseline package names from {path}")
    return names


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def get_baseline_packages(
    host_root: Path,
    os_id: str,
    version_id: str,
    executor=None,
    baseline_packages_file: Optional[Path] = None,
) -> Tuple[Optional[Set[str]], Optional[str], bool]:
    """Resolve the baseline package set.

    Returns ``(package_names, base_image_ref, no_baseline)``.

    Strategy (in priority order):
    1. ``--baseline-packages FILE`` — load from file (air-gapped).
    2. Query the target bootc base image via podman.
    3. Fall back to no-baseline mode.
    """
    # 1. Explicit file override
    if baseline_packages_file:
        names = load_baseline_packages_file(baseline_packages_file)
        if names:
            base_image = select_base_image(os_id, version_id)
            return (names, base_image, False)
        _debug("baseline packages file provided but empty/unreadable")

    # 2. Query the base image
    base_image = select_base_image(os_id, version_id)
    if base_image and executor is not None:
        names = query_base_image_packages(executor, base_image)
        if names:
            return (names, base_image, False)

    # 3. No baseline
    _debug("no baseline available")
    return (None, base_image, True)
