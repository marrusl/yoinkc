"""
Baseline generation from distribution comps XML.

Fetches or accepts comps XML, parses group definitions (mandatory + default packages),
resolves install profile (from kickstart or @minimal fallback), and returns the
package name set for the RPM inspector.
"""

import gzip
import re
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET


# Namespace commonly used in RHEL/CentOS comps
COMPS_NS = {"comps": "http://comps.redhat.com/comps"}
COMPS_NS_DEFAULT = "http://comps.redhat.com/comps"


def _parse_group_element(group_el: ET.Element) -> Tuple[Set[str], List[str]]:
    """Extract (package names set, list of groupreq ids) from a <group> element."""
    packages: Set[str] = set()
    groupreqs: List[str] = []

    # Handle both namespaced and non-namespaced
    def find_all(parent: ET.Element, tag: str) -> List[ET.Element]:
        out = []
        for c in parent:
            if c.tag == tag or (isinstance(c.tag, str) and c.tag.endswith("}" + tag)):
                out.append(c)
        return out

    def find_one(parent: ET.Element, tag: str) -> Optional[ET.Element]:
        for c in parent:
            if c.tag == tag or (isinstance(c.tag, str) and c.tag.endswith("}" + tag)):
                return c
        return None

    packagelist = find_one(group_el, "packagelist")
    if packagelist is not None:
        for preq in find_all(packagelist, "packagereq"):
            ptype = preq.get("type") or preq.get("{http://comps.redhat.com/comps}type")
            if ptype in ("mandatory", "default"):
                name = (preq.text or "").strip() or (preq.get("name") or "")
                if name:
                    packages.add(name)

    grouplist = find_one(group_el, "grouplist")
    if grouplist is not None:
        for greq in find_all(grouplist, "groupreq"):
            gid = (greq.text or "").strip() or (greq.get("name") or "")
            if gid:
                groupreqs.append(gid)

    return packages, groupreqs


def parse_comps_xml(xml_content: str) -> Dict[str, Tuple[Set[str], List[str]]]:
    """
    Parse comps XML and return a map: group_id -> (package_names_set, groupreq_ids).

    Only mandatory and default packages are included. Optional packages are excluded.
    """
    root = ET.fromstring(xml_content)
    # Strip default namespace for simpler local-name matching
    def local_tag(e: ET.Element) -> str:
        if isinstance(e.tag, str) and "}" in e.tag:
            return e.tag.split("}", 1)[1]
        return e.tag or ""

    result: Dict[str, Tuple[Set[str], List[str]]] = {}

    for group_el in root.iter():
        if local_tag(group_el) != "group":
            continue
        id_el = None
        for c in group_el:
            if local_tag(c) == "id":
                id_el = c
                break
        if id_el is None:
            continue
        gid = (id_el.text or "").strip()
        if not gid:
            continue
        packages, groupreqs = _parse_group_element(group_el)
        result[gid] = (packages, groupreqs)

    return result


def resolve_baseline_packages(
    comps_data: Dict[str, Tuple[Set[str], List[str]]],
    profile: str,
) -> Set[str]:
    """
    Resolve the full set of package names for the given profile (group id).

    Recursively includes packages from the group and any groupreq dependencies
    (e.g. @server -> @core). profile should be the group id without @ (e.g. "minimal", "server").
    """
    seen: Set[str] = set()
    out: Set[str] = set()

    def add_group(gid: str) -> None:
        if gid in seen:
            return
        seen.add(gid)
        if gid not in comps_data:
            return
        packages, groupreqs = comps_data[gid]
        out.update(packages)
        for req in groupreqs:
            add_group(req)

    add_group(profile)
    return out


def detect_profile(host_root: Path) -> Optional[str]:
    """
    Detect install profile from anaconda-ks.cfg, original-ks.cfg, or anaconda logs.

    Returns group id (e.g. "minimal", "server", "core") or None if not determined.
    """
    host_root = Path(host_root)
    candidates: List[Path] = [
        host_root / "root" / "anaconda-ks.cfg",
        host_root / "root" / "original-ks.cfg",
    ]
    for path in candidates:
        try:
            if not path.exists():
                continue
            text = path.read_text()
        except (PermissionError, OSError):
            continue
        # Look for %packages section and @group or group name
        in_packages = False
        for line in text.splitlines():
            line = line.strip()
            if line == "%packages":
                in_packages = True
                continue
            if in_packages and line.startswith("%"):
                break
            if in_packages and line:
                # @minimal, @server, @core, or just "minimal"
                if line.startswith("@"):
                    return line[1:].strip()
                if re.match(r"^[a-zA-Z0-9_-]+$", line):
                    return line
    # Optional: scan /var/log/anaconda for install logs (more involved)
    return None


def _substitute_repo_vars(url: str, releasever: str, basearch: str) -> str:
    """Replace $releasever, $basearch, and $stream in repo URL."""
    major = releasever.split(".")[0] if releasever else releasever
    return (
        url.replace("$releasever", releasever)
        .replace("$basearch", basearch)
        .replace("$stream", major)
    )


def _resolve_metalink(url: str) -> List[str]:
    """Fetch a metalink XML and extract mirror base URLs."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rhel2bootc/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
    except Exception:
        return []
    try:
        root = ET.fromstring(data)
    except Exception:
        return []
    urls: List[str] = []
    for el in root.iter():
        tag = el.tag.split("}")[-1] if "}" in str(el.tag) else str(el.tag)
        if tag == "url" and el.text:
            u = el.text.strip()
            if u.startswith("http"):
                # Metalink URLs point to repodata/repomd.xml — strip to get base
                if "/repodata/" in u:
                    u = u[:u.index("/repodata/")]
                urls.append(u)
    return urls


def _resolve_mirrorlist(url: str) -> List[str]:
    """Fetch a mirrorlist (plain-text list of URLs) and return base URLs."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rhel2bootc/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return []
    urls: List[str] = []
    for line in data.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.startswith("http"):
            urls.append(line.rstrip("/"))
    return urls


def _get_repo_baseurls(host_root: Path, releasever: str, basearch: str) -> List[str]:
    """Read repo files under host_root and return resolved base URLs.

    Handles baseurl, metalink, and mirrorlist directives.
    Only includes URLs from sections where enabled=1 or enabled is not set.
    """
    urls: List[str] = []
    seen: set = set()

    def _add(u: str) -> None:
        u = u.rstrip("/")
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    for subdir in ("etc/yum.repos.d", "etc/dnf"):
        d = host_root / subdir
        try:
            if not d.exists():
                continue
            entries = sorted(d.iterdir())
        except (PermissionError, OSError):
            continue
        for f in entries:
            if not f.is_file():
                continue
            try:
                content = f.read_text()
            except Exception:
                continue
            section_enabled = True
            section_baseurl = None
            section_metalink = None
            section_mirrorlist = None

            def _flush_section():
                if not section_enabled:
                    return
                if section_baseurl:
                    _add(section_baseurl)
                    return
                if section_metalink:
                    for mu in _resolve_metalink(section_metalink)[:3]:
                        _add(mu)
                    return
                if section_mirrorlist:
                    for mu in _resolve_mirrorlist(section_mirrorlist)[:3]:
                        _add(mu)

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    _flush_section()
                    section_enabled = True
                    section_baseurl = None
                    section_metalink = None
                    section_mirrorlist = None
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip().lower(), v.strip()
                if k == "enabled" and v.lower() in ("0", "false", "no"):
                    section_enabled = False
                elif k == "baseurl":
                    section_baseurl = _substitute_repo_vars(v, releasever, basearch)
                elif k == "metalink":
                    section_metalink = _substitute_repo_vars(v, releasever, basearch)
                elif k == "mirrorlist":
                    section_mirrorlist = _substitute_repo_vars(v, releasever, basearch)
            _flush_section()
    return urls


def _fetch_url(url: str, host_root: Path) -> Optional[bytes]:
    """Fetch URL; for file:// use host_root as base if path is relative."""
    if url.startswith("file://"):
        path = Path(url[7:])
        if not path.is_absolute():
            path = host_root / path
        if path.exists():
            return path.read_bytes()
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rhel2bootc/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read()
    except Exception:
        return None


def _find_group_href_in_repomd(repomd_xml: bytes) -> Optional[str]:
    """Parse repomd.xml and return href for group or group_gz data, or None."""
    root = ET.fromstring(repomd_xml)
    def local_tag(e: ET.Element) -> str:
        if isinstance(e.tag, str) and "}" in e.tag:
            return e.tag.split("}", 1)[1]
        return e.tag or ""

    for data in root.iter():
        if local_tag(data) != "data":
            continue
        dtype = data.get("type") or ""
        for c in data:
            if local_tag(c) == "location":
                href = c.get("href") or ""
                if dtype in ("group", "group_gz", "comps", "comps_gz") and href:
                    return href
    return None


def fetch_comps_from_repos(
    host_root: Path,
    id_val: str,
    version_id: str,
    basearch: str = "",
) -> Optional[str]:
    """
    Fetch comps XML from the host's configured repos.

    Uses repo files under host_root and substitutes releasever/basearch.
    Returns decompressed XML content or None if fetch failed.
    """
    host_root = Path(host_root)
    if not basearch:
        basearch = _detect_basearch(host_root)
    releasever = version_id
    baseurls = _get_repo_baseurls(host_root, releasever, basearch)
    if not baseurls:
        return None

    for base in baseurls:
        base = base.rstrip("/")
        repomd_url = f"{base}/repodata/repomd.xml"
        raw = _fetch_url(repomd_url, host_root)
        if not raw:
            continue
        href = _find_group_href_in_repomd(raw)
        if not href:
            continue
        if not href.startswith("http") and not href.startswith("file"):
            comps_url = f"{base}/{href}"
        else:
            comps_url = href
        comps_raw = _fetch_url(comps_url, host_root)
        if not comps_raw:
            continue
        if comps_url.endswith(".gz") or comps_raw[:2] == b"\x1f\x8b":
            try:
                comps_raw = gzip.decompress(comps_raw)
            except Exception:
                continue
        try:
            return comps_raw.decode("utf-8", errors="replace")
        except Exception:
            continue
    return None


def _detect_basearch(host_root: Path) -> str:
    """Detect the host's base architecture from /etc/rpm/platform or os-release."""
    rpm_platform = host_root / "etc" / "rpm" / "platform"
    try:
        if rpm_platform.exists():
            arch = rpm_platform.read_text().strip().split("-")[0]
            if arch:
                return arch
    except (PermissionError, OSError):
        pass
    # Fallback: check uname-like markers in /etc/os-release or kernel cmdline
    for marker_file in ("proc/cmdline",):
        p = host_root / marker_file
        try:
            if p.exists():
                text = p.read_text()
                if "aarch64" in text:
                    return "aarch64"
                if "x86_64" in text:
                    return "x86_64"
                if "ppc64le" in text:
                    return "ppc64le"
                if "s390x" in text:
                    return "s390x"
        except (PermissionError, OSError):
            pass
    import platform
    return platform.machine() or "x86_64"


def get_baseline_packages(
    host_root: Path,
    os_id: str,
    version_id: str,
    comps_file: Optional[Path] = None,
    basearch: str = "",
) -> Tuple[Optional[Set[str]], Optional[str], bool]:
    """
    Resolve baseline package set and profile used.

    Returns (baseline_names, profile_used, no_baseline).
    - If comps_file is set: load and parse from file.
    - Else: try fetch_comps_from_repos.
    - If we have comps: detect_profile or "minimal", resolve and return (set, profile, False).
    - If no comps: return (None, None, True) for all-packages mode.
    """
    if not basearch:
        basearch = _detect_basearch(host_root)
    xml_content: Optional[str] = None
    if comps_file and Path(comps_file).exists():
        try:
            xml_content = Path(comps_file).read_text()
        except Exception:
            xml_content = None
    if not xml_content:
        xml_content = fetch_comps_from_repos(host_root, os_id, version_id, basearch)

    if not xml_content:
        return (None, None, True)

    comps_data = parse_comps_xml(xml_content)
    profile = detect_profile(host_root)
    if profile is None or profile not in comps_data:
        profile = "minimal"
    baseline = resolve_baseline_packages(comps_data, profile)
    return (baseline, profile, False)
