"""
Baseline generation from distribution comps XML.

Fetches or accepts comps XML, parses group definitions (mandatory + default packages),
resolves install profile (from kickstart or @minimal fallback), and returns the
package name set for the RPM inspector.
"""

import gzip
import lzma
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET


_DEBUG = bool(os.environ.get("RHEL2BOOTC_DEBUG", ""))


def _debug(msg: str) -> None:
    if _DEBUG:
        print(f"[rhel2bootc] {msg}", file=sys.stderr)


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


def _parse_environment_element(env_el: ET.Element) -> List[str]:
    """Extract mandatory group ids from an <environment> element."""
    groups: List[str] = []

    def find_one(parent: ET.Element, tag: str) -> Optional[ET.Element]:
        for c in parent:
            if c.tag == tag or (isinstance(c.tag, str) and c.tag.endswith("}" + tag)):
                return c
        return None

    def find_all(parent: ET.Element, tag: str) -> List[ET.Element]:
        out = []
        for c in parent:
            if c.tag == tag or (isinstance(c.tag, str) and c.tag.endswith("}" + tag)):
                out.append(c)
        return out

    grouplist = find_one(env_el, "grouplist")
    if grouplist is not None:
        for gid_el in find_all(grouplist, "groupid"):
            gid = (gid_el.text or "").strip()
            if gid:
                groups.append(gid)
    return groups


def parse_comps_xml(xml_content: str) -> Dict[str, Tuple[Set[str], List[str]]]:
    """
    Parse comps XML and return a map: id -> (package_names_set, group_dependency_ids).

    Parses both <group> and <environment> elements. Environments are added to the
    same dict with their mandatory groups as dependencies, so
    resolve_baseline_packages() follows the full chain automatically.

    Only mandatory and default packages are included. Optional packages are excluded.
    """
    root = ET.fromstring(xml_content)

    def local_tag(e: ET.Element) -> str:
        if isinstance(e.tag, str) and "}" in e.tag:
            return e.tag.split("}", 1)[1]
        return e.tag or ""

    def find_id(parent: ET.Element) -> Optional[str]:
        for c in parent:
            if local_tag(c) == "id":
                return (c.text or "").strip() or None
        return None

    result: Dict[str, Tuple[Set[str], List[str]]] = {}

    for el in root.iter():
        tag = local_tag(el)
        if tag == "group":
            gid = find_id(el)
            if not gid:
                continue
            packages, groupreqs = _parse_group_element(el)
            result[gid] = (packages, groupreqs)
        elif tag == "environment":
            eid = find_id(el)
            if not eid:
                continue
            env_groups = _parse_environment_element(el)
            result[eid] = (set(), env_groups)
            _debug(f"comps: environment '{eid}' -> groups {env_groups}")

    _debug(f"comps: parsed {len([k for k, v in result.items() if v[0]])} groups, "
           f"{len([k for k, v in result.items() if not v[0] and v[1]])} environments")
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
    _debug(f"detect_profile: host_root={host_root}")
    for path in candidates:
        try:
            exists = path.exists()
            _debug(f"detect_profile: {path} exists={exists}")
            if not exists:
                # exists() returns False both when absent AND when parent dir
                # is unreadable (PermissionError is swallowed by Path.exists)
                parent = path.parent
                try:
                    parent_exists = parent.exists()
                    parent_listable = list(parent.iterdir()) if parent_exists else []
                    _debug(f"detect_profile: parent {parent} exists={parent_exists} listable={len(parent_listable)} entries")
                except (PermissionError, OSError) as exc:
                    _debug(f"detect_profile: parent {parent} not accessible: {exc}")
                continue
            text = path.read_text()
            _debug(f"detect_profile: read {path} ({len(text)} bytes)")
        except (PermissionError, OSError) as exc:
            _debug(f"detect_profile: cannot read {path}: {exc}")
            continue
        in_packages = False
        for line in text.splitlines():
            line = line.strip()
            if line == "%packages" or line.startswith("%packages "):
                in_packages = True
                continue
            if in_packages and line.startswith("%"):
                break
            if in_packages and line:
                if line.startswith("@"):
                    profile = line[1:].strip()
                    _debug(f"detect_profile: found profile=@{profile}")
                    return profile
                if re.match(r"^[a-zA-Z0-9_-]+$", line):
                    _debug(f"detect_profile: found profile={line}")
                    return line
    _debug("detect_profile: no profile found in any candidate")
    return None


def _read_dnf_vars(host_root: Path) -> Dict[str, str]:
    """Read all dnf variable files from {host_root}/etc/dnf/vars/.

    Each file in that directory defines a variable: the filename is the variable
    name and the first line of content is the value.  This is the standard DNF
    variable mechanism used by RHEL, CentOS Stream, and Fedora.
    """
    result: Dict[str, str] = {}
    vars_dir = host_root / "etc" / "dnf" / "vars"
    try:
        if not vars_dir.is_dir():
            return result
        for f in sorted(vars_dir.iterdir()):
            if not f.is_file():
                continue
            try:
                val = f.read_text().strip().splitlines()[0].strip()
                if val:
                    result[f.name] = val
            except (IndexError, PermissionError, OSError):
                continue
    except (PermissionError, OSError):
        pass
    _debug(f"dnf vars from {vars_dir}: {result}")
    return result


def _infer_stream_var(host_root: Path, releasever: str) -> str:
    """Synthesize a $stream value when /etc/dnf/vars/stream is absent.

    CentOS Stream expects $stream = "<major>-stream".  We detect this from
    os-release NAME or VARIANT_ID.  For plain RHEL/Fedora, fall back to the
    major version number.
    """
    major = releasever.split(".")[0] if releasever else releasever
    os_release = host_root / "etc" / "os-release"
    try:
        if os_release.exists():
            text = os_release.read_text()
            for line in text.splitlines():
                if line.startswith("VARIANT_ID="):
                    variant = line.split("=", 1)[1].strip().strip('"').lower()
                    if variant == "stream":
                        return f"{major}-stream"
                if line.startswith("NAME="):
                    name = line.split("=", 1)[1].strip().strip('"').lower()
                    if "stream" in name:
                        return f"{major}-stream"
    except (PermissionError, OSError):
        pass
    return major


def _substitute_repo_vars(
    url: str,
    releasever: str,
    basearch: str,
    dnf_vars: Optional[Dict[str, str]] = None,
) -> str:
    """Replace $releasever, $basearch, and any dnf vars ($stream, etc.) in a URL."""
    url = url.replace("$releasever", releasever).replace("$basearch", basearch)
    if dnf_vars:
        for key, val in dnf_vars.items():
            url = url.replace(f"${key}", val)
    return url


def _resolve_metalink(url: str) -> List[str]:
    """Fetch a metalink XML and extract mirror base URLs."""
    _debug(f"metalink fetch: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rhel2bootc/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
    except Exception as exc:
        _debug(f"metalink fetch failed: {exc}")
        return []
    try:
        root = ET.fromstring(data)
    except Exception as exc:
        _debug(f"metalink XML parse failed: {exc}")
        return []
    urls: List[str] = []
    for el in root.iter():
        tag = el.tag.split("}")[-1] if "}" in str(el.tag) else str(el.tag)
        if tag == "url" and el.text:
            u = el.text.strip()
            if u.startswith("http"):
                if "/repodata/" in u:
                    u = u[:u.index("/repodata/")]
                urls.append(u)
    _debug(f"metalink resolved {len(urls)} mirror(s)")
    return urls


def _resolve_mirrorlist(url: str) -> List[str]:
    """Fetch a mirrorlist (plain-text list of URLs) and return base URLs."""
    _debug(f"mirrorlist fetch: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rhel2bootc/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        _debug(f"mirrorlist fetch failed: {exc}")
        return []
    urls: List[str] = []
    for line in data.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.startswith("http"):
            urls.append(line.rstrip("/"))
    _debug(f"mirrorlist resolved {len(urls)} mirror(s)")
    return urls


def _get_repo_baseurls(host_root: Path, releasever: str, basearch: str) -> List[str]:
    """Read .repo files under host_root/etc/yum.repos.d/ and return resolved base URLs.

    Handles baseurl, metalink, and mirrorlist directives.
    Only includes URLs from sections where enabled=1 or enabled is not set.
    Reads dnf variable files from /etc/dnf/vars/ for $stream and other vars.
    """
    dnf_vars = _read_dnf_vars(host_root)
    if "stream" not in dnf_vars:
        dnf_vars["stream"] = _infer_stream_var(host_root, releasever)
        _debug(f"inferred $stream={dnf_vars['stream']} (no dnf var file)")

    urls: List[str] = []
    seen: set = set()

    def _add(u: str) -> None:
        u = u.rstrip("/")
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    repo_dir = host_root / "etc" / "yum.repos.d"
    try:
        if not repo_dir.is_dir():
            _debug(f"repo dir not found: {repo_dir}")
            return urls
        entries = sorted(repo_dir.iterdir())
    except (PermissionError, OSError) as exc:
        _debug(f"cannot read repo dir {repo_dir}: {exc}")
        return urls

    for f in entries:
        if not f.is_file() or not f.name.endswith(".repo"):
            continue
        _debug(f"parsing repo file: {f.name}")
        try:
            content = f.read_text()
        except Exception:
            continue
        section_enabled = True
        section_baseurl: Optional[str] = None
        section_metalink: Optional[str] = None
        section_mirrorlist: Optional[str] = None
        section_name: str = ""

        def _flush_section() -> None:
            if not section_enabled:
                _debug(f"  [{section_name}] disabled, skipping")
                return
            if section_baseurl:
                _debug(f"  [{section_name}] baseurl -> {section_baseurl}")
                _add(section_baseurl)
                return
            if section_metalink:
                _debug(f"  [{section_name}] metalink -> {section_metalink}")
                for mu in _resolve_metalink(section_metalink)[:3]:
                    _add(mu)
                return
            if section_mirrorlist:
                _debug(f"  [{section_name}] mirrorlist -> {section_mirrorlist}")
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
                section_name = line[1:-1]
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "enabled" and v.lower() in ("0", "false", "no"):
                section_enabled = False
            elif k == "baseurl":
                section_baseurl = _substitute_repo_vars(v, releasever, basearch, dnf_vars)
            elif k == "metalink":
                section_metalink = _substitute_repo_vars(v, releasever, basearch, dnf_vars)
            elif k == "mirrorlist":
                section_mirrorlist = _substitute_repo_vars(v, releasever, basearch, dnf_vars)
        _flush_section()

    _debug(f"resolved {len(urls)} base URL(s) from repo files")
    return urls


def _fetch_url(url: str, host_root: Path) -> Optional[bytes]:
    """Fetch URL; for file:// use host_root as base if path is relative."""
    _debug(f"fetch: {url}")
    if url.startswith("file://"):
        path = Path(url[7:])
        if not path.is_absolute():
            path = host_root / path
        if path.exists():
            data = path.read_bytes()
            _debug(f"  file read OK ({len(data)} bytes)")
            return data
        _debug(f"  file not found: {path}")
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rhel2bootc/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
            _debug(f"  HTTP {resp.status} ({len(data)} bytes)")
            return data
    except Exception as exc:
        _debug(f"  fetch failed: {exc}")
        return None


_GROUP_DATA_TYPES = ("group", "group_gz", "group_xz", "comps", "comps_gz", "comps_xz")


def _find_group_href_in_repomd(repomd_xml: bytes) -> Optional[str]:
    """Parse repomd.xml and return href for group/comps data, or None.

    Checks data types: group, group_gz, group_xz, comps, comps_gz, comps_xz.
    Prefers uncompressed over compressed when multiple are present.
    """
    root = ET.fromstring(repomd_xml)

    def local_tag(e: ET.Element) -> str:
        if isinstance(e.tag, str) and "}" in e.tag:
            return e.tag.split("}", 1)[1]
        return e.tag or ""

    candidates: Dict[str, str] = {}
    for data_el in root.iter():
        if local_tag(data_el) != "data":
            continue
        dtype = data_el.get("type") or ""
        if dtype not in _GROUP_DATA_TYPES:
            continue
        for c in data_el:
            if local_tag(c) == "location":
                href = c.get("href") or ""
                if href:
                    candidates[dtype] = href
                    _debug(f"repomd: found <data type=\"{dtype}\"> -> {href}")

    for preferred in _GROUP_DATA_TYPES:
        if preferred in candidates:
            _debug(f"repomd: selected type={preferred}")
            return candidates[preferred]

    _debug("repomd: no group/comps data found")
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
    _debug(f"fetch_comps: id={id_val} ver={version_id} arch={basearch}")
    baseurls = _get_repo_baseurls(host_root, releasever, basearch)
    if not baseurls:
        _debug("fetch_comps: no base URLs resolved from repo files")
        return None

    _debug(f"fetch_comps: trying {len(baseurls)} base URL(s)")
    for base in baseurls:
        base = base.rstrip("/")
        repomd_url = f"{base}/repodata/repomd.xml"
        raw = _fetch_url(repomd_url, host_root)
        if not raw:
            _debug(f"  repomd.xml not available at {base}")
            continue
        href = _find_group_href_in_repomd(raw)
        if not href:
            _debug(f"  no group/comps data in repomd.xml at {base}")
            continue
        if not href.startswith("http") and not href.startswith("file"):
            comps_url = f"{base}/{href}"
        else:
            comps_url = href
        comps_raw = _fetch_url(comps_url, host_root)
        if not comps_raw:
            _debug(f"  comps XML fetch failed: {comps_url}")
            continue
        # Decompress if needed (gzip or xz)
        if comps_url.endswith(".xz") or comps_raw[:6] == b"\xfd7zXZ\x00":
            try:
                comps_raw = lzma.decompress(comps_raw)
                _debug("  decompressed xz comps data")
            except Exception as exc:
                _debug(f"  xz decompress failed: {exc}")
                continue
        elif comps_url.endswith(".gz") or comps_raw[:2] == b"\x1f\x8b":
            try:
                comps_raw = gzip.decompress(comps_raw)
                _debug("  decompressed gzip comps data")
            except Exception as exc:
                _debug(f"  gzip decompress failed: {exc}")
                continue
        try:
            xml_text = comps_raw.decode("utf-8", errors="replace")
            _debug(f"  comps XML loaded ({len(xml_text)} chars)")
            return xml_text
        except Exception as exc:
            _debug(f"  comps decode failed: {exc}")
            continue
    _debug("fetch_comps: exhausted all base URLs without finding comps XML")
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


def _resolve_profile_id(
    comps_data: Dict[str, Tuple[Set[str], List[str]]],
    profile: Optional[str],
) -> Optional[str]:
    """Map a user-facing profile name to its comps id.

    Tries, in order:
      1. Exact match (e.g. "core", "server-product-environment")
      2. "{profile}-environment" (e.g. "minimal" -> "minimal-environment")
      3. "{profile}-product-environment" (e.g. "server" -> "server-product-environment")
    Returns the first match found in comps_data, or None.
    """
    if not profile:
        return None
    candidates = [
        profile,
        f"{profile}-environment",
        f"{profile}-product-environment",
    ]
    for c in candidates:
        if c in comps_data:
            _debug(f"_resolve_profile_id: '{profile}' matched '{c}'")
            return c
    _debug(f"_resolve_profile_id: '{profile}' not found in comps data")
    return None


def get_baseline_packages(
    host_root: Path,
    os_id: str,
    version_id: str,
    comps_file: Optional[Path] = None,
    basearch: str = "",
    profile_override: Optional[str] = None,
) -> Tuple[Optional[Set[str]], Optional[str], bool]:
    """
    Resolve baseline package set and profile used.

    Returns (baseline_names, profile_used, no_baseline).
    - If comps_file is set: load and parse from file.
    - Else: try fetch_comps_from_repos.
    - If we have comps: use profile_override, detect_profile, or "minimal" fallback.
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
    if profile_override:
        profile = profile_override.lstrip("@")
        _debug(f"using --profile override: {profile}")
    else:
        profile = detect_profile(host_root)

    resolved_id = _resolve_profile_id(comps_data, profile)
    if not resolved_id:
        resolved_id = _resolve_profile_id(comps_data, "minimal")
    if not resolved_id:
        resolved_id = "core"
    _debug(f"profile '{profile}' resolved to comps id '{resolved_id}'")
    baseline = resolve_baseline_packages(comps_data, resolved_id)
    _debug(f"baseline resolved: profile={resolved_id}, {len(baseline)} packages")
    return (baseline, profile or resolved_id, False)
