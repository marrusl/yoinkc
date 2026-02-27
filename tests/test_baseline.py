"""Tests for baseline (comps) parsing and resolution."""

import unittest.mock
from pathlib import Path

import pytest

from rhel2bootc.baseline import (
    _find_group_href_in_repomd,
    _infer_stream_var,
    _read_dnf_vars,
    _substitute_repo_vars,
    parse_comps_xml,
    resolve_baseline_packages,
    detect_profile,
    get_baseline_packages,
)


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_comps_xml():
    xml = (FIXTURES / "comps_minimal.xml").read_text()
    data = parse_comps_xml(xml)
    assert "minimal" in data
    pkgs, groupreqs = data["minimal"]
    assert "acl" in pkgs
    assert "bash" in pkgs
    assert "vim-enhanced" not in pkgs  # optional excluded
    assert groupreqs == []


def test_resolve_baseline_packages():
    xml = (FIXTURES / "comps_minimal.xml").read_text()
    data = parse_comps_xml(xml)
    baseline = resolve_baseline_packages(data, "minimal")
    assert "acl" in baseline
    assert "bash" in baseline
    assert "grep" in baseline
    assert "sed" in baseline


def test_detect_profile_empty_root(tmp_path):
    assert detect_profile(tmp_path) is None


def test_detect_profile_from_kickstart(tmp_path):
    (tmp_path / "root").mkdir(parents=True)
    (tmp_path / "root" / "anaconda-ks.cfg").write_text(
        "# Kickstart\n%packages\n@server\n%end\n"
    )
    assert detect_profile(tmp_path) == "server"


def test_resolve_baseline_packages_recursive_group_chain():
    """Group dependency resolution is recursive: @server -> @minimal -> @core; all packages included."""
    xml = (FIXTURES / "comps_server_core.xml").read_text()
    data = parse_comps_xml(xml)
    baseline = resolve_baseline_packages(data, "server")
    # From server
    assert "openssh-server" in baseline
    assert "httpd" in baseline
    # From minimal (server depends on minimal)
    assert "filesystem" in baseline
    assert "sed" in baseline
    # From core (minimal depends on core)
    assert "glibc" in baseline
    assert "bash" in baseline
    assert "coreutils" in baseline


def test_get_baseline_with_comps_file(host_root=None):
    host_root = host_root or (FIXTURES / "host_etc")
    comps_file = FIXTURES / "comps_minimal.xml"
    baseline_set, profile, no_baseline = get_baseline_packages(
        host_root, "rhel", "9.6", comps_file=comps_file
    )
    assert no_baseline is False
    assert profile == "minimal"
    assert baseline_set is not None
    assert "acl" in baseline_set
    assert "bash" in baseline_set


def test_get_baseline_comps_file_bypasses_network(host_root=None):
    """When --comps-file is provided, fetch_comps_from_repos is not called (no network)."""
    host_root = host_root or (FIXTURES / "host_etc")
    comps_file = FIXTURES / "comps_minimal.xml"
    with unittest.mock.patch("rhel2bootc.baseline.fetch_comps_from_repos") as mock_fetch:
        baseline_set, profile, no_baseline = get_baseline_packages(
            host_root, "rhel", "9.6", comps_file=comps_file
        )
        mock_fetch.assert_not_called()
    assert no_baseline is False
    assert baseline_set is not None


# --- dnf vars and $stream resolution ---

CENTOS_FIXTURES = FIXTURES / "host_etc_centos"


def test_read_dnf_vars():
    """_read_dnf_vars reads all files from /etc/dnf/vars/."""
    result = _read_dnf_vars(CENTOS_FIXTURES)
    assert result["stream"] == "9-stream"


def test_read_dnf_vars_missing_dir(tmp_path):
    """_read_dnf_vars returns empty dict when /etc/dnf/vars/ doesn't exist."""
    result = _read_dnf_vars(tmp_path)
    assert result == {}


def test_infer_stream_var_centos_stream():
    """_infer_stream_var returns '9-stream' for CentOS Stream os-release."""
    result = _infer_stream_var(CENTOS_FIXTURES, "9")
    assert result == "9-stream"


def test_infer_stream_var_plain_rhel():
    """_infer_stream_var returns major version for plain RHEL."""
    result = _infer_stream_var(FIXTURES / "host_etc", "9.6")
    assert result == "9"


def test_substitute_repo_vars_with_dnf_vars():
    """_substitute_repo_vars applies dnf vars like $stream correctly."""
    url = "https://mirrors.centos.org/metalink?repo=centos-baseos-$stream&arch=$basearch"
    result = _substitute_repo_vars(url, "9", "x86_64", {"stream": "9-stream"})
    assert result == "https://mirrors.centos.org/metalink?repo=centos-baseos-9-stream&arch=x86_64"


def test_substitute_repo_vars_without_dnf_vars():
    """_substitute_repo_vars works when no dnf_vars dict is provided."""
    url = "https://cdn.redhat.com/content/dist/rhel9/$releasever/$basearch/baseos/os"
    result = _substitute_repo_vars(url, "9.6", "x86_64")
    assert result == "https://cdn.redhat.com/content/dist/rhel9/9.6/x86_64/baseos/os"


# --- detect_profile with kickstart flags ---

def test_detect_profile_with_flags(tmp_path):
    """detect_profile handles %packages --ignoremissing and other flags."""
    (tmp_path / "root").mkdir(parents=True)
    (tmp_path / "root" / "anaconda-ks.cfg").write_text(
        "# Kickstart\n%packages --ignoremissing --retries=5\n@server\n%end\n"
    )
    assert detect_profile(tmp_path) == "server"


def test_detect_profile_centos_stream():
    """detect_profile works with the CentOS Stream fixture kickstart."""
    assert detect_profile(CENTOS_FIXTURES) == "server"


# --- repomd.xml group_xz support ---

def test_find_group_href_in_repomd_prefers_uncompressed():
    """_find_group_href_in_repomd prefers 'group' (uncompressed) over 'group_xz'."""
    repomd_xml = (FIXTURES / "centos_repomd.xml").read_bytes()
    href = _find_group_href_in_repomd(repomd_xml)
    assert href is not None
    assert href.endswith(".xml")
    assert not href.endswith(".xz")


def test_find_group_href_in_repomd_falls_back_to_xz():
    """_find_group_href_in_repomd falls back to group_xz when group is absent."""
    repomd_xml = (FIXTURES / "centos_repomd.xml").read_text()
    # Remove the uncompressed <data type="group"> block
    stripped = repomd_xml.replace(
        '  <data type="group">\n'
        '    <checksum type="sha256">0146aeaae330eaf817af5ba661296dcf37ac224eac896064b853aeb8bafc48ef</checksum>\n'
        '    <location href="repodata/0146aeaae330eaf817af5ba661296dcf37ac224eac896064b853aeb8bafc48ef-comps-BaseOS.x86_64.xml"/>\n'
        '    <timestamp>1700000000</timestamp>\n'
        '    <size>288219</size>\n'
        '  </data>\n',
        ""
    )
    href = _find_group_href_in_repomd(stripped.encode())
    assert href is not None
    assert href.endswith(".xml.xz")


# --- CentOS Stream end-to-end URL resolution ---

def test_centos_stream_repo_url_resolution():
    """Repo URL resolution substitutes $stream correctly for CentOS Stream 9.

    Mocks the metalink fetch to verify the correct URL is constructed.
    """
    from rhel2bootc.baseline import _get_repo_baseurls

    captured_urls = []

    def fake_metalink(url):
        captured_urls.append(url)
        return ["https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os"]

    with unittest.mock.patch("rhel2bootc.baseline._resolve_metalink", side_effect=fake_metalink):
        urls = _get_repo_baseurls(CENTOS_FIXTURES, "9", "x86_64")

    # The baseos metalink should use $stream=9-stream (from dnf vars), not just "9"
    assert any("centos-baseos-9-stream" in u for u in captured_urls), (
        f"Expected metalink URL with 9-stream, got: {captured_urls}"
    )
    # The appstream metalink should also use 9-stream
    assert any("centos-appstream-9-stream" in u for u in captured_urls), (
        f"Expected appstream metalink URL with 9-stream, got: {captured_urls}"
    )
    # CRB is disabled, should NOT be fetched
    assert not any("centos-crb" in u for u in captured_urls), (
        f"CRB is disabled but metalink was fetched: {captured_urls}"
    )
    # The resolved base URL from the fake metalink should be in the result
    assert "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os" in urls


def test_centos_stream_inferred_stream_without_dnf_vars(tmp_path):
    """When /etc/dnf/vars/ is absent, $stream is inferred from os-release VARIANT_ID."""
    from rhel2bootc.baseline import _get_repo_baseurls

    # Set up minimal centos-like structure without dnf vars dir
    (tmp_path / "etc" / "yum.repos.d").mkdir(parents=True)
    (tmp_path / "etc" / "os-release").write_text(
        'NAME="CentOS Stream"\nVERSION_ID=9\nVARIANT_ID=stream\n'
    )
    (tmp_path / "etc" / "yum.repos.d" / "centos.repo").write_text(
        "[baseos]\nmetalink=https://mirrors.centos.org/metalink?repo=centos-baseos-$stream&arch=$basearch\nenabled=1\n"
    )

    captured_urls = []

    def fake_metalink(url):
        captured_urls.append(url)
        return []

    with unittest.mock.patch("rhel2bootc.baseline._resolve_metalink", side_effect=fake_metalink):
        _get_repo_baseurls(tmp_path, "9", "x86_64")

    assert any("centos-baseos-9-stream" in u for u in captured_urls), (
        f"Expected inferred 9-stream in metalink URL, got: {captured_urls}"
    )
