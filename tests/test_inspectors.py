"""
Tests for inspectors using fixture data. No subprocess or real host required.
"""

from pathlib import Path

import pytest

from rhel2bootc.executor import Executor, RunResult
from rhel2bootc.inspectors import run_all
from rhel2bootc.inspectors.rpm import _parse_nevr, _parse_rpm_qa, _parse_rpm_va
from rhel2bootc.schema import InspectionSnapshot, RpmSection


FIXTURES = Path(__file__).parent / "fixtures"


def _fixture_executor(cmd, cwd=None):
    """Executor that returns fixture file content for known commands."""
    cmd_str = " ".join(cmd)
    if "rpm" in cmd and "-qa" in cmd:
        return RunResult(stdout=(FIXTURES / "rpm_qa_output.txt").read_text(), stderr="", returncode=0)
    if "rpm" in cmd and "-Va" in cmd:
        return RunResult(stdout=(FIXTURES / "rpm_va_output.txt").read_text(), stderr="", returncode=0)
    if "dnf" in cmd and "history" in cmd and "list" in cmd:
        return RunResult(stdout=(FIXTURES / "dnf_history_list.txt").read_text(), stderr="", returncode=0)
    if "dnf" in cmd and "history" in cmd and "info" in cmd and "4" in cmd:
        return RunResult(stdout=(FIXTURES / "dnf_history_info_4.txt").read_text(), stderr="", returncode=0)
    if "rpm" in cmd and "-ql" in cmd:
        return RunResult(stdout=(FIXTURES / "rpm_qla_output.txt").read_text(), stderr="", returncode=0)
    if "systemctl" in cmd and "list-unit-files" in cmd:
        return RunResult(stdout=(FIXTURES / "systemctl_list_unit_files.txt").read_text(), stderr="", returncode=0)
    return RunResult(stdout="", stderr="unknown command", returncode=1)


@pytest.fixture
def fixture_executor() -> Executor:
    return _fixture_executor


@pytest.fixture
def host_root() -> Path:
    return FIXTURES / "host_etc"


def test_parse_nevr():
    p = _parse_nevr("0:bash-5.2.15-2.el9.x86_64")
    assert p is not None
    assert p.name == "bash"
    assert p.version == "5.2.15"
    assert p.release == "2.el9"
    assert p.arch == "x86_64"


def test_parse_rpm_qa():
    text = (FIXTURES / "rpm_qa_output.txt").read_text()
    packages = _parse_rpm_qa(text)
    assert len(packages) >= 30
    names = [p.name for p in packages]
    assert "bash" in names
    assert "httpd" in names


def test_parse_rpm_va():
    text = (FIXTURES / "rpm_va_output.txt").read_text()
    entries = _parse_rpm_va(text)
    assert len(entries) == 5
    paths = [e.path for e in entries]
    assert "/etc/httpd/conf/httpd.conf" in paths
    assert "/etc/ssh/sshd_config" in paths


def test_rpm_inspector_with_fixtures(host_root, fixture_executor):
    """No comps available → no_baseline mode: all installed packages are 'added', tool continues."""
    from rhel2bootc.inspectors.rpm import run as run_rpm
    tool_root = Path(__file__).parent.parent
    section = run_rpm(host_root, fixture_executor, tool_root)
    assert section is not None
    assert section.no_baseline is True
    assert section.baseline_package_names is None
    assert len(section.packages_added) > 0
    assert "httpd" in [p.name for p in section.packages_added]
    assert len(section.rpm_va) == 5
    assert len(section.repo_files) >= 1
    assert "old-daemon" in section.dnf_history_removed


def test_rpm_inspector_with_comps_file(host_root, fixture_executor):
    """With --comps-file, baseline is applied; only packages beyond baseline are 'added'."""
    from rhel2bootc.inspectors.rpm import run as run_rpm
    comps_file = FIXTURES / "comps_minimal.xml"
    section = run_rpm(host_root, fixture_executor, comps_file=comps_file)
    assert section is not None
    assert section.no_baseline is False
    assert section.baseline_package_names is not None
    assert "acl" in section.baseline_package_names
    assert "bash" in section.baseline_package_names
    added_names = [p.name for p in section.packages_added]
    assert "httpd" in added_names
    assert "acl" not in added_names
    assert "bash" not in added_names


def test_service_inspector_with_fixtures(host_root, fixture_executor):
    from rhel2bootc.inspectors.service import run as run_service
    tool_root = Path(__file__).parent.parent
    section = run_service(host_root, fixture_executor, tool_root)
    assert section is not None
    assert any(s.unit == "httpd.service" and s.action == "enable" for s in section.state_changes)
    assert "httpd.service" in section.enabled_units


def test_config_inspector_with_fixtures(host_root, fixture_executor):
    from rhel2bootc.inspectors.config import run as run_config
    from rhel2bootc.inspectors.rpm import run as run_rpm
    tool_root = Path(__file__).parent.parent
    rpm_section = run_rpm(host_root, fixture_executor, tool_root)
    rpm_owned = set((FIXTURES / "rpm_qla_output.txt").read_text().strip().splitlines())
    section = run_config(host_root, fixture_executor, rpm_section=rpm_section, rpm_owned_paths_override=rpm_owned)
    assert section is not None
    modified = [f for f in section.files if f.kind.value == "rpm_owned_modified"]
    assert len(modified) >= 2  # httpd.conf, sshd_config at least
    assert any("/etc/httpd/conf/httpd.conf" == f.path for f in modified)


def test_network_inspector_with_fixtures(host_root, fixture_executor):
    from rhel2bootc.inspectors.network import run as run_network
    section = run_network(host_root, fixture_executor)
    assert section is not None
    assert hasattr(section, "connections") and isinstance(section.connections, list)
    assert hasattr(section, "firewall_zones") and isinstance(section.firewall_zones, list)
    assert section.resolv_provenance == "file"


def test_storage_inspector_with_fixtures(host_root, fixture_executor):
    from rhel2bootc.inspectors.storage import run as run_storage
    section = run_storage(host_root, fixture_executor)
    assert section is not None
    assert len(section.fstab_entries) >= 1
    assert any(e["mount_point"] == "/" for e in section.fstab_entries)


def test_scheduled_tasks_inspector_with_fixtures(host_root, fixture_executor):
    from rhel2bootc.inspectors.scheduled_tasks import run as run_scheduled_tasks
    section = run_scheduled_tasks(host_root, fixture_executor)
    assert section is not None
    assert any(j["path"].endswith("hourly-job") for j in section.cron_jobs)
    assert len(section.generated_timer_units) >= 1
    assert "OnCalendar" in section.generated_timer_units[0]["timer_content"]


def test_container_inspector_with_fixtures(host_root, fixture_executor):
    from rhel2bootc.inspectors.container import run as run_container
    section = run_container(host_root, fixture_executor, query_podman=False)
    assert section is not None
    assert len(section.quadlet_units) >= 1
    assert any("nginx" in u.get("name", "") for u in section.quadlet_units)
    assert section.quadlet_units[0].get("content", "").strip().startswith("[Unit]")


def test_non_rpm_software_inspector_with_fixtures(host_root, fixture_executor):
    from rhel2bootc.inspectors.non_rpm_software import run as run_non_rpm_software
    section = run_non_rpm_software(host_root, fixture_executor, deep_binary_scan=False)
    assert section is not None

    methods = {i.get("method") for i in section.items}
    # Unknown provenance (directory scan)
    assert any(i.get("name") == "dummy" for i in section.items)
    # pip dist-info with version
    pip_items = [i for i in section.items if i.get("method") == "pip dist-info"]
    assert len(pip_items) >= 2
    flask = next((i for i in pip_items if i["name"] == "flask"), None)
    assert flask is not None and flask["version"] == "2.3.2"
    requests_ = next((i for i in pip_items if i["name"] == "requests"), None)
    assert requests_ is not None and requests_["version"] == "2.31.0"
    # npm with lockfile content
    npm_items = [i for i in section.items if i.get("method") == "npm package-lock.json"]
    assert len(npm_items) >= 1
    assert npm_items[0]["name"] == "myapp"
    assert "package-lock.json" in npm_items[0].get("files", {})


def test_kernel_boot_inspector_with_fixtures(host_root, fixture_executor):
    from rhel2bootc.inspectors.kernel_boot import run as run_kernel_boot
    section = run_kernel_boot(host_root, fixture_executor)
    assert section is not None
    assert section.cmdline != ""
    assert "root=" in section.cmdline
    assert section.grub_defaults != ""
    assert "GRUB_CMDLINE_LINUX" in section.grub_defaults


def test_selinux_inspector_with_fixtures(host_root, fixture_executor):
    from rhel2bootc.inspectors.selinux import run as run_selinux
    section = run_selinux(host_root, fixture_executor)
    assert section is not None
    assert any("99-foo" in p for p in section.audit_rules)


def test_users_groups_inspector_with_fixtures(host_root, fixture_executor):
    from rhel2bootc.inspectors.users_groups import run as run_users_groups
    section = run_users_groups(host_root, fixture_executor)
    assert section is not None
    assert any(u.get("name") == "jdoe" and u.get("uid") == 1000 for u in section.users)
    assert any(g.get("name") == "jdoe" and g.get("gid") == 1000 for g in section.groups)


def test_run_all_with_fixtures(host_root, fixture_executor):
    """Full run without comps → no_baseline; no-baseline warning added, tool does not exit."""
    tool_root = Path(__file__).parent.parent
    snapshot = run_all(
        host_root,
        executor=fixture_executor,
        tool_root=tool_root,
        config_diffs=False,
        deep_binary_scan=False,
        query_podman=False,
    )
    assert isinstance(snapshot, InspectionSnapshot)
    assert snapshot.os_release is not None
    assert snapshot.os_release.name == "Red Hat Enterprise Linux"
    assert snapshot.rpm is not None
    assert snapshot.rpm.no_baseline is True
    assert len(snapshot.rpm.packages_added) > 0
    rpm_warnings = [w for w in snapshot.warnings if w.get("source") == "rpm"]
    no_baseline_msg = "Could not fetch comps XML"
    assert any(no_baseline_msg in w.get("message", "") for w in rpm_warnings)
    assert snapshot.services is not None
    assert snapshot.config is not None
    assert snapshot.network is not None
    assert snapshot.storage is not None
    assert snapshot.scheduled_tasks is not None
    assert snapshot.containers is not None
    assert snapshot.non_rpm_software is not None
    assert snapshot.kernel_boot is not None
    assert snapshot.selinux is not None
    assert snapshot.users_groups is not None


def test_run_all_minimal_fallback_warning(host_root, fixture_executor):
    """Comps from file but no kickstart → @minimal fallback; profile warning present, tool continues."""
    tool_root = Path(__file__).parent.parent
    comps_file = FIXTURES / "comps_minimal.xml"
    snapshot = run_all(
        host_root,
        executor=fixture_executor,
        tool_root=tool_root,
        config_diffs=False,
        deep_binary_scan=False,
        query_podman=False,
        comps_file=comps_file,
    )
    assert snapshot.rpm is not None
    assert snapshot.rpm.no_baseline is False
    assert snapshot.rpm.baseline_package_names is not None
    profile_warnings = [w for w in snapshot.warnings if "install profile" in w.get("message", "").lower() or "@minimal" in w.get("message", "")]
    assert any("@minimal" in w.get("message", "") for w in profile_warnings)


def test_snapshot_roundtrip_with_baseline(host_root, fixture_executor):
    """Resolved baseline is in inspection-snapshot.json; --from-snapshot re-renders without network."""
    import tempfile
    from rhel2bootc.pipeline import load_snapshot, save_snapshot
    from rhel2bootc.renderers import run_all as run_all_renderers
    tool_root = Path(__file__).parent.parent
    comps_file = FIXTURES / "comps_minimal.xml"
    snapshot = run_all(
        host_root,
        executor=fixture_executor,
        tool_root=tool_root,
        config_diffs=False,
        deep_binary_scan=False,
        query_podman=False,
        comps_file=comps_file,
    )
    assert snapshot.rpm is not None
    assert snapshot.rpm.no_baseline is False
    assert snapshot.rpm.baseline_package_names is not None
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        path = out / "inspection-snapshot.json"
        save_snapshot(snapshot, path)
        loaded = load_snapshot(path)
        assert loaded.rpm is not None
        assert loaded.rpm.baseline_package_names is not None
        assert loaded.rpm.no_baseline is False
        run_all_renderers(loaded, out)
        assert (out / "Containerfile").exists()
        assert (out / "audit-report.md").exists()
        assert (out / "report.html").exists()
