"""
Tests for renderers: run all renderers against a snapshot and verify output files exist.
Per-renderer tests use the same fixture pattern as inspector tests (snapshot + output_dir).
"""

import tempfile
from pathlib import Path

import pytest
from jinja2 import Environment

from rhel2bootc.pipeline import load_snapshot
from rhel2bootc.renderers import run_all
from rhel2bootc.renderers.audit_report import render as render_audit_report
from rhel2bootc.renderers.containerfile import render as render_containerfile
from rhel2bootc.renderers.html_report import render as render_html_report
from rhel2bootc.renderers.kickstart import render as render_kickstart
from rhel2bootc.renderers.readme import render as render_readme
from rhel2bootc.renderers.secrets_review import render as render_secrets_review
from rhel2bootc.schema import (
    InspectionSnapshot,
    OsRelease,
    PackageEntry,
    RpmSection,
    ServiceSection,
    ServiceStateChange,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _make_render_env():
    """Jinja2 env used by renderers (no templates dir required for current renderers)."""
    return Environment(autoescape=True)


@pytest.fixture
def snapshot_from_fixture():
    """Load snapshot from fixture JSON if present, else build minimal snapshot."""
    snapshot_path = FIXTURES.parent / "rhel2bootc-snapshot.json"
    if not snapshot_path.exists():
        # Build minimal snapshot so renderers don't crash
        from rhel2bootc.schema import (
            ConfigSection,
            OsRelease,
            RpmSection,
            ServiceSection,
            ConfigFileEntry,
            ConfigFileKind,
        )
        from rhel2bootc.inspectors.rpm import run as run_rpm
        from rhel2bootc.inspectors.service import run as run_service
        from rhel2bootc.inspectors.config import run as run_config
        from rhel2bootc.executor import RunResult

        fixtures = FIXTURES
        def exec_(cmd, cwd=None):
            c = " ".join(cmd)
            if "rpm" in c and "-qa" in c:
                return RunResult(stdout=(fixtures / "rpm_qa_output.txt").read_text(), stderr="", returncode=0)
            if "rpm" in c and "-Va" in c:
                return RunResult(stdout=(fixtures / "rpm_va_output.txt").read_text(), stderr="", returncode=0)
            if "dnf" in c and "list" in c:
                return RunResult(stdout=(fixtures / "dnf_history_list.txt").read_text(), stderr="", returncode=0)
            if "dnf" in c and "info" in c and "4" in c:
                return RunResult(stdout=(fixtures / "dnf_history_info_4.txt").read_text(), stderr="", returncode=0)
            if "rpm" in c and "-ql" in c:
                return RunResult(stdout=(fixtures / "rpm_qla_output.txt").read_text(), stderr="", returncode=0)
            if "systemctl" in c:
                return RunResult(stdout=(fixtures / "systemctl_list_unit_files.txt").read_text(), stderr="", returncode=0)
            return RunResult(stdout="", stderr="", returncode=1)

        host_root = fixtures / "host_etc"
        tool_root = Path(__file__).parent.parent
        from rhel2bootc.inspectors import run_all as run_inspectors
        return run_inspectors(host_root, executor=exec_, tool_root=tool_root)
    return load_snapshot(snapshot_path)


def test_renderers_produce_all_artifacts(snapshot_from_fixture):
    """Run all renderers and assert expected output files exist."""
    assert isinstance(snapshot_from_fixture, InspectionSnapshot)
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        run_all(snapshot_from_fixture, output_dir)
        assert (output_dir / "Containerfile").exists()
        assert (output_dir / "audit-report.md").exists()
        assert (output_dir / "report.html").exists()
        assert (output_dir / "README.md").exists()
        assert (output_dir / "secrets-review.md").exists()
        assert (output_dir / "kickstart-suggestion.ks").exists()
        assert (output_dir / "config").is_dir()


def test_renderers_handle_minimal_snapshot():
    """Renderers must not crash when sections are None (e.g. from-snapshot with sparse data)."""
    minimal = InspectionSnapshot(
        meta={"host_root": "/host"},
        os_release=OsRelease(name="RHEL", version_id="9.6"),
        rpm=None,
        config=None,
        services=None,
    )
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        run_all(minimal, output_dir)
        assert (output_dir / "Containerfile").exists()
        assert (output_dir / "audit-report.md").exists()
        assert (output_dir / "report.html").exists()
        assert (output_dir / "README.md").exists()
        assert (output_dir / "secrets-review.md").exists()
        assert (output_dir / "kickstart-suggestion.ks").exists()


def test_containerfile_renderer(snapshot_from_fixture):
    """Containerfile renderer produces FROM and COPY lines."""
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_containerfile(snapshot_from_fixture, env, output_dir)
        path = output_dir / "Containerfile"
        assert path.exists()
        content = path.read_text()
        assert "FROM " in content
        assert "COPY " in content or "config" in content


def test_containerfile_layer_ordering(snapshot_from_fixture):
    """Containerfile section headers appear in design-doc order."""
    import re
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_containerfile(snapshot_from_fixture, env, output_dir)
        content = (output_dir / "Containerfile").read_text()
        headers = re.findall(r"^# === (.+?) ===$", content, re.MULTILINE)
        DESIGN_ORDER = [
            "Base Image",
            "Repository Configuration",
            "Package Installation",
            "Service Enablement",
            "Firewall Configuration",
            "Scheduled Tasks",
            "Configuration Files",
            "Non-RPM Software",
            "Container Workloads (Quadlet)",
            "Users and Groups",
            "Kernel Configuration",
            "SELinux Customizations",
            "Network / Kickstart",
            "tmpfiles.d for /var structure",
        ]
        present = [h for h in DESIGN_ORDER if h in headers]
        for a, b in zip(present, present[1:]):
            ia = headers.index(a)
            ib = headers.index(b)
            assert ia < ib, f"Section '{a}' (pos {ia}) must come before '{b}' (pos {ib})"


def test_containerfile_copy_targets_exist(snapshot_from_fixture):
    """Every COPY in the Containerfile references a file/dir that exists in the output."""
    import re
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_containerfile(snapshot_from_fixture, env, output_dir)
        content = (output_dir / "Containerfile").read_text()
        for i, line in enumerate(content.splitlines(), 1):
            if line.startswith("#"):
                continue
            m = re.match(r"^COPY\s+(config/\S+|quadlet/\S*)", line)
            if m:
                src = m.group(1)
                src_path = output_dir / src
                assert src_path.exists(), f"COPY source missing at line {i}: {src}"


def test_containerfile_fixme_comments_are_actionable(snapshot_from_fixture):
    """Every FIXME comment explains what the operator needs to do (not just 'FIXME')."""
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_containerfile(snapshot_from_fixture, env, output_dir)
        content = (output_dir / "Containerfile").read_text()
        for i, line in enumerate(content.splitlines(), 1):
            if "FIXME" in line:
                after = line.split("FIXME", 1)[1].strip().lstrip(":").strip()
                assert len(after) > 10, (
                    f"FIXME at line {i} is not actionable (too short): {line.strip()!r}"
                )


def test_containerfile_syntax_valid(snapshot_from_fixture):
    """Containerfile uses only valid Dockerfile instructions; parseable by podman build."""
    import re
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_containerfile(snapshot_from_fixture, env, output_dir)
        content = (output_dir / "Containerfile").read_text()
        VALID = {"FROM", "RUN", "COPY", "ADD", "ENV", "ARG", "LABEL", "EXPOSE",
                 "ENTRYPOINT", "CMD", "VOLUME", "USER", "WORKDIR", "ONBUILD",
                 "STOPSIGNAL", "HEALTHCHECK", "SHELL"}
        in_continuation = False
        had_from = False
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                in_continuation = False
                continue
            if in_continuation:
                in_continuation = stripped.endswith("\\")
                continue
            m = re.match(r"^([A-Z]+)\s", stripped)
            if m:
                instr = m.group(1)
                assert instr in VALID, f"Unknown instruction at line {i}: {instr}"
                if instr == "FROM":
                    had_from = True
                in_continuation = stripped.endswith("\\")
            else:
                assert line[0] in (" ", "\t"), (
                    f"Line {i} is not a valid instruction or continuation: {stripped[:80]!r}"
                )
                in_continuation = stripped.endswith("\\")
        assert had_from, "Containerfile is missing a FROM instruction"


def test_containerfile_non_rpm_provenance(snapshot_from_fixture):
    """Non-RPM section emits real directives for known provenance, stubs for unknown."""
    import re
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_containerfile(snapshot_from_fixture, env, output_dir)
        content = (output_dir / "Containerfile").read_text()

        # pip dist-info: real RUN pip install (not commented out)
        assert re.search(r"^RUN pip install", content, re.MULTILINE), \
            "pip dist-info packages should produce a real RUN pip install line"
        assert "flask==2.3.2" in content
        assert "requests==2.31.0" in content

        # npm lockfile: real COPY and RUN (not commented out)
        assert re.search(r"^COPY config/opt/myapp/", content, re.MULTILINE), \
            "npm lockfile should produce a real COPY directive"
        assert re.search(r"^RUN cd /opt/myapp && npm ci", content, re.MULTILINE), \
            "npm lockfile should produce a real RUN npm ci directive"
        # lockfiles written to config tree
        assert (output_dir / "config" / "opt" / "myapp" / "package-lock.json").exists()
        assert (output_dir / "config" / "opt" / "myapp" / "package.json").exists()

        # unknown provenance: commented-out COPY stub
        assert re.search(r"^# COPY config/opt/dummy", content, re.MULTILINE), \
            "unknown-provenance items should remain as commented-out stubs"
        # no real (uncommented) COPY for opt/dummy
        assert not re.search(r"^COPY config/opt/dummy", content, re.MULTILINE), \
            "unknown-provenance items must not produce real COPY directives"


def test_audit_report_renderer(snapshot_from_fixture):
    """Audit report renderer produces markdown with summary and sections."""
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_audit_report(snapshot_from_fixture, env, output_dir)
        path = output_dir / "audit-report.md"
        assert path.exists()
        content = path.read_text()
        assert "# Audit Report" in content
        assert "Executive Summary" in content


def test_renderers_no_baseline_mode():
    """Containerfile, audit report, and HTML report show no-baseline message when no_baseline=True."""
    rpm = RpmSection(
        packages_added=[PackageEntry(name="httpd", version="2.4", release="1.el9", arch="x86_64")],
        packages_removed=[],
        no_baseline=True,
        baseline_package_names=None,
    )
    snapshot = InspectionSnapshot(
        meta={},
        os_release=OsRelease(name="RHEL", version_id="9.6"),
        rpm=rpm,
        config=None,
        services=None,
    )
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        render_audit_report(snapshot, env, out)
        assert "No baseline" in (out / "audit-report.md").read_text()
        assert "no baseline" in (out / "audit-report.md").read_text().lower()
        render_containerfile(snapshot, env, out)
        assert "No baseline" in (out / "Containerfile").read_text()
        render_html_report(snapshot, env, out)
        assert "No baseline" in (out / "report.html").read_text()


def test_renderers_baseline_available_mode():
    """With baseline available (no_baseline=False), audit and Containerfile use 'beyond baseline' wording."""
    rpm = RpmSection(
        packages_added=[PackageEntry(name="httpd", version="2.4", release="1.el9", arch="x86_64")],
        packages_removed=[],
        no_baseline=False,
        baseline_package_names=["bash", "coreutils"],
    )
    snapshot = InspectionSnapshot(
        meta={},
        os_release=OsRelease(name="RHEL", version_id="9.6"),
        rpm=rpm,
        config=None,
        services=None,
    )
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        render_audit_report(snapshot, env, out)
        content = (out / "audit-report.md").read_text()
        assert "beyond baseline" in content
        assert "No baseline" not in content
        render_containerfile(snapshot, env, out)
        assert "added beyond baseline" in (out / "Containerfile").read_text()
        assert "No baseline" not in (out / "Containerfile").read_text()


def test_html_report_renderer(snapshot_from_fixture):
    """HTML report renderer produces report.html with dashboard."""
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_html_report(snapshot_from_fixture, env, output_dir)
        path = output_dir / "report.html"
        assert path.exists()
        content = path.read_text()
        assert "rhel2bootc" in content
        assert "<!DOCTYPE html>" in content


def test_readme_renderer(snapshot_from_fixture):
    """README renderer produces README.md with build/deploy commands."""
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_readme(snapshot_from_fixture, env, output_dir)
        path = output_dir / "README.md"
        assert path.exists()
        content = path.read_text()
        assert "podman build" in content
        assert "rhel2bootc" in content or "output" in content


def test_kickstart_renderer(snapshot_from_fixture):
    """Kickstart renderer produces kickstart-suggestion.ks."""
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_kickstart(snapshot_from_fixture, env, output_dir)
        path = output_dir / "kickstart-suggestion.ks"
        assert path.exists()
        content = path.read_text()
        assert "Kickstart" in content or "kickstart" in content


def test_secrets_review_renderer(snapshot_from_fixture):
    """Secrets review renderer produces secrets-review.md."""
    env = _make_render_env()
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        render_secrets_review(snapshot_from_fixture, env, output_dir)
        path = output_dir / "secrets-review.md"
        assert path.exists()
        content = path.read_text()
        assert "Secrets Review" in content or "redact" in content.lower()


def test_renderers_handle_edge_case_none_and_empty():
    """
    Renderers must handle: None sections, empty lists, dict values that are None,
    and state_changes with all 'unchanged' (no header-only tables).
    Assert no crash, no literal 'None' in output, no empty tables with only headers.
    """
    # Services with only "unchanged" -> must not produce table with just headers
    services = ServiceSection(
        state_changes=[
            ServiceStateChange(unit="foo.service", current_state="enabled", default_state="enabled", action="unchanged"),
        ],
        enabled_units=[],
        disabled_units=[],
    )
    # Warnings/redactions with None or missing values
    edge = InspectionSnapshot(
        meta={"host_root": "/host"},
        os_release=OsRelease(name="RHEL", version_id="9.6", pretty_name="RHEL 9.6"),
        rpm=None,
        config=None,
        services=services,
        network=None,
        storage=None,
        scheduled_tasks=None,
        containers=None,
        non_rpm_software=None,
        kernel_boot=None,
        selinux=None,
        users_groups=None,
        warnings=[
            {"message": None},
            {"message": ""},
            {},
            {"message": "Real warning"},
        ],
        redactions=[
            {"path": None, "pattern": None, "remediation": None},
            {"path": "", "pattern": "PASSWORD", "remediation": "use secret"},
        ],
    )
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        run_all(edge, output_dir)

        audit = (output_dir / "audit-report.md").read_text()
        html = (output_dir / "report.html").read_text()
        readme = (output_dir / "README.md").read_text()
        secrets = (output_dir / "secrets-review.md").read_text()

        # No literal "None" rendered as text (allow "Unknown" or "—")
        assert "None" not in audit, "audit-report.md must not contain literal None"
        assert "None" not in html, "report.html must not contain literal None"
        assert "None" not in readme, "README.md must not contain literal None"
        assert "None" not in secrets, "secrets-review.md must not contain literal None"

        # No header-only tables: Services section must not have | Unit | ... | with zero data rows.
        # We have one state_change but action=unchanged, so table should be omitted.
        lines = audit.splitlines()
        in_services = False
        table_headers_seen = 0
        table_data_rows_after_services_header = 0
        for i, line in enumerate(lines):
            if "## Services" in line:
                in_services = True
                continue
            if in_services and "| Unit |" in line:
                table_headers_seen += 1
            if in_services and table_headers_seen >= 1 and line.strip().startswith("|") and "---" not in line and "Unit" not in line:
                table_data_rows_after_services_header += 1
            if in_services and line.strip() == "" and table_headers_seen > 0:
                break
        # We should have either no Services table at all (no header row), or no data rows
        assert table_data_rows_after_services_header == 0, "Services table must not be header-only"

        # HTML: same idea — no Services table with empty tbody
        if 'id="section-services"' in html and "<table>" in html:
            # There is a services section; if there's a table it must have at least one row
            services_section = html.split('id="section-services"')[1].split('id="section-')[0]
            if "<thead>" in services_section and "<tbody>" in services_section:
                tbody = services_section.split("<tbody>")[1].split("</tbody>")[0]
                # With all unchanged we expect "No service changes" and no <tr> for data
                assert "No service changes" in services_section or "<tr><td>" in tbody, "Services table must not be header-only"


def test_html_report_cards_and_tabs_link_to_sections():
    """
    Generate report from fixtures and verify: every category card data-section
    has a matching #section-{id}, every tab data-tab has a matching section,
    warning panel is present and populated when snapshot has warnings.
    """
    import re
    from rhel2bootc.executor import RunResult
    from rhel2bootc.inspectors import run_all as run_inspectors
    from rhel2bootc.redact import redact_snapshot
    from rhel2bootc.renderers import run_all as run_renderers

    F = Path(__file__).parent / "fixtures"
    def exec_(cmd, cwd=None):
        c = " ".join(cmd)
        if "rpm" in c and "-qa" in c:
            return RunResult(stdout=(F / "rpm_qa_output.txt").read_text(), stderr="", returncode=0)
        if "rpm" in c and "-Va" in c:
            return RunResult(stdout=(F / "rpm_va_output.txt").read_text(), stderr="", returncode=0)
        if "dnf" in c and "list" in c:
            return RunResult(stdout=(F / "dnf_history_list.txt").read_text(), stderr="", returncode=0)
        if "dnf" in c and "info" in c and "4" in c:
            return RunResult(stdout=(F / "dnf_history_info_4.txt").read_text(), stderr="", returncode=0)
        if "rpm" in c and "-ql" in c:
            return RunResult(stdout=(F / "rpm_qla_output.txt").read_text(), stderr="", returncode=0)
        if "systemctl" in c:
            return RunResult(stdout=(F / "systemctl_list_unit_files.txt").read_text(), stderr="", returncode=0)
        return RunResult(stdout="", stderr="", returncode=1)

    host_root = F / "host_etc"
    tool_root = Path(__file__).parent.parent
    snapshot = run_inspectors(
        host_root, executor=exec_, tool_root=tool_root,
        config_diffs=False, deep_binary_scan=False, query_podman=False,
    )
    snapshot = redact_snapshot(snapshot)
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        run_renderers(snapshot, output_dir)
        html = (output_dir / "report.html").read_text()

    # Every card data-section must have a section with id="section-{value}"
    card_sections = re.findall(r'class="card"\s+data-section="([^"]+)"', html)
    for sec in card_sections:
        assert f'id="section-{sec}"' in html, f"Card data-section={sec} has no matching #section-{sec}"

    # Every tab data-tab must have a section with id="section-{value}"
    tab_tabs = re.findall(r'data-tab="([^"]+)"', html)
    for tab in tab_tabs:
        assert f'id="section-{tab}"' in html, f"Tab data-tab={tab} has no matching #section-{tab}"

    # Summary is the default visible section
    assert 'id="section-summary"' in html and 'class="section visible"' in html
    assert html.index('section-summary') < html.index('class="section visible"') or 'id="section-summary" class="section visible"' in html

    # When snapshot has warnings, warning panel and Warnings section list must be populated
    if snapshot.warnings:
        assert "warning-panel" in html and "Warnings &amp; items to review" in html
        assert "id=\"warnings-list\"" in html
        # At least one list item in the Warnings section
        assert re.search(r'id="warnings-list"[^>]*>.*?<li>', html, re.DOTALL), "Warnings section should contain list items"
