"""Markdown audit report renderer."""

from pathlib import Path

from jinja2 import Environment

from ..schema import ConfigFileKind, InspectionSnapshot
from ._triage import compute_triage


def render(
    snapshot: InspectionSnapshot,
    env: Environment,
    output_dir: Path,
) -> None:
    output_dir = Path(output_dir)
    lines = ["# Audit Report", ""]
    if snapshot.os_release:
        lines.append(f"**OS:** {snapshot.os_release.pretty_name or snapshot.os_release.name}")
        lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    n_added = len(snapshot.rpm.packages_added) if snapshot.rpm else 0
    n_removed = len(snapshot.rpm.packages_removed) if snapshot.rpm else 0
    n_modified = len(snapshot.rpm.packages_modified) if snapshot.rpm else 0
    no_baseline = getattr(snapshot.rpm, "no_baseline", False) if snapshot.rpm else False
    n_config = len(snapshot.config.files) if snapshot.config else 0
    n_redactions = len(snapshot.redactions)
    n_containers = 0
    if snapshot.containers:
        n_containers = len(snapshot.containers.quadlet_units or []) + len(snapshot.containers.compose_files or [])

    triage = compute_triage(snapshot, output_dir)
    lines.append(f"**{triage['automatic']}** items handled automatically &nbsp;|&nbsp; "
                 f"**{triage['fixme']}** items with FIXME (need review) &nbsp;|&nbsp; "
                 f"**{triage['manual']}** items need manual intervention")
    lines.append("")
    if no_baseline:
        lines.append(f"- Packages (no baseline — all installed): {n_added}")
    else:
        lines.append(f"- Packages added (beyond baseline): {n_added}")
    lines.append(f"- Packages removed: {n_removed}")
    if n_modified:
        lines.append(f"- Packages with modified configs: {n_modified}")
    lines.append(f"- Config files captured: {n_config}")
    lines.append(f"- Containers/quadlet found: {n_containers}")
    lines.append(f"- Secrets redacted: {n_redactions}")
    lines.append("")

    if snapshot.rpm:
        lines.append("## RPM / Packages")
        lines.append("")
        if snapshot.rpm.no_baseline:
            lines.append("*No baseline — showing all packages.*")
            lines.append("")
        elif snapshot.rpm.baseline_package_names:
            lines.append(f"Baseline: {len(snapshot.rpm.baseline_package_names)} packages from detected profile.")
            lines.append("")
        lines.append("### Added")
        for p in snapshot.rpm.packages_added[:50]:
            lines.append(f"- {p.name} {p.version}-{p.release}.{p.arch}")
        if len(snapshot.rpm.packages_added) > 50:
            lines.append(f"- ... and {len(snapshot.rpm.packages_added) - 50} more")
        lines.append("")
        if snapshot.rpm.packages_removed:
            lines.append("### Removed (from baseline)")
            for p in snapshot.rpm.packages_removed:
                lines.append(f"- {p.name}")
            lines.append("")
        if snapshot.rpm.packages_modified:
            lines.append("### Modified (config changes detected by rpm -Va)")
            for p in snapshot.rpm.packages_modified:
                lines.append(f"- {p.name} {p.version}-{p.release}.{p.arch}")
            lines.append("")
        if snapshot.rpm.rpm_va:
            lines.append("### Modified file details (rpm -Va)")
            for e in snapshot.rpm.rpm_va:
                lines.append(f"- `{e.path}` ({e.flags})")
            lines.append("")
        if snapshot.rpm.dnf_history_removed:
            lines.append("### Previously installed then removed (dnf history)")
            lines.append("")
            lines.append("These packages were installed and later removed. They may have left behind config files or state.")
            lines.append("")
            for name in snapshot.rpm.dnf_history_removed[:30]:
                lines.append(f"- {name}")
            if len(snapshot.rpm.dnf_history_removed) > 30:
                lines.append(f"- ... and {len(snapshot.rpm.dnf_history_removed) - 30} more")
            lines.append("")

    if snapshot.services and snapshot.services.state_changes:
        service_rows = [s for s in snapshot.services.state_changes if s.action != "unchanged"]
        if service_rows:
            lines.append("## Services")
            lines.append("")
            lines.append("| Unit | Current | Default | Action |")
            lines.append("|------|---------|---------|--------|")
            for s in service_rows:
                lines.append(f"| {s.unit} | {s.current_state} | {s.default_state} | {s.action} |")
            lines.append("")

    if snapshot.config and snapshot.config.files:
        lines.append("## Configuration Files")
        lines.append("")
        modified = [f for f in snapshot.config.files if f.kind == ConfigFileKind.RPM_OWNED_MODIFIED]
        unowned = [f for f in snapshot.config.files if f.kind == ConfigFileKind.UNOWNED]
        orphaned = [f for f in snapshot.config.files if f.kind == ConfigFileKind.ORPHANED]
        lines.append(f"- RPM-owned modified: {len(modified)}")
        lines.append(f"- Unowned: {len(unowned)}")
        if orphaned:
            lines.append(f"- Orphaned (from removed packages): {len(orphaned)}")
        for f in snapshot.config.files:
            flags_note = f" — rpm -Va flags: `{f.rpm_va_flags}`" if f.rpm_va_flags else ""
            pkg_note = f" (package: {f.package})" if f.package else ""
            lines.append(f"- `{f.path}` ({f.kind.value}{flags_note}{pkg_note})")
            if f.diff_against_rpm and f.diff_against_rpm.strip():
                lines.append("  Diff against RPM default:")
                lines.append("```diff")
                lines.append(f.diff_against_rpm.strip())
                lines.append("```")
                lines.append("")
        lines.append("")

    has_network = snapshot.network and (
        snapshot.network.connections or snapshot.network.firewall_zones
        or snapshot.network.static_routes or snapshot.network.proxy
        or snapshot.network.hosts_additions
    )
    if has_network:
        lines.append("## Network")
        lines.append("")
        if snapshot.network.connections:
            lines.append("### Connections")
            for c in snapshot.network.connections:
                path = (c.get("path") or c.get("name") or "")
                lines.append(f"- `{path}`")
            lines.append("")
        if snapshot.network.firewall_zones:
            lines.append("### Firewall")
            for z in snapshot.network.firewall_zones:
                label = (z.get("name") or z.get("path") or "") if isinstance(z, dict) else str(z)
                lines.append(f"- {label}")
            lines.append("")
        if snapshot.network.static_routes:
            lines.append("### Static routes")
            for r in snapshot.network.static_routes:
                lines.append(f"- `{r.get('path') or r.get('name') or ''}`")
            lines.append("")
        if snapshot.network.hosts_additions:
            lines.append("### /etc/hosts additions")
            for h in snapshot.network.hosts_additions:
                lines.append(f"- `{h}`")
            lines.append("")
        if snapshot.network.proxy:
            lines.append("### Proxy configuration")
            for p in snapshot.network.proxy:
                lines.append(f"- {p.get('source') or ''}: `{p.get('line') or ''}`")
            lines.append("")

    if snapshot.storage and (snapshot.storage.fstab_entries or snapshot.storage.mount_points or snapshot.storage.lvm_info):
        lines.append("## Storage Migration Plan")
        lines.append("")
        lines.append("Each mount point below should be mapped to one of:")
        lines.append("- **Image-embedded** — small, static data seeded at initial bootstrap")
        lines.append("- **PVC / volume mount** — application data, databases")
        lines.append("- **External storage** — NFS/CIFS shared filesystems")
        lines.append("")
        if snapshot.storage.fstab_entries:
            lines.append("| Device | Mount Point | FS Type | Recommendation |")
            lines.append("|--------|-------------|---------|----------------|")
            for e in (snapshot.storage.fstab_entries or [])[:30]:
                dev = e.get("device") or ""
                mp = e.get("mount_point") or ""
                fs = e.get("fstype") or ""
                rec = "review"
                if any(k in mp for k in ("/var/lib", "/var/log", "/var/data")):
                    rec = "PVC / volume mount"
                elif "nfs" in fs.lower() or "cifs" in fs.lower():
                    rec = "external storage"
                elif mp in ("/", "/boot", "/boot/efi"):
                    rec = "image-embedded (default)"
                lines.append(f"| `{dev}` | `{mp}` | {fs} | {rec} |")
            lines.append("")
        if snapshot.storage.lvm_info:
            lines.append("### LVM Layout")
            for lv in (snapshot.storage.lvm_info or [])[:20]:
                lines.append(f"- {lv}")
            lines.append("")

    if snapshot.scheduled_tasks and (snapshot.scheduled_tasks.cron_jobs or snapshot.scheduled_tasks.systemd_timers or snapshot.scheduled_tasks.generated_timer_units):
        lines.append("## Scheduled tasks")
        lines.append("")
        for j in (snapshot.scheduled_tasks.cron_jobs or [])[:20]:
            lines.append(f"- Cron: `{j.get('path') or ''}` ({j.get('source') or ''})")
        for t in (snapshot.scheduled_tasks.systemd_timers or [])[:20]:
            label = (t.get("name") or t.get("path") or str(t)) if isinstance(t, dict) else str(t)
            lines.append(f"- Timer: {label}")
        for u in (snapshot.scheduled_tasks.generated_timer_units or [])[:20]:
            lines.append(f"- Generated: {u.get('name') or ''} (from {u.get('source_path') or ''})")
        lines.append("")

    if snapshot.containers and (snapshot.containers.quadlet_units or snapshot.containers.compose_files or snapshot.containers.running_containers):
        lines.append("## Container workloads")
        lines.append("")
        for u in (snapshot.containers.quadlet_units or []):
            lines.append(f"- Quadlet: `{u.get('path') or u.get('name') or ''}`")
        for c in (snapshot.containers.compose_files or []):
            lines.append(f"- Compose: `{c.get('path') or ''}`")
        for r in (snapshot.containers.running_containers or []):
            lines.append(f"- Running: {r.get('id') or ''} {r.get('image') or ''} {r.get('status') or ''}")
        lines.append("")

    if snapshot.non_rpm_software and snapshot.non_rpm_software.items:
        lines.append("## Non-RPM software")
        lines.append("")
        lines.append("| Path / Name | Version | Confidence | Method |")
        lines.append("|-------------|---------|------------|--------|")
        for i in snapshot.non_rpm_software.items[:30]:
            pn = (i.get('path') or i.get('name') or '')
            ver = (i.get('version') or '—')
            conf = (i.get('confidence') or 'unknown')
            method = (i.get('method') or '—')
            lines.append(f"| `{pn}` | {ver} | {conf} | {method} |")
        lines.append("")

    has_kernel = snapshot.kernel_boot and (
        snapshot.kernel_boot.cmdline or snapshot.kernel_boot.sysctl_overrides
        or snapshot.kernel_boot.modules_load_d or snapshot.kernel_boot.modprobe_d
        or snapshot.kernel_boot.dracut_conf
    )
    if has_kernel:
        lines.append("## Kernel and boot")
        lines.append("")
        if snapshot.kernel_boot.cmdline:
            lines.append(f"- cmdline: `{snapshot.kernel_boot.cmdline[:200]}`")
        if snapshot.kernel_boot.grub_defaults:
            lines.append(f"- GRUB defaults present")
        for s in (snapshot.kernel_boot.sysctl_overrides or [])[:20]:
            lines.append(f"- sysctl: `{s.get('path') or ''}`")
        for m in (snapshot.kernel_boot.modules_load_d or [])[:20]:
            lines.append(f"- modules-load.d: `{m}`")
        for m in (snapshot.kernel_boot.modprobe_d or [])[:20]:
            lines.append(f"- modprobe.d: `{m}`")
        for d in (snapshot.kernel_boot.dracut_conf or [])[:20]:
            lines.append(f"- dracut: `{d}`")
        lines.append("")

    has_selinux = snapshot.selinux and (
        snapshot.selinux.mode or snapshot.selinux.custom_modules
        or snapshot.selinux.boolean_overrides or snapshot.selinux.audit_rules
        or snapshot.selinux.fips_mode or snapshot.selinux.pam_configs
    )
    if has_selinux:
        lines.append("## SELinux / Security")
        lines.append("")
        if snapshot.selinux.mode:
            lines.append(f"- SELinux mode: {snapshot.selinux.mode}")
        if snapshot.selinux.fips_mode:
            lines.append("- FIPS mode: **enabled**")
        for m in (snapshot.selinux.custom_modules or [])[:20]:
            lines.append(f"- Custom module: `{m}`")
        for b in (snapshot.selinux.boolean_overrides or [])[:20]:
            raw = b.get("raw") or b.get("name") or str(b)
            lines.append(f"- Boolean: `{raw}`")
        if snapshot.selinux.audit_rules:
            lines.append(f"- Audit rule files: {len(snapshot.selinux.audit_rules)}")
            for a in snapshot.selinux.audit_rules[:10]:
                lines.append(f"  - `{a}`")
        if snapshot.selinux.pam_configs:
            lines.append(f"- PAM config files: {len(snapshot.selinux.pam_configs)}")
            for p in snapshot.selinux.pam_configs[:10]:
                lines.append(f"  - `{p}`")
        lines.append("")

    has_users = snapshot.users_groups and (
        snapshot.users_groups.users or snapshot.users_groups.groups
        or snapshot.users_groups.sudoers_rules or snapshot.users_groups.ssh_authorized_keys_refs
    )
    if has_users:
        lines.append("## Users and groups")
        lines.append("")
        for u in (snapshot.users_groups.users or [])[:30]:
            shell = u.get("shell") or ""
            home = u.get("home") or ""
            lines.append(f"- User: **{u.get('name') or ''}** (uid {u.get('uid') or ''}, home `{home}`, shell `{shell}`)")
        for g in (snapshot.users_groups.groups or [])[:30]:
            members = g.get("members") or []
            mem_str = f", members: {', '.join(members)}" if members else ""
            lines.append(f"- Group: **{g.get('name') or ''}** (gid {g.get('gid') or ''}{mem_str})")
        if snapshot.users_groups.sudoers_rules:
            lines.append("")
            lines.append("### Sudoers rules")
            for r in snapshot.users_groups.sudoers_rules[:20]:
                lines.append(f"- `{r}`")
        if snapshot.users_groups.ssh_authorized_keys_refs:
            lines.append("")
            lines.append("### SSH authorized_keys (flagged for manual handling)")
            for ref in snapshot.users_groups.ssh_authorized_keys_refs[:20]:
                lines.append(f"- User **{ref.get('user') or ''}**: `{ref.get('path') or ''}`")
        lines.append("")

    lines.append("## Data Migration Plan (/var)")
    lines.append("")
    lines.append("Content under `/var` is seeded at initial bootstrap and **not updated** by subsequent bootc deployments.")
    lines.append("`tmpfiles.d` snippets ensure expected directories exist on every boot.")
    lines.append("Review application data under `/var/lib`, `/var/log`, `/var/data` for separate migration strategies.")
    lines.append("")

    if snapshot.warnings:
        lines.append("## Items requiring manual intervention")
        lines.append("")
        for w in snapshot.warnings:
            lines.append(f"- {w.get('message') or '—'}")
        lines.append("")

    if snapshot.redactions:
        lines.append("## Redactions (secrets)")
        lines.append("")
        for r in snapshot.redactions:
            lines.append(f"- **{r.get('path') or ''}**: {r.get('pattern') or ''} — {r.get('remediation') or ''}")
        lines.append("")

    (output_dir / "audit-report.md").write_text("\n".join(lines))
