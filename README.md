# rhel2bootc

Inspect RHEL/CentOS hosts and produce bootc image artifacts (Containerfile, config tree, audit report, etc.).

## Architecture

- **Inspectors** run against a host root (default `/host`) and produce structured JSON (the inspection snapshot).
- **Renderers** consume the snapshot and produce output artifacts (Containerfile, markdown report, HTML report, etc.).

## Usage

All renderers write to the **output directory**, which is created if it does not exist. Default: `./rhel2bootc-output`.

```bash
# Inspect host mounted at /host, write to default ./rhel2bootc-output
rhel2bootc

# Specify output directory
rhel2bootc --output-dir ./my-output
# or: rhel2bootc -o ./my-output

# Save snapshot only (no render)
rhel2bootc --inspect-only -o ./out

# Render from existing snapshot
rhel2bootc --from-snapshot ./out/inspection-snapshot.json -o ./rendered
```

## Development

```bash
pip install -e .
rhel2bootc --help
pytest
```

## Container

Build the tool image:

```bash
podman build -t rhel2bootc .
```

Run it against a host. **Typically you run the container on the host you are inspecting**, so both the host root and the output directory are bind-mounted from that same host. The tool reads the host via `/host` and writes artifacts to `--output-dir`; with the mount below, those artifacts end up on the host at `./rhel2bootc-output`.

```bash
# On the host being inspected: mount its root at /host and a directory on the host for output
podman run --rm \
  -v /:/host:ro \
  -v ./rhel2bootc-output:/output \
  rhel2bootc --output-dir /output
```

After the run, `./rhel2bootc-output` on the host contains the Containerfile, config tree, reports, and snapshot. You can then copy that directory off the host or push it to GitHub with `--push-to-github`. The HTML report (`report.html`) is **self-contained and portable**: all content is embedded, so you can share or archive that file alone.

---

## Inspectors

Each inspector examines one aspect of the host and contributes a section to the inspection snapshot.

### RPM / Packages

- Full package inventory via `rpm -qa` with epoch/version/release/arch
- Dynamic baseline from comps XML — diffs installed packages against the expected set for the detected profile (`@server`, `@minimal`, etc.)
- Modified config detection via `rpm -Va` with verification flags
- Unowned file detection using bulk `rpm -qla` set subtraction (fast, avoids per-file lookups)
- `dnf history` analysis for packages that were installed then removed (orphaned configs)
- Repo file capture from `/etc/yum.repos.d/`
- Optional line-by-line diffs against RPM defaults (`--config-diffs`)

### Services

- Enabled/disabled/masked unit state from `systemctl list-unit-files`
- Diff against systemd preset defaults
- State change actions generated for the Containerfile (`systemctl enable`/`disable`)

### Configuration Files

- RPM-owned modified files (from `rpm -Va`)
- Unowned files in `/etc` (hand-placed configs)
- Orphaned configs from removed packages
- Sensitive content detection and automatic redaction

### Network

- NetworkManager connection profiles classified as **static** (bake into image) or **DHCP** (kickstart at deploy)
- Firewalld zone parsing: services, ports, and rich rules from zone XML
- Firewalld direct rules from `direct.xml`
- `resolv.conf` provenance detection: systemd-resolved, NetworkManager-managed, or hand-edited
- `ip route` and `ip rule` capture with default rule filtering
- `/etc/hosts` additions and proxy settings

### Storage

- `/etc/fstab` parsing
- LVM layout detection

### Scheduled Tasks

- Cron jobs from `/etc/cron.d`, `/etc/crontab`, periodic dirs, and user spool
- Automatic cron-to-systemd timer conversion (generates `.timer` + `.service` units)
- Existing systemd timer scanning from `/etc/systemd/system` (local) and `/usr/lib/systemd/system` (vendor) with `OnCalendar` and `ExecStart` extraction
- `at` job parsing: extracts actual command, user, and working directory from spool files

### Containers

- Quadlet `.container` unit discovery with `Image=` reference extraction
- Compose file discovery with per-service `image:` field parsing (no PyYAML dependency)
- Optional live container enumeration via `podman ps` + `podman inspect` (`--query-podman`): captures mounts, network settings, ports, and environment variables

### Non-RPM Software

- **readelf-based binary classification**: detects Go (`.note.go.buildid`), Rust (`.rustc`), and C/C++ binaries with static/dynamic linking and shared library enumeration
- **Python venv detection**: discovers venvs via `pyvenv.cfg`, flags `--system-site-packages`, scans dist-info and `pip list --path` for package inventories
- **pip dist-info scanning**: system-level pip packages with name and version
- **npm/yarn/gem lockfile detection**: captures lockfiles for reproducible installs
- **Git repository detection**: captures remote URL, branch, and commit hash for directories under `/opt` and `/usr/local`
- Optional deep binary strings scan for version extraction (`--deep-binary-scan`)

### Kernel & Boot

- `/proc/cmdline` and GRUB defaults
- `lsmod` parsing with module classification: default (from `modules-load.d`), configured, dependency, or non-default
- Runtime sysctl values from `/proc/sys` diffed against shipped defaults in `/usr/lib/sysctl.d` with source attribution
- `modules-load.d`, `modprobe.d`, and dracut configuration capture

### SELinux

- Mode detection (enforcing/permissive/disabled)
- Custom module discovery via `semodule -l` cross-referenced with priority-400 module store
- Non-default boolean identification via `semanage boolean -l` current vs. default comparison
- Audit rules and `fcontext` capture

### Users & Groups

- Non-system users and groups (UID/GID >= 1000)
- SSH authorized key references (paths only, not key material)
- Home directory detection

---

## Output Artifacts

| File | Description |
|------|-------------|
| `Containerfile` | Layered image definition with correct ordering for cache efficiency |
| `config/` | Config file tree preserving original paths, ready for `COPY` |
| `quadlet/` | Quadlet unit files for container workloads |
| `audit-report.md` | Detailed markdown report with triage breakdown |
| `report.html` | Self-contained interactive HTML dashboard |
| `README.md` | Build instructions, `podman build` command, `bootc switch` command, FIXME checklist |
| `kickstart-suggestion.ks` | Kickstart fragment for deploy-time config (DHCP, hostname, etc.) |
| `secrets-review.md` | List of redacted sensitive content for operator review |
| `inspection-snapshot.json` | Full structured snapshot (re-renderable with `--from-snapshot`) |

---

## CLI Reference

### Core Options

| Flag | Description |
|------|-------------|
| `--host-root PATH` | Root path for host inspection (default: `/host`) |
| `-o, --output-dir DIR` | Output directory for all artifacts (default: `./rhel2bootc-output`) |
| `--from-snapshot PATH` | Skip inspection; load snapshot from file and run renderers only |
| `--inspect-only` | Run inspectors and save snapshot; do not run renderers |

### Inspection Options

| Flag | Description |
|------|-------------|
| `--comps-file FILE` | Path to local comps XML for baseline generation (air-gapped environments) |
| `--profile NAME` | Override install profile for baseline (e.g. `server`, `minimal`, `workstation`); bypasses kickstart auto-detection |
| `--config-diffs` | Generate line-by-line diffs for modified configs via `rpm2cpio` |
| `--deep-binary-scan` | Full `strings` scan on unknown binaries for version detection (slow) |
| `--query-podman` | Connect to podman to enumerate running containers with full inspect data |

### Output Options

| Flag | Description |
|------|-------------|
| `--validate` | After generating output, run `podman build` to verify the Containerfile |
| `--push-to-github REPO` | Push output directory to a GitHub repository (e.g. `owner/repo`) |
| `--public` | When creating a new GitHub repo, make it public (default: private) |
| `--yes` | Skip interactive confirmation prompts |

---

## Containerfile Layer Ordering

The generated Containerfile follows a deliberate layer order optimized for build cache efficiency — layers that change least frequently come first:

1. **Base image** — auto-detected from `/etc/os-release`
2. **Repo files** — custom yum/dnf repositories
3. **Packages** — `dnf install` for added packages, `dnf remove` for removed
4. **Services** — `systemctl enable/disable`
5. **Firewall** — zone files, direct rules
6. **Scheduled tasks** — timer units (local + cron-converted), at job FIXMEs
7. **Config files** — all captured configs via `COPY config/`
8. **Non-RPM software** — provenance-aware: `pip install` for pip, `npm ci` for npm, FIXME for Go/Rust binaries, `git clone` comments for git repos
9. **Container workloads** — quadlet units
10. **Users & groups** — `useradd`/`groupadd`
11. **Kernel** — sysctl overrides, module notes
12. **SELinux** — booleans, custom modules
13. **Network** — static connection profiles, resolv.conf notes
14. **tmpfiles.d** — transient file/directory setup

---

## Baseline Generation

The tool dynamically generates a package baseline by fetching the distribution's **comps XML** from configured repositories. It detects the installed profile (e.g., `@server`, `@workstation`) from kickstart files or falls back to `@minimal`, then recursively resolves all mandatory and default packages from the group dependency chain.

**Fallback behavior:**

- **No profile detected** — falls back to `@minimal` with a warning
- **No network / no comps available** — enters "all-packages mode" where every installed package is treated as operator-added (no baseline subtraction), with a clear warning in the reports
- **Air-gapped environments** — use `--comps-file` to provide a local comps XML, bypassing all network access

**Profile detection and SELinux:** The tool auto-detects the install profile from `/root/anaconda-ks.cfg`. When running in a container, SELinux may prevent access to `/host/root/` even with `:ro` bind mounts. If you see the "Could not determine original install profile" warning, you have two options:

- Use `--profile server` (or `minimal`, `workstation`, etc.) to specify the profile directly
- Add `--security-opt label=disable` to the `podman run` command to allow full host filesystem access

The resolved baseline is cached in the inspection snapshot, so `--from-snapshot` re-renders work without network access.
