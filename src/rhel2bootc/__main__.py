"""
CLI entry point. Parses args and delegates to pipeline.
"""

import sys
from pathlib import Path
from typing import Optional

from .cli import parse_args
from .pipeline import run_pipeline
from .schema import InspectionSnapshot


def _run_inspectors(host_root: Path, args) -> InspectionSnapshot:
    """Run all inspectors and merge into one snapshot."""
    from .inspectors import run_all

    return run_all(
        host_root,
        config_diffs=args.config_diffs,
        deep_binary_scan=args.deep_binary_scan,
        query_podman=args.query_podman,
        comps_file=args.comps_file,
        profile_override=args.profile,
    )


def _run_renderers(snapshot: InspectionSnapshot, output_dir: Path) -> None:
    """Run all renderers."""
    from .renderers import run_all

    run_all(snapshot, output_dir)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)
    try:
        def run_inspectors(host_root: Path):
            return _run_inspectors(host_root, args)

        snapshot = run_pipeline(
            host_root=args.host_root,
            output_dir=args.output_dir,
            run_inspectors=run_inspectors,
            run_renderers=_run_renderers,
            from_snapshot_path=args.from_snapshot,
            inspect_only=args.inspect_only,
        )
        if not args.inspect_only and args.output_dir.exists():
            if args.validate:
                from .validate import run_validate
                run_validate(args.output_dir)
            if args.push_to_github:
                from .git_github import init_git_repo, add_and_commit, push_to_github, output_stats
                init_git_repo(args.output_dir)
                add_and_commit(args.output_dir)
                size, file_count, fixme_count = output_stats(args.output_dir)
                err = push_to_github(
                    args.output_dir,
                    args.push_to_github,
                    create_private=not args.public,
                    skip_confirmation=args.yes,
                    total_size_bytes=size,
                    file_count=file_count,
                    fixme_count=fixme_count,
                    redaction_count=len(snapshot.redactions),
                )
                if err:
                    print(f"GitHub push failed: {err}", file=sys.stderr)
                    return 1
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
