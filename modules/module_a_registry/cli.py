"""Standalone CLI entrypoint for Module A.

Per Module A Description 2.4 ("Independent testability"): Module A has its
own CLI entrypoint and can be run and evaluated without Modules B or C
present, supporting parallel development across the team. This is that
entrypoint — it does not depend on any Module B/C code.

Usage:
    python -m modules.module_a_registry.cli \\
        --case-name CASE01 --output-dir ./out \\
        --ntuser ./evidence/NTUSER.DAT \\
        --system ./evidence/SYSTEM \\
        --amcache ./evidence/Amcache.hve
"""

from __future__ import annotations

from pathlib import Path

import click

from core.config import TranceConfig

from .pipeline import run_module_a, write_output


@click.command()
@click.option("--case-name", required=True, help="Case identifier, used for logging/output naming.")
@click.option(
    "--output-dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory to write module_a_registry.json and the chain-of-custody log to.",
)
@click.option(
    "--ntuser",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to an acquired NTUSER.DAT hive (feeds UserAssist and RecentDocs).",
)
@click.option(
    "--system",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to an acquired SYSTEM hive (feeds ShimCache/AppCompatCache).",
)
@click.option(
    "--amcache",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to an acquired Amcache.hve hive.",
)
def main(
    case_name: str, output_dir: Path, ntuser: Path | None, system: Path | None, amcache: Path | None
) -> None:
    """Run Module A (Registry & Execution Evidence) against one or more acquired hives."""
    if not any([ntuser, system, amcache]):
        raise click.UsageError("At least one of --ntuser, --system, or --amcache must be provided.")

    output_dir.mkdir(parents=True, exist_ok=True)
    config = TranceConfig(case_name=case_name, output_dir=output_dir)

    result = run_module_a(config, ntuser=ntuser, system=system, amcache=amcache)
    output_path = write_output(result, output_dir / "module_a_registry.json")

    click.echo(f"Module A complete: {len(result.findings)} Tor-related finding(s).")
    click.echo(f"Summary: {result.summary}")
    click.echo(f"Output written to: {output_path}")
    click.echo(f"Chain-of-custody log: {result.custody_log_path}")

    if result.errors:
        click.echo(f"Encountered {len(result.errors)} extraction error(s):", err=True)
        for err in result.errors:
            click.echo(f"  - {err}", err=True)


if __name__ == "__main__":
    main()
