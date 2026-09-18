"""Module B — orchestrate profile, Tor daemon, and optional raw-image analysis."""

from __future__ import annotations

from pathlib import Path

from core.config import TranceConfig
from core.schema import Artifact, ModuleResult

MODULE_NAME = "module_b_disk"


def _profile_artifacts(report: dict) -> list[Artifact]:
    source = report["evidence_dir"]
    artifacts = []
    for item in report["places"].get("user_activity_candidates", []):
        artifacts.append(
            Artifact(
                MODULE_NAME,
                "browser_history",
                source,
                item["url"],
                timestamp=str(item.get("last_visit_date") or "") or None,
            )
        )
    for item in report["cookies"].get("moz_cookies", []):
        artifacts.append(
            Artifact(MODULE_NAME, "browser_cookie", source, f"{item['host']} — {item['name']}")
        )
    for item in report["favicons"].get("non_default_pages", []):
        artifacts.append(Artifact(MODULE_NAME, "favicon_page", source, item))
    for backup in report["bookmark_backups"].get("backups", []):
        for item in backup.get("non_default_bookmarks", []):
            artifacts.append(Artifact(MODULE_NAME, "bookmark", source, item["uri"]))
    return artifacts


def _daemon_artifacts(report: dict) -> list[Artifact]:
    source = report["tor_data_dir"]
    artifacts = []
    for guard in report["state"].get("guards_used", []):
        artifacts.append(
            Artifact(
                MODULE_NAME,
                "tor_guard_usage",
                source,
                f"Guard {guard['nickname']} ({guard['rsa_id']}); use attempts={guard['use_attempts']}",
                timestamp=guard.get("confirmed_on"),
            )
        )
    consensus = report["consensus"]
    if not consensus.get("error"):
        artifacts.append(
            Artifact(
                MODULE_NAME,
                "tor_consensus",
                source,
                f"Cached consensus valid after {consensus['valid_after_utc']}",
                timestamp=consensus.get("file_mtime_utc"),
            )
        )
    for credential in report["onion_auth"].get("credentials", []):
        artifacts.append(
            Artifact(
                MODULE_NAME,
                "onion_client_auth_configuration",
                source,
                f"Client credential configured for {credential['onion_address']}; "
                "this alone does not prove a visit",
                sha256=credential.get("sha256"),
                timestamp=credential.get("mtime_utc"),
            )
        )
    return artifacts


def _carve_artifacts(report: dict) -> list[Artifact]:
    source = report["image"]
    artifacts = []
    for address, hit in report["onion_addresses"].items():
        artifacts.append(
            Artifact(
                MODULE_NAME,
                "carved_onion_string",
                source,
                f"{address}; sampled offsets={hit['first_offsets']}",
                sha256=report["image_sha256"],
            )
        )
    for credential in report["client_auth_credentials"]:
        artifacts.append(
            Artifact(
                MODULE_NAME,
                "carved_onion_client_auth",
                source,
                f"Credential bytes for {credential['onion_address']}; presence alone does not prove a visit",
                sha256=report["image_sha256"],
            )
        )
    return artifacts


def run(
    config: TranceConfig,
    profile_dir: Path | None = None,
    tor_dir: Path | None = None,
    disk_image: Path | None = None,
    **_: object,
) -> ModuleResult:
    if not any((profile_dir, tor_dir, disk_image)):
        return ModuleResult(
            module=MODULE_NAME, status="skipped", message="no disk evidence supplied"
        )

    details: dict[str, dict] = {}
    artifacts: list[Artifact] = []
    errors = []
    if profile_dir:
        try:
            from modules.module_b_disk.recover_evidence import analyze_profile

            details["profile"] = analyze_profile(Path(profile_dir))
            artifacts.extend(_profile_artifacts(details["profile"]))
            if details["profile"]["analysis_status"] != "ok":
                errors.append("profile analysis incomplete")
        except Exception as exc:
            details["profile"] = {"error": f"{type(exc).__name__}: {exc}"}
            errors.append("profile analysis failed")
    if tor_dir:
        try:
            from modules.module_b_disk.analyze_tor_datadir import analyze_tor_directory

            details["tor_daemon"] = analyze_tor_directory(Path(tor_dir))
            artifacts.extend(_daemon_artifacts(details["tor_daemon"]))
            if details["tor_daemon"]["analysis_status"] != "ok":
                errors.append("Tor daemon analysis incomplete")
        except Exception as exc:
            details["tor_daemon"] = {"error": f"{type(exc).__name__}: {exc}"}
            errors.append("Tor daemon analysis failed")
    if disk_image:
        try:
            from modules.module_b_disk.carve_onion_strings import scan

            image = Path(disk_image).resolve(strict=True)
            if not image.is_file():
                raise ValueError(f"not a regular file: {image}")
            details["raw_carve"] = scan(image, [])
            artifacts.extend(_carve_artifacts(details["raw_carve"]))
        except Exception as exc:
            details["raw_carve"] = {"error": f"{type(exc).__name__}: {exc}"}
            errors.append("raw-image carve failed")
    return ModuleResult(
        module=MODULE_NAME,
        status="error" if errors else "ok",
        artifacts=artifacts,
        details=details,
        message="; ".join(errors) if errors else None,
    )
