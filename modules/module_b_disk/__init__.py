"""Module B — orchestrate profile, Tor daemon, and optional raw-image analysis."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from core.config import TranceConfig
from core.schema import Artifact, ModuleResult

MODULE_NAME = "module_b_disk"


def _parse_utc(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def daemon_window(daemon: dict) -> dict | None:
    """Bound the last Tor session: lock creation to the newest daemon write."""
    start = _parse_utc(daemon.get("daemon_start_utc"))
    ends = [_parse_utc(v) for v in daemon.get("file_mtimes_utc", {}).values()]
    ends.append(_parse_utc(daemon.get("state", {}).get("last_written_utc")))
    ends = [e for e in ends if e]
    if not start or not ends:
        return None
    return {"start_utc": start.isoformat(), "end_utc": max(ends).isoformat()}


def correlate_downloads(scan: dict, window: dict | None) -> dict:
    """Flag each internet-origin file as inside or outside the Tor daemon window."""
    start = _parse_utc(window["start_utc"]) if window else None
    end = _parse_utc(window["end_utc"]) if window else None
    for hit in scan["internet_origin_files"]:
        stamps = hit["timestamps"]
        created = _parse_utc(stamps["created_utc"] or stamps["modified_utc"])
        if not (start and end and created):
            hit["within_tor_daemon_window"] = None
        else:
            hit["within_tor_daemon_window"] = start <= created <= end
    scan["tor_daemon_window"] = window
    scan["note"] = (
        "Zone.Identifier proves network origin, not the source URL: Tor Browser omits "
        "HostUrl/ReferrerUrl by design. Only the last Tor session's window is recoverable "
        "from daemon artifacts; earlier sessions are overwritten."
    )
    return scan


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
    for item in report["places"].get("downloads", []):
        artifacts.append(
            Artifact(
                MODULE_NAME,
                "browser_download",
                source,
                f"{item['source_url']} -> {item['destination_file_uri']}",
                timestamp=str(item.get("date_added") or "") or None,
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


def _download_artifacts(scan: dict) -> list[Artifact]:
    source = scan["volume_root"]
    window = scan.get("tor_daemon_window")
    artifacts = []
    for hit in scan["internet_origin_files"]:
        stamps = hit["timestamps"]
        created = stamps["created_utc"] or stamps["modified_utc"]
        within = hit.get("within_tor_daemon_window")
        if within is True:
            correlation = (
                f"created while the Tor daemon was running ({window['start_utc']} to "
                f"{window['end_utc']}); network origin established, source URL not recoverable"
            )
        elif within is False:
            correlation = "created outside the last recorded Tor daemon window"
        else:
            correlation = "no Tor daemon window available for correlation"
        artifacts.append(
            Artifact(
                MODULE_NAME,
                "internet_origin_file",
                source,
                f"{hit['path']}; Zone.Identifier ZoneId={hit['zone_identifier']['zone_id']}; "
                f"{correlation}",
                sha256=hit["sha256"],
                timestamp=created,
            )
        )
    return artifacts


def run(
    config: TranceConfig,
    profile_dir: Path | None = None,
    tor_dir: Path | None = None,
    disk_image: Path | None = None,
    disk_root: Path | None = None,
    **_: object,
) -> ModuleResult:
    if not any((profile_dir, tor_dir, disk_image, disk_root)):
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
    if disk_root:
        try:
            from modules.module_b_disk.analyze_downloads import scan_volume

            daemon = details.get("tor_daemon", {})
            window = daemon_window(daemon) if not daemon.get("error") else None
            details["downloads"] = correlate_downloads(scan_volume(Path(disk_root)), window)
            artifacts.extend(_download_artifacts(details["downloads"]))
        except Exception as exc:
            details["downloads"] = {"error": f"{type(exc).__name__}: {exc}"}
            errors.append("volume download scan failed")
    return ModuleResult(
        module=MODULE_NAME,
        status="error" if errors else "ok",
        artifacts=artifacts,
        details=details,
        message="; ".join(errors) if errors else None,
    )
