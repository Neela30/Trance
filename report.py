"""Render findings.json into TRANCE's single HTML case report. Deterministic, offline, no LLM.

Module-specific presentation (what a module's `details` mean, which values deserve a
table, which caveats apply) lives with that module — see PRESENTERS. A module without a
presenter, or one that didn't run cleanly, gets a generic artifact table plus its status,
so a module plugs into the report by returning artifacts alone and can add a presenter
later without touching this file's rendering.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape

from modules.module_a_registry.report import build_context as registry_context
from modules.module_b_disk.report import build_context as disk_context
from modules.module_c_memory.report import build_context as memory_context

TEMPLATE_DIR = Path(__file__).parent
TEMPLATE_NAME = "report_template.html.j2"
REPORT_FILENAME = "report.html"
GENERIC_TABLE_CAP = 200

PRESENTERS: dict[str, Callable[[dict, str | None], dict]] = {
    "module_a_registry": registry_context,
    "module_b_disk": disk_context,
    "module_c_memory": memory_context,
}


def _format_timestamp(value: str | datetime | None) -> str:
    """One consistent, human-readable rendering for every timestamp the report shows --
    the raw value is either an ISO-8601 string (straight from Artifact.timestamp) or an
    already-parsed datetime (module_a_registry's component-timeline fields), and left to
    each one's own default text form, they used to show up differently (microseconds and
    a "+00:00" offset) depending on which path produced them."""
    if not value:
        return "—"
    dt = value
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return value
    if not isinstance(dt, datetime):
        return str(dt)
    return dt.strftime("%Y-%m-%d %H:%M:%S") + " UTC"


# Registry and memory times for one event agree to the second when they are the same event.
SAME_INSTANT = timedelta(seconds=5)
# A browser process this much older than the last opening the registry records is an earlier run.
EARLIER_RUN = timedelta(seconds=60)


def _relate_processes_to_registry(registry: dict | None, memory: dict | None) -> list[str]:
    """Plain notes juxtaposing Module A's last-opened / last-running times with the browser
    processes Volatility3 found in memory -- the two are independent evidence, so where they
    meet the report says so (and where memory shows more, it says that). Not a merge or a
    score: each note names both sources."""
    if not registry or not memory:
        return []
    activity = (memory.get("volatility3") or {}).get("process_activity") or {}
    if not activity.get("groups"):
        return []
    components = registry.get("component_timeline") or []
    firefox = next((c for c in components if c.get("basename") == "firefox.exe"), None)
    component = firefox or (components[0] if components else {})
    opened = component.get("userassist_last_run")
    last_running = component.get("bam_last_run")
    notes = []
    if opened:
        earlier = [g for g in activity["groups"] if g["first_start"] < opened - EARLIER_RUN]
        if earlier:
            started = min(g["first_start"] for g in earlier)
            note = (
                f"Tor Browser processes in memory started at {_format_timestamp(started)}, "
                f"before the last opening the registry records ({_format_timestamp(opened)}): "
                "Tor Browser also ran earlier than that"
            )
            if not any(g["still_running"] for g in earlier):
                ended = max(g["last_exit"] for g in earlier)
                note += f" (those processes had all exited by {_format_timestamp(ended)})"
            notes.append(note + ".")
    if last_running:
        for exited, pid, name in activity.get("exits", []):
            if name == "firefox.exe" and abs(exited - last_running) <= SAME_INSTANT:
                notes.append(
                    f"The registry's last-recorded-running time ({_format_timestamp(last_running)}) "
                    f"matches firefox.exe (PID {pid}) exiting at {_format_timestamp(exited)} in "
                    "memory: it marks when that run ended, not a new opening."
                )
                break
    return notes


def _wrap_path(value: str | None) -> Markup:
    """Lets a long file path wrap only at its own separators, never mid-word. The CSS
    alternative (`overflow-wrap: anywhere`) breaks a path at ANY character -- the exact
    cause of paths rendering as "C:\\Users\\Adm" / "in" across a line. Escapes the value
    itself (autoescape is on, but this filter's own <wbr> insertion means Jinja would
    otherwise treat the whole result as pre-escaped markup) and inserts a <wbr> -- a
    zero-width, invisible "it's OK to break here" hint -- after every backslash and
    forward slash, so the browser only ever wraps at a real path separator."""
    if not value:
        return Markup("—")
    escaped = str(escape(value))
    wrapped = re.sub(r"([\\/])", r"\1<wbr>", escaped)
    return Markup(wrapped)


def _resolve_local_tz(local_tz: str | None) -> str | None:
    """None means "auto-detect" -- resolved once here (not in core.config.TranceConfig)
    so a config built once and reused doesn't freeze in a stale "current machine" guess.
    Falls back to no local time at all (UTC-only display) if tzlocal can't determine the
    machine's zone, rather than failing the whole report over a timezone nicety."""
    if local_tz:
        return local_tz
    try:
        import tzlocal

        return tzlocal.get_localzone_name()
    except Exception:
        return None


def render_report(findings: dict, local_tz: str | None = None) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        # Not select_autoescape(["html"]): it decides by filename suffix and this template
        # is *.html.j2, which wouldn't match. It only ever renders HTML, so escape always.
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["fmt_ts"] = _format_timestamp
    env.filters["wrap_path"] = _wrap_path
    template = env.get_template(TEMPLATE_NAME)

    resolved_tz = _resolve_local_tz(local_tz)

    presented: dict[str, dict] = {}
    generic: list[dict] = []
    for name, module in findings["modules"].items():
        presenter = PRESENTERS.get(name)
        # "partial" (some extractors/sub-analyses failed, others didn't) still gets the
        # module's full presenter -- narrative, tables, everything -- same as "ok". Only
        # "error" (nothing in this module can be trusted -- e.g. an integrity hash
        # mismatch) falls back to the generic table below. This is the fix for one failed
        # extractor silently discarding every OTHER artifact type's real findings from
        # the report (status used to be a strict binary, so any failure looked identical
        # to a whole-module failure here).
        if presenter and module["status"] in ("ok", "partial"):
            presented[name] = presenter(module["details"], resolved_tz)
            presented[name]["module_status"] = module["status"]
            continue
        artifacts = [a for a in findings["artifacts"] if a["module"] == name]
        generic.append(
            {
                "name": name,
                "status": module["status"],
                "message": module["message"],
                "warnings": module.get("warnings", []),
                "artifacts": artifacts[:GENERIC_TABLE_CAP],
                "total": len(artifacts),
            }
        )

    # Every present module may contribute its own glossary dict (see Module A's
    # narrative.py for the reference shape); merged once here so a term defined by more
    # than one module (e.g. "UTC") only appears once, alphabetically, at the bottom of
    # the whole report rather than repeated per module section.
    memory_context = presented.get("module_c_memory")
    if memory_context is not None:
        memory_context["process_registry_notes"] = _relate_processes_to_registry(
            presented.get("module_a_registry"), memory_context
        )

    glossary: dict[str, str] = {}
    for context in presented.values():
        glossary.update(context.get("glossary", {}))

    return template.render(
        findings=findings,
        registry=presented.get("module_a_registry"),
        disk=presented.get("module_b_disk"),
        memory=presented.get("module_c_memory"),
        generic_modules=generic,
        glossary=sorted(glossary.items()),
    )


def write_report(findings: dict, output_dir: Path, local_tz: str | None = None) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / REPORT_FILENAME
    path.write_text(render_report(findings, local_tz), encoding="utf-8")
    return path
