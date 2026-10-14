"""Render findings.json into TRANCE's single HTML case report. Deterministic, offline, no LLM.

Module-specific presentation (what a module's `details` mean, which values deserve a
table, which caveats apply) lives with that module — see PRESENTERS. A module without a
presenter, or one that didn't run cleanly, gets a generic artifact table plus its status,
so a module plugs into the report by returning artifacts alone and can add a presenter
later without touching this file's rendering.
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape

from core.config import CASE_INFO_FIELDS
from modules.module_a_registry.report import build_context as registry_context
from modules.module_b_disk.report import build_context as disk_context
from modules.module_c_memory.report import build_context as memory_context

TEMPLATE_DIR = Path(__file__).parent
TEMPLATE_NAME = "report_template.html.j2"
REPORT_FILENAME = "report.html"
EXHIBIT_LIST_FILENAME = "exhibit_list.html"

# A one-page list of the evidence for filing with the court (Evidence (Special Provisions)
# Act No. 14 of 1995, s.7). Inline so packaging needs no second template file.
EXHIBIT_LIST_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Exhibit list · {{ case.name }}</title>
<style>
  @page { size: A4; margin: 18mm 14mm 20mm; }
  body { font: 10.5pt/1.45 system-ui, sans-serif; color: #111518; background: #fff; margin: 24px; }
  h1 { font-size: 18pt; margin: 0 0 4px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 14px; margin: 12px 0; }
  dt { color: #4a535c; }
  table { border-collapse: collapse; width: 100%; margin-top: 12px; }
  th, td { border-bottom: 1px solid #b9c0bf; padding: 6px 6px; text-align: left; vertical-align: top; }
  th { font-size: 9pt; text-transform: uppercase; letter-spacing: .04em; color: #4a535c; }
  .mono { font-family: ui-monospace, monospace; font-size: 8.5pt; word-break: break-all; }
  .note { color: #4a535c; font-size: 9.5pt; }
</style></head><body>
<h1>List of evidence</h1>
<p class="note">Evidence (Special Provisions) Act No. 14 of 1995, section 7 · produced by TRANCE</p>
<dl>
  <dt>Case</dt><dd>{{ case.name }}</dd>
  {% if case.evidence_dir %}<dt>Evidence folder</dt><dd class="mono">{{ case.evidence_dir }}</dd>{% endif %}
  {% for key, label in labels if info[key] %}<dt>{{ label }}</dt><dd>{{ info[key] }}</dd>{% endfor %}
  <dt>Report generated</dt><dd>{{ generated_at }}</dd>
</dl>
<table>
  <thead><tr><th>Exhibit</th><th>Description</th><th>File</th><th>Size</th><th>SHA-256</th><th>Check</th></tr></thead>
  <tbody>
  {% for row in rows %}
    <tr><td class="mono" style="white-space:nowrap;">{{ row.exhibit }}</td><td>{{ row.label }}{% if row.note %}<div class="note">{{ row.note }}</div>{% endif %}</td>
    <td class="mono">{{ row.path|relative_to(case.evidence_dir) }}</td><td style="white-space:nowrap;">{{ row.size_bytes|fmt_bytes }}</td>
    <td class="mono">{{ row.sha256 or "per file, in findings.json" }}</td><td>{{ checks.get(row.status, row.status) }}</td></tr>
  {% endfor %}
  </tbody>
</table>
<p class="note">Every SHA-256 was checked against the hash recorded when the evidence was acquired.
Copies of the exhibits are available on request. Prepared from findings.json{% if findings_sha256 %}
(SHA-256 <span class="mono">{{ findings_sha256 }}</span>){% endif %}.</p>
</body></html>
"""
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


def _relative_to(value: str | None, base: str | None) -> str | None:
    """An evidence path shown under the report's "Evidence dir" (already in the header)
    rather than repeating that whole prefix on every row; unchanged when outside it."""
    if not value or not base:
        return value
    try:
        return Path(value).relative_to(Path(base)).as_posix()
    except ValueError:
        return value


def _css_string(value: object) -> Markup:
    """A quoted CSS string literal for the print stylesheet's page headers. Escapes the
    quote and backslash, and writes "<" as a CSS escape so no value can close <style>."""
    text = str(value)
    escaped = "".join(f"\\{ord(c):x} " if c in '"\\<>&\n\r' else c for c in text)
    return Markup(f'"{escaped}"')


_SECRET_FIELD_RE = re.compile(r"pass|pwd|secret|token|key|pin", re.IGNORECASE)


def _mask(value: object) -> str:
    """A secret shortened for print (data minimisation): enough to match it against the
    full value in findings.json, not enough to reuse it."""
    text = str(value or "")
    if len(text) <= 6:
        return f"•••• ({len(text)} chars)"
    return f"{text[:2]}…{text[-2:]} ({len(text)} chars)"


def _is_secret_field(name: object) -> bool:
    return bool(_SECRET_FIELD_RE.search(str(name or "")))


def _format_bytes(value: int | None) -> str:
    if value is None:
        return "—"
    size = float(value)
    for unit in ("bytes", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{value:,} bytes" if unit == "bytes" else f"{size:,.1f} {unit}"
        size /= 1024
    return f"{value:,} bytes"


# Known limits of each analysis method, stated whenever that module contributed.
METHOD_LIMITS = {
    "module_a_registry": (
        (
            "Registry evidence records that programs ran and folders were opened, not what was "
            "done inside Tor Browser. Several registry timestamps are the last write of a key "
            "shared by many entries, not the time of one event; the report says so where it applies."
        ),
    ),
    "module_b_disk": (
        (
            "Tor Browser keeps no browsing history by design, so an empty profile is expected and "
            "is not evidence that the browser was unused."
        ),
        (
            "A file's internet-origin mark (Zone.Identifier) shows it was downloaded, not from which "
            "site; placing it inside the Tor session window is a timing correlation, not attribution."
        ),
    ),
    "module_c_memory": (
        (
            "Memory strings show what was held in memory at capture time. A link present on a page "
            "and a link that was actually visited cannot always be told apart."
        ),
        "The order of memory events follows their position in memory, not time.",
    ),
}


def _limitations(findings: dict) -> list[str]:
    """What this run could not establish or could not check, from what it recorded."""
    notes = []
    for name, module in findings["modules"].items():
        if module["status"] in ("skipped", "not_implemented"):
            notes.append(f"{name} was not run ({module.get('message') or module['status']}).")
        elif module["status"] == "error":
            notes.append(
                f"{name} failed and its findings are not relied on: {module.get('message')}."
            )
        for w in module.get("warnings", []):
            notes.append(
                f"{name}: {w.get('artifact_type')} could not be read"
                f"{' (' + str(w['source']) + ')' if w.get('source') else ''}: {w.get('reason')}."
            )
        if module["status"] in ("ok", "partial"):
            notes.extend(METHOD_LIMITS.get(name, ()))
    memory = findings["modules"].get("module_c_memory", {}).get("details", {})
    if memory.get("host_anchoring", {}).get("no_target"):
        notes.append(
            "The memory image was analysed without a target onion address or host, so nothing "
            "in memory is attributed to Tor Browser; memory matches are observations only."
        )
    provenance = findings.get("provenance") or {}
    for item in provenance.get("evidence_items", []):
        if item["status"] in ("MISMATCH", "missing"):
            notes.append(f"{item['label']} ({item['path']}) did not verify: {item['status']}.")
        elif item["status"] == "unrecorded":
            notes.append(
                f"{item['label']} ({item['path']}) has no hash recorded at acquisition, so it "
                "cannot be shown to be unchanged since then."
            )
        elif item["status"] == "not_hashed":
            notes.append(f"{item['label']} ({item['path']}): {item.get('note', 'not hashed')}.")
    if provenance and not provenance.get("acquisition"):
        notes.append(
            "No acquisition manifest accompanied the evidence; when and how it was acquired is "
            "not recorded in this report."
        )
    tool = provenance.get("tool", {})
    if tool.get("git_dirty"):
        notes.append(
            "TRANCE ran from source with uncommitted changes; the exact code cannot be "
            "recovered from the recorded commit alone."
        )
    return notes


def _glossary_needle(term: str) -> str:
    """What to look for in the report: "\\Device\\HarddiskVolumeN" appears with a number."""
    return term.removesuffix("N") if term.endswith("VolumeN") else term


def _evidence_rows(items: list[dict], prefix: str = "E") -> list[dict]:
    """The "Evidence examined" table: a folder whose files all verified becomes one row
    (its per-file hashes stay in findings.json); a file that did not verify is always
    listed on its own. Each row gets an exhibit number (<prefix>-01, -02, ...) in
    table order, which the rest of the report cites."""
    by_label: dict[str, list[dict]] = {}
    for item in items:
        by_label.setdefault(item["label"], []).append(item)
    rows = []
    for label, group in by_label.items():
        verified = [i for i in group if i["status"] == "verified"]
        if len(verified) > 1:
            folder = os.path.commonpath([i["path"] for i in verified])
            rows.append(
                {
                    "label": label,
                    "path": folder,
                    "kind": "folder",
                    "size_bytes": sum(i.get("size_bytes") or 0 for i in verified),
                    "sha256": None,
                    "status": "verified",
                    "note": f"{len(verified)} files, each SHA-256 matches acquisition; "
                    "per-file hashes are in findings.json",
                }
            )
            group = [i for i in group if i["status"] != "verified"]
        rows.extend(dict(i) for i in group)
    for n, row in enumerate(rows, start=1):
        row["exhibit"] = f"{prefix}-{n:02d}"
    return rows


def _exhibit_for(item: dict, rows: list[dict]) -> str | None:
    """The exhibit a basis entry's source file belongs to: the row for that file, the
    folder row holding it, or (for "hive") the hive row of that name."""
    source = item.get("source")
    for row in rows:
        path = row.get("path") or ""
        if source and (
            source == path or (row.get("kind") == "folder" and source.startswith(path + os.sep))
        ):
            return row["exhibit"]
        if item.get("hive") and row["label"].startswith(item["hive"] + " "):
            return row["exhibit"]
    return None


def _cite(items: list[dict], rows: list[dict]) -> list[str]:
    """ "Based on" entries as text: each statement once, with the exhibits it rests on,
    or the file name when the evidence list has no row for it."""
    cited: dict[str, list[str]] = {}
    for item in items or []:
        name = os.path.basename(item["source"]) if item.get("source") else None
        ref = _exhibit_for(item, rows) or (
            name if name and not item["what"].startswith(name + ":") else None
        )
        refs = cited.setdefault(item["what"], [])
        if ref and ref not in refs:
            refs.append(ref)
    return [f"{what} ({', '.join(refs)})" if refs else what for what, refs in cited.items()]


def render_exhibit_list(findings: dict, findings_sha256: str | None = None) -> str | None:
    """The s.7 list of evidence, or None when the findings have no evidence items."""
    provenance = findings.get("provenance") or {}
    if not provenance.get("evidence_items"):
        return None
    info = findings.get("case", {}).get("info") or {}
    env = Environment(autoescape=True)
    env.filters["fmt_bytes"] = _format_bytes
    env.filters["relative_to"] = _relative_to
    return env.from_string(EXHIBIT_LIST_TEMPLATE).render(
        case=findings.get("case", {}),
        info=info,
        labels=[(key, label) for key, label, _flag in CASE_INFO_FIELDS if key != "exhibit_prefix"],
        generated_at=findings.get("generated_at"),
        rows=_evidence_rows(provenance["evidence_items"], info.get("exhibit_prefix") or "E"),
        checks={
            "verified": "matches acquisition",
            "MISMATCH": "HASH DIFFERS",
            "unrecorded": "no acquisition hash",
            "missing": "missing",
            "not_hashed": "not hashed",
        },
        findings_sha256=findings_sha256,
    )


def render_report(
    findings: dict, local_tz: str | None = None, findings_sha256: str | None = None
) -> str:
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
    env.filters["fmt_bytes"] = _format_bytes
    env.filters["relative_to"] = _relative_to
    env.filters["css_string"] = _css_string
    env.filters["mask"] = _mask
    env.tests["secret_field"] = _is_secret_field
    template = env.get_template(TEMPLATE_NAME)

    resolved_tz = _resolve_local_tz(local_tz)

    presented: dict[str, dict] = {}
    generic: list[dict] = []
    for name, module in findings["modules"].items():
        presenter = PRESENTERS.get(name)
        # "partial" still gets the full presenter; only "error" (nothing trustworthy, e.g. an
        # integrity hash mismatch) falls back to the generic table below.
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

    provenance = findings.get("provenance")
    case_info = findings.get("case", {}).get("info") or {}

    evidence_rows = (
        _evidence_rows(provenance["evidence_items"], case_info.get("exhibit_prefix") or "E")
        if provenance
        else []
    )

    def render(terms: list[tuple[str, str]]) -> str:
        return template.render(
            findings=findings,
            registry=presented.get("module_a_registry"),
            disk=presented.get("module_b_disk"),
            memory=presented.get("module_c_memory"),
            generic_modules=generic,
            glossary=terms,
            provenance=provenance,
            evidence_rows=evidence_rows,
            cite=lambda items: _cite(items, evidence_rows),
            case_info=case_info,
            case_info_labels={key: label for key, label, _flag in CASE_INFO_FIELDS},
            limitations=_limitations(findings),
            findings_sha256=findings_sha256,
        )

    # Only define terms the printed report actually uses (whole words, outside tags).
    text = re.sub(r"<[^>]+>", " ", render([]))
    used = [
        (term, definition)
        for term, definition in sorted(glossary.items())
        if re.search(r"(?<!\w)" + re.escape(_glossary_needle(term)), text)
    ]
    return render(used)


def write_report(
    findings: dict,
    output_dir: Path,
    local_tz: str | None = None,
    findings_sha256: str | None = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / REPORT_FILENAME
    _write_atomic(path, render_report(findings, local_tz, findings_sha256))
    exhibit_list = render_exhibit_list(findings, findings_sha256)
    if exhibit_list is not None:
        _write_atomic(output_dir / EXHIBIT_LIST_FILENAME, exhibit_list)
    return path


def _write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".report-")
    try:
        os.write(fd, text.encode())
        os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        os.close(fd)
        os.unlink(tmp)
        raise
