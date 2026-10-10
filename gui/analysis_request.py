"""Everything the Analyse tab can ask for, as one Qt-free value: the GUI equivalent of
main.py's argparse namespace. It merges auto-discovered evidence (resolve_evidence)
with the examiner's overrides, validates with the same rules main.main() enforces, and
round-trips through JSON so the analysis can run in a child process (gui.processes)."""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path, PureWindowsPath
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from analyze_evidence import resolve_evidence
from main import CUSTODY_FILENAME, no_target_warning

SOURCE_TYPES = ("process", "full-memory")
OUTPUT_FILES = ("findings.json", "report.html", CUSTODY_FILENAME)


@dataclass(frozen=True)
class InputSpec:
    key: str  # resolve_evidence()/module_kwargs_from_resolved() key
    label: str
    is_dir: bool


# Every evidence input resolve_evidence() can discover, in display order.
INPUT_SPECS = (
    InputSpec("system", "SYSTEM hive", False),
    InputSpec("ntuser", "NTUSER.DAT hive", False),
    InputSpec("amcache", "Amcache.hve", False),
    InputSpec("dump", "Memory image", False),
    InputSpec("disk_profile", "Tor Browser profile", True),
    InputSpec("tor_dir", "Tor data folder", True),
    InputSpec("downloads_scan", "Downloads scan", False),
    InputSpec("ntfs_dir", "NTFS metadata", True),
)
INPUT_KEYS = tuple(spec.key for spec in INPUT_SPECS)


@dataclass
class AnalysisRequest:
    case_name: str
    output_dir: str
    evidence_dir: str | None = None
    overrides: dict[str, str] = field(default_factory=dict)  # INPUT_KEYS -> path
    source_type: str | None = None  # None = as discovered / guessed from the dump
    onion: str = ""
    host: str = ""
    username: str = ""
    cookie_names: str = ""  # comma-separated; blank = the analyzer's defaults
    report_timezone: str = ""  # IANA zone name; blank = auto-detect this machine's own
    disk_image: str | None = None
    mount_image: bool = False  # mount disk_image read-only and analyse the volume
    carve_image: bool = False  # raw byte carve of disk_image
    disk_root: str | None = None  # an already-mounted volume, or the GUI's mountpoint
    vol3_path: str | None = None
    vol3_extract_process: str | None = None
    vol3_extract_pid: int | None = None

    @property
    def case_dir(self) -> Path:
        return Path(self.output_dir) / self.case_name

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, text: str) -> AnalysisRequest:
        return cls(**json.loads(text))


@dataclass
class Issues:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def guess_source_type(dump: str) -> str:
    """trance-acquire names a WinPMEM image fullmem_*.raw and a live dump
    firefox_*.bin; anything else that looks like a whole-RAM image is treated as one."""
    name = Path(dump).name.lower()
    if name.startswith("fullmem_") or name.endswith((".raw", ".mem", ".vmem", ".elf", ".dmp")):
        return "full-memory"
    return "process"


def discovered_inputs(evidence_dir: str | None) -> dict:
    if not evidence_dir or not Path(evidence_dir).is_dir():
        return {}
    return resolve_evidence(Path(evidence_dir))


def effective_inputs(request: AnalysisRequest, discovered: dict | None = None) -> dict:
    """resolve_evidence()'s result with the examiner's overrides applied, plus the
    inputs that are never auto-discovered -- the dict module_kwargs_from_resolved()
    reads. An override always wins, exactly as an explicit CLI flag does."""
    inputs = dict(discovered if discovered is not None else discovered_inputs(request.evidence_dir))
    for key, value in request.overrides.items():
        if key in INPUT_KEYS and value:
            inputs[key] = value
    if request.overrides.get("dump"):
        inputs["source_type"] = guess_source_type(request.overrides["dump"])
    if request.source_type:
        inputs["source_type"] = request.source_type
    if request.disk_image and request.carve_image:
        inputs["disk_image"] = request.disk_image
    if request.disk_root:
        inputs["disk_root"] = request.disk_root
    for key in ("vol3_path", "vol3_extract_process", "vol3_extract_pid"):
        value = getattr(request, key)
        if value not in (None, ""):
            inputs[key] = value
    return inputs


def _is_single_component(name: str) -> bool:
    return (
        bool(name)
        and name not in (".", "..")
        and Path(name).name == name
        and PureWindowsPath(name).name == name
    )


def _inside(path: Path, root: str) -> bool:
    try:
        return path.resolve().is_relative_to(Path(root).resolve())
    except OSError:
        return False


def validate(request: AnalysisRequest, inputs: dict) -> Issues:
    """main.main()'s checks, plus the ones a form needs that argparse got for free."""
    issues = Issues()
    errors, warnings = issues.errors, issues.warnings

    if not _is_single_component(request.case_name.strip()):
        errors.append("Case name must be a single folder name, without path separators.")
    elif any((request.case_dir / name).exists() for name in OUTPUT_FILES):
        errors.append(
            f"This case already has outputs; choose a new case name ({request.case_dir})."
        )

    if request.evidence_dir and not Path(request.evidence_dir).is_dir():
        errors.append(f"Evidence folder not found: {request.evidence_dir}")

    analysable = [k for k in INPUT_KEYS if inputs.get(k)]
    if not analysable and not request.disk_image and not request.disk_root:
        errors.append(
            "Nothing to analyse: pick an evidence folder, a disk image or a mounted volume, "
            "or set at least one input."
        )

    labels = {spec.key: spec.label for spec in INPUT_SPECS}
    for spec in INPUT_SPECS:
        value = inputs.get(spec.key)
        if not value:
            continue
        path = Path(value)
        exists = path.is_dir() if spec.is_dir else path.is_file()
        if not exists:
            errors.append(f"{labels[spec.key]} not found: {value}")

    if request.disk_image:
        image = Path(request.disk_image)
        if not image.is_file():
            errors.append(f"Disk image not found: {request.disk_image}")
        if not (request.mount_image or request.carve_image):
            errors.append("Disk image chosen: tick 'Mount and analyse' and/or 'Raw carve'.")
        if request.mount_image and request.disk_root:
            errors.append(
                "Use either the disk image's mount or an already-mounted folder, not both."
            )
    if request.disk_root and not request.mount_image:
        root = Path(request.disk_root)
        if not root.is_dir():
            errors.append(f"Mounted volume folder not found: {request.disk_root}")
        elif not (root / "$MFT").exists():
            warnings.append(
                "The mounted volume does not expose $MFT: mount it with "
                "-o ro,show_sys_files,streams_interface=windows or $MFT/$UsnJrnl analysis "
                "is skipped."
            )

    # main.py: the case output must not land inside disk evidence.
    for key in ("disk_profile", "tor_dir"):
        if inputs.get(key) and _inside(request.case_dir, inputs[key]):
            errors.append(f"The output folder is inside the evidence ({inputs[key]}).")
    for root in (request.evidence_dir, request.disk_root):
        if root and _inside(request.case_dir, root):
            errors.append(f"The output folder is inside the evidence ({root}).")

    source_type = inputs.get("source_type", "process")
    if source_type not in SOURCE_TYPES:
        errors.append(f"Unknown memory source type: {source_type}")
    extracting = request.vol3_extract_process or request.vol3_extract_pid is not None
    if request.vol3_path and not (
        Path(request.vol3_path).is_file() or shutil.which(request.vol3_path)
    ):
        errors.append(f"Volatility3 'vol' not found: {request.vol3_path}")
    if extracting and not request.vol3_path:
        errors.append("Extracting one process needs the Volatility3 'vol' path.")
    if extracting and source_type != "full-memory":
        errors.append("Extracting one process only applies to a full-memory image.")
    if request.vol3_extract_pid is not None and request.vol3_extract_pid <= 0:
        errors.append("Process ID must be a positive number.")
    if request.vol3_extract_pid is not None and not request.vol3_extract_process:
        # module_c_memory.run() only extracts when a process name is set; a PID alone
        # would be silently ignored.
        errors.append("A process ID needs the process name too (e.g. firefox.exe).")

    if request.report_timezone:
        try:
            ZoneInfo(request.report_timezone)
        except (ZoneInfoNotFoundError, ValueError):
            errors.append(f"Unknown timezone: {request.report_timezone}")

    if inputs.get("dump") and not (request.onion or request.host):
        warnings.append(no_target_warning(source_type))
    return issues


@dataclass(frozen=True)
class SummaryRow:
    label: str
    state: str  # "found" | "missing" | "off" (optional and not in use)
    detail: str
    tooltip: str = ""


def display_path(path: str, evidence_dir: str | None) -> str:
    """A path as the examiner thinks of it: relative to the evidence folder when it's
    inside it, otherwise just the file or folder name (the tooltip has the full path)."""
    if evidence_dir:
        try:
            return Path(path).resolve().relative_to(Path(evidence_dir).resolve()).as_posix()
        except (OSError, ValueError):
            pass
    return Path(path).name or path


def summary_rows(request: AnalysisRequest, inputs: dict) -> list[SummaryRow]:
    """The 'Evidence found' checklist: what this run will analyse, one row per kind."""

    def row(label: str, key: str, describe=None) -> SummaryRow:
        value = inputs.get(key)
        if not value:
            return SummaryRow(label, "missing", "not found")
        shown = display_path(value, request.evidence_dir)
        if key in request.overrides:
            shown += " (chosen manually)"
        return SummaryRow(label, "found", describe(shown) if describe else shown, value)

    hives = [k for k in ("system", "ntuser", "amcache") if inputs.get(k)]
    registry = SummaryRow(
        "Registry hives",
        "found" if hives else "missing",
        f"{len(hives)} of 3 found" if hives else "not found",
        "\n".join(inputs[k] for k in hives),
    )
    memory_kind = (
        "full memory image"
        if inputs.get("source_type") == "full-memory"
        else "live browser process dump"
    )
    rows = [
        registry,
        row("Memory", "dump", lambda shown: f"{shown} · {memory_kind}"),
        row("Tor Browser profile", "disk_profile"),
        row("Tor data folder", "tor_dir"),
        row("Downloads scan", "downloads_scan"),
        row("NTFS metadata", "ntfs_dir"),
    ]
    if request.disk_image and (request.mount_image or request.carve_image):
        actions = [
            a
            for a, on in (
                ("mounted read-only", request.mount_image),
                ("byte search", request.carve_image),
            )
            if on
        ]
        rows.append(
            SummaryRow(
                "Disk image",
                "found",
                f"{Path(request.disk_image).name} · {' + '.join(actions)}",
                request.disk_image,
            )
        )
    elif request.disk_root:
        rows.append(
            SummaryRow("Disk volume", "found", f"{request.disk_root} (mounted)", request.disk_root)
        )
    else:
        rows.append(SummaryRow("Disk image", "off", "optional — add one under More options"))
    if request.report_timezone:
        rows.append(SummaryRow("Report timezone", "found", request.report_timezone))
    return rows
