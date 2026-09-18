"""Render findings.json into TRANCE's single HTML case report. Deterministic, offline, no LLM.

Module-specific presentation (what a module's `details` mean, which values deserve a
table, which caveats apply) lives with that module — see PRESENTERS. A module without a
presenter, or one that didn't run cleanly, gets a generic artifact table plus its status,
so a module plugs into the report by returning artifacts alone and can add a presenter
later without touching this file's rendering.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from jinja2 import Environment, FileSystemLoader

from modules.module_a_registry.report import build_context as registry_context
from modules.module_c_memory.report import build_context as memory_context

TEMPLATE_DIR = Path(__file__).parent
TEMPLATE_NAME = "report_template.html.j2"
REPORT_FILENAME = "report.html"
GENERIC_TABLE_CAP = 200

PRESENTERS: dict[str, Callable[[dict], dict]] = {
    "module_a_registry": registry_context,
    "module_c_memory": memory_context,
}


def render_report(findings: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        # Not select_autoescape(["html"]): it decides by filename suffix and this template
        # is *.html.j2, which wouldn't match. It only ever renders HTML, so escape always.
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(TEMPLATE_NAME)

    presented: dict[str, dict] = {}
    generic: list[dict] = []
    for name, module in findings["modules"].items():
        presenter = PRESENTERS.get(name)
        if presenter and module["status"] == "ok":
            presented[name] = presenter(module["details"])
            continue
        artifacts = [a for a in findings["artifacts"] if a["module"] == name]
        generic.append(
            {
                "name": name,
                "status": module["status"],
                "message": module["message"],
                "artifacts": artifacts[:GENERIC_TABLE_CAP],
                "total": len(artifacts),
            }
        )

    return template.render(
        findings=findings,
        registry=presented.get("module_a_registry"),
        memory=presented.get("module_c_memory"),
        generic_modules=generic,
    )


def write_report(findings: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / REPORT_FILENAME
    path.write_text(render_report(findings))
    return path
