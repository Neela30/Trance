"""The report's Methodology says the same inputs and TRANCE version give the same findings.
This runs the whole pipeline twice on the same evidence and checks exactly that."""

import main
from core.config import TranceConfig
from tests.test_disk_evidence import _create_profile, _create_tor_dir

# Facts about the run, not about the evidence: when it ran, where it wrote, and the inode
# of Module B's disposable working copy.
RUN_SPECIFIC = {"generated_at", "output_dir", "duration_seconds", "inode"}
RUN_SPECIFIC_PROVENANCE = {"analysis_started_at", "analysis_finished_at"}


def _strip(node):
    if isinstance(node, dict):
        return {k: _strip(v) for k, v in node.items() if k not in RUN_SPECIFIC}
    if isinstance(node, list):
        return [_strip(v) for v in node]
    return node


def test_same_evidence_gives_the_same_findings(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _create_profile(evidence / "profile")
    _create_tor_dir(evidence / "tor")
    dump = evidence / "dump.bin"
    dump.write_bytes(b"http://target.onion/login\x00session=abc123\x00" * 3)
    kwargs = {
        "module_a_registry": {},
        "module_b_disk": {"profile_dir": evidence / "profile", "tor_dir": evidence / "tor"},
        "module_c_memory": {"dump": dump, "onion": "target.onion"},
    }

    runs = []
    for n in (1, 2):
        findings = main.run_pipeline(TranceConfig("case", tmp_path / f"out{n}"), kwargs).findings
        for key in RUN_SPECIFIC_PROVENANCE:
            findings["provenance"].pop(key)
        runs.append(_strip(findings))

    assert runs[0]["modules"]["module_b_disk"]["status"] == "ok"
    assert runs[0]["modules"]["module_c_memory"]["status"] == "ok"
    assert runs[0]["artifacts"]
    assert runs[0] == runs[1]
