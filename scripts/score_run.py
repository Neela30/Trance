#!/usr/bin/env python3
"""Score one TRANCE run against a ground-truth file; optionally aggregate runs.

Score one run:
    python scripts/score_run.py score --ground-truth gt.json --findings findings.json \
        --run-id c4-r01 --condition C4 [--part-b] [--share-link URL] \
        [--server-gt c4-r01.json] [--baseline EVIDENCE_PATH ...] --out results/c4-r01.json

Aggregate (mean and range per condition):
    python scripts/score_run.py aggregate results/

Rules (from ground_truth.json "scoring_rules"):
  * recovered = any `match` string appears (case-insensitive) in the reported findings;
  * recall denominator = performed=true and decoy=false items of the included parts;
  * a decoy that appears in the findings is a false positive;
  * the `details.targeting` block only echoes the CLI targets and is NOT searched.
NC runs pass only if no non-SYS item is found at all.

--baseline (repeatable; evidence folders or files) is the "plain strings + search" control: every
evidence file is scanned as raw bytes (ASCII and UTF-16LE, case-insensitive) for each item's match
strings, with no parsing. It shows what is *present* in the evidence, so a miss by the tool can be
told apart from a marker that was never captured.
"""

import argparse
import json
import os
import statistics
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path


def load(path):
    with open(path) as fh:
        return json.load(fh)


def classify_source(artifact: dict) -> str:
    module, src = artifact.get("module", ""), (artifact.get("source") or "").replace("\\", "/")
    low = src.lower()
    if module == "module_a_registry":
        return "registry"
    if module == "module_c_memory":
        return "memory"
    if "pagefile" in low or "swapfile" in low:
        return "pagefile"
    if "/mft" in low or "usnjrnl" in low or "ntfs" in low:
        return "ntfs"
    if "/disk/profile" in low:
        return "browser-profile"
    if "/disk/tor_dir" in low:
        return "tor-dir"
    return "disk-other"


def walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, f"{path}/{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def build_corpus(findings: dict) -> list[tuple[str, str, str]]:
    """(source_category, text_lowercase, origin) for every searchable string."""
    corpus = []
    for a in findings.get("artifacts", []):
        text = f"{a.get('description', '')} {a.get('source', '')}".lower()
        corpus.append((classify_source(a), text, "artifact"))
    for mod, data in findings.get("modules", {}).items():
        details = dict(data.get("details") or {})
        details.pop("targeting", None)
        details.pop("warnings", None)
        cat = {"module_a_registry": "registry", "module_c_memory": "memory"}.get(mod, "disk-other")
        for p, s in walk_strings(details):
            corpus.append((cat, s.lower(), "details"))
    return corpus


def apply_overrides(items, server_gt, share_link, part_b):
    # The server-built file has no ids, so items are matched on (type, marker).
    server = {(i["type"], i["marker"]): i for i in (server_gt or {}).get("items", [])}
    for it in items:
        s = server.get((it["type"], it["marker"]))
        if s and it["part"] == "A":
            it["performed"], it["decoy"] = s["performed"], s["decoy"]
        if it["type"] == "share_link" and share_link:
            it["marker"], it["match"] = share_link, [share_link]
    return [i for i in items if part_b or i["part"] != "B"]


CHUNK = 64 << 20
SKIP_SUFFIXES = (".sha256", ".json")


def classify_file(path: Path) -> str:
    low = str(path).replace("\\", "/").lower()
    name = path.name.lower()
    if name.startswith("fullmem_") or name.endswith((".raw", ".mem", ".dmp")):
        return "ram-full"
    if "/memory/" in low:
        return "ram-process"
    if "pagefile" in name:
        return "pagefile"
    if "swapfile" in name:
        return "swapfile"
    if "hiberfil" in name:
        return "hiberfil"
    if name in ("mft", "$mft") or name.startswith("usnjrnl") or "$usnjrnl" in low:
        return "ntfs-metadata"
    if "/registry/" in low or name.startswith(
        ("ntuser", "usrclass", "system", "software", "amcache")
    ):
        return "registry"
    if "/disk/profile" in low:
        return "browser-profile"
    if "/disk/tor_dir" in low:
        return "tor-dir"
    return "other"


def baseline_files(paths) -> list[Path]:
    files = []
    for raw in paths:
        p = Path(raw)
        found = [p] if p.is_file() else [f for f in sorted(p.rglob("*")) if f.is_file()]
        files += [f for f in found if not f.name.lower().endswith(SKIP_SUFFIXES)]
    return files


def baseline_needles(items) -> dict[str, list[bytes]]:
    """Per item: lowercase match strings as ASCII and UTF-16LE bytes (redundant ones dropped)."""
    out = {}
    for it in items:
        if it["part"] == "SYS":
            continue
        strs = sorted({m.lower() for m in it["match"] if m}, key=len)
        keep = [m for m in strs if not any(o != m and o in m for o in strs)]
        out[it["id"]] = [m.encode() for m in keep] + [m.encode("utf-16-le") for m in keep]
    return out


def scan_file(path: str, needles: dict[str, list[bytes]]) -> set[str]:
    """Item ids with any needle present in the file (presence only; ASCII-lowercased compare)."""
    remaining = {k: v for k, v in needles.items() if v}
    found: set[str] = set()
    keep = max((len(n) for v in remaining.values() for n in v), default=1) - 1
    tail = b""
    with open(path, "rb") as fh:
        while remaining:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            buf = tail + chunk.lower()
            for item_id in list(remaining):
                if any(n in buf for n in remaining[item_id]):
                    found.add(item_id)
                    del remaining[item_id]
            tail = buf[-keep:] if keep else b""
    return found


def run_baseline(paths, items) -> dict[str, list[str]]:
    """item id -> sorted evidence-source classes where the item is present."""
    needles = baseline_needles(items)
    files = baseline_files(paths)
    workers = max(1, min(len(files) * 4, (os.cpu_count() or 2) - 1))
    shards = [dict(list(needles.items())[i::4]) for i in range(4)]
    present: dict[str, set[str]] = defaultdict(set)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        jobs = [(f, pool.submit(scan_file, str(f), sh)) for f in files for sh in shards]
        for f, job in jobs:
            for item_id in job.result():
                present[item_id].add(classify_file(f))
    return {k: sorted(v) for k, v in present.items()}


def score(args) -> dict:
    gt = load(args.ground_truth)
    findings = load(args.findings)
    server_gt = load(args.server_gt) if args.server_gt else None
    items = apply_overrides(gt["items"], server_gt, args.share_link, args.part_b)
    corpus = build_corpus(findings)

    rows = []
    for it in items:
        needles = [m.lower() for m in it["match"] if m]
        sources = (
            sorted({c for c, t, _ in corpus if any(n in t for n in needles)}) if needles else []
        )
        rows.append(
            {
                **{k: it[k] for k in ("id", "part", "type", "performed", "decoy")},
                "found": bool(sources),
                "sources": sources,
            }
        )

    scored = [r for r in rows if r["part"] != "SYS"]
    denom = [r for r in scored if r["performed"] and not r["decoy"]]
    recovered = [r for r in denom if r["found"]]
    false_pos = [r["id"] for r in scored if r["decoy"] and r["found"]]

    by_type, by_source = defaultdict(lambda: [0, 0]), defaultdict(int)
    for r in denom:
        by_type[r["type"]][1] += 1
        by_type[r["type"]][0] += r["found"]
        for s in r["sources"]:
            by_source[s] += 1

    baseline = None
    if args.baseline:
        present = run_baseline(args.baseline, items)
        in_evidence = [r for r in denom if r["id"] in present]
        both = [r for r in in_evidence if r["found"]]
        baseline = {
            "paths": [str(x) for x in args.baseline],
            "present_in_evidence": f"{len(in_evidence)}/{len(denom)}",
            "tool_recovered_of_present": f"{len(both)}/{len(in_evidence)}",
            "present_by_source": {
                src: sum(1 for r in denom if src in present.get(r["id"], []))
                for src in sorted({c for v in present.values() for c in v})
            },
            "tool_missed_but_present": [r["id"] for r in in_evidence if not r["found"]],
            "absent_from_evidence": [r["id"] for r in denom if r["id"] not in present],
            "tool_found_but_absent_in_evidence": [
                r["id"] for r in denom if r["found"] and r["id"] not in present
            ],
            "decoys_present_in_evidence": [
                r["id"] for r in scored if r["decoy"] and r["id"] in present
            ],
            "present": {k: v for k, v in sorted(present.items())},
        }

    # Precision proxy: artifacts from modules B/C whose text matches no ground-truth marker.
    all_needles = [m.lower() for it in items if it["part"] != "SYS" for m in it["match"] if m]
    arts = [a for a in findings.get("artifacts", []) if a["module"] != "module_a_registry"]
    matched = sum(
        1
        for a in arts
        if any(
            n in f"{a.get('description', '')} {a.get('source', '')}".lower() for n in all_needles
        )
    )
    result = {
        "run_id": args.run_id,
        "condition": args.condition,
        "part_b": args.part_b,
        "recall": (len(recovered) / len(denom)) if denom else None,
        "recovered": len(recovered),
        "denominator": len(denom),
        "recall_by_type": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_type.items())},
        "recovered_by_source": dict(sorted(by_source.items())),
        "decoy_false_positives": false_pos,
        "missed": [r["id"] for r in denom if not r["found"]],
        "module_bc_artifacts": len(arts),
        "module_bc_artifacts_matching_ground_truth": matched,
        "precision_proxy": (matched / len(arts)) if arts else None,
        "execution_evidence_found": any(r["found"] for r in rows if r["part"] == "SYS"),
        "baseline": baseline,
        "items": rows,
    }
    if args.condition == "NC":
        if baseline:
            baseline["nc_markers_present_in_evidence"] = sorted(
                i for i in present if not i.startswith("SYS")
            )
        hits = [r["id"] for r in scored if r["found"]]
        result["nc_pass"] = not hits
        result["nc_hits"] = hits
    return result


def print_result(r):
    print(f"Run {r['run_id']} ({r['condition']})")
    if r["condition"] == "NC":
        print(f"  NC {'PASS' if r['nc_pass'] else 'FAIL'}: hits = {r['nc_hits'] or 'none'}")
    else:
        pct = f"{r['recall']:.1%}" if r["recall"] is not None else "n/a"
        print(f"  Recall {r['recovered']}/{r['denominator']} = {pct}")
        print(f"  By type: {r['recall_by_type']}")
        print(f"  Recovered via source: {r['recovered_by_source']}")
        print(f"  Decoy false positives: {r['decoy_false_positives'] or 'none'}")
        print(f"  Missed: {r['missed'] or 'none'}")
    print(
        f"  Module B/C artifacts: {r['module_bc_artifacts']}, matching ground truth: "
        f"{r['module_bc_artifacts_matching_ground_truth']}"
    )
    print(f"  Tor execution evidence found: {r['execution_evidence_found']}")
    b = r.get("baseline")
    if b:
        print("  Strings baseline (raw search of the evidence):")
        print(
            f"    Present in evidence: {b['present_in_evidence']}  by source: {b['present_by_source']}"
        )
        print(f"    Tool recovered of those present: {b['tool_recovered_of_present']}")
        print(f"    Present but tool missed: {b['tool_missed_but_present'] or 'none'}")
        print(
            f"    Absent from evidence (no tool could find): {b['absent_from_evidence'] or 'none'}"
        )
        if b["tool_found_but_absent_in_evidence"]:
            print(f"    Tool found but baseline did not: {b['tool_found_but_absent_in_evidence']}")
        if r["condition"] == "NC":
            print(f"    NC markers in evidence: {b['nc_markers_present_in_evidence'] or 'none'}")


def aggregate(directory: Path):
    runs = [load(p) for p in sorted(directory.glob("*.json"))]
    runs = [r for r in runs if "condition" in r and "recall" in r]
    by_cond = defaultdict(list)
    for r in runs:
        by_cond[r["condition"]].append(r)
    print(f"{'Cond':<5}{'Runs':<6}{'Recall mean':<13}{'Range':<18}{'Decoy FPs':<11}{'In evidence'}")
    for cond, rs in sorted(by_cond.items()):
        if cond == "NC":
            print(f"{cond:<5}{len(rs):<6}{'pass' if all(r['nc_pass'] for r in rs) else 'FAIL'}")
            continue
        vals = [r["recall"] for r in rs if r["recall"] is not None]
        fps = sum(len(r["decoy_false_positives"]) for r in rs)
        mean = statistics.mean(vals)
        span = f"{min(vals):.1%}-{max(vals):.1%}"
        pres = [
            int(r["baseline"]["present_in_evidence"].split("/")[0]) / r["denominator"]
            for r in rs
            if r.get("baseline") and r["denominator"]
        ]
        pm = f"{statistics.mean(pres):.1%}" if pres else "n/a"
        print(f"{cond:<5}{len(rs):<6}{mean:<13.1%}{span:<18}{fps:<11}{pm}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("score")
    s.add_argument("--ground-truth", required=True)
    s.add_argument("--findings", required=True)
    s.add_argument("--run-id", required=True)
    s.add_argument("--condition", required=True, choices=["C1", "C3", "C4", "NC"])
    s.add_argument("--part-b", action="store_true", help="Part B was included in this run")
    s.add_argument("--share-link")
    s.add_argument("--server-gt", help="ground truth built from the server log for this session")
    s.add_argument("--baseline", action="append", help="evidence folder/file to string-search")
    s.add_argument("--out")
    a = sub.add_parser("aggregate")
    a.add_argument("directory", type=Path)
    args = ap.parse_args()
    if args.cmd == "aggregate":
        aggregate(args.directory)
        return 0
    result = score(args)
    print_result(result)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(result, indent=2))
    return 1 if args.condition == "NC" and not result["nc_pass"] else 0


if __name__ == "__main__":
    sys.exit(main())
