"""
Phase 8 corpus command line.

    python -m pipeline.corpus seed        # create/refresh the dataset registry (keeps existing records)
    python -m pipeline.corpus plan        # regenerate data/corpus/capture_plan.json from manifests + acquisition log
    python -m pipeline.corpus build       # extract, verify, validate and build corpus v3 (resumable)
    python -m pipeline.corpus admit       # admission report, sufficiency assessment, registry state updates
    python -m pipeline.corpus all         # seed + plan + build + admit
    python -m pipeline.corpus status      # print registry states
"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from pipeline.corpus import paths


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m pipeline.corpus")
    parser.add_argument("command", choices=["seed", "plan", "build", "admit", "all", "status"])
    parser.add_argument("--force", action="store_true", help="rebuild interim flow tables even if cached")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    from pipeline.corpus.registry import DatasetRegistry
    if args.command in ("seed", "all"):
        from pipeline.corpus.seed import seed_registry
        reg = seed_registry()
        print(f"Registry: {len(reg.records)} datasets -> {paths.rel(paths.REGISTRY_PATH)}")
    if args.command in ("plan", "all"):
        from pipeline.corpus.capture_plan import build_default_plan, save_plan
        plan = build_default_plan()
        save_plan(plan)
        inc = sum(1 for c in plan["captures"] if c["planned_use"] == "INCLUDE")
        print(f"Capture plan: {len(plan['captures'])} captures ({inc} included) -> {paths.rel(paths.CAPTURE_PLAN_PATH)}")
    if args.command in ("build", "all"):
        from pipeline.corpus.builder import build_corpus
        manifest = build_corpus(force=args.force)
        print(json.dumps({"rows": manifest["rows"], "label_counts": manifest["label_counts"],
                          "captures_built": len(manifest["captures_built"])}, indent=2))
    if args.command in ("admit", "all"):
        from pipeline.corpus.admission import assess_sufficiency, build_admission_report, update_registry_states
        report = build_admission_report()
        suff = assess_sufficiency()
        update_registry_states(report)
        print(json.dumps({k: v["met"] for k, v in suff["levels"].items()}, indent=2))
        print(f"Admission report -> {paths.rel(paths.ADMISSION_REPORT_MD)}")
    if args.command == "status":
        reg = DatasetRegistry(paths.REGISTRY_PATH)
        for rec in reg.all():
            print(f"{rec['dataset_id']:10s} {rec['state']:16s} {rec.get('access_category', '')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
