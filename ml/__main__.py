"""
ETTH research command line (Phases 9-10).

    python -m ml coverage
    python -m ml suite <name> [--models m1,m2] [--tracks t1,t2] [--n-boot 1000] [--suite-id ID]
    python -m ml suite-list
    python -m ml explain --suite-id ID --track A_FLOW --model random_forest
    python -m ml train-deployable --suite-id ID --track E_JA4_FLOW --model random_forest
    python -m ml activate --model-id etth-e_ja4_flow-random_forest --version 1 --reason "..."
    python -m ml rollback --track E_JA4_FLOW
    python -m ml sequence [--epochs 30] [--archs cnn,gru] [--datasets DS-009,DS-011]
    python -m ml report
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

DIAG_DIR = Path(__file__).resolve().parent.parent / "data" / "experiments" / "phase9" / "diagnostics"


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    print(f"wrote {path}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m ml")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("coverage")
    s = sub.add_parser("suite")
    s.add_argument("name")
    s.add_argument("--models")
    s.add_argument("--tracks")
    s.add_argument("--n-boot", type=int, default=1000)
    s.add_argument("--seed", type=int, default=42)
    s.add_argument("--suite-id")
    sub.add_parser("suite-list")
    e = sub.add_parser("explain")
    e.add_argument("--suite-id", required=True)
    e.add_argument("--track", required=True)
    e.add_argument("--model", required=True)
    t = sub.add_parser("train-deployable")
    t.add_argument("--suite-id", required=True)
    t.add_argument("--track", required=True)
    t.add_argument("--model", required=True)
    a = sub.add_parser("activate")
    a.add_argument("--model-id", required=True)
    a.add_argument("--version", type=int, required=True)
    a.add_argument("--reason", required=True)
    r = sub.add_parser("rollback")
    r.add_argument("--track", required=True)
    q = sub.add_parser("sequence")
    q.add_argument("--epochs", type=int, default=30)
    q.add_argument("--archs", default="cnn,gru")
    q.add_argument("--datasets")
    q.add_argument("--seed", type=int, default=42)
    q.add_argument("--max-len", type=int, default=64)
    sub.add_parser("report")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.cmd == "coverage":
        from ml.benchmark.runner import load_benchmark_frame
        from ml.diagnostics.coverage import coverage_report, shift_report
        df = load_benchmark_frame()
        _write(DIAG_DIR / "coverage_report.json", coverage_report(df))
        _write(DIAG_DIR / "shift_report.json", shift_report(df))
    elif args.cmd == "suite":
        from ml.benchmark.suites import run_suite
        res = run_suite(args.name, seed=args.seed, n_boot=args.n_boot,
                        models=args.models.split(",") if args.models else None,
                        tracks=args.tracks.split(",") if args.tracks else None, suite_id=args.suite_id)
        print(json.dumps({"suite_id": res["suite_id"], "status": res["status"]}, indent=2))
    elif args.cmd == "suite-list":
        from ml.benchmark.registry import list_suites
        for su in list_suites():
            print(su["suite_id"], su["status"], len(su.get("experiments", [])))
    elif args.cmd == "explain":
        from ml.benchmark.registry import PHASE9_ROOT, load_experiment
        from ml.benchmark.suites import SUITES, suite_frame
        from ml.diagnostics.explain import explain_track
        from ml.evaluation.splits import make_folds
        from ml.features.governance import population_mask
        from ml.model_registry import most_selected_params
        suite = json.loads((PHASE9_ROOT / args.suite_id / "suite.json").read_text(encoding="utf-8"))
        recs = [load_experiment(args.suite_id, x) for x in suite["experiments"]]
        rec = next(r for r in recs if r["config"]["track"] == args.track and r["config"]["model"] == args.model
                   and r.get("status") == "COMPLETED")
        df = suite_frame(SUITES[suite["name"]])
        pop = df.loc[population_mask(df, args.track)].reset_index(drop=True)
        folds = make_folds(pop, suite["config"]["protocol"], seed=suite["config"]["seed"],
                           capture_assignment=suite.get("capture_fold_assignment"))
        out = explain_track(df, args.track, args.model, most_selected_params(rec) or {}, folds)
        out["source_experiment"] = rec["experiment_id"]
        _write(PHASE9_ROOT / args.suite_id / f"explain_{args.track}_{args.model}.json", out)
    elif args.cmd == "train-deployable":
        from ml.benchmark.registry import PHASE9_ROOT, load_experiment
        from ml.benchmark.runner import load_benchmark_frame
        from ml.model_registry import most_selected_params, train_deployable
        suite = json.loads((PHASE9_ROOT / args.suite_id / "suite.json").read_text(encoding="utf-8"))
        recs = [load_experiment(args.suite_id, x) for x in suite["experiments"]]
        rec = next(r for r in recs if r["config"]["track"] == args.track and r["config"]["model"] == args.model
                   and r.get("status") == "COMPLETED")
        df = load_benchmark_frame(suite["config"].get("datasets"))
        entry = train_deployable(args.track, args.model, df, [rec["experiment_id"]], most_selected_params(rec))
        print(json.dumps({k: entry[k] for k in ("model_id", "version", "status", "calibration", "thresholds")}, indent=2, default=str))
    elif args.cmd == "activate":
        from ml.model_registry import activate
        entry = activate(args.model_id, args.version, args.reason)
        print(f"ACTIVE: {entry['model_id']} v{entry['version']} ({entry['track']})")
    elif args.cmd == "rollback":
        from ml.model_registry import rollback
        entry = rollback(args.track)
        print(f"ACTIVE after rollback: {entry['model_id']} v{entry['version']}")
    elif args.cmd == "sequence":
        from ml.sequence.experiment import run_sequence_suite
        res = run_sequence_suite(epochs=args.epochs, archs=args.archs.split(","), seed=args.seed, max_len=args.max_len,
                                 datasets=args.datasets.split(",") if args.datasets else None)
        print(json.dumps({"suite_id": res["suite_id"], "status": res["status"]}, indent=2))
    elif args.cmd == "report":
        from ml.reporting.report import generate_report
        paths = generate_report()
        print(json.dumps(paths, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
