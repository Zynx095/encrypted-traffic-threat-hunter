"""Phase 10: sequence construction, masking, training discipline and checkpoints (CPU)."""
import numpy as np
import pandas as pd
import pytest
import torch

from ml.sequence.dataset import CHANNELS, SequenceNormaliser, aggregate_features, build_sequences
from ml.sequence.models import ARCHITECTURES
from ml.sequence.train import load_checkpoint, predict, train_model


def _flows(n=6, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        k = int(rng.integers(3, 20))
        rows.append({
            "sequence_packet_lengths": list(rng.integers(40, 1500, size=k)),
            "sequence_relative_times": list(np.cumsum(rng.random(k))),
            "sequence_directions": list(rng.choice([1, -1], size=k)),
            "sequence_tcp_flags": list(rng.choice([0x10, 0x18, 0x02], size=k)),
        })
    return pd.DataFrame(rows)


def test_padding_mask_and_truncation():
    df = _flows()
    b = build_sequences(df, max_len=8)
    assert b.x.shape == (len(df), 8, len(CHANNELS))
    for i, L in enumerate(df["sequence_packet_lengths"]):
        k = min(len(L), 8)
        assert b.lengths[i] == k and b.mask[i, :k].all() and not b.mask[i, k:].any()
        assert np.all(b.x[i, k:] == 0)
    assert b.valid.all()


def test_malformed_sequences_are_rejected_not_repaired():
    df = _flows(3)
    df.at[0, "sequence_directions"] = [1]                                    # length mismatch
    df.at[1, "sequence_relative_times"] = [0.0, 2.0, 1.0] + [3.0] * (len(df.at[1, "sequence_packet_lengths"]) - 3)
    b = build_sequences(df, max_len=16)
    assert list(b.valid) == [False, False, True]
    assert b.reasons["length_mismatch"] == 1 and b.reasons["time_decreasing"] == 1


def test_normaliser_fits_training_rows_only():
    b = build_sequences(_flows(10), max_len=16)
    train, test = np.arange(5), np.arange(5, 10)
    norm = SequenceNormaliser().fit(b, train)
    mu_train = b.x[train][:, :, 1][b.mask[train]].mean()
    assert norm.stats[1][0] == pytest.approx(mu_train)
    out = norm.transform(b, test)
    assert np.all(out[~b.mask[test]] == 0)


def test_aggregate_features_use_only_real_steps():
    b = build_sequences(_flows(4), max_len=8)
    agg = aggregate_features(b)
    assert len(agg) == 4 and agg["seq_len"].tolist() == b.lengths.tolist()
    assert np.isfinite(agg.drop(columns=[c for c in agg.columns if c.endswith("_std")]).to_numpy()).all()


@pytest.mark.parametrize("arch", ["cnn", "gru"])
def test_models_ignore_padding(arch):
    torch.manual_seed(0)
    model = ARCHITECTURES[arch](len(CHANNELS)).eval()
    b = build_sequences(_flows(4), max_len=12)
    x, m, l = (torch.from_numpy(b.x), torch.from_numpy(b.mask), torch.from_numpy(b.lengths))
    with torch.no_grad():
        base = model(x, m, l)
        noisy = x.clone()
        noisy[~m] = 7.0                                   # garbage in padded positions
        assert torch.allclose(base, model(noisy, m, l), atol=1e-6)


def _toy_task(n=300, seed=0):
    rng = np.random.default_rng(seed)
    y = rng.integers(0, 2, size=n)
    df = _flows(n, seed)
    df["sequence_packet_lengths"] = [list(np.array(L) * (2 if t else 1) % 1500 + 40) for L, t in zip(df["sequence_packet_lengths"], y)]
    b = build_sequences(df, max_len=16)
    norm = SequenceNormaliser().fit(b, np.arange(200))
    pack = lambda idx: {"x": norm.transform(b, idx), "mask": b.mask[idx], "lengths": b.lengths[idx], "y": y[idx]}
    return pack(np.arange(200)), pack(np.arange(200, 300))


def test_training_is_deterministic_on_cpu_and_checkpoint_restores(tmp_path):
    tr, va = _toy_task()
    r1 = train_model("cnn", tr, va, seed=7, epochs=3, checkpoint_path=tmp_path / "c.safetensors")
    r2 = train_model("cnn", tr, va, seed=7, epochs=3)
    p1 = predict(r1["model"], va["x"], va["mask"], va["lengths"])
    p2 = predict(r2["model"], va["x"], va["mask"], va["lengths"])
    assert np.allclose(p1, p2, atol=1e-6)
    restored = load_checkpoint("cnn", tr["x"].shape[2], tmp_path / "c.safetensors")
    assert np.allclose(predict(restored, va["x"], va["mask"], va["lengths"]), p1, atol=1e-6)
    assert r1["device"] == "cpu" and r1["parameters"] > 0 and len(r1["history"]) == r1["epochs_run"]
    assert r1["best_epoch"] == int(np.argmax([h["val_ap"] for h in r1["history"]]))


def test_early_stopping_uses_validation_only():
    tr, va = _toy_task(seed=2)
    r = train_model("gru", tr, va, seed=1, epochs=40, patience=2)
    assert r["epochs_run"] <= 40
    assert all("val_ap" in h and "train_loss" in h for h in r["history"])


def test_sequence_suite_runs_end_to_end_on_synthetic_data(tmp_path, monkeypatch):
    """
    Regression: a refactor shadowed the contrast reading rule `interpret` with a local dict, so every
    re-run of `python -m ml sequence` failed after training. Runs the full suite on a tiny synthetic
    corpus in a temporary registry (never the real one).
    """
    import ml.benchmark.registry as R
    import ml.sequence.experiment as E
    from tests.ml_fixtures import synthetic_corpus

    monkeypatch.setattr(R, "PHASE10_ROOT", tmp_path / "phase10")
    monkeypatch.setattr(R, "REGISTRY_INDEX", tmp_path / "index.jsonl")
    monkeypatch.setattr(E, "PHASE10_ROOT", tmp_path / "phase10")

    def frame(datasets=None, per_capture_cap=None, seed=42):
        df = synthetic_corpus(captures_per_class=6, flows_per_capture=20)
        rng = np.random.default_rng(0)
        cols = {"sequence_packet_lengths": [], "sequence_relative_times": [], "sequence_directions": [],
                "sequence_tcp_flags": [], "sequence_original_length": []}
        for y in df["y"]:
            k = int(rng.integers(3, 40))
            cols["sequence_packet_lengths"].append(list((rng.integers(40, 1500, size=k) * (2 if y else 1)) % 1500 + 40))
            cols["sequence_relative_times"].append(list(np.cumsum(rng.random(k))))
            cols["sequence_directions"].append(list(rng.choice([1, -1], size=k)))
            cols["sequence_tcp_flags"].append(list(rng.choice([0x10, 0x18], size=k)))
            cols["sequence_original_length"].append(k)
        for c, v in cols.items():
            df[c] = v
        return df

    monkeypatch.setattr(E, "load_benchmark_frame", frame)
    res = E.run_sequence_suite(epochs=1, archs=["cnn"], n_boot=20)
    assert res["status"] == "COMPLETED", res
    assert res["summary"]["contrasts"] and all("interpretation" in c for c in res["summary"]["contrasts"])
    assert (tmp_path / "index.jsonl").exists()
