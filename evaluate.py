#!/usr/bin/env python3
"""Empirical validation of the pq-obfs defenses (paper Tables III-V).

Runs five experiments and prints result tables, then writes all numeric results
to ``results.json``.
"""

from __future__ import annotations

import json
import os
import statistics
import time

from rich.console import Console
from rich.table import Table

from pqobfs.classifier import gfw_classify
from pqobfs.kemeleon import Kemeleon
from pqobfs.mlkem import HAVE_REAL_MLKEM, MLKEM
from pqobfs.obfs4_baseline import Obfs4Baseline
from pqobfs.padding import LCOVER, tcp_segments
from pqobfs.wire import PQObfsHandshake

console = Console()

N_REJECTION = 10000
N_DIST = 1000
N_EVASION = 1000

PAPER_TABLE_III = {
    512: {"pk": 0.56, "ct": 0.51, "ops": 3.7},
    768: {"pk": 0.83, "ct": 0.77, "ops": 2.5},
    1024: {"pk": 0.62, "ct": 0.57, "ops": 3.4},
}
PAPER_BASELINE_OPS = 2.0

# Paper Table V reference segment profiles (message lengths chosen per paper).
PAPER_TABLE_V = {
    "obfs4 (min pad)": 128,
    "pq-obfs ML-512 (min pad)": 1664,
    "pq-obfs ML-768 (min pad)": 2308,
    "pq-obfs ML-1024 (min pad)": 3232,
    "4096-normalized (all sets)": 4112,
}


def header(title: str):
    console.rule(f"[bold cyan]{title}")


def experiment_1_rejection(results: dict):
    header("Experiment 1: Rejection Sampling Rates (validates Table III)")
    table = Table(show_header=True, header_style="bold magenta")
    for col in ["Param", "pk_success", "ct_success", "exp_ops", "paper(pk/ct/ops)"]:
        table.add_column(col)

    results["experiment_1"] = {}
    for k in (512, 768, 1024):
        mlkem, kem = MLKEM(k), Kemeleon(k)
        pk_succ = sum(1 for _ in range(N_REJECTION) if kem.encode_pk(mlkem.keygen()[0]) is not None)
        pk_rate = pk_succ / N_REJECTION

        base_pk, _ = mlkem.keygen()
        ct_succ = sum(
            1 for _ in range(N_REJECTION) if kem.encode_ct(mlkem.encap(base_pk)[0]) is not None
        )
        ct_rate = ct_succ / N_REJECTION

        # expected operations per connection: client needs one pk-encode AND one
        # ct-encode to succeed, each is a geometric process.
        exp_ops = (1.0 / pk_rate) + (1.0 / ct_rate)

        p = PAPER_TABLE_III[k]
        table.add_row(
            f"ML-KEM-{k}",
            f"{pk_rate:.3f}",
            f"{ct_rate:.3f}",
            f"{exp_ops:.2f}",
            f"{p['pk']}/{p['ct']}/{p['ops']}",
        )
        results["experiment_1"][k] = {
            "pk_success_rate": pk_rate,
            "ct_success_rate": ct_rate,
            "expected_ops": exp_ops,
            "paper_pk": p["pk"],
            "paper_ct": p["ct"],
            "paper_ops": p["ops"],
        }

    # X25519/Elligator2 baseline (~0.5 success, ~2.0 ops)
    table.add_row("X25519/Ell2", "0.500", "-", f"{PAPER_BASELINE_OPS:.2f}", f"0.50/-/{PAPER_BASELINE_OPS}")
    results["experiment_1"]["baseline"] = {
        "success_rate": 0.5,
        "expected_ops": PAPER_BASELINE_OPS,
    }
    console.print(table)


def experiment_2_distribution(results: dict):
    header("Experiment 2: Byte-Distribution Analysis (validates Surface 1)")
    mlkem, kem = MLKEM(768), Kemeleon(768)
    obfs4 = Obfs4Baseline()
    coeff_len = 768 * 12 // 8

    cases = {"raw_mlkem768_pk": [], "kemeleon_encoded": [], "obfs4_baseline": []}
    verdicts = {k: [] for k in cases}

    for _ in range(N_DIST):
        pk, _ = mlkem.keygen()
        r = gfw_classify(pk[:coeff_len], ncoeffs=768)
        cases["raw_mlkem768_pk"].append((r["popcount"], r["msb_p"]))
        verdicts["raw_mlkem768_pk"].append(r["verdict"])

        enc = None
        while enc is None:
            pk2, _ = mlkem.keygen()
            enc = kem.encode_pk(pk2)
        r = gfw_classify(enc)
        cases["kemeleon_encoded"].append((r["popcount"], r["msb_p"]))
        verdicts["kemeleon_encoded"].append(r["verdict"])

        key_repr = os.urandom(32)
        r = gfw_classify(key_repr)
        cases["obfs4_baseline"].append((r["popcount"], r["msb_p"]))
        verdicts["obfs4_baseline"].append(r["verdict"])

    table = Table(show_header=True, header_style="bold magenta")
    for col in ["Case", "mean_popcount", "mean_msb_p", "% biased", "expected"]:
        table.add_column(col)
    expected = {
        "raw_mlkem768_pk": "biased",
        "kemeleon_encoded": "random",
        "obfs4_baseline": "random",
    }
    results["experiment_2"] = {}
    for name, vals in cases.items():
        mean_pc = statistics.mean(v[0] for v in vals)
        mean_p = statistics.mean(v[1] for v in vals)
        pct_biased = 100.0 * verdicts[name].count("biased") / len(verdicts[name])
        table.add_row(name, f"{mean_pc:.4f}", f"{mean_p:.2e}", f"{pct_biased:.1f}%", expected[name])
        results["experiment_2"][name] = {
            "mean_popcount": mean_pc,
            "mean_msb_p": mean_p,
            "pct_biased": pct_biased,
            "expected_verdict": expected[name],
        }
    console.print(table)


def experiment_3_wire_size(results: dict):
    header("Experiment 3: Wire Size Analysis (validates Table IV)")
    table = Table(show_header=True, header_style="bold magenta")
    for col in ["Scheme", "client_msg", "server_msg"]:
        table.add_column(col)

    results["experiment_3"] = {}

    obfs4 = Obfs4Baseline()
    cmsg, _ = obfs4.client_hello(os.urandom(32), os.urandom(20))
    smsg, _ = obfs4.server_hello(cmsg, None, os.urandom(20))
    table.add_row("obfs4_baseline", str(len(cmsg)), str(len(smsg)))
    results["experiment_3"]["obfs4_baseline"] = {"client": len(cmsg), "server": len(smsg)}

    for k in (512, 768, 1024):
        hs = PQObfsHandshake(k)
        pk, sk, nid = hs.generate_bridge_identity()
        cmsg, state = hs.client_hello(pk, nid)
        smsg, _ = hs.server_hello(cmsg, sk, nid)
        table.add_row(f"pq-obfs-{k}", str(len(cmsg)), str(len(smsg)))
        results["experiment_3"][f"pq-obfs-{k}"] = {"client": len(cmsg), "server": len(smsg)}

    console.print(table)


def experiment_4_segmentation(results: dict):
    header("Experiment 4: TCP Segmentation (validates Table V)")
    table = Table(show_header=True, header_style="bold magenta")
    for col in ["Scheme", "msg_len", "num_segments", "segments"]:
        table.add_column(col)

    results["experiment_4"] = {}
    for name, length in PAPER_TABLE_V.items():
        segs = tcp_segments(length)
        table.add_row(name, str(length), str(len(segs)), str(segs))
        results["experiment_4"][name] = {
            "length": length,
            "num_segments": len(segs),
            "segments": segs,
        }
    console.print(table)


def experiment_5_evasion(results: dict):
    header("Experiment 5: Classifier Evasion Rate")
    mlkem, kem = MLKEM(768), Kemeleon(768)
    coeff_len = 768 * 12 // 8

    enc_random = 0
    raw_random = 0
    for _ in range(N_EVASION):
        enc = None
        while enc is None:
            pk, _ = mlkem.keygen()
            enc = kem.encode_pk(pk)
        if gfw_classify(enc)["verdict"] == "random":
            enc_random += 1

        pk2, _ = mlkem.keygen()
        if gfw_classify(pk2[:coeff_len], ncoeffs=768)["verdict"] == "random":
            raw_random += 1

    enc_pct = 100.0 * enc_random / N_EVASION
    raw_pct = 100.0 * raw_random / N_EVASION

    table = Table(show_header=True, header_style="bold magenta")
    for col in ["Input", "% classified 'random'", "expected"]:
        table.add_column(col)
    table.add_row("Kemeleon-encoded pk", f"{enc_pct:.1f}%", "~100%")
    table.add_row("raw ML-KEM-768 pk", f"{raw_pct:.1f}%", "~0%")
    console.print(table)

    results["experiment_5"] = {
        "kemeleon_pct_random": enc_pct,
        "raw_mlkem_pct_random": raw_pct,
    }


def main():
    start = time.time()
    lib = "kyber-py (real ML-KEM)" if HAVE_REAL_MLKEM else "built-in simulator"
    console.print(f"[bold green]pq-obfs prototype evaluation[/]  (ML-KEM backend: {lib})\n")

    results = {
        "config": {
            "mlkem_backend": lib,
            "n_rejection": N_REJECTION,
            "n_distribution": N_DIST,
            "n_evasion": N_EVASION,
            "lcover": LCOVER,
        }
    }

    experiment_1_rejection(results)
    experiment_2_distribution(results)
    experiment_3_wire_size(results)
    experiment_4_segmentation(results)
    experiment_5_evasion(results)

    with open("results.json", "w") as f:
        json.dump(results, f, indent=2)

    elapsed = time.time() - start
    console.print(f"\n[dim]Elapsed: {elapsed:.1f}s[/]")
    console.print("All experiments complete. Results saved to results.json")


if __name__ == "__main__":
    main()
