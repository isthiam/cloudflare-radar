# -*- coding: utf-8 -*-
"""
make_graphs_radar_layer3_bytes.py

Génère des graphes d'illustration pour l'analyse Cloudflare Radar L3 (bytes):
1) Série temporelle log1p(bytes) par pays
2) Scatter alpha vs H (H_median)
3) Boxplot des incréments Δlog1p(bytes)
4) Courbes H(n) par pays (à partir du fichier detail)

Entrées attendues (dans le même dossier par défaut):
- radar_attacks_l3_bytes_daily_by_country.csv
- hurst_results_layer3_bytes_daily.csv
- hurst_detail_layer3_bytes_daily.csv

Sorties:
- figures/01_timeseries_logbytes.png
- figures/02_alpha_vs_H.png
- figures/03_boxplot_dlogbytes.png
- figures/04_H_by_scale.png
"""

from __future__ import annotations

from pathlib import Path
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


def load_inputs(data_csv: Path, res_csv: Path, det_csv: Path) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    df = pd.read_csv(data_csv, parse_dates=["date"])
    if "country" not in df.columns:
        # fallback éventuel
        if "country_iso3" in df.columns:
            df = df.rename(columns={"country_iso3": "country"})
        else:
            raise ValueError("Le fichier data doit contenir une colonne 'country' (ou 'country_iso3').")

    # bytes col
    if "attack_bytes" not in df.columns:
        raise ValueError("Le fichier data doit contenir la colonne 'attack_bytes'.")

    df = df.sort_values(["country", "date"]).reset_index(drop=True)
    df["log_bytes"] = np.log1p(df["attack_bytes"].astype(float))

    res = pd.read_csv(res_csv)
    # colonnes attendues: country, alpha, H_median
    for col in ("country", "alpha", "H_median"):
        if col not in res.columns:
            raise ValueError(f"Le fichier results doit contenir la colonne '{col}'.")

    det = pd.read_csv(det_csv)
    # colonnes attendues: country, n, H
    for col in ("country", "n", "H"):
        if col not in det.columns:
            raise ValueError(f"Le fichier detail doit contenir la colonne '{col}'.")

    return df, res, det


def plot_timeseries(df: pd.DataFrame, outpath: Path) -> None:
    plt.figure(figsize=(12, 5))
    for c, sub in df.groupby("country"):
        plt.plot(sub["date"], sub["log_bytes"], label=c, alpha=0.85)

    plt.title("Attaques L3 quotidiennes – log(1 + bytes)")
    plt.xlabel("Date")
    plt.ylabel("log(1 + bytes)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(outpath, dpi=200)
    plt.close()


def plot_alpha_vs_H(res: pd.DataFrame, outpath: Path) -> None:
    plt.figure(figsize=(6.5, 6.5))

    # Repères
    plt.axhline(0, linestyle="--", linewidth=1)  # H=0
    plt.axvline(2, linestyle="--", linewidth=1)  # alpha=2

    # Points
    plt.scatter(res["alpha"], res["H_median"], s=90)

    # Labels pays
    for _, r in res.iterrows():
        a = float(r["alpha"])
        h = float(r["H_median"])
        lab = str(r["country"])
        if np.isfinite(a) and np.isfinite(h):
            plt.text(a + 0.03, h, lab)

    plt.title("Synthèse : queues lourdes (α) vs mémoire (H)")
    plt.xlabel("Indice de queue α (Hill)")
    plt.ylabel("Hurst H (médiane)")
    plt.tight_layout()
    plt.savefig(outpath, dpi=220)
    plt.close()


def plot_boxplot_increments(df: pd.DataFrame, outpath: Path) -> None:
    # Δ log(1+bytes)
    data = []
    labels = []
    for c, sub in df.groupby("country"):
        y = sub["log_bytes"].to_numpy(dtype=float)
        dy = np.diff(y)
        dy = dy[np.isfinite(dy)]
        if len(dy) == 0:
            continue
        data.append(dy)
        labels.append(c)

    if not data:
        raise ValueError("Aucun incrément disponible pour boxplot.")

    plt.figure(figsize=(10, 4.8))
    plt.boxplot(data, labels=labels, showfliers=False)
    plt.title("Distribution des incréments – Δ log(1 + bytes)")
    plt.xlabel("Pays")
    plt.ylabel("Δ log(1 + bytes)")
    plt.tight_layout()
    plt.savefig(outpath, dpi=220)
    plt.close()


def plot_H_by_scale(det: pd.DataFrame, outpath: Path) -> None:
    plt.figure(figsize=(10, 5))
    for c, sub in det.groupby("country"):
        sub = sub.sort_values("n")
        plt.plot(sub["n"], sub["H"], marker="o", label=c, alpha=0.9)

    plt.axhline(0, linestyle="--", linewidth=1)
    plt.title("H(n) par échelle dyadique")
    plt.xlabel("Échelle n (2^n points)")
    plt.ylabel("H estimé")
    plt.legend()
    plt.tight_layout()
    plt.savefig(outpath, dpi=220)
    plt.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="radar_attacks_l3_bytes_daily_by_country.csv", help="CSV data bytes daily")
    ap.add_argument("--results", default="hurst_results_layer3_bytes_daily.csv", help="CSV results alpha/H")
    ap.add_argument("--detail", default="hurst_detail_layer3_bytes_daily.csv", help="CSV detail H(n)")
    ap.add_argument("--outdir", default="figures", help="Dossier de sortie des figures")
    args = ap.parse_args()

    data_csv = Path(args.data)
    res_csv = Path(args.results)
    det_csv = Path(args.detail)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df, res, det = load_inputs(data_csv, res_csv, det_csv)

    plot_timeseries(df, outdir / "01_timeseries_logbytes.png")
    plot_alpha_vs_H(res, outdir / "02_alpha_vs_H.png")
    plot_boxplot_increments(df, outdir / "03_boxplot_dlogbytes.png")
    plot_H_by_scale(det, outdir / "04_H_by_scale.png")

    print("\n✅ Figures générées dans :", outdir.resolve())
    for p in sorted(outdir.glob("*.png")):
        print(" -", p.name)


if __name__ == "__main__":
    main()
