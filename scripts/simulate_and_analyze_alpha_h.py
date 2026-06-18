# -*- coding: utf-8 -*-
"""
simulate_and_analyze_alpha_h.py

Simule des séries "type attaques" puis calcule:
- alpha (Hill) sur |Δ log1p(X)|
- H via ratio de p-variations (multi-échelle)

Scénarios simulés:
A) Baseline: Lognormal i.i.d. (pas de mémoire, queues modérées)
B) Heavy-tail i.i.d.: Pareto i.i.d. (queues lourdes, pas de mémoire)
C) Anti-persistence: AR(1) sur log-intensité avec phi négatif + spikes Pareto
D) Persistence: AR(1) sur log-intensité avec phi positif + spikes Pareto

Sorties:
- simulated_results.csv
- simulated_detail.csv
- figures_sim/01_timeseries.png
- figures_sim/02_alpha_vs_H.png
- figures_sim/03_boxplot_increments.png
- figures_sim/04_H_by_scale.png
"""

from __future__ import annotations

import math
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# =========================
# PARAMS GÉNÉRAUX
# =========================
SEED = 42
N_DAYS = 365
N_MIN = 5
N_MAX = 8
R_USED = 1

MIN_NONZERO = 120
MAX_P_CAP = 1.5

OUTDIR = Path("figures_sim")
OUTDIR.mkdir(parents=True, exist_ok=True)

rng = np.random.default_rng(SEED)


# =========================
# OUTILS ESTIMATION
# =========================
def pick_hill_k(n: int) -> int:
    k = int(math.sqrt(n))
    k = max(30, min(k, n // 5))
    return k


def hill_alpha_hat(dx: np.ndarray, k=None) -> float:
    x = np.asarray(dx, dtype=float)
    x = x[np.isfinite(x)]
    x = np.abs(x)
    x = x[x > 0]

    if len(x) < MIN_NONZERO:
        return float("nan")

    y = np.sort(x)[::-1]
    if k is None:
        k = pick_hill_k(len(y))

    if k <= 2 or k >= len(y) - 2:
        return float("nan")

    yk1 = y[k]
    if yk1 <= 0:
        return float("nan")

    gamma = np.mean(np.log(y[:k]) - np.log(yk1))
    if not np.isfinite(gamma) or gamma <= 0:
        return float("nan")

    return float(1.0 / gamma)


def choose_p(alpha: float) -> float:
    if not np.isfinite(alpha) or alpha <= 0:
        return float("nan")
    p = min(MAX_P_CAP, 0.8 * alpha)
    p = min(p, alpha - 1e-3)
    p = max(0.3, p)
    return float(p) if np.isfinite(p) and p > 0 else float("nan")


def max_n_from_length(L: int) -> int:
    if L <= 2:
        return 0
    return int(math.floor(math.log2(L - 1)))


def p_variation(signal: np.ndarray, n: int, p: float, r: int = 0) -> float:
    N = 2 ** n
    lag = 2 ** r
    if len(signal) < N + 1:
        return float("nan")
    x = signal[: N + 1]
    inc = x[lag:] - x[:-lag]
    if len(inc) == 0:
        return float("nan")
    return float(np.mean(np.abs(inc) ** p))


def hurst_detail(signal: np.ndarray, p: float, r: int, n_min: int, n_max: int):
    rows = []
    for n in range(n_min, n_max + 1):
        V0 = p_variation(signal, n, p, r=0)
        Vr = p_variation(signal, n, p, r=r)
        if np.isfinite(V0) and np.isfinite(Vr) and V0 > 0 and Vr > 0:
            H = (1.0 / (r * p)) * np.log2(Vr / V0)
            rows.append((n, H, V0, Vr))
    return rows


def analyze_series(x_level: np.ndarray, name: str) -> tuple[dict, pd.DataFrame]:
    """
    Pipeline identique à Cloudflare:
    y = log1p(x_level)
    dy = diff(y)
    alpha = Hill(|dy|)
    p = choose_p(alpha)
    H(n) via ratio p-variations (r=1)
    """
    y = np.log1p(np.asarray(x_level, dtype=float))
    dy = np.diff(y)
    dy = dy[np.isfinite(dy)]
    n_obs = len(dy)

    alpha = hill_alpha_hat(dy)
    p = choose_p(alpha)

    n_max_possible = max_n_from_length(n_obs)
    n_min = min(N_MIN, n_max_possible)
    n_max = min(N_MAX, n_max_possible)

    if not np.isfinite(p) or n_max < 5 or n_max < n_min:
        summary = {
            "series": name,
            "n_obs": n_obs,
            "alpha": alpha,
            "p_used": p,
            "n_min": np.nan,
            "n_max": np.nan,
            "H_median": np.nan,
            "H_mean": np.nan,
            "H_min": np.nan,
            "H_max": np.nan,
            "note": "insufficient_scales_or_bad_alpha",
        }
        return summary, pd.DataFrame(columns=["series", "n", "H", "V0", "Vr", "alpha", "p_used"])

    rows = hurst_detail(dy, p=p, r=R_USED, n_min=n_min, n_max=n_max)
    if not rows:
        summary = {
            "series": name,
            "n_obs": n_obs,
            "alpha": alpha,
            "p_used": p,
            "n_min": n_min,
            "n_max": n_max,
            "H_median": np.nan,
            "H_mean": np.nan,
            "H_min": np.nan,
            "H_max": np.nan,
            "note": "no_valid_scales",
        }
        return summary, pd.DataFrame(columns=["series", "n", "H", "V0", "Vr", "alpha", "p_used"])

    Hs = [h for (n, h, v0, vr) in rows]
    summary = {
        "series": name,
        "n_obs": n_obs,
        "alpha": float(alpha),
        "p_used": float(p),
        "n_min": int(n_min),
        "n_max": int(n_max),
        "H_median": float(np.median(Hs)),
        "H_mean": float(np.mean(Hs)),
        "H_min": float(np.min(Hs)),
        "H_max": float(np.max(Hs)),
        "note": "OK",
    }

    detail = pd.DataFrame(
        [
            {
                "series": name,
                "n": int(n),
                "H": float(h),
                "V0": float(v0),
                "Vr": float(vr),
                "alpha": float(alpha),
                "p_used": float(p),
            }
            for (n, h, v0, vr) in rows
        ]
    )
    return summary, detail


# =========================
# SIMULATEURS
# =========================
def sim_lognormal_iid(n: int, mu=8.0, sigma=1.0) -> np.ndarray:
    # intensité >0, queues modérées (lognormal)
    return rng.lognormal(mean=mu, sigma=sigma, size=n)


def sim_pareto_iid(n: int, alpha=1.6, xm=1.0, scale=1e6) -> np.ndarray:
    # Pareto: P(X>t) ~ t^{-alpha}
    u = rng.random(n)
    x = xm * (u ** (-1.0 / alpha))
    return scale * x


def sim_ar1_log_intensity(n: int, phi: float, sigma: float, base=8.0) -> np.ndarray:
    # AR(1) sur log-intensité : z_t = base + phi*(z_{t-1}-base) + eps
    z = np.empty(n)
    z[0] = base + rng.normal(0, sigma)
    for t in range(1, n):
        z[t] = base + phi * (z[t-1] - base) + rng.normal(0, sigma)
    return np.exp(z)  # >0


def add_spikes(x: np.ndarray, spike_prob=0.03, spike_alpha=1.4, spike_scale=1e8) -> np.ndarray:
    n = len(x)
    spikes = rng.random(n) < spike_prob
    if spikes.any():
        # spikes Pareto
        u = rng.random(spikes.sum())
        s = (u ** (-1.0 / spike_alpha)) * spike_scale
        x = x.copy()
        x[spikes] += s
    return x


# =========================
# MAIN
# =========================
def main():
    dates = pd.date_range("2025-01-01", periods=N_DAYS, freq="D")

    series_dict = {}

    # A) baseline: lognormal iid
    series_dict["A_lognormal_iid"] = sim_lognormal_iid(N_DAYS, mu=8.0, sigma=0.8)

    # B) heavy tail iid
    series_dict["B_pareto_iid"] = sim_pareto_iid(N_DAYS, alpha=1.6, scale=2e6)

    # C) anti-persistence (phi négatif) + spikes
    xC = sim_ar1_log_intensity(N_DAYS, phi=-0.45, sigma=0.35, base=8.0)
    series_dict["C_AR1_neg_phi_spikes"] = add_spikes(xC, spike_prob=0.03, spike_alpha=1.4, spike_scale=5e8)

    # D) persistence (phi positif) + spikes
    xD = sim_ar1_log_intensity(N_DAYS, phi=0.65, sigma=0.25, base=8.0)
    series_dict["D_AR1_pos_phi_spikes"] = add_spikes(xD, spike_prob=0.03, spike_alpha=1.4, spike_scale=5e8)

    # ---- Dataframe long (pour graphes)
    df = pd.concat(
        [
            pd.DataFrame({"date": dates, "series": name, "value": vals})
            for name, vals in series_dict.items()
        ],
        ignore_index=True,
    )

    # ---- Analyse
    summaries = []
    details = []
    for name, vals in series_dict.items():
        summary, det = analyze_series(vals, name=name)
        summaries.append(summary)
        details.append(det)

    res_df = pd.DataFrame(summaries).sort_values("series")
    det_df = pd.concat(details, ignore_index=True) if details else pd.DataFrame()

    res_df.to_csv("simulated_results.csv", index=False, encoding="utf-8")
    det_df.to_csv("simulated_detail.csv", index=False, encoding="utf-8")

    print("\n=== Résultats simulés (log1p -> diff) ===")
    print(res_df.to_string(index=False))
    print("\nExports: simulated_results.csv, simulated_detail.csv")

    # =========================
    # FIG 1: timeseries log1p
    # =========================
    plt.figure(figsize=(12, 5))
    for name in series_dict.keys():
        sub = df[df["series"] == name].copy()
        plt.plot(sub["date"], np.log1p(sub["value"]), label=name, alpha=0.85)
    plt.title("Séries simulées – log(1 + value)")
    plt.xlabel("Date")
    plt.ylabel("log(1 + value)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUTDIR / "01_timeseries.png", dpi=200)
    plt.close()

    # =========================
    # FIG 2: alpha vs H
    # =========================
    plt.figure(figsize=(7, 6))
    plt.axhline(0, linestyle="--", linewidth=1)
    plt.axvline(2, linestyle="--", linewidth=1)

    plt.scatter(res_df["alpha"], res_df["H_median"], s=90)
    for _, r in res_df.iterrows():
        a = r["alpha"]
        h = r["H_median"]
        if np.isfinite(a) and np.isfinite(h):
            plt.text(a + 0.03, h, r["series"], fontsize=9)

    plt.title("Simulations : queues lourdes (α) vs mémoire (H)")
    plt.xlabel("Indice de queue α (Hill)")
    plt.ylabel("Hurst H (médiane)")
    plt.tight_layout()
    plt.savefig(OUTDIR / "02_alpha_vs_H.png", dpi=220)
    plt.close()

    # =========================
    # FIG 3: boxplot increments
    # =========================
    data = []
    labels = []
    for name in series_dict.keys():
        y = np.log1p(series_dict[name])
        dy = np.diff(y)
        dy = dy[np.isfinite(dy)]
        data.append(dy)
        labels.append(name)

    plt.figure(figsize=(12, 4.8))
    plt.boxplot(data, labels=labels, showfliers=False)
    plt.axhline(0, linewidth=1)
    plt.title("Distribution des incréments – Δ log(1 + value)")
    plt.ylabel("Δ log(1 + value)")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(OUTDIR / "03_boxplot_increments.png", dpi=220)
    plt.close()

    # =========================
    # FIG 4: H(n) par échelle
    # =========================
    if not det_df.empty:
        plt.figure(figsize=(10, 5))
        for name, sub in det_df.groupby("series"):
            sub = sub.sort_values("n")
            plt.plot(sub["n"], sub["H"], marker="o", label=name, alpha=0.9)
        plt.axhline(0, linestyle="--", linewidth=1)
        plt.title("H(n) par échelle dyadique – simulations")
        plt.xlabel("Échelle n (2^n points)")
        plt.ylabel("H estimé")
        plt.legend(fontsize=8)
        plt.tight_layout()
        plt.savefig(OUTDIR / "04_H_by_scale.png", dpi=220)
        plt.close()

    print("\n✅ Figures dans :", OUTDIR.resolve())
    for p in sorted(OUTDIR.glob("*.png")):
        print(" -", p.name)


if __name__ == "__main__":
    main()
