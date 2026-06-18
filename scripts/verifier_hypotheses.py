# -*- coding: utf-8 -*-
"""
Vérification des hypothèses du papier sur Cloudflare Radar (GBR)
- Série: attaques L3 bytes (daily)
- Pré-traitement: log1p(bytes) puis incréments
- Tests/diagnostics:
  1) Stationnarité des incréments (rolling stats + ADF/KPSS)
  2) Faible dépendance court terme (ACF/PACF)
  3) Scaling / autosimilarité (p-variations log-log + stabilité de H(n))
  4) Processus "pur" (stabilité de H dans le temps via fenêtres glissantes)
  5) Queue lourde / alpha plausible (Hill + tail plot)
Exports:
  - gbr_hypotheses_summary.txt
  - gbr_pvariations.csv
  - gbr_H_by_scale.csv
  - gbr_H_rolling.csv
  - PNG: diagnostics
"""

from __future__ import annotations
import math
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from statsmodels.tsa.stattools import adfuller, kpss
from statsmodels.graphics.tsaplots import plot_acf, plot_pacf


# ======================
# PARAMÈTRES
# ======================
CSV_PATH = r"E:\\Webscraping\\cloudflare_radar_vulnerabilite\\radar_attacks_l3_bytes_daily_by_country.csv"
OUT_DIR  = r"E:\\Webscraping\\cloudflare_radar_vulnerabilite\\outputs_gbr_hypotheses"
COUNTRY_ISO3 = "FRA"

DATE_COL = "date"
COUNTRY_COL = "country"
VALUE_COL = "attack_bytes"   # <-- change si besoin (ex: "attack_bytes" etc.)

# p-variations / H
R = 1                # ratio échelle 2^R (souvent 1)
N_MIN = 5
N_MAX = 9            # sera borné automatiquement
# Choix p (papier: p < alpha si alpha-stable). En pratique pour bytes log1p, p=1 ou 1.5 marche bien.
P_FIXED = 1.5

# Rolling window pour tester "processus pur"
ROLL_WINDOW_DAYS = 120
ROLL_STEP_DAYS = 14


# ======================
# UTILITAIRES
# ======================
def ensure_dir(p: str | Path) -> Path:
    p = Path(p)
    p.mkdir(parents=True, exist_ok=True)
    return p

def compute_n_max_from_length(length: int) -> int:
    # besoin de 2^n + 1 points
    if length <= 2:
        return 0
    return int(math.floor(math.log2(length - 1)))

def hill_alpha_hat(x: np.ndarray, k: int | None = None) -> float:
    """
    Hill estimator sur |x| (queues). Renvoie alpha_hat.
    Attention: c'est un diagnostic "queue lourde" pratique, pas une preuve.
    """
    x = np.asarray(x, dtype=float)
    x = x[np.isfinite(x)]
    x = np.abs(x)
    x = x[x > 0]
    if len(x) < 200:
        return float("nan")

    y = np.sort(x)[::-1]
    n = len(y)
    if k is None:
        k = int(math.sqrt(n))
        k = max(50, min(k, n // 5))

    if k <= 5 or k >= n - 1:
        return float("nan")

    yk1 = y[k]
    if yk1 <= 0:
        return float("nan")

    gamma_hat = np.mean(np.log(y[:k]) - np.log(yk1))
    if not np.isfinite(gamma_hat) or gamma_hat <= 0:
        return float("nan")
    return float(1.0 / gamma_hat)

def p_variation(signal: np.ndarray, n: int, p: float, r: int = 0) -> float:
    x = np.asarray(signal, dtype=float)
    N = 2 ** n
    lag = 2 ** r
    needed = N + 1
    if len(x) < needed:
        return float("nan")
    x = x[:needed]
    inc = x[lag:] - x[:-lag]
    if len(inc) == 0:
        return float("nan")
    V = np.mean(np.abs(inc) ** p)
    return float(V)

def hurst_by_scales(signal: np.ndarray, p: float, r: int, n_min: int, n_max: int) -> pd.DataFrame:
    rows = []
    for n in range(n_min, n_max + 1):
        V0 = p_variation(signal, n=n, p=p, r=0)
        Vr = p_variation(signal, n=n, p=p, r=r)
        if not (np.isfinite(V0) and np.isfinite(Vr)) or V0 <= 0 or Vr <= 0:
            continue
        H = (1.0 / (r * p)) * np.log2(Vr / V0)
        rows.append({"n": n, "V0": V0, "Vr": Vr, "H_tilde": H})
    return pd.DataFrame(rows)

def safe_adf(x: np.ndarray) -> tuple[float, float]:
    # retourne (stat, pvalue)
    x = np.asarray(x, dtype=float)
    x = x[np.isfinite(x)]
    if len(x) < 50:
        return (float("nan"), float("nan"))
    stat, pval, *_ = adfuller(x, autolag="AIC")
    return float(stat), float(pval)

def safe_kpss(x: np.ndarray) -> tuple[float, float]:
    x = np.asarray(x, dtype=float)
    x = x[np.isfinite(x)]
    if len(x) < 50:
        return (float("nan"), float("nan"))
    stat, pval, *_ = kpss(x, regression="c", nlags="auto")
    return float(stat), float(pval)

def rolling_H(signal: np.ndarray, dates: pd.Series, p: float, r: int, n_min: int, n_max: int,
              window: int, step: int) -> pd.DataFrame:
    """
    H médian sur fenêtres glissantes (pour détecter mélange/régimes)
    signal = série (ici incréments ou log)
    """
    rows = []
    N = len(signal)
    for start in range(0, N - window + 1, step):
        seg = signal[start:start+window]
        max_possible = compute_n_max_from_length(len(seg))
        n_max_used = min(n_max, max_possible)
        n_min_used = min(n_min, n_max_used)
        det = hurst_by_scales(seg, p=p, r=r, n_min=n_min_used, n_max=n_max_used)
        if det.empty:
            Hmed = float("nan")
        else:
            Hmed = float(np.median(det["H_tilde"].values))
        rows.append({
            "start_date": dates.iloc[start],
            "end_date": dates.iloc[start+window-1],
            "H_median": Hmed,
            "n_min_used": n_min_used,
            "n_max_used": n_max_used
        })
    return pd.DataFrame(rows)


# ======================
# MAIN
# ======================
def main():
    out_dir = ensure_dir(OUT_DIR)

    df = pd.read_csv(CSV_PATH, parse_dates=[DATE_COL])
    df.columns = [c.strip() for c in df.columns]
    df[COUNTRY_COL] = df[COUNTRY_COL].astype(str).str.upper().str.strip()

    if VALUE_COL not in df.columns:
        raise ValueError(f"Colonne '{VALUE_COL}' introuvable. Colonnes disponibles: {list(df.columns)}")

    gbr = df[df[COUNTRY_COL] == COUNTRY_ISO3].copy()
    if gbr.empty:
        raise ValueError(f"Aucune ligne pour {COUNTRY_ISO3} dans le CSV.")

    gbr = gbr.sort_values(DATE_COL)
    gbr[VALUE_COL] = pd.to_numeric(gbr[VALUE_COL], errors="coerce")
    gbr = gbr.dropna(subset=[VALUE_COL])

    # Pré-traitement (bytes -> log1p)
    gbr["log1p_bytes"] = np.log1p(gbr[VALUE_COL].values.astype(float))

    # Incréments (objet principal pour stationnarité)
    gbr["dlog1p_bytes"] = gbr["log1p_bytes"].diff()
    gbr = gbr.dropna(subset=["dlog1p_bytes"]).reset_index(drop=True)

    dates = gbr[DATE_COL]
    x = gbr["dlog1p_bytes"].values
    n_obs = len(x)

    # --------------------------
    # (1) Stationnarité incréments
    # --------------------------
    adf_stat, adf_p = safe_adf(x)
    kpss_stat, kpss_p = safe_kpss(x)

    # Rolling stats
    roll_mean = gbr["dlog1p_bytes"].rolling(30).mean()
    roll_std  = gbr["dlog1p_bytes"].rolling(30).std()

    plt.figure()
    plt.plot(dates, gbr["dlog1p_bytes"].values)
    plt.title("GBR – Incréments dlog(1+bytes)")
    plt.xlabel("Date"); plt.ylabel("dlog1p(bytes)")
    plt.tight_layout()
    plt.savefig(out_dir / "01_gbr_dlog_series.png", dpi=160)
    plt.close()

    plt.figure()
    plt.plot(dates, roll_mean, label="rolling mean (30j)")
    plt.plot(dates, roll_std, label="rolling std (30j)")
    plt.title("GBR – Rolling stats sur dlog(1+bytes)")
    plt.xlabel("Date")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_dir / "02_gbr_rolling_stats.png", dpi=160)
    plt.close()

    # --------------------------
    # (2) ACF / PACF
    # --------------------------
    fig = plt.figure()
    plot_acf(x, lags=30)
    plt.title("GBR – ACF des incréments dlog(1+bytes)")
    plt.tight_layout()
    plt.savefig(out_dir / "03_gbr_acf.png", dpi=160)
    plt.close(fig)

    fig = plt.figure()
    plot_pacf(x, lags=30, method="ywm")
    plt.title("GBR – PACF des incréments dlog(1+bytes)")
    plt.tight_layout()
    plt.savefig(out_dir / "04_gbr_pacf.png", dpi=160)
    plt.close(fig)

    # --------------------------
    # (3) Scaling / autosimilarité (p-variations)
    # --------------------------
    max_possible = compute_n_max_from_length(n_obs)
    n_max_used = min(N_MAX, max_possible)
    n_min_used = min(N_MIN, n_max_used)

    detail = hurst_by_scales(x, p=P_FIXED, r=R, n_min=n_min_used, n_max=n_max_used)
    if detail.empty:
        H_median = float("nan")
    else:
        H_median = float(np.median(detail["H_tilde"].values))

    # log-log p-variations (diagnostic scaling)
    # On regarde log2(V0) vs n (puisqu’échelle ~ 2^n)
    if not detail.empty:
        plt.figure()
        plt.plot(detail["n"], np.log2(detail["V0"]), marker="o")
        plt.title(f"GBR – log2(V0) vs n (p={P_FIXED})")
        plt.xlabel("n (échelle dyadique)"); plt.ylabel("log2(V0)")
        plt.tight_layout()
        plt.savefig(out_dir / "05_gbr_logV0_vs_n.png", dpi=160)
        plt.close()

        plt.figure()
        plt.plot(detail["n"], detail["H_tilde"], marker="o")
        plt.axhline(H_median, linestyle="--")
        plt.title(f"GBR – H~(n) par échelle (médiane={H_median:.3f})")
        plt.xlabel("n"); plt.ylabel("H~")
        plt.tight_layout()
        plt.savefig(out_dir / "06_gbr_H_by_scale.png", dpi=160)
        plt.close()

    detail.to_csv(out_dir / "gbr_H_by_scale.csv", index=False, encoding="utf-8")

    # --------------------------
    # (4) Processus "pur" : H rolling
    # --------------------------
    Hroll = rolling_H(
        signal=x,
        dates=dates,
        p=P_FIXED,
        r=R,
        n_min=N_MIN,
        n_max=N_MAX,
        window=ROLL_WINDOW_DAYS,
        step=ROLL_STEP_DAYS
    )
    Hroll.to_csv(out_dir / "gbr_H_rolling.csv", index=False, encoding="utf-8")

    plt.figure()
    plt.plot(Hroll["start_date"], Hroll["H_median"], marker="o")
    plt.title(f"GBR – H médian (rolling {ROLL_WINDOW_DAYS}j, step {ROLL_STEP_DAYS}j)")
    plt.xlabel("Début fenêtre"); plt.ylabel("H_median")
    plt.tight_layout()
    plt.savefig(out_dir / "07_gbr_H_rolling.png", dpi=160)
    plt.close()

    # --------------------------
    # (5) Queue lourde / alpha plausible
    # --------------------------
    alpha_hat = hill_alpha_hat(x, k=None)

    # Tail plot: log P(|X|>u) vs log u (diagnostic de queue lourde)
    absx = np.abs(x[np.isfinite(x)])
    absx = absx[absx > 0]
    absx_sorted = np.sort(absx)
    # seuils sur quantiles élevés
    qs = np.linspace(0.90, 0.995, 30)
    us = np.quantile(absx_sorted, qs)
    surv = np.array([np.mean(absx > u) for u in us])

    plt.figure()
    plt.plot(np.log(us), np.log(surv), marker="o")
    plt.title("GBR – Tail plot (log survie vs log seuil)")
    plt.xlabel("log(u)"); plt.ylabel("log P(|X|>u)")
    plt.tight_layout()
    plt.savefig(out_dir / "08_gbr_tail_plot.png", dpi=160)
    plt.close()

    # --------------------------
    # Rapport texte (résumé)
    # --------------------------
    lines = []
    lines.append("=== Vérification hypothèses papier – GBR (Cloudflare Radar, L3 bytes daily) ===\n")
    lines.append(f"Observations (incréments) : n_obs={n_obs}\n")
    lines.append("Pré-traitement : log1p(bytes) puis dlog1p\n\n")

    lines.append("1) Stationnarité des incréments\n")
    lines.append(f"   - ADF p-value  : {adf_p:.4g} (p<0.05 => stationnaire)\n")
    lines.append(f"   - KPSS p-value : {kpss_p:.4g} (p>0.05 => stationnaire)\n\n")

    lines.append("2) Dépendance court terme (ACF/PACF)\n")
    lines.append("   - Vérifier visuellement: peu de lags significatifs + décroissance rapide.\n\n")

    lines.append("3) Scaling / autosimilarité (p-variations)\n")
    lines.append(f"   - p fixé={P_FIXED}, r={R}, échelles n=[{n_min_used},{n_max_used}]\n")
    lines.append(f"   - H médian (sur échelles) : {H_median:.4f}\n")
    lines.append("   - Vérifier: log2(V0) vs n ~ quasi-linéaire + H(n) stable.\n\n")

    lines.append("4) Processus pur (monofractal)\n")
    lines.append(f"   - Rolling H : fenêtre={ROLL_WINDOW_DAYS} jours, pas={ROLL_STEP_DAYS} jours\n")
    lines.append("   - Vérifier: H_median ne change pas brutalement (ruptures/régimes).\n\n")

    lines.append("5) Queue lourde / α-stable plausible\n")
    lines.append(f"   - Hill alpha_hat : {alpha_hat:.4f}\n")
    lines.append("   - Attendu papier: 1 < α < 2 (si on vise strictement α-stable)\n")
    lines.append("   - Vérifier: tail plot approx linéaire en log-log (diagnostic).\n\n")

    lines.append("Fichiers générés (PNG/CSV) dans :\n")
    lines.append(str(out_dir) + "\n")

    (out_dir / "gbr_hypotheses_summary_FRA.txt").write_text("".join(lines), encoding="utf-8")

    print("\n".join(lines))


if __name__ == "__main__":
    main()
