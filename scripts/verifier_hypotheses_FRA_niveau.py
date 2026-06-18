# -*- coding: utf-8 -*-
"""
Vérification des hypothèses du papier – FRA (Cloudflare Radar, L3 bytes daily)
ESTIMATION DE H "PAPIER-CONFORME" SUR LE NIVEAU:
    Y_t = log(1 + bytes_t)

Diagnostics supplémentaires:
- Stationnarité des incréments dY (ADF + KPSS)
- ACF / PACF sur incréments dY
- Scaling multi-échelle (p-variations) sur le NIVEAU Y
- Stabilité temporelle (rolling H) sur le NIVEAU Y
- Queue lourde (Hill alpha) sur incréments dY (diagnostic)

Exports:
- fra_H_by_scale.csv
- fra_H_rolling.csv
- PNG diagnostics (série, rolling stats, ACF/PACF, logV vs n, H(n), rolling H, tail plot)
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
OUT_DIR  = r"E:\\Webscraping\\cloudflare_radar_vulnerabilite\\outputs_fra_hypotheses_niveau"

COUNTRY_ISO3 = "FRA"
DATE_COL = "date"
COUNTRY_COL = "country"

# le nom exact de la colonne bytes dans mon CSV
VALUE_COL = "attack_bytes"

# p-variations / H (sur le niveau Y)
R = 1
N_MIN = 5
N_MAX = 9   # borné automatiquement par la longueur
P_FIXED = 1.5

# Rolling-H (sur niveau Y)
ROLL_WINDOW_DAYS = 180
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

def safe_adf(x: np.ndarray) -> tuple[float, float]:
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

def hill_alpha_hat(x: np.ndarray, k: int | None = None) -> float:
    
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
    """
    V_{n,p}^{(r)} sur une trajectoire discrète.
    Besoin de 2^n + 1 points.
    """
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
    return float(np.mean(np.abs(inc) ** p))

def hurst_by_scales(signal: np.ndarray, p: float, r: int, n_min: int, n_max: int) -> pd.DataFrame:
    """
    H~_{n,p}^{(r)} = (1/(r p)) log2( V^{(r)} / V^{(0)} )
    """
    rows = []
    for n in range(n_min, n_max + 1):
        V0 = p_variation(signal, n=n, p=p, r=0)
        Vr = p_variation(signal, n=n, p=p, r=r)
        if not (np.isfinite(V0) and np.isfinite(Vr)) or V0 <= 0 or Vr <= 0:
            continue
        H = (1.0 / (r * p)) * np.log2(Vr / V0)
        rows.append({"n": n, "V0": V0, "Vr": Vr, "H_tilde": H})
    return pd.DataFrame(rows)

def rolling_H(signal: np.ndarray, dates: pd.Series, p: float, r: int, n_min: int, n_max: int,
              window: int, step: int) -> pd.DataFrame:
    """
    H médian sur fenêtres glissantes (niveau Y)
    """
    rows = []
    N = len(signal)
    for start in range(0, N - window + 1, step):
        seg = signal[start:start + window]
        max_possible = compute_n_max_from_length(len(seg))
        n_max_used = min(n_max, max_possible)
        n_min_used = min(n_min, n_max_used)
        det = hurst_by_scales(seg, p=p, r=r, n_min=n_min_used, n_max=n_max_used)
        Hmed = float(np.median(det["H_tilde"].values)) if not det.empty else float("nan")
        rows.append({
            "start_date": dates.iloc[start],
            "end_date": dates.iloc[start + window - 1],
            "H_median": Hmed,
            "n_min_used": n_min_used,
            "n_max_used": n_max_used
        })
    return pd.DataFrame(rows)


# ======================
# programme principal
# ======================
def main():
    out_dir = ensure_dir(OUT_DIR)

    df = pd.read_csv(CSV_PATH, parse_dates=[DATE_COL])
    df.columns = [c.strip() for c in df.columns]
    df[COUNTRY_COL] = df[COUNTRY_COL].astype(str).str.upper().str.strip()

    if VALUE_COL not in df.columns:
        raise ValueError(f"Colonne '{VALUE_COL}' introuvable. Colonnes disponibles: {list(df.columns)}")

    fra = df[df[COUNTRY_COL] == COUNTRY_ISO3].copy()
    if fra.empty:
        raise ValueError(f"Aucune ligne pour {COUNTRY_ISO3} dans le CSV.")

    fra = fra.sort_values(DATE_COL)
    fra[VALUE_COL] = pd.to_numeric(fra[VALUE_COL], errors="coerce")
    fra = fra.dropna(subset=[VALUE_COL]).reset_index(drop=True)

    dates = fra[DATE_COL]

    # NIVEAU (papier-conforme)
    fra["Y_log1p"] = np.log1p(fra[VALUE_COL].values.astype(float))
    Y = fra["Y_log1p"].values
    n_obs_level = len(Y)

    # INCRÉMENTS (diagnostics stationnarité + ACF/PACF + alpha)
    fra["dY"] = fra["Y_log1p"].diff()
    fra_inc = fra.dropna(subset=["dY"]).reset_index(drop=True)
    dY = fra_inc["dY"].values
    dates_inc = fra_inc[DATE_COL]
    n_obs_inc = len(dY)

    # --------------------------
    # (1) Stationnarité des incréments dY
    # --------------------------
    adf_stat, adf_p = safe_adf(dY)
    kpss_stat, kpss_p = safe_kpss(dY)

    # Rolling stats sur dY
    roll_mean = fra_inc["dY"].rolling(30).mean()
    roll_std  = fra_inc["dY"].rolling(30).std()

    plt.figure()
    plt.plot(dates, Y)
    plt.title("FRA – Niveau Y = log(1+bytes)")
    plt.xlabel("Date"); plt.ylabel("log1p(bytes)")
    plt.tight_layout()
    plt.savefig(out_dir / "01_fra_level_log1p.png", dpi=160)
    plt.close()

    plt.figure()
    plt.plot(dates_inc, dY)
    plt.title("FRA – Incréments dY")
    plt.xlabel("Date"); plt.ylabel("dlog1p(bytes)")
    plt.tight_layout()
    plt.savefig(out_dir / "02_fra_increments_dY.png", dpi=160)
    plt.close()

    plt.figure()
    plt.plot(dates_inc, roll_mean, label="rolling mean (30j)")
    plt.plot(dates_inc, roll_std, label="rolling std (30j)")
    plt.title("FRA – Rolling stats sur dY (30 jours)")
    plt.xlabel("Date")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_dir / "03_fra_rolling_stats_dY.png", dpi=160)
    plt.close()

    # --------------------------
    # (2) ACF / PACF sur dY
    # --------------------------
    fig = plt.figure()
    plot_acf(dY, lags=30)
    plt.title("FRA – ACF des incréments dY")
    plt.tight_layout()
    plt.savefig(out_dir / "04_fra_acf_dY.png", dpi=160)
    plt.close(fig)

    fig = plt.figure()
    plot_pacf(dY, lags=30, method="ywm")
    plt.title("FRA – PACF des incréments dY")
    plt.tight_layout()
    plt.savefig(out_dir / "05_fra_pacf_dY.png", dpi=160)
    plt.close(fig)

    # --------------------------
    # (3) Scaling / autosimilarité via p-variations SUR LE NIVEAU Y
    # --------------------------
    max_possible = compute_n_max_from_length(n_obs_level)
    n_max_used = min(N_MAX, max_possible)
    n_min_used = min(N_MIN, n_max_used)

    detail = hurst_by_scales(Y, p=P_FIXED, r=R, n_min=n_min_used, n_max=n_max_used)
    H_median = float(np.median(detail["H_tilde"].values)) if not detail.empty else float("nan")

    detail.to_csv(out_dir / "fra_H_by_scale.csv", index=False, encoding="utf-8")

    if not detail.empty:
        plt.figure()
        plt.plot(detail["n"], np.log2(detail["V0"]), marker="o")
        plt.title(f"FRA – log2(V0) vs n (niveau Y, p={P_FIXED})")
        plt.xlabel("n (échelle dyadique)"); plt.ylabel("log2(V0)")
        plt.tight_layout()
        plt.savefig(out_dir / "06_fra_logV0_vs_n_level.png", dpi=160)
        plt.close()

        plt.figure()
        plt.plot(detail["n"], detail["H_tilde"], marker="o")
        plt.axhline(H_median, linestyle="--")
        plt.title(f"FRA – H~(n) par échelle (niveau Y) – médiane={H_median:.3f}")
        plt.xlabel("n"); plt.ylabel("H~")
        plt.tight_layout()
        plt.savefig(out_dir / "07_fra_H_by_scale_level.png", dpi=160)
        plt.close()

    # --------------------------
    # (4) Processus pur : Rolling H SUR LE NIVEAU Y
    # --------------------------
    Hroll = rolling_H(
        signal=Y,
        dates=dates,
        p=P_FIXED,
        r=R,
        n_min=N_MIN,
        n_max=N_MAX,
        window=ROLL_WINDOW_DAYS,
        step=ROLL_STEP_DAYS
    )
    Hroll.to_csv(out_dir / "fra_H_rolling.csv", index=False, encoding="utf-8")

    plt.figure()
    plt.plot(Hroll["start_date"], Hroll["H_median"], marker="o")
    plt.title(f"FRA – Rolling H médian (niveau Y) – fenêtre={ROLL_WINDOW_DAYS}j, step={ROLL_STEP_DAYS}j")
    plt.xlabel("Début fenêtre"); plt.ylabel("H_median")
    plt.tight_layout()
    plt.savefig(out_dir / "08_fra_H_rolling_level.png", dpi=160)
    plt.close()

    # --------------------------
    # (5) Queue lourde / alpha plausible (diagnostic sur incréments dY)
    # --------------------------
    alpha_hat = hill_alpha_hat(dY, k=None)

    absx = np.abs(dY[np.isfinite(dY)])
    absx = absx[absx > 0]
    absx_sorted = np.sort(absx)
    qs = np.linspace(0.90, 0.995, 30)
    us = np.quantile(absx_sorted, qs)
    surv = np.array([np.mean(absx > u) for u in us])

    plt.figure()
    plt.plot(np.log(us), np.log(surv), marker="o")
    plt.title("FRA – Tail plot (log survie vs log seuil) sur incréments dY")
    plt.xlabel("log(u)"); plt.ylabel("log P(|dY|>u)")
    plt.tight_layout()
    plt.savefig(out_dir / "09_fra_tail_plot_dY.png", dpi=160)
    plt.close()

    

if __name__ == "__main__":
    main()
