# -*- coding: utf-8 -*-
"""
simulate_paper_processes.py

Séries simulées qui vérifient les conditions classiques "papier":
1) fBm (fractional Brownian motion) -> H in (0,1)
2) Lévy motion alpha-stable (SαS)    -> alpha in (0,2]

Estimations:
- H via ratio de p-variations (comme ton estimateur)
- alpha via Hill sur |increments| (attention: Hill n'est pas "l'alpha théorique" parfait,
  mais sur SαS il est cohérent dans l'esprit queue lourde)

Sorties:
- results_paper_sim.csv
- detail_paper_sim.csv
- figures_paper_sim/...
"""

from __future__ import annotations
import math
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# ======================
# PARAMÈTRES
# ======================
SEED = 123
N = 2**12  # longueur dyadique pour scaling (4096)
N_MIN = 5
N_MAX = 11
R_USED = 1

OUTDIR = Path("figures_paper_sim")
OUTDIR.mkdir(parents=True, exist_ok=True)

rng = np.random.default_rng(SEED)


# ======================
# 1) fBm via Davies–Harte
# ======================
def autocov_fgn(k: np.ndarray, H: float) -> np.ndarray:
    # Covariance du bruit gaussien fractionnaire (fGn)
    # gamma(k) = 0.5 (|k-1|^{2H} - 2|k|^{2H} + |k+1|^{2H})
    k = np.asarray(k, dtype=float)
    return 0.5 * (np.abs(k - 1) ** (2 * H) - 2 * np.abs(k) ** (2 * H) + np.abs(k + 1) ** (2 * H))

def fbm_davies_harte(n: int, H: float, rng: np.random.Generator) -> np.ndarray:
    """
    Simule un fBm de longueur n+1 (B_H(0..n)).
    Davies–Harte sur fGn puis cumul.
    """
    # taille embedding
    m = 2 * n
    k = np.arange(0, n + 1)
    r = autocov_fgn(k, H)
    # vecteur circulant de taille 2n
    c = np.concatenate([r, r[n-1:0:-1]])  # len=2n
    # FFT des valeurs propres
    lam = np.real(np.fft.fft(c))
    if np.any(lam < -1e-10):
        raise RuntimeError("Davies–Harte: valeurs propres négatives (numérique). Essaye autre n ou H.")
    lam = np.maximum(lam, 0.0)

    # variables gaussiennes complexes
    W = rng.normal(size=m) + 1j * rng.normal(size=m)
    Z = np.fft.ifft(np.sqrt(lam) * W).real

    fgn = Z[:n]  # incréments
    fbm = np.concatenate([[0.0], np.cumsum(fgn)])
    return fbm


# ======================
# 2) SαS Lévy motion via CMS
# ======================
def sas_rvs(alpha: float, size: int, rng: np.random.Generator) -> np.ndarray:
    """
    Symmetric alpha-stable (SαS), beta=0, location=0, scale=1
    Chambers-Mallows-Stuck
    """
    U = rng.uniform(-np.pi/2, np.pi/2, size=size)
    W = rng.exponential(scale=1.0, size=size)

    if abs(alpha - 1.0) > 1e-12:
        part1 = np.sin(alpha * U) / (np.cos(U) ** (1.0 / alpha))
        part2 = (np.cos((1 - alpha) * U) / W) ** ((1 - alpha) / alpha)
        return part1 * part2
    else:
        # cas alpha=1
        return (2/np.pi) * ( (np.pi/2 + U) * np.tan(U) - np.log((np.pi/2 * W * np.cos(U)) / (np.pi/2 + U)) )

def levy_motion_sas(n: int, alpha: float, rng: np.random.Generator) -> np.ndarray:
    """
    Lévy motion SαS: X_0=0, X_t = somme d'incréments i.i.d. alpha-stables
    """
    inc = sas_rvs(alpha=alpha, size=n, rng=rng)
    X = np.concatenate([[0.0], np.cumsum(inc)])
    return X


# ======================
# ESTIMATION alpha (Hill) + H (p-variations)
# ======================
def pick_hill_k(n: int) -> int:
    k = int(math.sqrt(n))
    k = max(50, min(k, n // 5))
    return k

def hill_alpha_hat(dx: np.ndarray, k=None) -> float:
    x = np.asarray(dx, dtype=float)
    x = x[np.isfinite(x)]
    x = np.abs(x)
    x = x[x > 0]
    if len(x) < 300:
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

def choose_p_for_paper(alpha_hat: float) -> float:
    """
    Dans le papier: il faut p < alpha (pour les processus alpha-stables).
    Pour fBm (gaussien), alpha=2, donc p peut être <2.
    """
    if not np.isfinite(alpha_hat) or alpha_hat <= 0:
        return float("nan")
    p = 0.8 * alpha_hat
    p = min(p, alpha_hat - 1e-3)
    p = max(0.5, min(p, 1.5))  # pratique & stable
    return float(p)

def max_n_from_length(L: int) -> int:
    if L <= 2:
        return 0
    return int(math.floor(math.log2(L - 1)))

def p_variation(signal: np.ndarray, n: int, p: float, r: int = 0) -> float:
    N = 2 ** n
    lag = 2 ** r
    if len(signal) < N + 1:
        return float("nan")
    x = signal[:N+1]
    inc = x[lag:] - x[:-lag]
    if len(inc) == 0:
        return float("nan")
    return float(np.mean(np.abs(inc) ** p))

def hurst_detail(signal: np.ndarray, p: float, r: int, n_min: int, n_max: int) -> pd.DataFrame:
    rows = []
    for n in range(n_min, n_max + 1):
        V0 = p_variation(signal, n=n, p=p, r=0)
        Vr = p_variation(signal, n=n, p=p, r=r)
        if np.isfinite(V0) and np.isfinite(Vr) and V0 > 0 and Vr > 0:
            H = (1.0 / (r * p)) * np.log2(Vr / V0)
            rows.append({"n": n, "H": H, "V0": V0, "Vr": Vr})
    return pd.DataFrame(rows)

def analyze_process(X: np.ndarray, name: str) -> tuple[dict, pd.DataFrame]:
    """
    IMPORTANT (papier):
    - On analyse les incréments dX (stationnaires) pour alpha (queue)
    - Pour H via p-variations, on peut aussi travailler sur X OU sur dX selon la définition du papier.
      Ici, on suit ta formule sur un signal discret: on utilise dX pour cohérence.
    """
    X = np.asarray(X, dtype=float)
    dX = np.diff(X)
    dX = dX[np.isfinite(dX)]
    n_obs = len(dX)

    alpha_hat = hill_alpha_hat(dX)
    # pour fBm, alpha théorique=2 (gaussien) ; Hill peut donner >2 si les queues sont fines (normal)
    # ce n'est pas un problème, on borne juste p à < 2.
    if name.startswith("fBm"):
        alpha_for_p = min(2.0, alpha_hat) if np.isfinite(alpha_hat) else 2.0
    else:
        alpha_for_p = alpha_hat

    p = choose_p_for_paper(alpha_for_p)

    n_max_possible = max_n_from_length(n_obs)
    n_min = min(N_MIN, n_max_possible)
    n_max = min(N_MAX, n_max_possible)

    det = hurst_detail(signal=dX, p=p, r=R_USED, n_min=n_min, n_max=n_max)

    if det.empty:
        summary = {"series": name, "n_obs": n_obs, "alpha_hat": alpha_hat, "p_used": p,
                   "H_median": np.nan, "H_mean": np.nan, "H_min": np.nan, "H_max": np.nan,
                   "note": "no_scales"}
        return summary, det

    Hs = det["H"].to_numpy(dtype=float)
    summary = {"series": name, "n_obs": n_obs, "alpha_hat": alpha_hat, "p_used": p,
               "H_median": float(np.median(Hs)),
               "H_mean": float(np.mean(Hs)),
               "H_min": float(np.min(Hs)),
               "H_max": float(np.max(Hs)),
               "note": "OK"}
    det = det.copy()
    det.insert(0, "series", name)
    det.insert(1, "alpha_hat", alpha_hat)
    det.insert(2, "p_used", p)
    return summary, det


# ======================
# MAIN
# ======================
def main():
    # --- Séries compatibles "papier"
    sims = {}

    # fBm: H dans (0,1)
    sims["fBm_H0.3"] = fbm_davies_harte(n=N, H=0.3, rng=rng)
    sims["fBm_H0.7"] = fbm_davies_harte(n=N, H=0.7, rng=rng)

    # Lévy motion SαS: alpha dans (0,2]
    sims["Levy_a1.2"] = levy_motion_sas(n=N, alpha=1.2, rng=rng)
    sims["Levy_a1.7"] = levy_motion_sas(n=N, alpha=1.7, rng=rng)

    # --- Analyse
    summaries = []
    details = []
    for name, X in sims.items():
        s, d = analyze_process(X, name)
        summaries.append(s)
        if not d.empty:
            details.append(d)

    res = pd.DataFrame(summaries).sort_values("series")
    det = pd.concat(details, ignore_index=True) if details else pd.DataFrame()

    res.to_csv("results_paper_sim.csv", index=False, encoding="utf-8")
    det.to_csv("detail_paper_sim.csv", index=False, encoding="utf-8")

    print("\n=== Résultats (simulations compatibles papier) ===")
    print(res.to_string(index=False))
    print("\nExports: results_paper_sim.csv, detail_paper_sim.csv")

    # --- FIG 1: trajectoires
    plt.figure(figsize=(12,5))
    for name, X in sims.items():
        plt.plot(X[:1000], label=name, alpha=0.85)
    plt.title("Trajectoires simulées (extrait 1000 points)")
    plt.xlabel("t")
    plt.ylabel("X_t")
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUTDIR / "01_paths.png", dpi=200)
    plt.close()

    # --- FIG 2: H(n)
    if not det.empty:
        plt.figure(figsize=(10,5))
        for name, sub in det.groupby("series"):
            sub = sub.sort_values("n")
            plt.plot(sub["n"], sub["H"], marker="o", label=name)
        plt.axhline(0.5, linestyle="--", linewidth=1)  # repère visuel
        plt.title("H(n) par échelle – simulations papier")
        plt.xlabel("n")
        plt.ylabel("H estimé")
        plt.legend()
        plt.tight_layout()
        plt.savefig(OUTDIR / "02_H_by_scale.png", dpi=220)
        plt.close()

    print("\n✅ Figures dans:", OUTDIR.resolve())
    for p in sorted(OUTDIR.glob("*.png")):
        print(" -", p.name)


if __name__ == "__main__":
    main()
