import math
import numpy as np
import pandas as pd

# ======================
# PARAMÈTRES
# ======================

CSV = "radar_attacks_l3_ip_version_daily_by_country.csv"

DEFAULT_N_MIN = 5
DEFAULT_N_MAX = 8        # 2^8 = 256 < 365
R_USED = 1               # lag dyadique
MIN_NONZERO = 80         # seuil minimal pour Hill

# ======================
# UTILS
# ======================

def pick_hill_k(n: int) -> int:
    k = int(math.sqrt(n))
    k = max(20, min(k, n // 5))
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

    if k <= 1 or k >= len(y) - 1:
        return float("nan")

    yk1 = y[k]
    gamma = np.mean(np.log(y[:k]) - np.log(yk1))
    if not np.isfinite(gamma) or gamma <= 0:
        return float("nan")

    return float(1.0 / gamma)

def choose_p(alpha: float) -> float:
    if not np.isfinite(alpha) or alpha <= 0:
        return float("nan")
    p = min(1.5, 0.8 * alpha)
    p = min(p, alpha - 1e-3)
    p = max(0.3, p)
    return p if np.isfinite(p) and p > 0 else float("nan")

def p_variation(signal: np.ndarray, n: int, p: float, r: int = 0) -> float:
    N = 2 ** n
    lag = 2 ** r
    if len(signal) < N + 1:
        return float("nan")
    x = signal[:N + 1]
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

# ======================
# CHARGEMENT DONNÉES
# ======================

df = pd.read_csv(CSV, parse_dates=["date"])
df = df.sort_values(["country_iso3", "date"])

# ======================
# ANALYSE PAR PAYS
# ======================

results = []
details = []

for country, sub in df.groupby("country_iso3"):
    x_level = sub["attack_ipv4_pct"].astype(float).values
    dx = np.diff(x_level)
    dx = dx[np.isfinite(dx)]

    alpha = hill_alpha_hat(dx)
    p = choose_p(alpha)

    max_possible = int(math.floor(math.log2(len(dx) - 1))) if len(dx) > 2 else 0
    n_min = min(DEFAULT_N_MIN, max_possible)
    n_max = min(DEFAULT_N_MAX, max_possible)

    if not np.isfinite(p) or n_max < n_min or n_max < 5:
        results.append({
            "country": country,
            "n_obs": len(dx),
            "alpha": alpha,
            "p_used": p,
            "H_median": np.nan,
            "note": "insufficient_scales_or_bad_alpha"
        })
        continue

    rows = hurst_detail(dx, p=p, r=R_USED, n_min=n_min, n_max=n_max)
    if not rows:
        results.append({
            "country": country,
            "n_obs": len(dx),
            "alpha": alpha,
            "p_used": p,
            "H_median": np.nan,
            "note": "no_valid_scales"
        })
        continue

    Hs = [h for (_, h, _, _) in rows]

    results.append({
        "country": country,
        "n_obs": len(dx),
        "alpha": alpha,
        "p_used": p,
        "n_min": n_min,
        "n_max": n_max,
        "H_median": float(np.median(Hs)),
        "H_mean": float(np.mean(Hs)),
        "H_min": float(np.min(Hs)),
        "H_max": float(np.max(Hs)),
        "note": "OK"
    })

    for (n, h, v0, vr) in rows:
        details.append({
            "country": country,
            "n": n,
            "H": h,
            "V0": v0,
            "Vr": vr,
            "alpha": alpha,
            "p_used": p
        })

# ======================
# EXPORT
# ======================

res_df = pd.DataFrame(results).sort_values("country")
det_df = pd.DataFrame(details).sort_values(["country", "n"])

res_df.to_csv("hurst_results_ipv4_daily_by_country.csv", index=False, encoding="utf-8")
det_df.to_csv("hurst_detail_ipv4_daily_by_country.csv", index=False, encoding="utf-8")

print("\n=== Résultats DAILY – IPv4 ===")
print(res_df.to_string(index=False))
print("\nExports:")
print(" - hurst_results_ipv4_daily_by_country.csv")
print(" - hurst_detail_ipv4_daily_by_country.csv")
