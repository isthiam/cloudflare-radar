# ============================================================
#  Cloudflare Radar (percentage) -> alpha (Hill) -> H (p-variations)
#  Multi-pays: MAR, SEN, FRA, CIV, GHA, EGY, ZAF
#  Output:
#    - results_by_country.csv  (résumé par pays)
#    - detail_by_country.csv   (H(n) par pays)
# ============================================================

from __future__ import annotations

import sys
import math
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple

import numpy as np
import pandas as pd



df = pd.read_csv("E:/Webscraping/cloudflare_radar_vulnerabilite/data/radar_api_donnees_brutes_daily.csv", parse_dates=["date"])
df = df.sort_values("date")

# Série IPv6 (%)
x = df["attack_ipv6_pct"].astype(float)

# Incréments (objet math du modèle)
dx = x.diff().dropna().values
# -----------------------------
# Configuration
# -----------------------------
DEFAULT_COUNTRIES = ["MAR", "SEN", "FRA", "CIV", "GHA", "EGY", "ZAF"]

# Echelles dyadiques à tester (ajuste si besoin)
DEFAULT_N_MIN = 5
DEFAULT_N_MAX = 9  # sera automatiquement borné par la longueur de série

# Paramètres Hill (estimation alpha)
DEFAULT_HILL_K = None  # None -> règle sqrt(n) bornée


@dataclass
class CountryResult:
    country: str
    n_obs: int
    alpha_hat: float
    p_used: float
    r_used: int
    n_min_used: int
    n_max_used: int
    H_median: float
    H_mean: float
    H_std: float
    H_min: float
    H_max: float
    quality_flag: str


# -----------------------------
# Utilitaires
# -----------------------------
def safe_float(x) -> float:
    try:
        return float(x)
    except Exception:
        return float("nan")


def pick_hill_k(n: int) -> int:
    """
    Choix simple de k (nb d'extrêmes) pour Hill.
    """
    k = int(math.sqrt(n))
    k = max(20, min(k, n // 5))
    return k


def hill_alpha_hat(increments: np.ndarray, k: Optional[int] = None) -> float:
    """
    Hill estimator sur les queues de |increments|.
    Renvoie alpha_hat = 1/gamma_hat.
    """
    x = np.asarray(increments, dtype=float)
    x = x[np.isfinite(x)]
    x = np.abs(x)
    x = x[x > 0]

    if len(x) < 50:
        return float("nan")

    y = np.sort(x)[::-1]  # décroissant

    if k is None:
        k = pick_hill_k(len(y))

    # sécurité
    if k <= 1 or k >= len(y) - 1:
        return float("nan")

    yk1 = y[k]  # (k+1)-ème plus grand
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

    V = np.mean(np.abs(inc) ** p)
    return float(V)


def hurst_unbiased_detail(signal: np.ndarray, p: float, r: int, n_min: int, n_max: int) -> pd.DataFrame:
    """
    Calcule H~_{n,p}^{(r)} = (1/(r p)) log2( V^{(r)} / V^{(0)} ) pour plusieurs n.
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


def choose_p(alpha_hat: float) -> float:
    """
    Choix automatique "prudent" de p < alpha_hat.
    - Cap à 1.0 (pratique sur données %)
    - On prend 0.8*alpha_hat, puis on force p < alpha_hat
    - On borne p dans [0.2, 1.0]
    """
    if not np.isfinite(alpha_hat) or alpha_hat <= 0:
        return float("nan")

    p = min(1.0, 0.8 * alpha_hat)
    p = min(p, alpha_hat - 1e-3)
    p = max(0.2, p)
    if p <= 0 or not np.isfinite(p):
        return float("nan")
    return float(p)


def compute_n_max_from_length(length: int) -> int:
    """
    Donne n_max tel que 2^n + 1 <= length.
    """
    if length <= 2:
        return 0
    return int(math.floor(math.log2(length - 1)))


def quality_flag(alpha_hat: float, H_median: float, detail: pd.DataFrame) -> str:
    """
    Petit diagnostic utile pour rapport.
    """
    flags = []
    if not np.isfinite(alpha_hat):
        flags.append("alpha_nan")
    elif alpha_hat < 1.0:
        flags.append("alpha<1_extreme_jumps")

    if detail.empty or len(detail) < 2:
        flags.append("few_scales")

    if np.isfinite(H_median) and H_median < -0.2:
        flags.append("H_negative_strong")

    if len(flags) == 0:
        return "OK"
    return "|".join(flags)


# -----------------------------
# Chargement données
# -----------------------------
def load_radar_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["date"])
    # normalisation colonnes
    df.columns = [c.strip() for c in df.columns]

    required = {"date", "country", "attack_ipv6_pct", "attack_ipv4_pct"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Colonnes manquantes dans le CSV: {sorted(missing)}")

    df["country"] = df["country"].astype(str).str.upper().str.strip()

    # cast values
    df["attack_ipv6_pct"] = pd.to_numeric(df["attack_ipv6_pct"], errors="coerce")
    df["attack_ipv4_pct"] = pd.to_numeric(df["attack_ipv4_pct"], errors="coerce")

    df = df.dropna(subset=["date", "country", "attack_ipv6_pct"])
    df = df.sort_values(["country", "date"]).reset_index(drop=True)
    return df


# -----------------------------
# Analyse par pays
# -----------------------------
def analyze_country_series(
    sub: pd.DataFrame,
    value_col: str = "attack_ipv6_pct",
    r: int = 1,
    n_min: int = DEFAULT_N_MIN,
    n_max: int = DEFAULT_N_MAX,
    hill_k: Optional[int] = DEFAULT_HILL_K,
) -> Tuple[CountryResult, pd.DataFrame]:
    """
    Analyse un pays: alpha (Hill) + H (p-variations ratio).
    Retourne (résumé, detail H(n))
    """
    country = str(sub["country"].iloc[0])
    x_level = sub[value_col].astype(float).values

    # Incréments (objet principal)
    x = np.diff(x_level)
    x = x[np.isfinite(x)]

    # Longueur utile pour p-variations : on travaille sur la série x (incréments)
    n_obs = len(x)

    # alpha sur incréments de la série d'incréments ? (ici directement x, déjà des incréments du niveau)
    alpha_hat = hill_alpha_hat(x, k=hill_k)

    p_used = choose_p(alpha_hat)
    if not np.isfinite(p_used):
        # retourne vide mais propre
        empty_detail = pd.DataFrame(columns=["n", "V0", "Vr", "H_tilde"])
        res = CountryResult(
            country=country,
            n_obs=n_obs,
            alpha_hat=float(alpha_hat),
            p_used=float("nan"),
            r_used=r,
            n_min_used=n_min,
            n_max_used=n_min,
            H_median=float("nan"),
            H_mean=float("nan"),
            H_std=float("nan"),
            H_min=float("nan"),
            H_max=float("nan"),
            quality_flag="p_nan_or_alpha_bad",
        )
        return res, empty_detail

    # n_max ajusté selon longueur
    max_possible = compute_n_max_from_length(n_obs)
    n_max_used = min(n_max, max_possible)
    n_min_used = min(n_min, n_max_used)

    detail = hurst_unbiased_detail(signal=x, p=p_used, r=r, n_min=n_min_used, n_max=n_max_used)

    if detail.empty:
        res = CountryResult(
            country=country,
            n_obs=n_obs,
            alpha_hat=float(alpha_hat),
            p_used=float(p_used),
            r_used=r,
            n_min_used=n_min_used,
            n_max_used=n_max_used,
            H_median=float("nan"),
            H_mean=float("nan"),
            H_std=float("nan"),
            H_min=float("nan"),
            H_max=float("nan"),
            quality_flag="no_detail_scales",
        )
        return res, detail

    Hs = detail["H_tilde"].astype(float).values
    res = CountryResult(
        country=country,
        n_obs=n_obs,
        alpha_hat=float(alpha_hat),
        p_used=float(p_used),
        r_used=r,
        n_min_used=int(detail["n"].min()),
        n_max_used=int(detail["n"].max()),
        H_median=float(np.median(Hs)),
        H_mean=float(np.mean(Hs)),
        H_std=float(np.std(Hs, ddof=1)) if len(Hs) > 1 else 0.0,
        H_min=float(np.min(Hs)),
        H_max=float(np.max(Hs)),
        quality_flag=quality_flag(alpha_hat, float(np.median(Hs)), detail),
    )

    return res, detail


def run_multi_country(
    csv_path: Path,
    countries: List[str] = DEFAULT_COUNTRIES,
    value_col: str = "attack_ipv6_pct",
    r: int = 1,
    n_min: int = DEFAULT_N_MIN,
    n_max: int = DEFAULT_N_MAX,
    hill_k: Optional[int] = DEFAULT_HILL_K,
    out_dir: Optional[Path] = None,
) -> None:
    df = load_radar_csv(csv_path)

    countries = [c.upper().strip() for c in countries]
    df = df[df["country"].isin(countries)].copy()

    if df.empty:
        raise ValueError("Aucune ligne après filtrage pays. Vérifie les codes pays dans le CSV.")

    results: List[CountryResult] = []
    detail_all = []

    for c in countries:
        sub = df[df["country"] == c].copy()
        if sub.empty:
            print(f"[WARN] Pays {c}: aucune donnée.", file=sys.stderr)
            continue

        res, detail = analyze_country_series(
            sub=sub,
            value_col=value_col,
            r=r,
            n_min=n_min,
            n_max=n_max,
            hill_k=hill_k,
        )
        results.append(res)

        if not detail.empty:
            tmp = detail.copy()
            tmp.insert(0, "country", c)
            tmp.insert(1, "p_used", res.p_used)
            tmp.insert(2, "alpha_hat", res.alpha_hat)
            detail_all.append(tmp)

    res_df = pd.DataFrame([r.__dict__ for r in results]).sort_values("country")
    detail_df = pd.concat(detail_all, ignore_index=True) if detail_all else pd.DataFrame()

    # Sortie
    if out_dir is None:
        out_dir = csv_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    res_file = out_dir / "results_by_country.csv"
    det_file = out_dir / "detail_by_country.csv"

    res_df.to_csv(res_file, index=False, encoding="utf-8")
    if not detail_df.empty:
        detail_df.to_csv(det_file, index=False, encoding="utf-8")

    # Affichage résumé console
    print("\n=== Résultats (par pays) ===")
    print(res_df.to_string(index=False))

    print(f"\nFichiers générés :\n- {res_file}")
    if not detail_df.empty:
        print(f"- {det_file}")
    else:
        print("- detail_by_country.csv NON généré (pas de détails)")

    # Petite interprétation rapide
    print("\n=== Aide interprétation rapide ===")
    print("alpha_hat < 1  : dynamique dominée par événements extrêmes (sauts/raréfaction)")
    print("H_median ~ 0.5 : mémoire faible (type bruit)")
    print("H_median > 0.6 : persistance (dynamique structurée / campagnes)")
    print("H_median < 0   : variations localisées + régulation / absence de scaling stable")


# -----------------------------
# Point d'entrée CLI
# -----------------------------
def main():
    # Exemples de chemins Windows:
    #   python radar_hurst_multicountry.py "E:/Webscraping/.../data/radar_api_donnees_brutes_daily.csv"
    #   python radar_hurst_multicountry.py r"E:\Webscraping\...\radar_api_donnees_brutes_daily.csv"

    if len(sys.argv) < 2:
        print("Usage: python radar_hurst_multicountry.py <path_csv> [out_dir]", file=sys.stderr)
        sys.exit(2)

    csv_path = Path(sys.argv[1])

    out_dir = Path(sys.argv[2]) if len(sys.argv) >= 3 else csv_path.parent

    run_multi_country(
        csv_path=csv_path,
        countries=DEFAULT_COUNTRIES,
        value_col="attack_ipv6_pct",
        r=1,
        n_min=DEFAULT_N_MIN,
        n_max=DEFAULT_N_MAX,
        hill_k=DEFAULT_HILL_K,
        out_dir=out_dir,
    )


if __name__ == "__main__":
    main()
