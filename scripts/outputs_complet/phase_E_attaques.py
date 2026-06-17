#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase E — Analyse détaillée attaques L3 (53 semaines) & L7 (85 jours)."""

import pandas as pd
import numpy as np
import os
import warnings
from datetime import datetime
from scipy import stats

warnings.filterwarnings("ignore")

BASE = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/cleaned"
OUT  = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/rapport_phase_E.md"

# ── Chargement ──────────────────────────────────────────────────────────────
print("Chargement des donnees...")

l3_proto = pd.read_csv(f"{BASE}/attacks_l3_protocol_clean.csv", parse_dates=["date"])
l3_rate  = pd.read_csv(f"{BASE}/attacks_l3_bitrate_clean.csv",  parse_dates=["date"])
l3_ip    = pd.read_csv(f"{BASE}/attacks_l3_ip_version_clean.csv", parse_dates=["date"])
l7_vert  = pd.read_csv(f"{BASE}/attacks_l7_vertical_clean.csv",  parse_dates=["date"])
l7_meth  = pd.read_csv(f"{BASE}/attacks_l7_http_method_clean.csv", parse_dates=["date"])
l7_ver   = pd.read_csv(f"{BASE}/attacks_l7_http_version_clean.csv", parse_dates=["date"])

# Colonnes utiles par fichier
PROTO_COLS  = ["UDP", "TCP", "GRE", "ICMP"]
RATE_COLS   = ["UNDER_500_MBPS", "_500_MBPS_TO_1_GBPS", "_1_GBPS_TO_10_GBPS",
               "_10_GBPS_TO_100_GBPS", "OVER_100_GBPS"]
IP_COLS     = ["IPv4", "IPv6"]
VERT_COLS   = ["Computer and Electronics", "Internet and Telecom", "other",
               "Shopping & General Merchandise", "Finance", "Gambling",
               "News, Media, and Publications", "Business and Industry",
               "Professional Services", "Art, Entertainment & Recreation"]
METH_COLS   = ["GET", "POST", "HEAD", "OPTIONS", "PATCH", "DELETE",
               "PUT", "UNKNOWN", "ACL"]
VER_COLS    = ["HTTP/2", "HTTP/1.x", "HTTP/3"]

# ── Helpers statistiques ────────────────────────────────────────────────────
def desc_stats(series):
    s = series.dropna()
    return {
        "N": len(s), "Moy": s.mean(), "Med": s.median(), "Std": s.std(),
        "CV%": s.std()/s.mean()*100 if s.mean() != 0 else np.nan,
        "Min": s.min(), "Max": s.max(),
        "P25": s.quantile(.25), "P75": s.quantile(.75),
        "Skew": float(stats.skew(s)), "Kurt": float(stats.kurtosis(s))
    }

def mann_kendall(y):
    """Test Mann-Kendall simplifié via scipy."""
    n = len(y)
    if n < 4:
        return None, None, None
    s = 0
    for i in range(n - 1):
        for j in range(i + 1, n):
            s += np.sign(y[j] - y[i])
    var_s = n * (n - 1) * (2 * n + 5) / 18
    if s > 0:
        z = (s - 1) / np.sqrt(var_s)
    elif s < 0:
        z = (s + 1) / np.sqrt(var_s)
    else:
        z = 0
    p = 2 * (1 - stats.norm.cdf(abs(z)))
    tau = s / (n * (n - 1) / 2)
    return tau, z, p

def ols_trend(x, y):
    """Régression linéaire OLS : retourne (pente, r2, p)."""
    n = len(y)
    if n < 3:
        return np.nan, np.nan, np.nan
    xi = np.arange(n, dtype=float)
    slope, intercept, r, p, _ = stats.linregress(xi, y)
    return slope, r**2, p

def zscore_anomalies(series, threshold=2.5):
    """Détecte les anomalies |Z| >= threshold."""
    s = series.dropna()
    z = (s - s.mean()) / s.std()
    return [(series.index[i] if hasattr(series.index, '__iter__') else i,
             s.iloc[i], round(z.iloc[i], 3))
            for i in range(len(s)) if abs(z.iloc[i]) >= threshold]

def trend_label(tau, p):
    if p is None:
        return "N/A"
    star = "***" if p < 0.001 else ("**" if p < 0.01 else ("*" if p < 0.05 else "n.s."))
    if p >= 0.05:
        return f"→ neutre {star}"
    return ("↑ hausse" if tau > 0 else "↓ baisse") + f" {star}"

def hhi(values):
    """Herfindahl-Hirschman Index (concentration) de 0 à 10000."""
    v = np.array(values, dtype=float)
    v = v[~np.isnan(v)]
    if v.sum() == 0:
        return np.nan
    shares = v / v.sum()
    return float(np.sum(shares**2) * 10000)

def fv(v, fmt=".4f", na="N/A"):
    """Formate une valeur numérique ou retourne na si None/NaN."""
    if v is None:
        return na
    try:
        if np.isnan(v):
            return na
    except (TypeError, ValueError):
        pass
    return format(v, fmt)

def ascii_bar(val, max_val=100, width=28, unit="%"):
    if pd.isna(val):
        return "N/A"
    filled = int(round(abs(val) / max_val * width))
    filled = min(filled, width)
    bar = "#" * filled + "." * (width - filled)
    return f"[{bar}] {val:.1f}{unit}"

def weekday_profile(df, date_col, cols):
    """Profil jour de la semaine pour un DataFrame daily."""
    df2 = df.copy()
    df2["weekday"] = pd.to_datetime(df2[date_col]).dt.day_name()
    order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    grp = df2.groupby("weekday")[cols].mean().reindex(order)
    return grp

def p_stars(p):
    if p is None or np.isnan(p):
        return "n.s."
    return "***" if p < 0.001 else ("**" if p < 0.01 else ("*" if p < 0.05 else "n.s."))

# ── SECTION L3 ──────────────────────────────────────────────────────────────
print("Analyse L3...")

# dates L3 formatées
l3_proto["date_str"] = l3_proto["date"].dt.strftime("%Y-%m-%d")
l3_rate["date_str"]  = l3_rate["date"].dt.strftime("%Y-%m-%d")
l3_ip["date_str"]    = l3_ip["date"].dt.strftime("%Y-%m-%d")

# Statistiques L3 protocoles
proto_stats = {}
for c in PROTO_COLS:
    proto_stats[c] = desc_stats(l3_proto[c])
    y = l3_proto[c].values
    tau, z_mk, p_mk = mann_kendall(y)
    slope, r2, p_ols = ols_trend(np.arange(len(y)), y)
    proto_stats[c].update({"tau": tau, "z_mk": z_mk, "p_mk": p_mk,
                            "slope": slope, "r2": r2, "p_ols": p_ols})

# Statistiques L3 bitrate
rate_stats = {}
for c in RATE_COLS:
    rate_stats[c] = desc_stats(l3_rate[c])
    y = l3_rate[c].values
    tau, z_mk, p_mk = mann_kendall(y)
    slope, r2, p_ols = ols_trend(np.arange(len(y)), y)
    rate_stats[c].update({"tau": tau, "z_mk": z_mk, "p_mk": p_mk,
                           "slope": slope, "r2": r2, "p_ols": p_ols})

# Statistiques L3 IP version
ip_stats = {}
for c in IP_COLS:
    ip_stats[c] = desc_stats(l3_ip[c])
    y = l3_ip[c].values
    tau, z_mk, p_mk = mann_kendall(y)
    slope, r2, p_ols = ols_trend(np.arange(len(y)), y)
    ip_stats[c].update({"tau": tau, "z_mk": z_mk, "p_mk": p_mk,
                         "slope": slope, "r2": r2, "p_ols": p_ols})

# Z-score anomalies L3
proto_anomalies = {c: zscore_anomalies(l3_proto[c].reset_index(drop=True)) for c in PROTO_COLS}
rate_anomalies  = {c: zscore_anomalies(l3_rate[c].reset_index(drop=True)) for c in RATE_COLS}

# Corrélations L3
proto_corr = l3_proto[PROTO_COLS].corr()

# Weighted attack size (mean bitrate class)
SIZE_MID = {"UNDER_500_MBPS": 250, "_500_MBPS_TO_1_GBPS": 750,
            "_1_GBPS_TO_10_GBPS": 5500, "_10_GBPS_TO_100_GBPS": 55000,
            "OVER_100_GBPS": 150000}
l3_rate["weighted_size_mbps"] = sum(
    l3_rate[c] / 100 * SIZE_MID[c] for c in RATE_COLS
)

# ── SECTION L7 ──────────────────────────────────────────────────────────────
print("Analyse L7...")

l7_vert["date_str"] = l7_vert["date"].dt.strftime("%Y-%m-%d")
l7_meth["date_str"] = l7_meth["date"].dt.strftime("%Y-%m-%d")
l7_ver["date_str"]  = l7_ver["date"].dt.strftime("%Y-%m-%d")

# Statistiques L7 verticaux
vert_stats = {}
for c in VERT_COLS:
    vert_stats[c] = desc_stats(l7_vert[c])
    y = l7_vert[c].dropna().values
    tau, z_mk, p_mk = mann_kendall(y)
    slope, r2, p_ols = ols_trend(np.arange(len(y)), y)
    vert_stats[c].update({"tau": tau, "z_mk": z_mk, "p_mk": p_mk,
                           "slope": slope, "r2": r2, "p_ols": p_ols})

# Statistiques L7 méthodes HTTP
meth_stats = {}
for c in METH_COLS:
    meth_stats[c] = desc_stats(l7_meth[c])
    y = l7_meth[c].dropna().values
    tau, z_mk, p_mk = mann_kendall(y)
    slope, r2, p_ols = ols_trend(np.arange(len(y)), y)
    meth_stats[c].update({"tau": tau, "z_mk": z_mk, "p_mk": p_mk,
                           "slope": slope, "r2": r2, "p_ols": p_ols})

# Statistiques L7 HTTP version
ver_stats = {}
for c in VER_COLS:
    ver_stats[c] = desc_stats(l7_ver[c])
    y = l7_ver[c].dropna().values
    tau, z_mk, p_mk = mann_kendall(y)
    slope, r2, p_ols = ols_trend(np.arange(len(y)), y)
    ver_stats[c].update({"tau": tau, "z_mk": z_mk, "p_mk": p_mk,
                          "slope": slope, "r2": r2, "p_ols": p_ols})

# HHI concentration
vert_hhi  = {c: hhi(l7_vert[c].dropna().values) for c in VERT_COLS}
meth_hhi  = {c: hhi(l7_meth[c].dropna().values) for c in METH_COLS}

# Profils jour de la semaine L7
wdp_vert = weekday_profile(l7_vert, "date", VERT_COLS)
wdp_meth = weekday_profile(l7_meth, "date", METH_COLS)
wdp_ver  = weekday_profile(l7_ver,  "date", VER_COLS)

# Anomalies L7
vert_anomalies = {c: zscore_anomalies(l7_vert[c].reset_index(drop=True)) for c in VERT_COLS}
meth_anomalies = {c: zscore_anomalies(l7_meth[c].reset_index(drop=True)) for c in METH_COLS}
ver_anomalies  = {c: zscore_anomalies(l7_ver[c].reset_index(drop=True)) for c in VER_COLS}

# Évolution mensuelle L7
l7_vert["month"] = l7_vert["date"].dt.to_period("M")
l7_meth["month"] = l7_meth["date"].dt.to_period("M")
l7_ver["month"]  = l7_ver["date"].dt.to_period("M")
vert_monthly = l7_vert.groupby("month")[VERT_COLS].mean()
meth_monthly = l7_meth.groupby("month")[METH_COLS].mean()
ver_monthly  = l7_ver.groupby("month")[VER_COLS].mean()

# Corrélations L7
vert_corr = l7_vert[VERT_COLS].corr()
meth_corr = l7_meth[METH_COLS].corr()

# ── GÉNÉRATION DU RAPPORT ────────────────────────────────────────────────────
print("Generation du rapport Phase E...")

ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
lines = []

lines.append("# Rapport Phase E — Analyse Détaillée des Attaques L3 & L7")
lines.append("**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  ")
lines.append("**Chercheur :** Issakha Thiam — Université Clermont Auvergne  ")
lines.append(f"**Généré le :** {ts}")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 : RÉSUMÉ EXÉCUTIF
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 1. Résumé Exécutif")
lines.append("")
lines.append("| Jeu de données | Période | Granularité | Points |")
lines.append("|---|---|---|---:|")
lines.append(f"| L3 Protocole | 2025-06-09 → 2026-06-08 | Hebdomadaire | {len(l3_proto)} |")
lines.append(f"| L3 Débit (bitrate) | 2025-06-09 → 2026-06-08 | Hebdomadaire | {len(l3_rate)} |")
lines.append(f"| L3 Version IP | 2025-06-09 → 2026-06-08 | Hebdomadaire | {len(l3_ip)} |")
lines.append(f"| L7 Secteur ciblé (vertical) | 2026-03-17 → 2026-06-09 | Quotidien | {len(l7_vert)} |")
lines.append(f"| L7 Méthode HTTP | 2026-03-17 → 2026-06-09 | Quotidien | {len(l7_meth)} |")
lines.append(f"| L7 Version HTTP | 2026-03-17 → 2026-06-09 | Quotidien | {len(l7_ver)} |")
lines.append("")

# Top findings
lines.append("**Findings clés :**")
lines.append("")
udp_mean = proto_stats["UDP"]["Moy"]
tcp_mean = proto_stats["TCP"]["Moy"]
over100_mean = rate_stats["OVER_100_GBPS"]["Moy"]
top_sector = max(VERT_COLS, key=lambda c: vert_stats[c]["Moy"])
lines.append(f"- **L3 protocole dominant :** UDP ({udp_mean:.1f}% en moyenne) vs TCP ({tcp_mean:.1f}%)")
lines.append(f"- **L3 taille :** {rate_stats['UNDER_500_MBPS']['Moy']:.1f}% des attaques sous 500 Mbps — "
             f"attaques volumétriques >100 Gbps : {over100_mean:.3f}%")
lines.append(f"- **L3 IP :** IPv4 domine massivement ({ip_stats['IPv4']['Moy']:.2f}% en moyenne)")
lines.append(f"- **L7 secteur le plus ciblé :** {top_sector} ({vert_stats[top_sector]['Moy']:.1f}% en moyenne)")
lines.append(f"- **L7 méthode principale :** GET ({meth_stats['GET']['Moy']:.1f}% en moyenne)")
lines.append(f"- **L7 version HTTP :** HTTP/2 ({ver_stats['HTTP/2']['Moy']:.1f}%) dominant, "
             f"HTTP/3 montant ({ver_stats['HTTP/3']['Moy']:.1f}%)")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 : L3 — PROTOCOLES D'ATTAQUE
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 2. L3 — Protocoles d'Attaque (UDP / TCP / GRE / ICMP)")
lines.append("")
lines.append("### 2.1 Statistiques Descriptives par Protocole")
lines.append("")
lines.append("| Protocole | N | Moy (%) | Méd (%) | Std | CV% | Min | Max | Skew | Kurt |")
lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
for c in PROTO_COLS:
    s = proto_stats[c]
    lines.append(f"| **{c}** | {s['N']} | {s['Moy']:.2f} | {s['Med']:.2f} | "
                 f"{s['Std']:.2f} | {s['CV%']:.1f} | {s['Min']:.2f} | {s['Max']:.2f} | "
                 f"{s['Skew']:.2f} | {s['Kurt']:.2f} |")
lines.append("")

lines.append("### 2.2 Tendances Mann-Kendall & OLS")
lines.append("")
lines.append("| Protocole | Tendance MK | Tau | p-value | Pente OLS (%/sem) | R² |")
lines.append("|---|---|---:|---:|---:|---:|")
for c in PROTO_COLS:
    s = proto_stats[c]
    tl = trend_label(s["tau"], s["p_mk"])
    lines.append(f"| **{c}** | {tl} | {s['tau']:.4f} | {s['p_mk']:.4f} {p_stars(s['p_mk'])} | "
                 f"{s['slope']:.4f} | {s['r2']:.4f} |")
lines.append("")

lines.append("### 2.3 Tableau Complet Hebdomadaire — L3 Protocoles")
lines.append("")
lines.append("| # | Date | UDP (%) | TCP (%) | GRE (%) | ICMP (%) | Z(UDP) | Z(TCP) |")
lines.append("|---:|---|---:|---:|---:|---:|---:|---:|")
z_udp = (l3_proto["UDP"] - l3_proto["UDP"].mean()) / l3_proto["UDP"].std()
z_tcp = (l3_proto["TCP"] - l3_proto["TCP"].mean()) / l3_proto["TCP"].std()
for i, row in l3_proto.iterrows():
    anom_u = " ⚠️" if abs(z_udp.iloc[i]) >= 2.5 else ""
    anom_t = " ⚠️" if abs(z_tcp.iloc[i]) >= 2.5 else ""
    lines.append(f"| S{i+1:02d} | {row['date_str']} | {row['UDP']:.2f} | {row['TCP']:.2f} | "
                 f"{row['GRE']:.3f} | {row['ICMP']:.4f} | "
                 f"{z_udp.iloc[i]:.2f}{anom_u} | {z_tcp.iloc[i]:.2f}{anom_t} |")
lines.append("")

lines.append("### 2.4 Anomalies Détectées (|Z| ≥ 2,5)")
lines.append("")
any_proto_anom = False
for c in PROTO_COLS:
    anom = proto_anomalies[c]
    if anom:
        any_proto_anom = True
        lines.append(f"**{c} :**")
        lines.append("")
        lines.append("| Semaine | Valeur (%) | Z-score | Type |")
        lines.append("|---:|---:|---:|---|")
        for idx, val, z in anom:
            t = "PIC" if z > 0 else "CREUX"
            date_str = l3_proto["date_str"].iloc[idx]
            lines.append(f"| S{idx+1:02d} ({date_str}) | {val:.2f} | {z:.3f} | **{t}** |")
        lines.append("")
if not any_proto_anom:
    lines.append("Aucune anomalie détectée (|Z| < 2,5) pour tous les protocoles.")
    lines.append("")

lines.append("### 2.5 Matrice de Corrélation Protocoles")
lines.append("")
lines.append("| | UDP | TCP | GRE | ICMP |")
lines.append("|---|---:|---:|---:|---:|")
for r in PROTO_COLS:
    row_vals = " | ".join(f"{proto_corr.loc[r, c]:.3f}" for c in PROTO_COLS)
    lines.append(f"| **{r}** | {row_vals} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 : L3 — DÉBIT DES ATTAQUES
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 3. L3 — Distribution des Débits d'Attaque")
lines.append("")

RATE_LABELS = {
    "UNDER_500_MBPS": "< 500 Mbps (petites)",
    "_500_MBPS_TO_1_GBPS": "500 Mbps–1 Gbps",
    "_1_GBPS_TO_10_GBPS": "1–10 Gbps (moyennes)",
    "_10_GBPS_TO_100_GBPS": "10–100 Gbps (larges)",
    "OVER_100_GBPS": "> 100 Gbps (volumétriques)"
}

lines.append("### 3.1 Statistiques Descriptives par Classe de Débit")
lines.append("")
lines.append("| Classe de débit | N | Moy (%) | Méd (%) | Std | Min | Max | Tendance MK |")
lines.append("|---|---:|---:|---:|---:|---:|---:|---|")
for c in RATE_COLS:
    s = rate_stats[c]
    tl = trend_label(s["tau"], s["p_mk"])
    lines.append(f"| **{RATE_LABELS[c]}** | {s['N']} | {s['Moy']:.2f} | {s['Med']:.2f} | "
                 f"{s['Std']:.2f} | {s['Min']:.2f} | {s['Max']:.2f} | {tl} |")
lines.append("")

lines.append("### 3.2 Tableau Complet Hebdomadaire — Distribution Débits")
lines.append("")
lines.append("| # | Date | <500M (%) | 500M-1G (%) | 1-10G (%) | 10-100G (%) | >100G (%) | Taille moy. (Mbps) |")
lines.append("|---:|---|---:|---:|---:|---:|---:|---:|")
for i, row in l3_rate.iterrows():
    lines.append(
        f"| S{i+1:02d} | {row['date_str']} | "
        f"{row['UNDER_500_MBPS']:.1f} | {row['_500_MBPS_TO_1_GBPS']:.1f} | "
        f"{row['_1_GBPS_TO_10_GBPS']:.1f} | {row['_10_GBPS_TO_100_GBPS']:.2f} | "
        f"{row['OVER_100_GBPS']:.3f} | {row['weighted_size_mbps']:.0f} |"
    )
lines.append("")

lines.append("### 3.3 Anomalies Débits (|Z| ≥ 2,5)")
lines.append("")
any_rate_anom = False
for c in RATE_COLS:
    anom = rate_anomalies[c]
    if anom:
        any_rate_anom = True
        lines.append(f"**{RATE_LABELS[c]} :**")
        lines.append("")
        lines.append("| Semaine | Valeur (%) | Z-score | Type |")
        lines.append("|---:|---:|---:|---|")
        for idx, val, z in anom:
            t = "PIC" if z > 0 else "CREUX"
            date_str = l3_rate["date_str"].iloc[idx]
            lines.append(f"| S{idx+1:02d} ({date_str}) | {val:.3f} | {z:.3f} | **{t}** |")
        lines.append("")
if not any_rate_anom:
    lines.append("Aucune anomalie détectée.")
    lines.append("")

# Taille moyenne pondérée stats
ws = l3_rate["weighted_size_mbps"]
lines.append("### 3.4 Taille Moyenne Pondérée des Attaques L3 (Mbps)")
lines.append("")
lines.append("| Statistique | Valeur |")
lines.append("|---|---:|")
lines.append(f"| Moyenne | {ws.mean():.0f} Mbps |")
lines.append(f"| Médiane | {ws.median():.0f} Mbps |")
lines.append(f"| Min | {ws.min():.0f} Mbps (S{ws.idxmin()+1}) |")
lines.append(f"| Max | {ws.max():.0f} Mbps (S{ws.idxmax()+1}) |")
lines.append(f"| Std | {ws.std():.0f} Mbps |")

tau_ws, z_ws, p_ws = mann_kendall(ws.values)
tl_ws = trend_label(tau_ws, p_ws)
lines.append(f"| Tendance | {tl_ws} (Tau={tau_ws:.3f}) |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 : L3 — VERSION IP
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 4. L3 — Version IP des Attaques (IPv4 vs IPv6)")
lines.append("")
lines.append("### 4.1 Statistiques et Tendances")
lines.append("")
lines.append("| Version | Moy (%) | Méd (%) | Min | Max | Std | Tendance MK | Tau | p-value |")
lines.append("|---|---:|---:|---:|---:|---:|---|---:|---:|")
for c in IP_COLS:
    s = ip_stats[c]
    tl = trend_label(s["tau"], s["p_mk"])
    lines.append(f"| **{c}** | {s['Moy']:.3f} | {s['Med']:.3f} | {s['Min']:.3f} | "
                 f"{s['Max']:.3f} | {s['Std']:.3f} | {tl} | {s['tau']:.4f} | "
                 f"{s['p_mk']:.4f} {p_stars(s['p_mk'])} |")
lines.append("")

lines.append("### 4.2 Tableau Complet Hebdomadaire — IPv4 vs IPv6")
lines.append("")
lines.append("| # | Date | IPv4 (%) | IPv6 (%) | Z(IPv6) |")
lines.append("|---:|---|---:|---:|---:|")
z_ipv6 = (l3_ip["IPv6"] - l3_ip["IPv6"].mean()) / l3_ip["IPv6"].std()
for i, row in l3_ip.iterrows():
    anom = " ⚠️" if abs(z_ipv6.iloc[i]) >= 2.5 else ""
    lines.append(f"| S{i+1:02d} | {row['date_str']} | {row['IPv4']:.3f} | "
                 f"{row['IPv6']:.3f} | {z_ipv6.iloc[i]:.2f}{anom} |")
lines.append("")
lines.append("> **Note :** IPv6 < 1% en permanence dans les attaques L3 — "
             "contraste fort avec l'adoption IPv6 générale (≈20% du trafic global).")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 : L7 — SECTEURS CIBLÉS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 5. L7 — Secteurs Ciblés (Vertical)")
lines.append("")
lines.append(f"**Période : 2026-03-17 → 2026-06-09 ({len(l7_vert)} jours)**")
lines.append("")

lines.append("### 5.1 Statistiques Descriptives et Tendances par Secteur")
lines.append("")
lines.append("| Secteur | Moy (%) | Méd (%) | Std | Min | Max | Tendance MK | Tau | R² OLS |")
lines.append("|---|---:|---:|---:|---:|---:|---|---:|---:|")
# tri par moyenne décroissante
sorted_vert = sorted(VERT_COLS, key=lambda c: vert_stats[c]["Moy"], reverse=True)
for c in sorted_vert:
    s = vert_stats[c]
    tl = trend_label(s["tau"], s["p_mk"])
    tau_s = fv(s["tau"])
    r2_s  = fv(s["r2"])
    lines.append(f"| **{c}** | {s['Moy']:.2f} | {s['Med']:.2f} | {s['Std']:.2f} | "
                 f"{s['Min']:.2f} | {s['Max']:.2f} | {tl} | {tau_s} | {r2_s} |")
lines.append("")

# HHI
global_hhi = hhi(l7_vert[VERT_COLS].mean().values)
lines.append(f"**Indice HHI de concentration sectorielle (moyen) : {global_hhi:.0f}/10 000**")
lines.append("")
if global_hhi > 2500:
    lines.append("> HHI > 2 500 → marché très concentré (quelques secteurs dominent les cibles L7).")
elif global_hhi > 1500:
    lines.append("> HHI 1 500–2 500 → marché modérément concentré.")
else:
    lines.append("> HHI < 1 500 → cibles relativement dispersées entre secteurs.")
lines.append("")

lines.append("### 5.2 Tableau Quotidien Complet — Secteurs L7")
lines.append("")
# Colonnes courtes pour le tableau
short = {
    "Computer and Electronics": "Comput&Elec",
    "Internet and Telecom": "Net&Telecom",
    "other": "Autre",
    "Shopping & General Merchandise": "Shopping",
    "Finance": "Finance",
    "Gambling": "Gambling",
    "News, Media, and Publications": "News&Media",
    "Business and Industry": "Business",
    "Professional Services": "Pro Svc",
    "Art, Entertainment & Recreation": "Art&Ent"
}
header = " | ".join([f"{short[c]}" for c in VERT_COLS])
lines.append(f"| # | Date | {header} | Top secteur |")
lines.append("|---:|---|" + "---:|" * len(VERT_COLS) + "---|")
for i, row in l7_vert.iterrows():
    vals = [row[c] for c in VERT_COLS]
    top_c = VERT_COLS[int(np.nanargmax(vals))]
    vals_str = " | ".join(f"{v:.1f}" for v in vals)
    lines.append(f"| D{i+1:02d} | {row['date_str']} | {vals_str} | {short[top_c]} |")
lines.append("")

lines.append("### 5.3 Évolution Mensuelle — Secteurs L7")
lines.append("")
lines.append("| Mois | " + " | ".join(short.values()) + " |")
lines.append("|---|" + "---:|" * len(VERT_COLS) + "")
for month, row in vert_monthly.iterrows():
    vals_str = " | ".join(f"{row[c]:.1f}" for c in VERT_COLS)
    lines.append(f"| {month} | {vals_str} |")
lines.append("")

lines.append("### 5.4 Profil Jour de la Semaine — Secteurs L7")
lines.append("")
lines.append("| Jour | " + " | ".join(short.values()) + " |")
lines.append("|---|" + "---:|" * len(VERT_COLS) + "")
for day, row in wdp_vert.iterrows():
    vals_str = " | ".join(f"{row[c]:.1f}" for c in VERT_COLS)
    lines.append(f"| {day} | {vals_str} |")
lines.append("")

lines.append("### 5.5 Anomalies Secteurs (|Z| ≥ 2,5)")
lines.append("")
any_vert_anom = False
for c in sorted_vert:
    anom = vert_anomalies[c]
    if anom:
        any_vert_anom = True
        lines.append(f"**{c} :**")
        lines.append("")
        lines.append("| Jour | Date | Valeur (%) | Z-score | Type |")
        lines.append("|---:|---|---:|---:|---|")
        for idx, val, z in anom:
            t = "PIC" if z > 0 else "CREUX"
            date_str = l7_vert["date_str"].iloc[idx]
            lines.append(f"| D{idx+1:02d} | {date_str} | {val:.2f} | {z:.3f} | **{t}** |")
        lines.append("")
if not any_vert_anom:
    lines.append("Aucune anomalie détectée.")
    lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 : L7 — MÉTHODES HTTP
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 6. L7 — Méthodes HTTP des Attaques")
lines.append("")

lines.append("### 6.1 Statistiques Descriptives et Tendances")
lines.append("")
lines.append("| Méthode | Moy (%) | Méd (%) | Std | Min | Max | Tendance MK | R² OLS |")
lines.append("|---|---:|---:|---:|---:|---:|---|---:|")
sorted_meth = sorted(METH_COLS, key=lambda c: meth_stats[c]["Moy"], reverse=True)
for c in sorted_meth:
    s = meth_stats[c]
    tl = trend_label(s["tau"], s["p_mk"])
    r2_s = fv(s["r2"])
    lines.append(f"| **{c}** | {s['Moy']:.3f} | {s['Med']:.3f} | {s['Std']:.3f} | "
                 f"{s['Min']:.3f} | {s['Max']:.3f} | {tl} | {r2_s} |")
lines.append("")

lines.append("### 6.2 Tableau Quotidien Complet — Méthodes HTTP")
lines.append("")
lines.append("| # | Date | GET (%) | POST (%) | HEAD (%) | OPT (%) | PATCH (%) | DEL (%) | PUT (%) | UNK (%) | ACL (%) |")
lines.append("|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
for i, row in l7_meth.iterrows():
    lines.append(
        f"| D{i+1:02d} | {row['date_str']} | "
        f"{row['GET']:.2f} | {row['POST']:.2f} | {row['HEAD']:.2f} | "
        f"{row['OPTIONS']:.3f} | {row['PATCH']:.3f} | {row['DELETE']:.3f} | "
        f"{row['PUT']:.3f} | {row['UNKNOWN']:.4f} | {row['ACL']:.6f} |"
    )
lines.append("")

lines.append("### 6.3 Évolution Mensuelle — Méthodes HTTP")
lines.append("")
lines.append("| Mois | GET (%) | POST (%) | HEAD (%) | OPTIONS (%) | PATCH (%) | DELETE (%) |")
lines.append("|---|---:|---:|---:|---:|---:|---:|")
for month, row in meth_monthly.iterrows():
    lines.append(f"| {month} | {row['GET']:.2f} | {row['POST']:.2f} | {row['HEAD']:.2f} | "
                 f"{row['OPTIONS']:.3f} | {row['PATCH']:.3f} | {row['DELETE']:.3f} |")
lines.append("")

lines.append("### 6.4 Profil Jour de la Semaine — Méthodes HTTP")
lines.append("")
lines.append("| Jour | GET (%) | POST (%) | HEAD (%) | OPTIONS (%) | PATCH (%) | DELETE (%) |")
lines.append("|---|---:|---:|---:|---:|---:|---:|")
for day, row in wdp_meth.iterrows():
    lines.append(f"| {day} | {row['GET']:.2f} | {row['POST']:.2f} | {row['HEAD']:.2f} | "
                 f"{row['OPTIONS']:.3f} | {row['PATCH']:.3f} | {row['DELETE']:.3f} |")
lines.append("")

lines.append("### 6.5 Anomalies Méthodes HTTP (|Z| ≥ 2,5)")
lines.append("")
any_meth_anom = False
for c in sorted_meth:
    anom = meth_anomalies[c]
    if anom:
        any_meth_anom = True
        lines.append(f"**{c} :**")
        lines.append("")
        lines.append("| Jour | Date | Valeur (%) | Z-score | Type |")
        lines.append("|---:|---|---:|---:|---|")
        for idx, val, z in anom:
            t = "PIC" if z > 0 else "CREUX"
            date_str = l7_meth["date_str"].iloc[idx]
            lines.append(f"| D{idx+1:02d} | {date_str} | {val:.4f} | {z:.3f} | **{t}** |")
        lines.append("")
if not any_meth_anom:
    lines.append("Aucune anomalie détectée.")
    lines.append("")

lines.append("### 6.6 Barre ASCII — Répartition moyenne des méthodes")
lines.append("")
lines.append("```")
max_meth = meth_stats["GET"]["Moy"]
for c in sorted_meth:
    v = meth_stats[c]["Moy"]
    bar = "#" * int(v / max_meth * 40) + "." * (40 - int(v / max_meth * 40))
    lines.append(f"{c:10s} [{bar}] {v:.3f}%")
lines.append("```")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 : L7 — VERSION HTTP
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 7. L7 — Version HTTP des Attaques")
lines.append("")

lines.append("### 7.1 Statistiques Descriptives et Tendances")
lines.append("")
lines.append("| Version | Moy (%) | Méd (%) | Std | Min | Max | Tendance MK | Tau | p-value |")
lines.append("|---|---:|---:|---:|---:|---:|---|---:|---:|")
for c in VER_COLS:
    s = ver_stats[c]
    tl = trend_label(s["tau"], s["p_mk"])
    tau_s = fv(s["tau"])
    pmk_s = "N/A" if s["p_mk"] is None else f"{s['p_mk']:.4f} {p_stars(s['p_mk'])}"
    lines.append(f"| **{c}** | {s['Moy']:.2f} | {s['Med']:.2f} | {s['Std']:.2f} | "
                 f"{s['Min']:.2f} | {s['Max']:.2f} | {tl} | {tau_s} | {pmk_s} |")
lines.append("")

lines.append("### 7.2 Tableau Quotidien Complet — Version HTTP des Attaques")
lines.append("")
lines.append("| # | Date | HTTP/2 (%) | HTTP/1.x (%) | HTTP/3 (%) |")
lines.append("|---:|---|---:|---:|---:|")
for i, row in l7_ver.iterrows():
    lines.append(f"| D{i+1:02d} | {row['date_str']} | {row['HTTP/2']:.2f} | "
                 f"{row['HTTP/1.x']:.2f} | {row['HTTP/3']:.2f} |")
lines.append("")

lines.append("### 7.3 Évolution Mensuelle — Version HTTP")
lines.append("")
lines.append("| Mois | HTTP/2 (%) | HTTP/1.x (%) | HTTP/3 (%) |")
lines.append("|---|---:|---:|---:|")
for month, row in ver_monthly.iterrows():
    lines.append(f"| {month} | {row['HTTP/2']:.2f} | {row['HTTP/1.x']:.2f} | {row['HTTP/3']:.2f} |")
lines.append("")

lines.append("### 7.4 Profil Jour de la Semaine — Version HTTP")
lines.append("")
lines.append("| Jour | HTTP/2 (%) | HTTP/1.x (%) | HTTP/3 (%) |")
lines.append("|---|---:|---:|---:|")
for day, row in wdp_ver.iterrows():
    lines.append(f"| {day} | {row['HTTP/2']:.2f} | {row['HTTP/1.x']:.2f} | {row['HTTP/3']:.2f} |")
lines.append("")

lines.append("### 7.5 Anomalies Version HTTP (|Z| ≥ 2,5)")
lines.append("")
any_ver_anom = False
for c in VER_COLS:
    anom = ver_anomalies[c]
    if anom:
        any_ver_anom = True
        lines.append(f"**{c} :**")
        lines.append("")
        lines.append("| Jour | Date | Valeur (%) | Z-score | Type |")
        lines.append("|---:|---|---:|---:|---|")
        for idx, val, z in anom:
            t = "PIC" if z > 0 else "CREUX"
            date_str = l7_ver["date_str"].iloc[idx]
            lines.append(f"| D{idx+1:02d} | {date_str} | {val:.2f} | {z:.3f} | **{t}** |")
        lines.append("")
if not any_ver_anom:
    lines.append("Aucune anomalie détectée.")
    lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 : ANALYSE CROISÉE L3 × L7
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 8. Analyse Croisée L3 × L7")
lines.append("")

lines.append("### 8.1 Comparaison Adoption IPv6 : Attaques vs Trafic Général")
lines.append("")
lines.append("| Indicateur | IPv6 moyen (%) | Source |")
lines.append("|---|---:|---|")
lines.append(f"| Attaques L3 | {ip_stats['IPv6']['Moy']:.3f} | Cloudflare Radar attacks_l3 |")
lines.append(f"| Trafic HTTP global | ~20 | Cloudflare Radar http_ip_version (Phase D) |")
lines.append("")
lines.append("> **Paradoxe de l'IPv6 dans les attaques :** Le trafic d'attaque L3 est quasi-exclusivement "
             "IPv4 (<1% IPv6) alors que ~20% du trafic légitime global circule déjà en IPv6. "
             "Cela suggère que les attaquants évitent délibérément IPv6 (moins bien routé, "
             "plus traçable via attribution ASN, ou simplement parce que les botnets restent IPv4-only).")
lines.append("")

lines.append("### 8.2 Comparaison HTTP/3 : Attaques L7 vs Trafic Général")
lines.append("")
lines.append("| Indicateur | HTTP/3 moyen (%) | Source |")
lines.append("|---|---:|---|")
lines.append(f"| Attaques L7 | {ver_stats['HTTP/3']['Moy']:.2f} | Cloudflare Radar attacks_l7 |")
lines.append(f"| Trafic HTTP global | ~12–15 | Cloudflare Radar http_http_version (Phase D) |")
lines.append("")
lines.append("> HTTP/3 est sous-représenté dans les attaques L7 par rapport au trafic légitime, "
             "ce qui indique que les outils d'attaque DDoS n'ont pas encore adopté massivement QUIC/HTTP3.")
lines.append("")

lines.append("### 8.3 Profil d'Attaque Hebdomadaire vs Quotidien")
lines.append("")
lines.append("| Dimension | Granularité | Séries | Période couverte |")
lines.append("|---|---|---|---|")
lines.append("| L3 (protocole, débit, IP) | Hebdomadaire | 3 séries × 53 obs. | Juin 2025 – Juin 2026 |")
lines.append("| L7 (vertical, méthode, HTTP ver.) | Quotidien | 3 séries × 85 obs. | Mars 2026 – Juin 2026 |")
lines.append("")
lines.append("> **Limitation :** Les données L7 couvrent uniquement le Q2 2026 (85 jours). "
             "Toute comparaison temporelle L3–L7 est limitée à la plage commune mars–juin 2026.")
lines.append("")

# Comparaison sur la période commune (mars-juin 2026 pour L3)
l3_proto["date_only"] = l3_proto["date"].dt.date
common_start = pd.Timestamp("2026-03-17").date()
l3_recent = l3_proto[l3_proto["date_only"] >= common_start]
lines.append("**L3 protocoles — période commune avec L7 (mars–juin 2026) :**")
lines.append("")
lines.append("| Stat | UDP (%) | TCP (%) | GRE (%) | ICMP (%) |")
lines.append("|---|---:|---:|---:|---:|")
for stat_name, func in [("Moy", "mean"), ("Méd", "median"), ("Min", "min"), ("Max", "max")]:
    row_vals = " | ".join(f"{getattr(l3_recent[c], func)():.2f}" for c in PROTO_COLS)
    lines.append(f"| {stat_name} | {row_vals} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 : CORRÉLATIONS L7
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 9. Corrélations Intra-L7")
lines.append("")
lines.append("### 9.1 Corrélation Secteurs (Spearman)")
lines.append("")
vert_spear = l7_vert[VERT_COLS].corr(method="spearman")
short_h = list(short.values())
lines.append("| | " + " | ".join(short_h) + " |")
lines.append("|---|" + "---:|" * len(VERT_COLS))
for i, c in enumerate(VERT_COLS):
    row_vals = " | ".join(f"{vert_spear.loc[c, c2]:.2f}" for c2 in VERT_COLS)
    lines.append(f"| **{short[c]}** | {row_vals} |")
lines.append("")

lines.append("### 9.2 Corrélation Méthodes HTTP (Spearman)")
lines.append("")
meth_spear = l7_meth[METH_COLS].corr(method="spearman")
lines.append("| | " + " | ".join(METH_COLS) + " |")
lines.append("|---|" + "---:|" * len(METH_COLS))
for c in METH_COLS:
    row_vals = " | ".join(f"{meth_spear.loc[c, c2]:.2f}" for c2 in METH_COLS)
    lines.append(f"| **{c}** | {row_vals} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 : SYNTHÈSE ET IMPLICATIONS SÉCURITÉ
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 10. Synthèse et Implications Sécurité")
lines.append("")

lines.append("### 10.1 Tableau Récapitulatif des Tendances")
lines.append("")
lines.append("| Série | Tendance | Tau MK | p-value | Implication |")
lines.append("|---|---|---:|---:|---|")

all_series = (
    [(f"L3 {c}", proto_stats[c]) for c in PROTO_COLS] +
    [(f"L3 {RATE_LABELS[c]}", rate_stats[c]) for c in RATE_COLS] +
    [(f"L3 {c}", ip_stats[c]) for c in IP_COLS] +
    [(f"L7 Vertical: {c}", vert_stats[c]) for c in sorted_vert] +
    [(f"L7 Méthode: {c}", meth_stats[c]) for c in sorted_meth] +
    [(f"L7 HTTP: {c}", ver_stats[c]) for c in VER_COLS]
)
implications = {
    "UDP": "Amplification/Réflexion UDP dominante",
    "TCP": "SYN floods / connexions TCP",
    "GRE": "Tunnels GRE — vecteur encapsulation",
    "ICMP": "ICMP flood — vecteur mineur",
    "UNDER_500_MBPS": "Majorité d'attaques en volume faible",
    "_500_MBPS_TO_1_GBPS": "Classe intermédiaire",
    "_1_GBPS_TO_10_GBPS": "Attaques de capacité notable",
    "_10_GBPS_TO_100_GBPS": "Attaques larges bande",
    "OVER_100_GBPS": "Hyper-volumétriques — impact infrastructure",
    "IPv4": "Vecteur quasi-exclusif des attaques L3",
    "IPv6": "IPv6 absent des attaques — botnets IPv4-only",
    "Computer and Electronics": "Secteur tech très exposé",
    "Internet and Telecom": "Infrastructures réseau ciblées",
    "other": "Cibles non catégorisées",
    "Shopping & General Merchandise": "E-commerce — cibles financières",
    "Finance": "Secteur financier — haute valeur",
    "Gambling": "Jeux en ligne — cible extorsion DDoS",
    "News, Media, and Publications": "Médias — souvent politiquement motivé",
    "Business and Industry": "Infrastructure corporate",
    "Professional Services": "Services pro — données sensibles",
    "Art, Entertainment & Recreation": "Divertissement — cible mineure",
    "GET": "Flood de requêtes GET — emulation trafic légitime",
    "POST": "Attaques applicatives POST",
    "HEAD": "Flood HEAD — reconnaissance/bypass WAF",
    "OPTIONS": "Flood OPTIONS — CORS bypass tentatives",
    "PATCH": "Attaques applicatives PATCH",
    "DELETE": "Tentatives de suppression applicative",
    "PUT": "Tentatives d'upload malveillant",
    "UNKNOWN": "Méthodes non standard",
    "ACL": "Attaques ACL — vecteur rare",
    "HTTP/2": "HTTP/2 — vecteur DDoS dominant",
    "HTTP/1.x": "HTTP/1.x — vecteur legacy encore actif",
    "HTTP/3": "HTTP/3/QUIC — vecteur émergent",
}
for name, s in all_series:
    key = name.split(": ")[-1].split(" ")[-1] if ":" in name else name.replace("L3 ", "").replace("L7 ", "")
    impl = implications.get(s.get("_key", ""), "—")
    for k, v in implications.items():
        if k in name:
            impl = v
            break
    tl = trend_label(s.get("tau"), s.get("p_mk"))
    tau_v = f"{s['tau']:.3f}" if s.get("tau") is not None else "N/A"
    p_v   = f"{s['p_mk']:.4f}" if s.get("p_mk") is not None and not np.isnan(s['p_mk']) else "N/A"
    lines.append(f"| {name} | {tl} | {tau_v} | {p_v} | {impl} |")
lines.append("")

lines.append("### 10.2 Findings Clés")
lines.append("")
lines.append("1. **UDP amplifié dominant :** " +
             f"UDP représente {proto_stats['UDP']['Moy']:.1f}% des attaques L3 en moyenne, "
             "avec des pics à " + f"{proto_stats['UDP']['Max']:.1f}% — "
             "reflet de la prévalence des attaques par amplification DNS/NTP/SSDP.")
lines.append("")
lines.append("2. **Attaques majoritairement sous 500 Mbps :** " +
             f"{rate_stats['UNDER_500_MBPS']['Moy']:.1f}% des attaques restent sous 500 Mbps, "
             "suggérant une stratégie de multitude d'attaques de faible volume plutôt que "
             "quelques méga-attaques — difficile à filtrer par seuil simple.")
lines.append("")
lines.append("3. **Concentration des cibles L7 :** Secteur Computer & Electronics " +
             f"({vert_stats['Computer and Electronics']['Moy']:.1f}%) et Internet & Telecom " +
             f"({vert_stats['Internet and Telecom']['Moy']:.1f}%) concentrent plus de "
             f"{vert_stats['Computer and Electronics']['Moy'] + vert_stats['Internet and Telecom']['Moy']:.0f}% "
             "des attaques applicatives.")
lines.append("")
lines.append("4. **GET flood majoritaire :** " +
             f"{meth_stats['GET']['Moy']:.1f}% des attaques L7 utilisent GET — "
             "méthode la plus simple à usurper car identique au trafic navigateur légitime.")
lines.append("")
lines.append(f"5. **HTTP/3 dans les attaques :** {ver_stats['HTTP/3']['Moy']:.1f}% — "
             "sous-représenté par rapport au trafic légitime, mais tendance " +
             trend_label(ver_stats['HTTP/3']['tau'], ver_stats['HTTP/3']['p_mk']) + ". "
             "La montée de QUIC dans les attaques requiert des capacités de filtrage L4 spécifiques.")
lines.append("")
lines.append("6. **Gambling et Finance : risque d'extorsion DDoS :** " +
             f"Finance ({vert_stats['Finance']['Moy']:.1f}%) et Gambling " +
             f"({vert_stats['Gambling']['Moy']:.1f}%) sont des cibles de choix pour "
             "les campagnes RDoS (Ransom DDoS) — pression temporelle maximale.")
lines.append("")
lines.append("---")
lines.append(f"*Rapport généré automatiquement par `phase_E_attaques.py` le {ts}.*  ")
lines.append("*Sources : Cloudflare Radar API v4 — attacks_l3_*, attacks_l7_* datasets.*  ")
lines.append("*Prochaine étape : Phase F — Analyse détaillée email security (DMARC/DKIM/SPF/SPAM/SPOOF).*")

# ── Écriture ─────────────────────────────────────────────────────────────────
content = "\n".join(lines)
with open(OUT, "w", encoding="utf-8") as f:
    f.write(content)

size_kb = os.path.getsize(OUT) / 1024
n_lines = content.count("\n") + 1
print(f"\nRapport ecrit : {OUT}")
print(f"Taille : {size_kb:.1f} Ko")
print(f"Lignes : {n_lines}")
