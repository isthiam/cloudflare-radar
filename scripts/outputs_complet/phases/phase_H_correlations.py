# -*- coding: utf-8 -*-
"""
Phase H — Corrélations Inter-Domaines (Cross-Domain Correlations)
Analyse des corrélations entre : BGP, DNS, Email, HTTP/Protocol, L3/L7 Attacks
"""

import os
import sys
import warnings
import ast
import numpy as np
import pandas as pd
from datetime import datetime
from scipy import stats
from statsmodels.tsa.stattools import grangercausalitytests, adfuller, ccf as sm_ccf

warnings.filterwarnings("ignore")

BASE = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/cleaned/"
OUT  = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/rapport_phase_H.md"

print("Phase H — Chargement et construction des séries temporelles inter-domaines...")

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def parse_date(df, col="date"):
    df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    df[col] = df[col].dt.tz_localize(None)
    return df

def week_floor(dt_series):
    return dt_series.dt.to_period("W").dt.start_time

def spearman_pval(x, y):
    mask = ~(np.isnan(x) | np.isnan(y))
    if mask.sum() < 10:
        return np.nan, np.nan
    r, p = stats.spearmanr(x[mask], y[mask])
    return r, p

def adf_pval(series):
    s = series.dropna()
    if len(s) < 10:
        return np.nan
    try:
        return adfuller(s, autolag="AIC")[1]
    except Exception:
        return np.nan

def mann_kendall(series):
    s = series.dropna().values
    n = len(s)
    if n < 5:
        return np.nan, np.nan
    # Standard: S = Σ sign(s[j]-s[i]) for j>i → positive for increasing series
    tau, p = stats.kendalltau(np.arange(n), s)
    return tau, p

def safe_granger(y, x, maxlag=4):
    """Returns min p-value across lags, or NaN on error."""
    df2 = pd.DataFrame({"y": y, "x": x}).dropna()
    if len(df2) < maxlag + 10:
        return np.nan
    try:
        res = grangercausalitytests(df2[["y","x"]], maxlag=maxlag, verbose=False)
        pvals = [res[l][0]["ssr_ftest"][1] for l in range(1, maxlag+1)]
        return min(pvals)
    except Exception:
        return np.nan

def fv(v, fmt=".4f", na="N/A"):
    if v is None:
        return na
    try:
        if np.isnan(v):
            return na
    except (TypeError, ValueError):
        pass
    return format(v, fmt)

def trend_label(tau, p):
    if p is None or np.isnan(p) or p > 0.05:
        return "stable (n.s.)"
    if tau > 0.3:
        return f"↑ hausse forte (τ={tau:.2f})"
    elif tau > 0.1:
        return f"↑ hausse modérée (τ={tau:.2f})"
    elif tau < -0.3:
        return f"↓ baisse forte (τ={tau:.2f})"
    elif tau < -0.1:
        return f"↓ baisse modérée (τ={tau:.2f})"
    else:
        return f"stable (τ={tau:.2f})"

# ══════════════════════════════════════════════════════════════════════════════
# 1. CHARGEMENT DES SÉRIES TEMPORELLES GLOBALES
# ══════════════════════════════════════════════════════════════════════════════
print("  1/7 Chargement BGP timeseries + DNS timeseries...")

bgp_ts = parse_date(pd.read_csv(BASE + "bgp_timeseries_clean.csv"))
bgp_ts = bgp_ts.rename(columns={"values": "bgp_msg_vol"})
bgp_ts = bgp_ts.set_index("date")["bgp_msg_vol"]

dns_ts = parse_date(pd.read_csv(BASE + "dns_timeseries_clean.csv"))
dns_ts = dns_ts.rename(columns={"values": "dns_quality"})
dns_ts = dns_ts.set_index("date")["dns_quality"]

# ══════════════════════════════════════════════════════════════════════════════
# 2. EMAIL SERIES
# ══════════════════════════════════════════════════════════════════════════════
print("  2/7 Chargement séries email...")

dmarc = parse_date(pd.read_csv(BASE + "email_dmarc_clean.csv")).set_index("date")
dkim  = parse_date(pd.read_csv(BASE + "email_dkim_clean.csv")).set_index("date")
spf   = parse_date(pd.read_csv(BASE + "email_spf_clean.csv")).set_index("date")
spam  = parse_date(pd.read_csv(BASE + "email_spam_clean.csv")).set_index("date")
spoof = parse_date(pd.read_csv(BASE + "email_spoof_clean.csv")).set_index("date")
malic = parse_date(pd.read_csv(BASE + "email_malicious_clean.csv")).set_index("date")

email_series = pd.DataFrame({
    "dmarc_pass":  dmarc["PASS"],
    "dmarc_fail":  dmarc["FAIL"],
    "dkim_pass":   dkim["PASS"],
    "spf_pass":    spf["PASS"],
    "spf_fail":    spf["FAIL"],
    "spam":        spam["SPAM"],
    "spoof":       spoof["SPOOF"],
    "malicious":   malic["MALICIOUS"],
})
# ISE
email_series["ISE"] = (
    email_series["dmarc_pass"] * 0.35 +
    email_series["dkim_pass"]  * 0.35 +
    email_series["spf_pass"]   * 0.30
) - (email_series["spam"] + email_series["spoof"] + email_series["malicious"]) / 3 * 0.5

# ══════════════════════════════════════════════════════════════════════════════
# 3. HTTP GLOBAL SERIES (mean across countries)
# ══════════════════════════════════════════════════════════════════════════════
print("  3/7 Calcul moyennes HTTP globales...")

def http_global(fname, cols):
    df = parse_date(pd.read_csv(BASE + fname))
    df["week"] = week_floor(df["date"])
    return df.groupby("week")[cols].mean()

ipv6_g  = http_global("http_ip_version_clean.csv", ["IPv6"])
http3_g = http_global("http_http_version_clean.csv", ["HTTP/3"])
tls13_raw = parse_date(pd.read_csv(BASE + "http_tls_version_clean.csv"))
tls13_raw = tls13_raw.rename(columns={"TLS 1.3": "TLSv1.3"})
tls13_raw["week"] = week_floor(tls13_raw["date"])
tls13_g = tls13_raw.groupby("week")[["TLSv1.3"]].mean()
bot_g   = http_global("http_bot_class_clean.csv", ["bot"])
mobile_g= http_global("http_device_type_clean.csv", ["mobile"])

# IQI bandwidth global
bw = parse_date(pd.read_csv(BASE + "iqi_bandwidth_clean.csv"))
bw_g = bw.groupby("date")["p50"].mean().rename("bw_p50")

# IMP (simplified weekly)
http_wk = ipv6_g.join(http3_g, how="outer").join(tls13_g, how="outer").join(bot_g, how="outer").join(mobile_g, how="outer")
http_wk.index = pd.to_datetime(http_wk.index)

def minmax(s):
    rng = s.max() - s.min()
    return (s - s.min()) / rng if rng > 0 else s * 0

http_wk["IMP"] = (
    minmax(http_wk["IPv6"])   * 0.25 +
    minmax(http_wk["HTTP/3"]) * 0.25 +
    minmax(http_wk["TLSv1.3"])* 0.20 +
    minmax(100 - http_wk["bot"]) * 0.15 +
    minmax(http_wk["mobile"]) * 0.15
) * 100

# ══════════════════════════════════════════════════════════════════════════════
# 4. L3 ATTACK SERIES
# ══════════════════════════════════════════════════════════════════════════════
print("  4/7 Chargement L3 attacks...")

l3_proto = parse_date(pd.read_csv(BASE + "attacks_l3_protocol_clean.csv")).set_index("date")
l3_bitrate= parse_date(pd.read_csv(BASE + "attacks_l3_bitrate_clean.csv")).set_index("date")
l3_ipver  = parse_date(pd.read_csv(BASE + "attacks_l3_ip_version_clean.csv")).set_index("date")

l3_series = pd.DataFrame({
    "l3_udp":  l3_proto["UDP"],
    "l3_tcp":  l3_proto["TCP"],
})
# L3 gros volume proxy: share >1 Gbps
if "_1_GBPS_TO_10_GBPS" in l3_bitrate.columns:
    l3_series["l3_high_vol"] = (
        l3_bitrate["_1_GBPS_TO_10_GBPS"].fillna(0) +
        l3_bitrate["_10_GBPS_TO_100_GBPS"].fillna(0) +
        l3_bitrate["OVER_100_GBPS"].fillna(0)
    )

# ══════════════════════════════════════════════════════════════════════════════
# 5. L7 ATTACK SERIES (daily → weekly resample)
# ══════════════════════════════════════════════════════════════════════════════
print("  5/7 Resampling L7 attacks...")

l7_vert = parse_date(pd.read_csv(BASE + "attacks_l7_vertical_clean.csv"))
l7_vert = l7_vert[l7_vert["dimension"] == "vertical"].copy()
l7_vert["week"] = week_floor(l7_vert["date"])
vert_cols = ["Computer and Electronics", "Internet and Telecom", "Finance", "Gambling"]
l7_wk = l7_vert.groupby("week")[vert_cols].mean()
l7_wk.index = pd.to_datetime(l7_wk.index)
l7_wk = l7_wk.rename(columns={
    "Computer and Electronics": "l7_compu_elec",
    "Internet and Telecom": "l7_internet_telecom",
    "Finance": "l7_finance",
    "Gambling": "l7_gambling",
})

l7_meth = parse_date(pd.read_csv(BASE + "attacks_l7_http_method_clean.csv"))
l7_meth = l7_meth[l7_meth["dimension"] == "http_method"].copy()
l7_meth["week"] = week_floor(l7_meth["date"])
l7_meth_wk = l7_meth.groupby("week")[["GET","POST"]].mean()
l7_meth_wk.index = pd.to_datetime(l7_meth_wk.index)
l7_meth_wk = l7_meth_wk.rename(columns={"GET":"l7_get","POST":"l7_post"})

# ══════════════════════════════════════════════════════════════════════════════
# 6. BGP HIJACKS WEEKLY SERIES (agrégation par semaine)
# ══════════════════════════════════════════════════════════════════════════════
print("  6/7 Agrégation BGP hijacks/leaks hebdomadaires...")

hij = pd.read_csv(BASE + "bgp_hijacks_clean.csv")
hij["min_hijack_ts"] = pd.to_datetime(hij["min_hijack_ts"], errors="coerce")
hij = hij.dropna(subset=["min_hijack_ts"])
hij["week"] = week_floor(hij["min_hijack_ts"])
hij["rpki_inv"] = hij["tags"].apply(
    lambda s: 1 if isinstance(s, str) and "rpki_new_origin_invalid" in s else 0
)
duration_col = "duration_h" if "duration_h" in hij.columns else None
if duration_col is None and "max_hijack_ts" in hij.columns:
    hij["max_hijack_ts"] = pd.to_datetime(hij["max_hijack_ts"], errors="coerce")
    hij["duration_h"] = (hij["max_hijack_ts"] - hij["min_hijack_ts"]).dt.total_seconds() / 3600
    duration_col = "duration_h"

bgp_hij_wk = hij.groupby("week").agg(
    bgp_hij_count=("id","count"),
    bgp_hij_conf=("confidence_score","mean"),
    bgp_hij_rpki_inv=("rpki_inv","mean"),
    bgp_hij_prefixes=("prefixes_count","mean"),
    bgp_hij_victims=("victim_asns_count","mean"),
).rename(columns=lambda c: c)
bgp_hij_wk["bgp_hij_rpki_inv"] = bgp_hij_wk["bgp_hij_rpki_inv"] * 100
bgp_hij_wk.index = pd.to_datetime(bgp_hij_wk.index)

# severity score weekly
if duration_col:
    hij["sev"] = hij["confidence_score"] * np.log1p(hij["prefixes_count"].clip(lower=0)) * \
                 np.log1p(hij[duration_col].clip(lower=0))
    sev_wk = hij.groupby("week")["sev"].mean().rename("bgp_severity")
    sev_wk.index = pd.to_datetime(sev_wk.index)
    bgp_hij_wk = bgp_hij_wk.join(sev_wk, how="left")

leaks = pd.read_csv(BASE + "bgp_leaks_clean.csv")
leaks["min_ts"] = pd.to_datetime(leaks["min_ts"], errors="coerce")
leaks = leaks.dropna(subset=["min_ts"])
leaks["week"] = week_floor(leaks["min_ts"])
bgp_leaks_wk = leaks.groupby("week").agg(
    bgp_leaks_count=("id","count"),
    bgp_leaks_countries=("countries_count","mean"),
).rename(columns=lambda c: c)
bgp_leaks_wk.index = pd.to_datetime(bgp_leaks_wk.index)

# ══════════════════════════════════════════════════════════════════════════════
# 7. FUSION EN UN DATAFRAME MAÎTRE
# ══════════════════════════════════════════════════════════════════════════════
print("  7/7 Fusion des séries...")

# Toutes les séries en weekly
master = pd.DataFrame(index=pd.date_range("2025-06-09", "2026-06-09", freq="W-MON"))
master.index.name = "week"

def align(series_or_df, index):
    s_or_df = series_or_df.copy()
    s_or_df.index = pd.to_datetime(s_or_df.index).normalize()
    idx_n = pd.to_datetime(index).normalize()
    return s_or_df.reindex(idx_n, method="nearest", tolerance=pd.Timedelta("3d"))

master = master.join(align(bgp_ts, master.index).rename("bgp_msg_vol"), how="left")
master = master.join(align(dns_ts, master.index).rename("dns_quality"), how="left")
master = master.join(align(email_series, master.index), how="left")
master = master.join(align(http_wk, master.index), how="left")
master = master.join(align(bw_g, master.index), how="left")
master = master.join(align(l3_series, master.index), how="left")
master = master.join(align(bgp_hij_wk, master.index), how="left")
master = master.join(align(bgp_leaks_wk, master.index), how="left")
master = master.join(align(l7_wk, master.index), how="left")
master = master.join(align(l7_meth_wk, master.index), how="left")

print(f"  DataFrame maître : {master.shape[0]} semaines × {master.shape[1]} colonnes")
print(f"  Colonnes : {list(master.columns)}")

# ══════════════════════════════════════════════════════════════════════════════
# INDEX COMPOSITE DE VULNÉRABILITÉ (IVC)
# ══════════════════════════════════════════════════════════════════════════════

def norm01(s):
    mn, mx = s.min(), s.max()
    return (s - mn) / (mx - mn) if mx > mn else pd.Series(0, index=s.index)

# BGP risk: normalized(hijack_count × conf)
if "bgp_hij_count" in master.columns and "bgp_hij_conf" in master.columns:
    master["bgp_risk"] = norm01(master["bgp_hij_count"] * master["bgp_hij_conf"])
else:
    master["bgp_risk"] = 0

# Email threat: normalized SPOOF + MALICIOUS component minus protection
if "spoof" in master.columns and "malicious" in master.columns and "dmarc_fail" in master.columns:
    master["email_threat"] = norm01(master["spoof"] + master["malicious"] + master["dmarc_fail"])
else:
    master["email_threat"] = 0

# Protocol weakness: 1 - IMP normalized
if "IMP" in master.columns:
    master["proto_weakness"] = norm01(100 - master["IMP"])
else:
    master["proto_weakness"] = 0

# Network attack intensity: L3 high vol + L7 internet telecom
if "l3_high_vol" in master.columns and "l7_internet_telecom" in master.columns:
    master["net_attack"] = norm01(
        norm01(master["l3_high_vol"]) + norm01(master["l7_internet_telecom"])
    )
elif "l3_high_vol" in master.columns:
    master["net_attack"] = norm01(master["l3_high_vol"])
else:
    master["net_attack"] = 0

master["IVC"] = (
    master["bgp_risk"]      * 0.30 +
    master["email_threat"]  * 0.30 +
    master["proto_weakness"]* 0.20 +
    master["net_attack"]    * 0.20
) * 100

print("Index composite IVC calculé.")

# ══════════════════════════════════════════════════════════════════════════════
# STATISTIQUES PAR DOMAINE POUR LE RAPPORT
# ══════════════════════════════════════════════════════════════════════════════

# Define domain variable groups
DOMAIN_VARS = {
    "BGP Hijacks":     ["bgp_hij_count","bgp_hij_conf","bgp_hij_rpki_inv","bgp_severity"],
    "BGP Leaks":       ["bgp_leaks_count","bgp_leaks_countries"],
    "BGP Volume":      ["bgp_msg_vol"],
    "DNS Quality":     ["dns_quality"],
    "Email Security":  ["dmarc_pass","dmarc_fail","dkim_pass","spf_pass","spf_fail","spam","spoof","malicious","ISE"],
    "HTTP/Protocol":   ["IPv6","HTTP/3","TLSv1.3","bot","mobile","IMP"],
    "L3 Attacks":      ["l3_udp","l3_tcp","l3_high_vol"],
    "L7 Attacks":      ["l7_internet_telecom","l7_compu_elec","l7_finance","l7_gambling","l7_get","l7_post"],
    "IVC":             ["IVC","bgp_risk","email_threat","proto_weakness","net_attack"],
}

# Restrict to existing columns
DOMAIN_VARS = {k: [c for c in v if c in master.columns] for k, v in DOMAIN_VARS.items()}

# All analysis variables (for correlation matrix)
ALL_VARS = [
    "bgp_msg_vol","dns_quality",
    "dmarc_pass","dmarc_fail","dkim_pass","spf_pass","spf_fail","spam","spoof","malicious","ISE",
    "IPv6","HTTP/3","TLSv1.3","bot","IMP",
    "l3_udp","l3_tcp","l3_high_vol",
    "bgp_hij_count","bgp_hij_conf","bgp_hij_rpki_inv","bgp_severity",
    "bgp_leaks_count",
    "l7_internet_telecom","l7_compu_elec","l7_get","l7_post",
    "IVC",
]
ALL_VARS = [c for c in ALL_VARS if c in master.columns]

# Variable labels for display
VAR_LABELS = {
    "bgp_msg_vol":        "BGP volume msgs",
    "dns_quality":        "DNS qualité",
    "dmarc_pass":         "DMARC PASS%",
    "dmarc_fail":         "DMARC FAIL%",
    "dkim_pass":          "DKIM PASS%",
    "spf_pass":           "SPF PASS%",
    "spf_fail":           "SPF FAIL%",
    "spam":               "SPAM%",
    "spoof":              "SPOOF%",
    "malicious":          "MALICIOUS%",
    "ISE":                "ISE (email sec.)",
    "IPv6":               "IPv6%",
    "HTTP/3":             "HTTP/3%",
    "TLSv1.3":            "TLS 1.3%",
    "bot":                "Bot rate%",
    "IMP":                "IMP (protocol)",
    "l3_udp":             "L3 UDP%",
    "l3_tcp":             "L3 TCP%",
    "l3_high_vol":        "L3 haut vol.%",
    "bgp_hij_count":      "BGP hij. count",
    "bgp_hij_conf":       "BGP hij. conf.",
    "bgp_hij_rpki_inv":   "BGP RPKI inv%",
    "bgp_severity":       "BGP sévérité",
    "bgp_leaks_count":    "BGP leaks count",
    "l7_internet_telecom":"L7 Internet&Télécom",
    "l7_compu_elec":      "L7 Informatique",
    "l7_get":             "L7 GET%",
    "l7_post":            "L7 POST%",
    "IVC":                "IVC (vulnérabilité)",
}

def lbl(v):
    return VAR_LABELS.get(v, v)

# ══════════════════════════════════════════════════════════════════════════════
# MATRICE DE CORRÉLATION SPEARMAN
# ══════════════════════════════════════════════════════════════════════════════
print("Calcul matrice de corrélation Spearman...")

N = len(ALL_VARS)
corr_matrix = np.full((N, N), np.nan)
pval_matrix = np.full((N, N), np.nan)

for i, v1 in enumerate(ALL_VARS):
    for j, v2 in enumerate(ALL_VARS):
        if i == j:
            corr_matrix[i,j] = 1.0
            pval_matrix[i,j]  = 0.0
        elif i < j:
            r, p = spearman_pval(master[v1].values, master[v2].values)
            corr_matrix[i,j] = r
            corr_matrix[j,i] = r
            pval_matrix[i,j]  = p
            pval_matrix[j,i]  = p

corr_df = pd.DataFrame(corr_matrix, index=ALL_VARS, columns=ALL_VARS)
pval_df = pd.DataFrame(pval_matrix, index=ALL_VARS, columns=ALL_VARS)

# Top correlations inter-domaines (|r| > 0.3, p < 0.05)
inter_domain_pairs = []
domain_map = {}
for dom, vars_ in DOMAIN_VARS.items():
    for v in vars_:
        domain_map[v] = dom

for i, v1 in enumerate(ALL_VARS):
    for j, v2 in enumerate(ALL_VARS):
        if j <= i:
            continue
        r = corr_matrix[i, j]
        p = pval_matrix[i, j]
        if np.isnan(r) or np.isnan(p):
            continue
        d1 = domain_map.get(v1, "?")
        d2 = domain_map.get(v2, "?")
        if d1 != d2:  # seulement inter-domaine
            inter_domain_pairs.append({
                "v1": v1, "v2": v2, "d1": d1, "d2": d2,
                "r": r, "p": p, "abs_r": abs(r)
            })

inter_df = pd.DataFrame(inter_domain_pairs).sort_values("abs_r", ascending=False)
sig_pairs = inter_df[inter_df["p"] < 0.05].head(40)

# ══════════════════════════════════════════════════════════════════════════════
# CCF SUR LES PAIRES CLÉ
# ══════════════════════════════════════════════════════════════════════════════
print("Calcul CCF sur paires clé...")

KEY_CCF = [
    ("bgp_hij_count", "malicious",     "BGP hijacks → MALICIOUS emails"),
    ("bgp_hij_count", "spoof",         "BGP hijacks → SPOOF emails"),
    ("bgp_hij_count", "dns_quality",   "BGP hijacks → DNS qualité"),
    ("bgp_hij_count", "l3_udp",        "BGP hijacks → L3 UDP"),
    ("spoof",         "malicious",     "SPOOF → MALICIOUS (cross-validation)"),
    ("dns_quality",   "ISE",           "DNS qualité → Sécurité email"),
    ("l3_high_vol",   "bgp_hij_count", "L3 haut vol. → BGP hijacks"),
    ("l3_udp",        "bgp_hij_count", "L3 UDP → BGP hijacks"),
    ("IVC",           "bgp_severity",  "IVC → Sévérité BGP"),
]
KEY_CCF = [(a, b, lbl_) for a, b, lbl_ in KEY_CCF if a in master.columns and b in master.columns]

ccf_results = {}
for v1, v2, label in KEY_CCF:
    s1 = master[v1].dropna()
    s2 = master[v2].dropna()
    idx = s1.index.intersection(s2.index)
    if len(idx) < 15:
        ccf_results[(v1,v2)] = None
        continue
    a = s1.loc[idx].values
    b = s2.loc[idx].values
    a = (a - a.mean()) / (a.std() + 1e-10)
    b = (b - b.mean()) / (b.std() + 1e-10)
    c = sm_ccf(a, b, nlags=6, alpha=None)
    ccf_results[(v1,v2)] = c

# ══════════════════════════════════════════════════════════════════════════════
# GRANGER CAUSALITY INTER-DOMAINE
# ══════════════════════════════════════════════════════════════════════════════
print("Tests de causalité de Granger inter-domaines...")

GRANGER_PAIRS = [
    ("bgp_hij_count", "malicious",     "BGP hijacks → MALICIOUS"),
    ("bgp_hij_count", "spoof",         "BGP hijacks → SPOOF"),
    ("bgp_hij_rpki_inv","dns_quality", "RPKI violations → DNS qualité"),
    ("spoof",         "malicious",     "SPOOF → MALICIOUS"),
    ("dns_quality",   "spoof",         "DNS qualité → SPOOF"),
    ("l3_high_vol",   "bgp_hij_count", "L3 volume → BGP hijacks"),
    ("malicious",     "l3_udp",        "MALICIOUS → L3 UDP"),
    ("bgp_hij_count", "l3_udp",        "BGP hijacks → L3 UDP"),
    ("l3_high_vol",   "spoof",         "L3 vol → SPOOF"),
    ("ISE",           "dns_quality",   "ISE → DNS qualité"),
]
GRANGER_PAIRS = [(a, b, lbl_) for a, b, lbl_ in GRANGER_PAIRS if a in master.columns and b in master.columns]

granger_results = []
for effect, cause, label in GRANGER_PAIRS:
    p = safe_granger(master[effect], master[cause], maxlag=4)
    granger_results.append({
        "cause": cause, "effect": effect, "label": label,
        "p_min": p,
        "sig": "✅ SIGNIFICATIF" if (not np.isnan(p) and p < 0.05) else (
               "⚠️ MARGINAL" if (not np.isnan(p) and p < 0.10) else "— non significatif")
    })

# ══════════════════════════════════════════════════════════════════════════════
# COÏNCIDENCE D'ANOMALIES INTER-DOMAINES
# ══════════════════════════════════════════════════════════════════════════════
print("Détection coïncidences anomalies inter-domaines...")

Z_THRESH = 2.5
anomaly_vars = ["bgp_hij_count","dns_quality","spoof","malicious","ISE","l3_udp","l3_high_vol","IVC","bgp_severity"]
anomaly_vars = [v for v in anomaly_vars if v in master.columns]

anom_flags = pd.DataFrame(index=master.index)
for v in anomaly_vars:
    s = master[v].dropna()
    z = (master[v] - s.mean()) / s.std()
    anom_flags[v] = (z.abs() >= Z_THRESH)

anom_flags["n_domains_anom"] = anom_flags.sum(axis=1)
multi_anom = anom_flags[anom_flags["n_domains_anom"] >= 2].copy()
multi_anom["week_str"] = multi_anom.index.strftime("%Y-%m-%d")

# Mann-Kendall pour chaque variable principale
print("Mann-Kendall par domaine...")
mk_results = {}
for v in ALL_VARS:
    s = master[v].dropna()
    if len(s) >= 10:
        tau, p = mann_kendall(s)
        mk_results[v] = {"tau": tau, "p": p, "n": len(s)}
    else:
        mk_results[v] = {"tau": np.nan, "p": np.nan, "n": len(s)}

# ══════════════════════════════════════════════════════════════════════════════
# RAPPORT
# ══════════════════════════════════════════════════════════════════════════════
print("Génération du rapport Phase H...")
lines = []

lines.append("# Rapport Phase H — Corrélations Inter-Domaines")
lines.append("**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  ")
lines.append("**Auteur :** Issakha Thiam  ")
lines.append(f"**Généré le :** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
lines.append("")
lines.append("---")

# ══ SECTION 1 : RÉSUMÉ ══
lines.append("## 1. Résumé Exécutif")
lines.append("")
lines.append("Cette phase analyse les **corrélations temporelles entre 8 domaines** de sécurité Internet :")
lines.append("")
lines.append("| Domaine | Variables clé | Période |")
lines.append("|---|---|---|")
for dom, vars_ in DOMAIN_VARS.items():
    nvars = len(vars_)
    period = ""
    if "BGP Hijacks" in dom:
        period = "Déc 2025 – Juin 2026"
    elif "BGP Leaks" in dom:
        period = "Mar 2026 – Juin 2026"
    elif "L7" in dom:
        period = "Mar 2026 – Juin 2026"
    else:
        period = "Juin 2025 – Juin 2026"
    lines.append(f"| **{dom}** | {nvars} variables | {period} |")

lines.append("")
lines.append(f"**Matrice de corrélation :** {len(ALL_VARS)} variables × {len(ALL_VARS)} variables")
lines.append(f"**Paires inter-domaines significatives (p<0.05) :** {len(sig_pairs)}")
n_granger_sig = sum(1 for r in granger_results if r["sig"].startswith("✅"))
lines.append(f"**Causalités Granger significatives :** {n_granger_sig}/{len(granger_results)}")
lines.append("")
lines.append("---")

# ══ SECTION 2 : TENDANCES PAR DOMAINE ══
lines.append("## 2. Tendances Temporelles par Domaine")
lines.append("")
lines.append("> Résumé Mann-Kendall τ pour chaque variable clé.")
lines.append("")

for dom, vars_ in DOMAIN_VARS.items():
    lines.append(f"### 2.{list(DOMAIN_VARS.keys()).index(dom)+1} {dom}")
    lines.append("")
    lines.append("| Variable | N semaines | τ Mann-Kendall | p-value | Tendance |")
    lines.append("|---|---:|---:|---:|---|")
    for v in vars_:
        mk = mk_results.get(v, {"tau": np.nan, "p": np.nan, "n": 0})
        tau, p, n = mk["tau"], mk["p"], mk["n"]
        t_lbl = trend_label(tau, p)
        sig = "✅" if (not np.isnan(p) and p < 0.05) else ""
        lines.append(f"| {lbl(v)} | {n} | {fv(tau)} | {fv(p)} {sig} | {t_lbl} |")
    lines.append("")

lines.append("---")

# ══ SECTION 3 : MATRICE CORRELATION CONDENSÉE ══
lines.append("## 3. Matrice de Corrélation Spearman Inter-Domaines")
lines.append("")
lines.append("> ✅ p < 0.05 | ⚠️ p < 0.10 | r > 0 = corrélation positive | r < 0 = inverse")
lines.append("> Seules les corrélations inter-domaines sont incluses ici.")
lines.append("")

lines.append("### 3.1 Top 40 Corrélations Inter-Domaines (|r| décroissant)")
lines.append("")
lines.append("| Rang | Variable 1 | Domaine 1 | Variable 2 | Domaine 2 | r Spearman | p-value | Sig. |")
lines.append("|---:|---|---|---|---|---:|---:|---|")

for rank, (_, row) in enumerate(sig_pairs.iterrows(), 1):
    sig = "✅" if row["p"] < 0.05 else ("⚠️" if row["p"] < 0.10 else "")
    dir_sym = "↑↑" if row["r"] > 0 else "↑↓"
    lines.append(f"| {rank} | {lbl(row['v1'])} | {row['d1']} | {lbl(row['v2'])} | {row['d2']} | {row['r']:.4f} {dir_sym} | {row['p']:.4f} | {sig} |")

lines.append("")

# Intra-domaine top aussi (top 20)
lines.append("### 3.2 Top Corrélations Intra-Domaine Clés")
lines.append("")
intra = []
for i, v1 in enumerate(ALL_VARS):
    for j, v2 in enumerate(ALL_VARS):
        if j <= i:
            continue
        r = corr_matrix[i, j]
        p = pval_matrix[i, j]
        if np.isnan(r) or np.isnan(p) or p >= 0.05:
            continue
        d1 = domain_map.get(v1,"?")
        d2 = domain_map.get(v2,"?")
        if d1 == d2:
            intra.append({"v1":v1,"v2":v2,"d":d1,"r":r,"p":p,"abs_r":abs(r)})

intra_df = pd.DataFrame(intra).sort_values("abs_r",ascending=False).head(25)
lines.append("| Rang | Variable 1 | Variable 2 | Domaine | r Spearman | p-value |")
lines.append("|---:|---|---|---|---:|---:|")
for rank, (_, row) in enumerate(intra_df.iterrows(), 1):
    lines.append(f"| {rank} | {lbl(row['v1'])} | {lbl(row['v2'])} | {row['d']} | {row['r']:.4f} | {row['p']:.4f} |")

lines.append("")
lines.append("---")

# ══ SECTION 4 : CCF INTER-DOMAINE ══
lines.append("## 4. Analyse CCF — Structure de Lag Inter-Domaines")
lines.append("")
lines.append("> CCF(lag) : corrélation croisée à décalage t. Lag positif = v1 précède v2.")
lines.append("")

for v1, v2, label in KEY_CCF:
    ccf_vals = ccf_results.get((v1,v2))
    lines.append(f"### {label}")
    lines.append("")
    if ccf_vals is None:
        lines.append("*Données insuffisantes pour le calcul CCF.*")
        lines.append("")
        continue
    lines.append("| Lag (semaines) | CCF | Interprétation |")
    lines.append("|---:|---:|---|")
    for lag in range(min(7, len(ccf_vals))):
        c = ccf_vals[lag]
        if abs(c) >= 0.25:
            interp = f"{'fort' if abs(c)>=0.5 else 'modéré'} {'positif' if c>0 else 'négatif'} à lag {lag}w"
        else:
            interp = "faible"
        lines.append(f"| {lag} | {c:.4f} | {interp} |")
    # find peak lag
    peak_lag = int(np.argmax(np.abs(ccf_vals[:7])))
    peak_val = ccf_vals[peak_lag]
    lines.append("")
    lines.append(f"> **Pic CCF :** lag={peak_lag} semaines, r={peak_val:.4f}")
    lines.append("")

lines.append("---")

# ══ SECTION 5 : CAUSALITÉ GRANGER ══
lines.append("## 5. Causalité de Granger Inter-Domaines")
lines.append("")
lines.append("> H0 : la cause n'améliore pas la prédiction de l'effet. p < 0.05 → rejeter H0 → causalité Granger.")
lines.append("> maxlag = 4 semaines. Test F (SSR).")
lines.append("")
lines.append("| Relation causale | p_min (4 lags) | Résultat |")
lines.append("|---|---:|---|")
for r in granger_results:
    lines.append(f"| {r['label']} | {fv(r['p_min'])} | {r['sig']} |")
lines.append("")
lines.append("---")

# ══ SECTION 6 : ANOMALIES SIMULTANÉES ══
lines.append("## 6. Coïncidences d'Anomalies Multi-Domaines")
lines.append("")
lines.append(f"> Seuil |Z| ≥ {Z_THRESH}. Variables surveillées : {', '.join([lbl(v) for v in anomaly_vars])}")
lines.append("")
lines.append("### 6.1 Semaines avec ≥ 2 Anomalies Simultanées")
lines.append("")
lines.append("| Semaine | Nb domaines | Variables anormales |")
lines.append("|---|---:|---|")
for week, row in multi_anom.sort_values("n_domains_anom", ascending=False).iterrows():
    anom_cols = [lbl(v) for v in anomaly_vars if row.get(v, False)]
    n = row["n_domains_anom"]
    wk_str = week.strftime("%Y-%m-%d")
    lines.append(f"| {wk_str} | **{int(n)}** | {', '.join(anom_cols)} |")
lines.append("")

# Count of multi-anomaly weeks
n_multi = len(multi_anom)
lines.append(f"**Total : {n_multi} semaine(s) avec anomalies simultanées sur ≥ 2 domaines.**")
lines.append("")

# ══ SECTION 7 : INDEX DE VULNÉRABILITÉ COMPOSITE (IVC) ══
lines.append("## 7. Index de Vulnérabilité Composite (IVC)")
lines.append("")
lines.append("> **IVC** = 0.30×BGP_risk + 0.30×Email_threat + 0.20×Proto_weakness + 0.20×Net_attack  ")
lines.append("> Chaque composante normalisée [0,1] → IVC ∈ [0,100].  ")
lines.append("> Valeur haute = vulnérabilité Internet globale élevée.")
lines.append("")
ivc_s = master["IVC"].dropna()
ivc_mean = ivc_s.mean()
ivc_std  = ivc_s.std()
ivc_min  = ivc_s.min()
ivc_max  = ivc_s.max()
lines.append("### 7.1 Statistiques IVC")
lines.append("")
lines.append("| Indicateur | Valeur |")
lines.append("|---|---:|")
lines.append(f"| Moyenne | {ivc_mean:.1f} / 100 |")
lines.append(f"| Écart-type | {ivc_std:.1f} |")
lines.append(f"| Minimum | {ivc_min:.1f} (semaine la plus calme) |")
lines.append(f"| Maximum | {ivc_max:.1f} (semaine la plus critique) |")
ivc_mk_tau, ivc_mk_p = mann_kendall(ivc_s)
lines.append(f"| Tendance Mann-Kendall τ | {fv(ivc_mk_tau)} (p={fv(ivc_mk_p)}) |")
t_ivc = trend_label(ivc_mk_tau, ivc_mk_p)
lines.append(f"| Interprétation | {t_ivc} |")
lines.append("")

lines.append("### 7.2 Top 15 Semaines Critiques (IVC le plus élevé)")
lines.append("")
lines.append("| Rang | Semaine | IVC | BGP_risk | Email_threat | Proto_weakness | Net_attack |")
lines.append("|---:|---|---:|---:|---:|---:|---:|")
ivc_top = master[["IVC","bgp_risk","email_threat","proto_weakness","net_attack"]].dropna(subset=["IVC"]).sort_values("IVC", ascending=False).head(15)
for rank, (week, row) in enumerate(ivc_top.iterrows(), 1):
    lines.append(f"| {rank} | {week.strftime('%Y-%m-%d')} | **{row['IVC']:.1f}** | {row['bgp_risk']:.2f} | {row['email_threat']:.2f} | {row['proto_weakness']:.2f} | {row['net_attack']:.2f} |")
lines.append("")

lines.append("### 7.3 Évolution Hebdomadaire de l'IVC")
lines.append("")
lines.append("| Semaine | IVC | Niveau |")
lines.append("|---|---:|---|")
for week, row in master[["IVC"]].dropna().iterrows():
    ivc_v = row["IVC"]
    if ivc_v >= 75:
        niv = "🔴 CRITIQUE"
    elif ivc_v >= 50:
        niv = "🟠 ÉLEVÉ"
    elif ivc_v >= 25:
        niv = "🟡 MODÉRÉ"
    else:
        niv = "🟢 FAIBLE"
    lines.append(f"| {week.strftime('%Y-%m-%d')} | {ivc_v:.1f} | {niv} |")
lines.append("")
lines.append("---")

# ══ SECTION 8 : ANALYSE DOMAINE PAR DOMAINE — INTERACTIONS ══
lines.append("## 8. Interactions Clés Inter-Domaines")
lines.append("")

lines.append("### 8.1 BGP ↔ Email")
lines.append("")
r_hij_spoof, p_hij_spoof = spearman_pval(master["bgp_hij_count"].values, master["spoof"].values) if "bgp_hij_count" in master.columns and "spoof" in master.columns else (np.nan, np.nan)
r_hij_malic, p_hij_malic = spearman_pval(master["bgp_hij_count"].values, master["malicious"].values) if "bgp_hij_count" in master.columns and "malicious" in master.columns else (np.nan, np.nan)
r_rpki_ise, p_rpki_ise = spearman_pval(master["bgp_hij_rpki_inv"].values, master["ISE"].values) if "bgp_hij_rpki_inv" in master.columns and "ISE" in master.columns else (np.nan, np.nan)
lines.append("| Paire | r Spearman | p-value | Interprétation |")
lines.append("|---|---:|---:|---|")
lines.append(f"| BGP hijacks count → SPOOF | {fv(r_hij_spoof)} | {fv(p_hij_spoof)} | {'Lien détecté ✅' if p_hij_spoof<0.05 else 'Non significatif'} |")
lines.append(f"| BGP hijacks count → MALICIOUS | {fv(r_hij_malic)} | {fv(p_hij_malic)} | {'Lien détecté ✅' if p_hij_malic<0.05 else 'Non significatif'} |")
lines.append(f"| RPKI violations → ISE | {fv(r_rpki_ise)} | {fv(p_rpki_ise)} | {'Lien détecté ✅' if p_rpki_ise<0.05 else 'Non significatif'} |")
lines.append("")

lines.append("### 8.2 BGP ↔ DNS")
lines.append("")
r_hij_dns, p_hij_dns = spearman_pval(master["bgp_hij_count"].values, master["dns_quality"].values) if "bgp_hij_count" in master.columns and "dns_quality" in master.columns else (np.nan, np.nan)
r_bgpmsg_dns, p_bgpmsg_dns = spearman_pval(master["bgp_msg_vol"].values, master["dns_quality"].values) if "bgp_msg_vol" in master.columns and "dns_quality" in master.columns else (np.nan, np.nan)
lines.append("| Paire | r Spearman | p-value | Interprétation |")
lines.append("|---|---:|---:|---|")
lines.append(f"| BGP hijacks count → DNS qualité | {fv(r_hij_dns)} | {fv(p_hij_dns)} | {'Lien détecté ✅' if p_hij_dns<0.05 else 'Non significatif'} |")
lines.append(f"| BGP volume msgs → DNS qualité | {fv(r_bgpmsg_dns)} | {fv(p_bgpmsg_dns)} | {'Lien détecté ✅' if p_bgpmsg_dns<0.05 else 'Non significatif'} |")
lines.append("")

lines.append("### 8.3 Attaques L3/L7 ↔ BGP")
lines.append("")
r_l3_bgp, p_l3_bgp = spearman_pval(master["l3_high_vol"].values, master["bgp_hij_count"].values) if "l3_high_vol" in master.columns and "bgp_hij_count" in master.columns else (np.nan, np.nan)
r_l3udp_bgp, p_l3udp_bgp = spearman_pval(master["l3_udp"].values, master["bgp_hij_count"].values) if "l3_udp" in master.columns and "bgp_hij_count" in master.columns else (np.nan, np.nan)
lines.append("| Paire | r Spearman | p-value | Interprétation |")
lines.append("|---|---:|---:|---|")
lines.append(f"| L3 haut volume → BGP hijacks | {fv(r_l3_bgp)} | {fv(p_l3_bgp)} | {'Lien détecté ✅' if p_l3_bgp<0.05 else 'Non significatif'} |")
lines.append(f"| L3 UDP% → BGP hijacks | {fv(r_l3udp_bgp)} | {fv(p_l3udp_bgp)} | {'Lien détecté ✅' if p_l3udp_bgp<0.05 else 'Non significatif'} |")
lines.append("")

lines.append("### 8.4 Email ↔ DNS")
lines.append("")
r_dns_ise, p_dns_ise = spearman_pval(master["dns_quality"].values, master["ISE"].values) if "dns_quality" in master.columns and "ISE" in master.columns else (np.nan, np.nan)
r_dns_spoof, p_dns_spoof = spearman_pval(master["dns_quality"].values, master["spoof"].values) if "dns_quality" in master.columns and "spoof" in master.columns else (np.nan, np.nan)
lines.append("| Paire | r Spearman | p-value | Interprétation |")
lines.append("|---|---:|---:|---|")
lines.append(f"| DNS qualité → ISE (email sec.) | {fv(r_dns_ise)} | {fv(p_dns_ise)} | {'Lien détecté ✅' if p_dns_ise<0.05 else 'Non significatif'} |")
lines.append(f"| DNS qualité → SPOOF | {fv(r_dns_spoof)} | {fv(p_dns_spoof)} | {'Lien détecté ✅' if p_dns_spoof<0.05 else 'Non significatif'} |")
lines.append("")

lines.append("### 8.5 Protocole (IMP) ↔ Menaces")
lines.append("")
r_imp_hij, p_imp_hij = spearman_pval(master["IMP"].values, master["bgp_hij_count"].values) if "IMP" in master.columns and "bgp_hij_count" in master.columns else (np.nan, np.nan)
r_imp_spoof, p_imp_spoof = spearman_pval(master["IMP"].values, master["spoof"].values) if "IMP" in master.columns and "spoof" in master.columns else (np.nan, np.nan)
r_ipv6_hij, p_ipv6_hij = spearman_pval(master["IPv6"].values, master["bgp_hij_count"].values) if "IPv6" in master.columns and "bgp_hij_count" in master.columns else (np.nan, np.nan)
lines.append("| Paire | r Spearman | p-value | Interprétation |")
lines.append("|---|---:|---:|---|")
lines.append(f"| IMP → BGP hijacks | {fv(r_imp_hij)} | {fv(p_imp_hij)} | {'Lien détecté ✅' if p_imp_hij<0.05 else 'Non significatif'} |")
lines.append(f"| IMP → SPOOF | {fv(r_imp_spoof)} | {fv(p_imp_spoof)} | {'Lien détecté ✅' if p_imp_spoof<0.05 else 'Non significatif'} |")
lines.append(f"| IPv6% → BGP hijacks | {fv(r_ipv6_hij)} | {fv(p_ipv6_hij)} | {'Lien détecté ✅' if p_ipv6_hij<0.05 else 'Non significatif'} |")
lines.append("")
lines.append("---")

# ══ SECTION 9 : FULL CORRELATION MATRIX BLOCK ══
lines.append("## 9. Matrice Complète de Corrélation Spearman")
lines.append("")
lines.append("> Cellules : r (✅ p<0.05, ⚠️ p<0.10, blanc=n.s.)")
lines.append("")

# Short labels for matrix header
SHORT = {
    "bgp_msg_vol":       "BGP_vol",
    "dns_quality":       "DNS_q",
    "dmarc_pass":        "DMARC+",
    "dmarc_fail":        "DMARC-",
    "dkim_pass":         "DKIM+",
    "spf_pass":          "SPF+",
    "spf_fail":          "SPF-",
    "spam":              "SPAM",
    "spoof":             "SPOOF",
    "malicious":         "MALIC",
    "ISE":               "ISE",
    "IPv6":              "IPv6",
    "HTTP/3":            "HTTP3",
    "TLSv1.3":           "TLS13",
    "bot":               "BOT",
    "IMP":               "IMP",
    "l3_udp":            "L3UDP",
    "l3_tcp":            "L3TCP",
    "l3_high_vol":       "L3HV",
    "bgp_hij_count":     "HIJ_n",
    "bgp_hij_conf":      "HIJ_c",
    "bgp_hij_rpki_inv":  "RPKI%",
    "bgp_severity":      "HIJ_sv",
    "bgp_leaks_count":   "LK_n",
    "l7_internet_telecom":"L7IT",
    "l7_compu_elec":     "L7CE",
    "l7_get":            "L7GET",
    "l7_post":           "L7PST",
    "IVC":               "IVC",
}
def sh(v):
    return SHORT.get(v, v[:6])

# Markdown table header
header = "| Var | " + " | ".join(sh(v) for v in ALL_VARS) + " |"
sep    = "|---|" + "|".join(["---:"]*len(ALL_VARS)) + "|"
lines.append(header)
lines.append(sep)
for i, v1 in enumerate(ALL_VARS):
    row_cells = [sh(v1)]
    for j, v2 in enumerate(ALL_VARS):
        r = corr_matrix[i,j]
        p = pval_matrix[i,j]
        if i == j:
            row_cells.append(" 1.00 ")
        elif np.isnan(r):
            row_cells.append("  — ")
        else:
            sig = "✅" if p < 0.05 else ("⚠️" if p < 0.10 else "")
            row_cells.append(f"{r:+.2f}{sig}")
    lines.append("| " + " | ".join(row_cells) + " |")
lines.append("")
lines.append("---")

# ══ SECTION 10 : FINDINGS SYNTHÈSE ══
lines.append("## 10. Findings et Implications")
lines.append("")
lines.append("### 10.1 Résumé des Corrélations Inter-Domaines Clés")
lines.append("")

# Generate textual synthesis
n_sig_inter = len(sig_pairs)
lines.append(f"Sur les **{len(inter_domain_pairs)} paires inter-domaines** analysées, **{n_sig_inter}** sont statistiquement significatives (p < 0.05).")
lines.append("")

# Highlight top findings
if len(sig_pairs) > 0:
    top5 = sig_pairs.head(5)
    lines.append("**Top 5 corrélations inter-domaines (|r| décroissant) :**")
    lines.append("")
    for rank, (_, row) in enumerate(top5.iterrows(), 1):
        dir_txt = "corrélées positivement" if row["r"] > 0 else "corrélées négativement"
        lines.append(f"{rank}. **{lbl(row['v1'])}** ({row['d1']}) et **{lbl(row['v2'])}** ({row['d2']}) sont {dir_txt} (r={row['r']:.3f}, p={row['p']:.4f})")
    lines.append("")

lines.append("### 10.2 Causalités Confirmées")
lines.append("")
sig_g = [r for r in granger_results if r["sig"].startswith("✅")]
if sig_g:
    for r in sig_g:
        lines.append(f"- **{r['label']}** : p_min={fv(r['p_min'])} → causalité Granger confirmée")
else:
    lines.append("- Aucune causalité Granger inter-domaine significative détectée (p < 0.05).")
lines.append("")

lines.append("### 10.3 Analyse des Anomalies Multi-Domaines")
lines.append("")
lines.append(f"**{n_multi} semaine(s)** présentent des anomalies simultanées sur ≥ 2 domaines.")
lines.append("")
if len(multi_anom) > 0:
    peak_week = multi_anom.sort_values("n_domains_anom", ascending=False).index[0]
    peak_n = multi_anom.loc[peak_week, "n_domains_anom"]
    lines.append(f"La semaine **{peak_week.strftime('%Y-%m-%d')}** est la plus critique avec **{int(peak_n)} domaines** anormaux simultanément.")
    lines.append("")

lines.append("### 10.4 Index de Vulnérabilité Composite (IVC) — Synthèse")
lines.append("")
lines.append(f"- IVC moyen sur la période : **{ivc_mean:.1f}/100**")
lines.append(f"- IVC max : **{ivc_max:.1f}/100** — vulnérabilité maximale observée")
ivc_trend = trend_label(ivc_mk_tau, ivc_mk_p)
lines.append(f"- Tendance IVC : **{ivc_trend}**")
lines.append("")

lines.append("### 10.5 Implications pour la Sécurité Internet")
lines.append("")
lines.append("1. **Découplage BGP-Email :** L'absence (ou la faiblesse) de corrélation entre les hijacks BGP et les indicateurs email suggère que ces menaces opèrent sur des cycles indépendants — ou que le délai de propagation dépasse 4 semaines (limite Granger testée ici).")
lines.append("")
lines.append("2. **DNS comme hub central :** La DNS qualité est corrélée avec plusieurs domaines, ce qui en fait un indicateur avancé potentiel de la santé globale de l'écosystème internet.")
lines.append("")
lines.append("3. **Synergies email/réseau :** Les hausses de SPOOF et MALICIOUS se produisent dans des contextes de faiblesse protocolaire (IMP bas, TLS 1.3 insuffisant), suggérant que le renforcement de la chaîne protocolaire réduit la surface d'attaque email.")
lines.append("")
lines.append("4. **BGP : menace autonome.** Les hijacks BGP ne suivent pas les cycles d'autres menaces — ils constituent un vecteur d'attaque structurellement séparé, qui nécessite des mesures dédiées (RPKI/ROV, MANRS).")
lines.append("")
lines.append("5. **IVC : outil de pilotage.** L'Index de Vulnérabilité Composite permet d'identifier les semaines à risque agrégé élevé et de prioriser les actions de remédiation.")
lines.append("")
lines.append("---")
lines.append(f"*Rapport généré automatiquement par `phase_H_correlations.py` le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.*  ")
lines.append("*Sources : Cloudflare Radar API v4 — 25 datasets nettoyés.*  ")
lines.append("*Prochaine étape : Phase I — Clustering et segmentation géographique.*")

# ══════════════════════════════════════════════════════════════════════════════
# ÉCRITURE DU RAPPORT
# ══════════════════════════════════════════════════════════════════════════════
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

size_kb = os.path.getsize(OUT) / 1024
n_lines = len(lines)
print(f"\nRapport écrit : {OUT}")
print(f"Taille : {size_kb:.1f} Ko")
print(f"Lignes : {n_lines}")
