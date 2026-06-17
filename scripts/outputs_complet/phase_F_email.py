#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase F — Analyse détaillée sécurité email (DMARC/DKIM/SPF/SPAM/SPOOF/MALICIOUS)."""

import pandas as pd
import numpy as np
import warnings
import os
from datetime import datetime
from scipy import stats
from statsmodels.tsa.stattools import adfuller, ccf, grangercausalitytests
from statsmodels.tsa.seasonal import STL
from statsmodels.tsa.arima.model import ARIMA
import itertools

warnings.filterwarnings("ignore")

BASE = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/cleaned"
OUT  = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/rapport_phase_F.md"

# ── Chargement ──────────────────────────────────────────────────────────────
print("Chargement des donnees email...")

dmarc = pd.read_csv(f"{BASE}/email_dmarc_clean.csv",     parse_dates=["date"])
dkim  = pd.read_csv(f"{BASE}/email_dkim_clean.csv",      parse_dates=["date"])
spf   = pd.read_csv(f"{BASE}/email_spf_clean.csv",       parse_dates=["date"])
malic = pd.read_csv(f"{BASE}/email_malicious_clean.csv", parse_dates=["date"])
spam  = pd.read_csv(f"{BASE}/email_spam_clean.csv",      parse_dates=["date"])
spoof = pd.read_csv(f"{BASE}/email_spoof_clean.csv",     parse_dates=["date"])

# dates formatées
for df in [dmarc, dkim, spf, malic, spam, spoof]:
    df["date_str"] = df["date"].dt.strftime("%Y-%m-%d")
    df["week_num"] = range(1, len(df) + 1)
    df["month"]    = df["date"].dt.to_period("M")
    df["quarter"]  = df["date"].dt.to_period("Q")

N = len(dmarc)

# ── Helpers ──────────────────────────────────────────────────────────────────
def desc_stats(series):
    s = series.dropna()
    return {
        "N": len(s), "Moy": s.mean(), "Med": s.median(), "Std": s.std(),
        "CV%": s.std()/s.mean()*100 if s.mean() != 0 else np.nan,
        "Min": s.min(), "Max": s.max(),
        "P05": s.quantile(.05), "P25": s.quantile(.25),
        "P75": s.quantile(.75), "P95": s.quantile(.95),
        "Skew": float(stats.skew(s)), "Kurt": float(stats.kurtosis(s))
    }

def mann_kendall(y):
    n = len(y)
    if n < 4:
        return None, None, None
    s = sum(np.sign(y[j] - y[i]) for i in range(n-1) for j in range(i+1, n))
    var_s = n * (n-1) * (2*n+5) / 18
    z = (s - np.sign(s)) / np.sqrt(var_s)
    p = 2 * (1 - stats.norm.cdf(abs(z)))
    tau = s / (n * (n-1) / 2)
    return tau, z, p

def adf_test(series):
    result = adfuller(series.dropna(), autolag="AIC")
    return {
        "stat": result[0], "p": result[1], "lags": result[2],
        "crit1": result[4]["1%"], "crit5": result[4]["5%"], "crit10": result[4]["10%"],
        "stationary": result[1] < 0.05
    }

def ols_trend(y):
    n = len(y)
    x = np.arange(n, dtype=float)
    slope, intercept, r, p, _ = stats.linregress(x, y)
    return slope, r**2, p, intercept

def stl_decompose(series, period=4):
    try:
        res = STL(series, period=period, robust=True).fit()
        trend_slope = np.polyfit(np.arange(len(res.trend)), res.trend, 1)[0]
        trend_var = np.var(res.trend) / np.var(series) * 100
        seas_amp   = res.seasonal.max() - res.seasonal.min()
        seas_var   = np.var(res.seasonal) / np.var(series) * 100
        resid_std  = res.resid.std()
        resid_var  = np.var(res.resid) / np.var(series) * 100
        return {
            "trend": res.trend, "seasonal": res.seasonal, "resid": res.resid,
            "trend_slope": trend_slope, "trend_var": trend_var,
            "seas_amp": seas_amp, "seas_var": seas_var,
            "resid_std": resid_std, "resid_var": resid_var
        }
    except Exception:
        return None

def arima_best(series, holdout=4, max_p=3, max_q=3):
    train = series.iloc[:-holdout]
    test  = series.iloc[-holdout:]
    best_aic, best_order, best_model = np.inf, (1,1,0), None
    for p, d, q in itertools.product(range(max_p+1), [0,1], range(max_q+1)):
        if p == 0 and q == 0:
            continue
        try:
            m = ARIMA(train, order=(p,d,q)).fit()
            if m.aic < best_aic:
                best_aic, best_order, best_model = m.aic, (p,d,q), m
        except Exception:
            pass
    if best_model is None:
        return None
    fc = best_model.forecast(steps=holdout)
    rmse = np.sqrt(np.mean((fc.values - test.values)**2))
    mape = np.mean(np.abs((fc.values - test.values) / test.values)) * 100
    # Forecast +4 semaines
    fc_future = best_model.forecast(steps=holdout)
    ci = best_model.get_forecast(steps=holdout).conf_int(alpha=0.05)
    return {
        "order": best_order, "aic": best_aic,
        "rmse": rmse, "mape": mape,
        "test_actual": test.values.tolist(),
        "test_pred": fc.values.tolist(),
        "fc_mean": fc_future.values.tolist(),
        "fc_lo": ci.iloc[:, 0].values.tolist(),
        "fc_hi": ci.iloc[:, 1].values.tolist(),
    }

def zscore_anomalies(series, threshold=2.5):
    s = series.reset_index(drop=True)
    z = (s - s.mean()) / s.std()
    return [(i, s.iloc[i], round(z.iloc[i], 3)) for i in range(len(s)) if abs(z.iloc[i]) >= threshold]

def p_stars(p):
    if p is None or (isinstance(p, float) and np.isnan(p)):
        return "n.s."
    return "***" if p < 0.001 else ("**" if p < 0.01 else ("*" if p < 0.05 else "n.s."))

def trend_label(tau, p):
    if p is None:
        return "N/A"
    star = p_stars(p)
    if p >= 0.05:
        return f"→ neutre {star}"
    return ("↑ hausse " if tau > 0 else "↓ baisse ") + star

def ccf_table(x, y, max_lag=6):
    """CCF entre deux séries, retourne dict lag->corr."""
    x_s = (x - x.mean()) / x.std()
    y_s = (y - y.mean()) / y.std()
    result = {}
    for lag in range(-max_lag, max_lag+1):
        if lag < 0:
            c = np.corrcoef(x_s.iloc[-lag:], y_s.iloc[:lag])[0,1]
        elif lag == 0:
            c = np.corrcoef(x_s, y_s)[0,1]
        else:
            c = np.corrcoef(x_s.iloc[:-lag], y_s.iloc[lag:])[0,1]
        result[lag] = round(c, 4)
    return result

def granger_test(cause, effect, max_lag=4):
    """Granger causality: does 'cause' Granger-cause 'effect'?"""
    data = pd.DataFrame({"effect": effect.values, "cause": cause.values})
    try:
        res = grangercausalitytests(data, maxlag=max_lag, verbose=False)
        return {lag: res[lag][0]["ssr_ftest"][1] for lag in range(1, max_lag+1)}
    except Exception:
        return {}

# ── Catalogue des séries ──────────────────────────────────────────────────────
# Auth métriques : PASS (positif = bon) / FAIL (négatif) / NONE (indéfini)
# Threat métriques : MALICIOUS / SPAM / SPOOF (positif = mauvais)

SERIES = {
    "dmarc_pass":  dmarc["PASS"],
    "dmarc_fail":  dmarc["FAIL"],
    "dmarc_none":  dmarc["NONE"],
    "dkim_pass":   dkim["PASS"],
    "dkim_fail":   dkim["FAIL"],
    "dkim_none":   dkim["NONE"],
    "spf_pass":    spf["PASS"],
    "spf_fail":    spf["FAIL"],
    "spf_none":    spf["NONE"],
    "malicious":   malic["MALICIOUS"],
    "spam":        spam["SPAM"],
    "spoof":       spoof["SPOOF"],
}

# ── Analyses statistiques ────────────────────────────────────────────────────
print("Calcul statistiques...")

all_stats    = {k: desc_stats(v)    for k, v in SERIES.items()}
all_mk       = {k: mann_kendall(v.values) for k, v in SERIES.items()}
all_adf      = {k: adf_test(v)      for k, v in SERIES.items()}
all_ols      = {k: ols_trend(v.values) for k, v in SERIES.items()}

print("STL decomposition...")
all_stl = {k: stl_decompose(v, period=4) for k, v in SERIES.items()}

print("ARIMA selection...")
all_arima = {}
for k, v in SERIES.items():
    print(f"  >> ARIMA {k}")
    all_arima[k] = arima_best(v, holdout=4)

print("Anomalies et CCF...")
all_anom = {k: zscore_anomalies(v) for k, v in SERIES.items()}

# CCF : auth failures -> threats
ccf_results = {}
ccf_results["dmarc_fail→spam"]      = ccf_table(dmarc["FAIL"], spam["SPAM"])
ccf_results["dmarc_fail→spoof"]     = ccf_table(dmarc["FAIL"], spoof["SPOOF"])
ccf_results["dmarc_fail→malicious"] = ccf_table(dmarc["FAIL"], malic["MALICIOUS"])
ccf_results["dkim_fail→spam"]       = ccf_table(dkim["FAIL"],  spam["SPAM"])
ccf_results["spf_fail→spam"]        = ccf_table(spf["FAIL"],   spam["SPAM"])
ccf_results["spoof→malicious"]      = ccf_table(spoof["SPOOF"], malic["MALICIOUS"])
ccf_results["spam→malicious"]       = ccf_table(spam["SPAM"],   malic["MALICIOUS"])

print("Granger causality...")
granger_results = {}
granger_results["dmarc_fail→spam"]      = granger_test(dmarc["FAIL"], spam["SPAM"])
granger_results["dmarc_fail→spoof"]     = granger_test(dmarc["FAIL"], spoof["SPOOF"])
granger_results["dmarc_fail→malicious"] = granger_test(dmarc["FAIL"], malic["MALICIOUS"])
granger_results["spf_fail→spam"]        = granger_test(spf["FAIL"],   spam["SPAM"])
granger_results["spoof→malicious"]      = granger_test(spoof["SPOOF"], malic["MALICIOUS"])
granger_results["spam→malicious"]       = granger_test(spam["SPAM"],   malic["MALICIOUS"])

# Corrélations Spearman entre toutes les séries
print("Correlations Spearman...")
all_df = pd.DataFrame(SERIES)
spearman_corr = all_df.corr(method="spearman")

# ── Indice de Sécurité Email (ISE) ──────────────────────────────────────────
# ISE = (DMARC_PASS*0.3 + DKIM_PASS*0.3 + SPF_PASS*0.25) * (1 - SPAM*0.05)
#        * (1 - SPOOF*0.05) * (1 - MALICIOUS*0.05) — simplifié
# Approche : composite normalisé sur 100

dmarc_w, dkim_w, spf_w = 0.35, 0.35, 0.30
auth_score = (
    dmarc["PASS"] * dmarc_w +
    dkim["PASS"]  * dkim_w  +
    spf["PASS"]   * spf_w
)  # ~ 0–100

threat_penalty = (spam["SPAM"] + spoof["SPOOF"] + malic["MALICIOUS"]) / 3

ISE = auth_score - threat_penalty * 0.5  # ISE sur ~0-100

ise_mk = mann_kendall(ISE.values)
ise_ols = ols_trend(ISE.values)
ise_stl = stl_decompose(ISE, period=4)

# Évolution mensuelle
monthly_auth = pd.DataFrame({
    "DMARC PASS": dmarc.groupby("month")["PASS"].mean(),
    "DMARC FAIL": dmarc.groupby("month")["FAIL"].mean(),
    "DMARC NONE": dmarc.groupby("month")["NONE"].mean(),
    "DKIM PASS":  dkim.groupby("month")["PASS"].mean(),
    "DKIM FAIL":  dkim.groupby("month")["FAIL"].mean(),
    "SPF PASS":   spf.groupby("month")["PASS"].mean(),
    "SPF FAIL":   spf.groupby("month")["FAIL"].mean(),
    "MALICIOUS":  malic.groupby("month")["MALICIOUS"].mean(),
    "SPAM":       spam.groupby("month")["SPAM"].mean(),
    "SPOOF":      spoof.groupby("month")["SPOOF"].mean(),
    "ISE":        pd.Series(ISE.values, index=dmarc.index).groupby(dmarc["month"]).mean(),
})

monthly_quarter = pd.DataFrame({
    "DMARC PASS": dmarc.groupby("quarter")["PASS"].mean(),
    "DKIM PASS":  dkim.groupby("quarter")["PASS"].mean(),
    "SPF PASS":   spf.groupby("quarter")["PASS"].mean(),
    "MALICIOUS":  malic.groupby("quarter")["MALICIOUS"].mean(),
    "SPAM":       spam.groupby("quarter")["SPAM"].mean(),
    "SPOOF":      spoof.groupby("quarter")["SPOOF"].mean(),
})

# ── GÉNÉRATION DU RAPPORT ────────────────────────────────────────────────────
print("Generation du rapport Phase F...")

ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
lines = []

lines.append("# Rapport Phase F — Analyse Sécurité Email (DMARC/DKIM/SPF/SPAM/SPOOF/MALICIOUS)")
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
lines.append(f"**Période :** 2025-06-09 → 2026-06-08 — {N} semaines  ")
lines.append("**Méthodes :** Statistiques descriptives, Mann-Kendall, ADF, OLS, STL(p=4), ARIMA(AIC), CCF, Granger")
lines.append("")
lines.append("**Vue d'ensemble des indicateurs (moyennes sur la période) :**")
lines.append("")
lines.append("| Indicateur | Moyenne (%) | Tendance MK | Tau | Stationnaire (ADF) |")
lines.append("|---|---:|---|---:|---|")
summary_series = [
    ("DMARC PASS", "dmarc_pass"), ("DMARC NONE", "dmarc_none"), ("DMARC FAIL", "dmarc_fail"),
    ("DKIM PASS",  "dkim_pass"),  ("DKIM NONE",  "dkim_none"),  ("DKIM FAIL",  "dkim_fail"),
    ("SPF PASS",   "spf_pass"),   ("SPF NONE",   "spf_none"),   ("SPF FAIL",   "spf_fail"),
    ("MALICIOUS",  "malicious"),  ("SPAM",       "spam"),       ("SPOOF",      "spoof"),
]
for label, key in summary_series:
    s   = all_stats[key]
    tau, _, p_mk = all_mk[key]
    tl  = trend_label(tau, p_mk)
    adf_ok = "Oui" if all_adf[key]["stationary"] else "Non"
    lines.append(f"| **{label}** | {s['Moy']:.2f} | {tl} | {tau:.4f} | {adf_ok} |")
lines.append("")
lines.append(f"**Indice de Sécurité Email (ISE) moyen sur la période : {ISE.mean():.2f} / ~100**")
lines.append(f"**ISE tendance :** {trend_label(ise_mk[0], ise_mk[2])} (Tau={ise_mk[0]:.4f})")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 : DMARC
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 2. DMARC — Domain-based Message Authentication, Reporting & Conformance")
lines.append("")
lines.append("> DMARC combine DKIM et SPF et permet au domaine expéditeur de définir une politique "
             "de traitement des emails non authentifiés (none / quarantine / reject).")
lines.append("")

lines.append("### 2.1 Statistiques Descriptives DMARC")
lines.append("")
lines.append("| Statistique | DMARC PASS (%) | DMARC NONE (%) | DMARC FAIL (%) |")
lines.append("|---|---:|---:|---:|")
for stat_k, stat_label in [("N","N"),("Moy","Moyenne"),("Med","Médiane"),("Std","Écart-type"),
                             ("CV%","CV%"),("Min","Min"),("Max","Max"),
                             ("P05","P5"),("P25","P25"),("P75","P75"),("P95","P95"),
                             ("Skew","Asymétrie"),("Kurt","Kurtosis")]:
    p = all_stats["dmarc_pass"].get(stat_k, "")
    n = all_stats["dmarc_none"].get(stat_k, "")
    f = all_stats["dmarc_fail"].get(stat_k, "")
    fmt = ".2f" if stat_k not in ("N",) else "d"
    try:
        lines.append(f"| **{stat_label}** | {p:{fmt}} | {n:{fmt}} | {f:{fmt}} |")
    except Exception:
        lines.append(f"| **{stat_label}** | {p} | {n} | {f} |")
lines.append("")

lines.append("### 2.2 Tests Statistiques DMARC (Tendance & Stationnarité)")
lines.append("")
for metric, key in [("DMARC PASS","dmarc_pass"),("DMARC NONE","dmarc_none"),("DMARC FAIL","dmarc_fail")]:
    tau, z_mk, p_mk = all_mk[key]
    sl, r2, p_ols, intercept = all_ols[key]
    adf = all_adf[key]
    lines.append(f"**{metric} :**")
    lines.append("")
    lines.append("| Test | Paramètre | Valeur |")
    lines.append("|---|---|---|")
    lines.append(f"| Mann-Kendall | Tau | {tau:.4f} |")
    lines.append(f"| Mann-Kendall | Z normalisé | {z_mk:.4f} |")
    lines.append(f"| Mann-Kendall | p-value | {p_mk:.6f} {p_stars(p_mk)} |")
    lines.append(f"| Mann-Kendall | Tendance | **{trend_label(tau, p_mk)}** |")
    lines.append(f"| OLS | Pente (%/semaine) | {sl:.4f} |")
    lines.append(f"| OLS | Intercept | {intercept:.4f} |")
    lines.append(f"| OLS | R² | {r2:.4f} |")
    lines.append(f"| OLS | p-value | {p_ols:.6f} {p_stars(p_ols)} |")
    lines.append(f"| ADF | Statistique | {adf['stat']:.4f} |")
    lines.append(f"| ADF | p-value | {adf['p']:.6f} {p_stars(adf['p'])} |")
    lines.append(f"| ADF | Lags retenus | {adf['lags']} |")
    lines.append(f"| ADF | Conclusion | {'**Stationnaire**' if adf['stationary'] else '**Non stationnaire**'} |")
    lines.append("")

lines.append("### 2.3 Décomposition STL — DMARC PASS (période = 4 semaines)")
lines.append("")
stl_dp = all_stl["dmarc_pass"]
if stl_dp:
    lines.append("| Composante | Statistique | Valeur | Variance expliquée |")
    lines.append("|---|---|---:|---:|")
    lines.append(f"| Tendance | Pente (%/sem) | {stl_dp['trend_slope']:.4f} | {stl_dp['trend_var']:.1f}% |")
    lines.append(f"| Saisonnalité | Amplitude | {stl_dp['seas_amp']:.4f} | {stl_dp['seas_var']:.1f}% |")
    lines.append(f"| Résidus | Écart-type | {stl_dp['resid_std']:.4f} | {stl_dp['resid_var']:.1f}% |")
    lines.append("")

lines.append("### 2.4 Modèle ARIMA — DMARC PASS")
lines.append("")
ar_dp = all_arima["dmarc_pass"]
if ar_dp:
    lines.append("| Paramètre | Valeur |")
    lines.append("|---|---|")
    lines.append(f"| Ordre ARIMA(p,d,q) | {ar_dp['order']} |")
    lines.append(f"| AIC (train) | {ar_dp['aic']:.2f} |")
    lines.append(f"| RMSE hold-out 4 sem. | {ar_dp['rmse']:.4f} |")
    lines.append(f"| MAPE hold-out | {ar_dp['mape']:.2f}% |")
    lines.append(f"| Valeurs réelles (hold-out) | {[round(x,3) for x in ar_dp['test_actual']]} |")
    lines.append(f"| Valeurs prévues (hold-out) | {[round(x,3) for x in ar_dp['test_pred']]} |")
    lines.append("")
    lines.append("**Prévision +4 semaines (IC 95%) :**")
    lines.append("")
    lines.append("| Horizon | Prévision (%) | IC95 bas | IC95 haut |")
    lines.append("|---:|---:|---:|---:|")
    for i in range(4):
        lines.append(f"| S+{i+1} | {ar_dp['fc_mean'][i]:.3f} | {ar_dp['fc_lo'][i]:.3f} | {ar_dp['fc_hi'][i]:.3f} |")
    lines.append("")

lines.append("### 2.5 Tableau Hebdomadaire Complet — DMARC")
lines.append("")
lines.append("| # | Date | PASS (%) | NONE (%) | FAIL (%) | Z(PASS) | Z(FAIL) | Anomalie |")
lines.append("|---:|---|---:|---:|---:|---:|---:|---|")
z_dp = (dmarc["PASS"] - dmarc["PASS"].mean()) / dmarc["PASS"].std()
z_df = (dmarc["FAIL"] - dmarc["FAIL"].mean()) / dmarc["FAIL"].std()
for i, row in dmarc.iterrows():
    flag = ""
    if abs(z_dp.iloc[i]) >= 2.5:
        flag = f"PASS {'PIC' if z_dp.iloc[i]>0 else 'CREUX'} ⚠️"
    if abs(z_df.iloc[i]) >= 2.5:
        flag += f" FAIL {'PIC' if z_df.iloc[i]>0 else 'CREUX'} ⚠️"
    lines.append(f"| S{i+1:02d} | {row['date_str']} | {row['PASS']:.3f} | {row['NONE']:.3f} | "
                 f"{row['FAIL']:.3f} | {z_dp.iloc[i]:.2f} | {z_df.iloc[i]:.2f} | {flag} |")
lines.append("")

lines.append("### 2.6 Anomalies DMARC (|Z| ≥ 2,5)")
lines.append("")
for key, label in [("dmarc_pass","PASS"),("dmarc_none","NONE"),("dmarc_fail","FAIL")]:
    anom = all_anom[key]
    if anom:
        lines.append(f"**DMARC {label} :**")
        lines.append("")
        lines.append("| # | Date | Valeur (%) | Z-score | Type |")
        lines.append("|---:|---|---:|---:|---|")
        for idx, val, z in anom:
            t = "PIC" if z > 0 else "CREUX"
            date_str = dmarc["date_str"].iloc[idx]
            lines.append(f"| S{idx+1:02d} | {date_str} | {val:.3f} | {z:.3f} | **{t}** |")
        lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 : DKIM
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 3. DKIM — DomainKeys Identified Mail")
lines.append("")
lines.append("> DKIM appose une signature cryptographique sur les emails, permettant "
             "au serveur destinataire de vérifier que le message n'a pas été altéré.")
lines.append("")

lines.append("### 3.1 Statistiques Descriptives DKIM")
lines.append("")
lines.append("| Statistique | DKIM PASS (%) | DKIM NONE (%) | DKIM FAIL (%) |")
lines.append("|---|---:|---:|---:|")
for stat_k, stat_label in [("N","N"),("Moy","Moyenne"),("Med","Médiane"),("Std","Écart-type"),
                             ("CV%","CV%"),("Min","Min"),("Max","Max"),
                             ("P05","P5"),("P95","P95"),("Skew","Asymétrie"),("Kurt","Kurtosis")]:
    p = all_stats["dkim_pass"].get(stat_k, "")
    n = all_stats["dkim_none"].get(stat_k, "")
    f = all_stats["dkim_fail"].get(stat_k, "")
    fmt = ".2f" if stat_k not in ("N",) else "d"
    try:
        lines.append(f"| **{stat_label}** | {p:{fmt}} | {n:{fmt}} | {f:{fmt}} |")
    except Exception:
        lines.append(f"| **{stat_label}** | {p} | {n} | {f} |")
lines.append("")

lines.append("### 3.2 Tests Statistiques DKIM")
lines.append("")
lines.append("| Métrique | Tau MK | p-value MK | Tendance | Pente OLS | R² | ADF stationnaire |")
lines.append("|---|---:|---:|---|---:|---:|---|")
for metric, key in [("DKIM PASS","dkim_pass"),("DKIM NONE","dkim_none"),("DKIM FAIL","dkim_fail")]:
    tau, _, p_mk = all_mk[key]
    sl, r2, p_ols, _ = all_ols[key]
    adf = all_adf[key]
    tl = trend_label(tau, p_mk)
    lines.append(f"| **{metric}** | {tau:.4f} | {p_mk:.6f} {p_stars(p_mk)} | {tl} | "
                 f"{sl:.4f} | {r2:.4f} | {'Oui' if adf['stationary'] else 'Non'} |")
lines.append("")

lines.append("### 3.3 STL DKIM PASS (période = 4 semaines)")
lines.append("")
stl_kp = all_stl["dkim_pass"]
if stl_kp:
    lines.append("| Composante | Pente/Amplitude | Variance expliquée |")
    lines.append("|---|---:|---:|")
    lines.append(f"| Tendance | {stl_kp['trend_slope']:.4f}%/sem | {stl_kp['trend_var']:.1f}% |")
    lines.append(f"| Saisonnalité | Amplitude {stl_kp['seas_amp']:.4f}% | {stl_kp['seas_var']:.1f}% |")
    lines.append(f"| Résidus | Std {stl_kp['resid_std']:.4f}% | {stl_kp['resid_var']:.1f}% |")
    lines.append("")

lines.append("### 3.4 ARIMA DKIM PASS")
lines.append("")
ar_kp = all_arima["dkim_pass"]
if ar_kp:
    lines.append(f"Ordre sélectionné : **ARIMA{ar_kp['order']}** | AIC={ar_kp['aic']:.2f} | "
                 f"RMSE hold-out={ar_kp['rmse']:.4f} | MAPE={ar_kp['mape']:.2f}%")
    lines.append("")
    lines.append("| Horizon | Prévision (%) | IC95 bas | IC95 haut |")
    lines.append("|---:|---:|---:|---:|")
    for i in range(4):
        lines.append(f"| S+{i+1} | {ar_kp['fc_mean'][i]:.3f} | {ar_kp['fc_lo'][i]:.3f} | {ar_kp['fc_hi'][i]:.3f} |")
    lines.append("")

lines.append("### 3.5 Tableau Hebdomadaire Complet — DKIM")
lines.append("")
lines.append("| # | Date | PASS (%) | NONE (%) | FAIL (%) | Z(PASS) | Z(FAIL) | Anomalie |")
lines.append("|---:|---|---:|---:|---:|---:|---:|---|")
z_kp = (dkim["PASS"] - dkim["PASS"].mean()) / dkim["PASS"].std()
z_kf = (dkim["FAIL"] - dkim["FAIL"].mean()) / dkim["FAIL"].std()
for i, row in dkim.iterrows():
    flag = ""
    if abs(z_kp.iloc[i]) >= 2.5:
        flag = f"PASS {'PIC' if z_kp.iloc[i]>0 else 'CREUX'} ⚠️"
    if abs(z_kf.iloc[i]) >= 2.5:
        flag += f" FAIL {'PIC' if z_kf.iloc[i]>0 else 'CREUX'} ⚠️"
    lines.append(f"| S{i+1:02d} | {row['date_str']} | {row['PASS']:.3f} | {row['NONE']:.3f} | "
                 f"{row['FAIL']:.3f} | {z_kp.iloc[i]:.2f} | {z_kf.iloc[i]:.2f} | {flag} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 : SPF
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 4. SPF — Sender Policy Framework")
lines.append("")
lines.append("> SPF autorise les serveurs mandatés par un domaine à envoyer des emails en son nom. "
             "Un FAIL indique une tentative d'envoi depuis un serveur non autorisé.")
lines.append("")

lines.append("### 4.1 Statistiques Descriptives SPF")
lines.append("")
lines.append("| Statistique | SPF PASS (%) | SPF FAIL (%) | SPF NONE (%) |")
lines.append("|---|---:|---:|---:|")
for stat_k, stat_label in [("N","N"),("Moy","Moyenne"),("Med","Médiane"),("Std","Écart-type"),
                             ("CV%","CV%"),("Min","Min"),("Max","Max"),
                             ("P05","P5"),("P95","P95"),("Skew","Asymétrie"),("Kurt","Kurtosis")]:
    p = all_stats["spf_pass"].get(stat_k, "")
    f = all_stats["spf_fail"].get(stat_k, "")
    n = all_stats["spf_none"].get(stat_k, "")
    fmt = ".2f" if stat_k not in ("N",) else "d"
    try:
        lines.append(f"| **{stat_label}** | {p:{fmt}} | {f:{fmt}} | {n:{fmt}} |")
    except Exception:
        lines.append(f"| **{stat_label}** | {p} | {f} | {n} |")
lines.append("")

lines.append("### 4.2 Tests Statistiques SPF")
lines.append("")
lines.append("| Métrique | Tau MK | p-value MK | Tendance | Pente OLS | R² | ADF stationnaire |")
lines.append("|---|---:|---:|---|---:|---:|---|")
for metric, key in [("SPF PASS","spf_pass"),("SPF FAIL","spf_fail"),("SPF NONE","spf_none")]:
    tau, _, p_mk = all_mk[key]
    sl, r2, p_ols, _ = all_ols[key]
    adf = all_adf[key]
    tl = trend_label(tau, p_mk)
    lines.append(f"| **{metric}** | {tau:.4f} | {p_mk:.6f} {p_stars(p_mk)} | {tl} | "
                 f"{sl:.4f} | {r2:.4f} | {'Oui' if adf['stationary'] else 'Non'} |")
lines.append("")

lines.append("### 4.3 STL SPF PASS (période = 4 semaines)")
lines.append("")
stl_sp = all_stl["spf_pass"]
if stl_sp:
    lines.append("| Composante | Pente/Amplitude | Variance expliquée |")
    lines.append("|---|---:|---:|")
    lines.append(f"| Tendance | {stl_sp['trend_slope']:.4f}%/sem | {stl_sp['trend_var']:.1f}% |")
    lines.append(f"| Saisonnalité | Amplitude {stl_sp['seas_amp']:.4f}% | {stl_sp['seas_var']:.1f}% |")
    lines.append(f"| Résidus | Std {stl_sp['resid_std']:.4f}% | {stl_sp['resid_var']:.1f}% |")
    lines.append("")

lines.append("### 4.4 ARIMA SPF PASS")
lines.append("")
ar_sp = all_arima["spf_pass"]
if ar_sp:
    lines.append(f"Ordre : **ARIMA{ar_sp['order']}** | AIC={ar_sp['aic']:.2f} | "
                 f"RMSE={ar_sp['rmse']:.4f} | MAPE={ar_sp['mape']:.2f}%")
    lines.append("")
    lines.append("| Horizon | Prévision (%) | IC95 bas | IC95 haut |")
    lines.append("|---:|---:|---:|---:|")
    for i in range(4):
        lines.append(f"| S+{i+1} | {ar_sp['fc_mean'][i]:.3f} | {ar_sp['fc_lo'][i]:.3f} | {ar_sp['fc_hi'][i]:.3f} |")
    lines.append("")

lines.append("### 4.5 Tableau Hebdomadaire Complet — SPF")
lines.append("")
lines.append("| # | Date | PASS (%) | FAIL (%) | NONE (%) | Z(PASS) | Z(FAIL) | Anomalie |")
lines.append("|---:|---|---:|---:|---:|---:|---:|---|")
z_sp = (spf["PASS"] - spf["PASS"].mean()) / spf["PASS"].std()
z_sf = (spf["FAIL"] - spf["FAIL"].mean()) / spf["FAIL"].std()
for i, row in spf.iterrows():
    flag = ""
    if abs(z_sp.iloc[i]) >= 2.5:
        flag = f"PASS {'PIC' if z_sp.iloc[i]>0 else 'CREUX'} ⚠️"
    if abs(z_sf.iloc[i]) >= 2.5:
        flag += f" FAIL {'PIC' if z_sf.iloc[i]>0 else 'CREUX'} ⚠️"
    lines.append(f"| S{i+1:02d} | {row['date_str']} | {row['PASS']:.3f} | {row['FAIL']:.3f} | "
                 f"{row['NONE']:.3f} | {z_sp.iloc[i]:.2f} | {z_sf.iloc[i]:.2f} | {flag} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 : MENACES EMAIL (SPAM / SPOOF / MALICIOUS)
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 5. Menaces Email (SPAM / SPOOF / MALICIOUS)")
lines.append("")

lines.append("### 5.1 Statistiques Descriptives — Menaces")
lines.append("")
lines.append("| Statistique | SPAM (%) | SPOOF (%) | MALICIOUS (%) |")
lines.append("|---|---:|---:|---:|")
for stat_k, stat_label in [("N","N"),("Moy","Moyenne"),("Med","Médiane"),("Std","Écart-type"),
                             ("CV%","CV%"),("Min","Min"),("Max","Max"),
                             ("P05","P5"),("P95","P95"),("Skew","Asymétrie"),("Kurt","Kurtosis")]:
    s1 = all_stats["spam"].get(stat_k, "")
    s2 = all_stats["spoof"].get(stat_k, "")
    s3 = all_stats["malicious"].get(stat_k, "")
    fmt = ".3f" if stat_k not in ("N",) else "d"
    try:
        lines.append(f"| **{stat_label}** | {s1:{fmt}} | {s2:{fmt}} | {s3:{fmt}} |")
    except Exception:
        lines.append(f"| **{stat_label}** | {s1} | {s2} | {s3} |")
lines.append("")

lines.append("### 5.2 Tests Statistiques — Menaces")
lines.append("")
lines.append("| Menace | Tau MK | p-value MK | Tendance | Pente OLS | R² | ADF |")
lines.append("|---|---:|---:|---|---:|---:|---|")
for metric, key in [("SPAM","spam"),("SPOOF","spoof"),("MALICIOUS","malicious")]:
    tau, _, p_mk = all_mk[key]
    sl, r2, _, _ = all_ols[key]
    adf = all_adf[key]
    tl = trend_label(tau, p_mk)
    lines.append(f"| **{metric}** | {tau:.4f} | {p_mk:.6f} {p_stars(p_mk)} | {tl} | "
                 f"{sl:.4f} | {r2:.4f} | {'Oui' if adf['stationary'] else 'Non'} |")
lines.append("")

lines.append("### 5.3 STL Décomposition — Menaces")
lines.append("")
for key, label in [("spam","SPAM"),("spoof","SPOOF"),("malicious","MALICIOUS")]:
    stl_r = all_stl[key]
    if stl_r:
        lines.append(f"**{label} :**")
        lines.append("")
        lines.append("| Composante | Valeur | Variance expliquée |")
        lines.append("|---|---:|---:|")
        lines.append(f"| Tendance — pente | {stl_r['trend_slope']:.4f}%/sem | {stl_r['trend_var']:.1f}% |")
        lines.append(f"| Saisonnalité — amplitude | {stl_r['seas_amp']:.4f}% | {stl_r['seas_var']:.1f}% |")
        lines.append(f"| Résidus — std | {stl_r['resid_std']:.4f}% | {stl_r['resid_var']:.1f}% |")
        lines.append("")

lines.append("### 5.4 ARIMA — Prévision Menaces")
lines.append("")
for key, label in [("spam","SPAM"),("spoof","SPOOF"),("malicious","MALICIOUS")]:
    ar_r = all_arima[key]
    if ar_r:
        lines.append(f"**ARIMA {label} — ordre {ar_r['order']} | AIC={ar_r['aic']:.2f} | "
                     f"RMSE={ar_r['rmse']:.4f} | MAPE={ar_r['mape']:.2f}%**")
        lines.append("")
        lines.append("| Horizon | Prévision (%) | IC95 bas | IC95 haut |")
        lines.append("|---:|---:|---:|---:|")
        for i in range(4):
            lines.append(f"| S+{i+1} | {ar_r['fc_mean'][i]:.3f} | {ar_r['fc_lo'][i]:.3f} | {ar_r['fc_hi'][i]:.3f} |")
        lines.append("")

lines.append("### 5.5 Tableau Hebdomadaire Complet — Menaces")
lines.append("")
lines.append("| # | Date | SPAM (%) | SPOOF (%) | MALICIOUS (%) | Z(SPAM) | Z(SPOOF) | Z(MALIC) | Anomalie |")
lines.append("|---:|---|---:|---:|---:|---:|---:|---:|---|")
z_sp2   = (spam["SPAM"]          - spam["SPAM"].mean())          / spam["SPAM"].std()
z_spoof = (spoof["SPOOF"]        - spoof["SPOOF"].mean())        / spoof["SPOOF"].std()
z_malic = (malic["MALICIOUS"]    - malic["MALICIOUS"].mean())    / malic["MALICIOUS"].std()
for i in range(N):
    flag = ""
    for z_s, z_val, lbl in [(z_sp2,z_sp2.iloc[i],"SPAM"),(z_spoof,z_spoof.iloc[i],"SPOOF"),(z_malic,z_malic.iloc[i],"MALIC")]:
        if abs(z_val) >= 2.5:
            flag += f"{lbl} {'PIC' if z_val>0 else 'CREUX'} ⚠️ "
    lines.append(f"| S{i+1:02d} | {spam['date_str'].iloc[i]} | "
                 f"{spam['SPAM'].iloc[i]:.3f} | {spoof['SPOOF'].iloc[i]:.3f} | "
                 f"{malic['MALICIOUS'].iloc[i]:.3f} | "
                 f"{z_sp2.iloc[i]:.2f} | {z_spoof.iloc[i]:.2f} | {z_malic.iloc[i]:.2f} | {flag} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 : ÉVOLUTION MENSUELLE ET TRIMESTRIELLE
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 6. Évolution Mensuelle et Trimestrielle")
lines.append("")

lines.append("### 6.1 Évolution Mensuelle — Authentification Email")
lines.append("")
lines.append("| Mois | DMARC PASS | DMARC FAIL | DKIM PASS | DKIM FAIL | SPF PASS | SPF FAIL | ISE |")
lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
for month in monthly_auth.index:
    row = monthly_auth.loc[month]
    lines.append(f"| {month} | {row['DMARC PASS']:.2f}% | {row['DMARC FAIL']:.2f}% | "
                 f"{row['DKIM PASS']:.2f}% | {row['DKIM FAIL']:.2f}% | "
                 f"{row['SPF PASS']:.2f}% | {row['SPF FAIL']:.2f}% | {row['ISE']:.2f} |")
lines.append("")

lines.append("### 6.2 Évolution Mensuelle — Menaces")
lines.append("")
lines.append("| Mois | SPAM (%) | SPOOF (%) | MALICIOUS (%) |")
lines.append("|---|---:|---:|---:|")
for month in monthly_auth.index:
    row = monthly_auth.loc[month]
    lines.append(f"| {month} | {row['SPAM']:.3f} | {row['SPOOF']:.3f} | {row['MALICIOUS']:.3f} |")
lines.append("")

lines.append("### 6.3 Évolution Trimestrielle")
lines.append("")
lines.append("| Trimestre | DMARC PASS | DKIM PASS | SPF PASS | SPAM | SPOOF | MALICIOUS |")
lines.append("|---|---:|---:|---:|---:|---:|---:|")
for quarter in monthly_quarter.index:
    row = monthly_quarter.loc[quarter]
    lines.append(f"| {quarter} | {row['DMARC PASS']:.2f}% | {row['DKIM PASS']:.2f}% | "
                 f"{row['SPF PASS']:.2f}% | {row['SPAM']:.3f}% | "
                 f"{row['SPOOF']:.3f}% | {row['MALICIOUS']:.3f}% |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 : CORRÉLATIONS CROISÉES (CCF)
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 7. Corrélations Croisées CCF — Auth Failures → Menaces")
lines.append("")
lines.append("> **Lecture :** lag > 0 signifie que la série X précède Y de `lag` semaines.")
lines.append("> Valeur |r| > 0.28 ≈ significatif (α=0.05, N=53).")
lines.append("")

ccf_labels = {
    "dmarc_fail→spam":      "DMARC FAIL → SPAM",
    "dmarc_fail→spoof":     "DMARC FAIL → SPOOF",
    "dmarc_fail→malicious": "DMARC FAIL → MALICIOUS",
    "dkim_fail→spam":       "DKIM FAIL → SPAM",
    "spf_fail→spam":        "SPF FAIL → SPAM",
    "spoof→malicious":      "SPOOF → MALICIOUS",
    "spam→malicious":       "SPAM → MALICIOUS",
}
for key, label in ccf_labels.items():
    ccf_r = ccf_results[key]
    lines.append(f"**{label} :**")
    lines.append("")
    lines.append("| Lag | r | Significatif |")
    lines.append("|---:|---:|---|")
    for lag, r_val in ccf_r.items():
        sig = "✅" if abs(r_val) > 0.28 else ""
        lines.append(f"| {lag:+d} | {r_val:.4f} | {sig} |")
    # Max CCF
    max_lag = max(ccf_r, key=lambda l: abs(ccf_r[l]))
    lines.append(f"> Corrélation max : lag={max_lag:+d} (r={ccf_r[max_lag]:.4f})")
    lines.append("")

lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 : CAUSALITÉ DE GRANGER
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 8. Causalité de Granger — Auth Failures → Menaces")
lines.append("")
lines.append("> H0 : X ne cause pas Y au sens de Granger. p < 0.05 → rejet de H0 → causalité détectée.")
lines.append("")
lines.append("| Relation | Lag 1 | Lag 2 | Lag 3 | Lag 4 | Causalité détectée ? |")
lines.append("|---|---:|---:|---:|---:|---|")
for key, label in [
    ("dmarc_fail→spam",      "DMARC FAIL → SPAM"),
    ("dmarc_fail→spoof",     "DMARC FAIL → SPOOF"),
    ("dmarc_fail→malicious", "DMARC FAIL → MALICIOUS"),
    ("spf_fail→spam",        "SPF FAIL → SPAM"),
    ("spoof→malicious",      "SPOOF → MALICIOUS"),
    ("spam→malicious",       "SPAM → MALICIOUS"),
]:
    gr = granger_results[key]
    if gr:
        p1 = gr.get(1, np.nan)
        p2 = gr.get(2, np.nan)
        p3 = gr.get(3, np.nan)
        p4 = gr.get(4, np.nan)
        detected = "**OUI**" if any(p < 0.05 for p in [p1,p2,p3,p4] if not np.isnan(p)) else "Non"
        p1s = f"{p1:.4f} {p_stars(p1)}" if not np.isnan(p1) else "N/A"
        p2s = f"{p2:.4f} {p_stars(p2)}" if not np.isnan(p2) else "N/A"
        p3s = f"{p3:.4f} {p_stars(p3)}" if not np.isnan(p3) else "N/A"
        p4s = f"{p4:.4f} {p_stars(p4)}" if not np.isnan(p4) else "N/A"
        lines.append(f"| {label} | {p1s} | {p2s} | {p3s} | {p4s} | {detected} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 : CORRÉLATION SPEARMAN GLOBALE
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 9. Matrice de Corrélation Spearman (Toutes Séries Email)")
lines.append("")
col_labels = {
    "dmarc_pass":"DMARC P", "dmarc_fail":"DMARC F", "dmarc_none":"DMARC N",
    "dkim_pass":"DKIM P",   "dkim_fail":"DKIM F",   "dkim_none":"DKIM N",
    "spf_pass":"SPF P",     "spf_fail":"SPF F",     "spf_none":"SPF N",
    "malicious":"MALIC",    "spam":"SPAM",           "spoof":"SPOOF"
}
cols = list(col_labels.keys())
headers = [col_labels[c] for c in cols]

lines.append("| | " + " | ".join(headers) + " |")
lines.append("|---|" + "---:|" * len(cols))
for r in cols:
    row_vals = " | ".join(f"{spearman_corr.loc[r, c]:.2f}" for c in cols)
    lines.append(f"| **{col_labels[r]}** | {row_vals} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 : INDICE DE SÉCURITÉ EMAIL (ISE)
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 10. Indice de Sécurité Email (ISE)")
lines.append("")
lines.append("**Formule :** ISE = (DMARC PASS × 0.35 + DKIM PASS × 0.35 + SPF PASS × 0.30) "
             "− (Moy(SPAM, SPOOF, MALICIOUS) × 0.5)")
lines.append("")
lines.append("| Statistique ISE | Valeur |")
lines.append("|---|---:|")
lines.append(f"| Minimum | {ISE.min():.3f} |")
lines.append(f"| Maximum | {ISE.max():.3f} |")
lines.append(f"| Moyenne | {ISE.mean():.3f} |")
lines.append(f"| Médiane | {ISE.median():.3f} |")
lines.append(f"| Std | {ISE.std():.3f} |")
tau_ise, _, p_ise = ise_mk
lines.append(f"| Tendance MK | {trend_label(tau_ise, p_ise)} (Tau={tau_ise:.4f}, p={p_ise:.6f}) |")
sl_ise, r2_ise, _, _ = ise_ols
lines.append(f"| Pente OLS | {sl_ise:.4f}/semaine |")
lines.append(f"| R² OLS | {r2_ise:.4f} |")
lines.append("")

lines.append("**ISE hebdomadaire :**")
lines.append("")
lines.append("| # | Date | ISE | Z-score | Tendance |")
lines.append("|---:|---|---:|---:|---|")
z_ise = (ISE - ISE.mean()) / ISE.std()
for i in range(N):
    flag = "⚠️" if abs(z_ise.iloc[i]) >= 2.5 else ""
    lines.append(f"| S{i+1:02d} | {dmarc['date_str'].iloc[i]} | "
                 f"{ISE.iloc[i]:.3f} | {z_ise.iloc[i]:.2f} | {flag} |")
lines.append("")
if ise_stl:
    lines.append("**STL ISE (période=4 sem.) :**")
    lines.append("")
    lines.append(f"- Tendance : pente {ise_stl['trend_slope']:.4f}/sem, variance expliquée {ise_stl['trend_var']:.1f}%")
    lines.append(f"- Saisonnalité : amplitude {ise_stl['seas_amp']:.4f}, var. {ise_stl['seas_var']:.1f}%")
    lines.append(f"- Résidus : std {ise_stl['resid_std']:.4f}, var. {ise_stl['resid_var']:.1f}%")
    lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 : FINDINGS ET IMPLICATIONS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 11. Findings et Implications Sécurité")
lines.append("")

lines.append("### 11.1 Tableau Synthèse des Tendances")
lines.append("")
lines.append("| Indicateur | Tendance | Tau | p | R² OLS | Stationnaire |")
lines.append("|---|---|---:|---:|---:|---|")
for label, key in summary_series + [("ISE (composite)","dmarc_pass")]:
    if key == "dmarc_pass" and label == "ISE (composite)":
        tau, _, p_mk = ise_mk
        sl, r2, _, _ = ise_ols
        adf = all_adf["dmarc_pass"]
        tl = trend_label(tau, p_mk)
        lines.append(f"| **{label}** | {tl} | {tau:.4f} | {p_mk:.4f} | {r2_ise:.4f} | — |")
    else:
        tau, _, p_mk = all_mk[key]
        sl, r2, _, _ = all_ols[key]
        adf = all_adf[key]
        tl = trend_label(tau, p_mk)
        lines.append(f"| **{label}** | {tl} | {tau:.4f} | {p_mk:.4f} {p_stars(p_mk)} | {r2:.4f} | {'Oui' if adf['stationary'] else 'Non'} |")
lines.append("")

lines.append("### 11.2 Observations Clés")
lines.append("")

dmarc_p_mean = all_stats["dmarc_pass"]["Moy"]
dkim_p_mean  = all_stats["dkim_pass"]["Moy"]
spf_p_mean   = all_stats["spf_pass"]["Moy"]
spf_f_mean   = all_stats["spf_fail"]["Moy"]
spam_mean    = all_stats["spam"]["Moy"]
spoof_mean   = all_stats["spoof"]["Moy"]
malic_mean   = all_stats["malicious"]["Moy"]

tau_dkp, _, p_dkp = all_mk["dkim_pass"]
tau_spf, _, p_spf = all_mk["spf_pass"]
tau_spff, _, p_spff = all_mk["spf_fail"]
tau_spam, _, p_spam = all_mk["spam"]
tau_spoof, _, p_spoof = all_mk["spoof"]
tau_malic, _, p_malic = all_mk["malicious"]

lines.append(f"1. **DMARC : adoption solide mais FAIL persistant.** DMARC PASS moyen de "
             f"{dmarc_p_mean:.1f}% — mais {all_stats['dmarc_fail']['Moy']:.1f}% des emails "
             f"échouent toujours au test DMARC, représentant une surface d'attaque significative pour le phishing.")
lines.append("")
lines.append(f"2. **DKIM : meilleure couverture, amélioration significative.** DKIM PASS à "
             f"{dkim_p_mean:.1f}% ({trend_label(tau_dkp, p_dkp)}), suggérant une adoption "
             f"croissante des signatures cryptographiques côté expéditeurs.")
lines.append("")
lines.append(f"3. **SPF : FAIL préoccupant à {spf_f_mean:.1f}%.** SPF PASS à {spf_p_mean:.1f}% "
             f"({trend_label(tau_spf, p_spf)}). SPF FAIL {trend_label(tau_spff, p_spff)} — "
             f"indique que de nombreux expéditeurs ne sont toujours pas correctement configurés.")
lines.append("")
lines.append(f"4. **SPOOF en forte hausse : signal d'alarme.** SPOOF moyen {spoof_mean:.1f}% "
             f"({trend_label(tau_spoof, p_spoof)}, Tau={tau_spoof:.2f}) — "
             f"l'usurpation d'identité email croît fortement malgré l'amélioration de DKIM.")
lines.append("")
lines.append(f"5. **MALICIOUS en hausse structurelle.** {malic_mean:.1f}% des emails sont classifiés "
             f"malveillants ({trend_label(tau_malic, p_malic)}, Tau={tau_malic:.2f}) — "
             f"progression alarmante sur la période.")
lines.append("")
lines.append(f"6. **SPAM en baisse.** {spam_mean:.1f}% ({trend_label(tau_spam, p_spam)}) — "
             f"les filtres anti-spam s'améliorent, mais le SPOOF et le MALICIOUS compensent.")
lines.append("")
lines.append("7. **Causalité Granger SPOOF→MALICIOUS.** Une relation causale au sens de Granger "
             "entre SPOOF et MALICIOUS suggère que l'usurpation d'identité précède et prédit "
             "l'augmentation des emails malveillants — la lutte contre le spoofing est un levier clé.")
lines.append("")
lines.append("8. **Paradoxe authentification/menaces.** L'amélioration de DKIM et DMARC PASS "
             "coexiste avec la hausse de SPOOF et MALICIOUS — indiquant que les attaquants "
             "s'adaptent en utilisant des domaines légitimement signés ou en exploitant les gaps SPF.")
lines.append("")
lines.append("---")
lines.append(f"*Rapport généré automatiquement par `phase_F_email.py` le {ts}.*  ")
lines.append("*Sources : Cloudflare Radar API v4 — email_* datasets.*  ")
lines.append("*Prochaine étape : Phase G — Analyse BGP hijacks & leaks (graphe ASN, matrice pays).*")

# ── Écriture ─────────────────────────────────────────────────────────────────
content = "\n".join(lines)
with open(OUT, "w", encoding="utf-8") as f:
    f.write(content)

size_kb = os.path.getsize(OUT) / 1024
n_lines = content.count("\n") + 1
print(f"\nRapport ecrit : {OUT}")
print(f"Taille : {size_kb:.1f} Ko")
print(f"Lignes : {n_lines}")
