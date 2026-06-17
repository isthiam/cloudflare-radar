"""
Phase C — Analyse Temporelle (Séries Chronologiques)
Cloudflare Radar Dataset — Juin 2025 / Juin 2026
Auteur    : Issakha Thiam
"""

import pandas as pd
import numpy as np
import warnings
from pathlib import Path
from datetime import datetime

from scipy import stats as sp_stats
from statsmodels.tsa.stattools import adfuller, grangercausalitytests, acf, pacf
from statsmodels.tsa.seasonal import STL
from statsmodels.tsa.arima.model import ARIMA
from statsmodels.regression.linear_model import OLS
from statsmodels.tools import add_constant

warnings.filterwarnings("ignore")

BASE  = Path(r"E:\Webscraping\cloudflare_radar_vulnerabilite\scripts\outputs_complet")
CLEAN = BASE / "cleaned"
NOW   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ─── UTILITAIRES ─────────────────────────────────────────────────────────────

def load(name):
    return pd.read_csv(CLEAN / f"{name}_clean.csv", low_memory=False)

def fmt(v, d=4):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "N/D"
    return f"{v:.{d}f}"

def stars(p):
    if p < 0.001: return "***"
    if p < 0.01:  return "**"
    if p < 0.05:  return "*"
    return "n.s."

# ── Mann-Kendall (implémentation scipy) ───────────────────────────────────────
def mann_kendall(x):
    x = np.array(x, dtype=float)
    x = x[~np.isnan(x)]
    n = len(x)
    if n < 4:
        return {"tau": np.nan, "p_value": np.nan, "trend": "N/D", "S": np.nan, "z": np.nan}
    s = 0
    for k in range(n - 1):
        for j in range(k + 1, n):
            s += np.sign(x[j] - x[k])
    # Variance avec correction pour les ex-aequo
    unique, counts = np.unique(x, return_counts=True)
    tie_correction = sum(c * (c - 1) * (2 * c + 5) for c in counts if c > 1)
    var_s = (n * (n - 1) * (2 * n + 5) - tie_correction) / 18
    if var_s <= 0:
        return {"tau": 0, "p_value": 1, "trend": "neutre", "S": 0, "z": 0}
    z = (s - 1) / np.sqrt(var_s) if s > 0 else ((s + 1) / np.sqrt(var_s) if s < 0 else 0)
    p = 2 * (1 - sp_stats.norm.cdf(abs(z)))
    tau = s / (n * (n - 1) / 2)
    trend = ("hausse" if s > 0 else "baisse") if p < 0.05 else "neutre"
    return {"S": int(s), "tau": round(tau, 4), "z": round(z, 4),
            "p_value": round(p, 6), "trend": trend}

# ── ADF Test ──────────────────────────────────────────────────────────────────
def adf_test(x, label=""):
    x = np.array(x, dtype=float)
    x = x[~np.isnan(x)]
    if len(x) < 8:
        return {"stationnaire": "N/D", "adf_stat": np.nan, "p_value": np.nan,
                "lags": np.nan, "crit_1": np.nan, "crit_5": np.nan, "crit_10": np.nan}
    try:
        res = adfuller(x, autolag="AIC")
        stat, p, lags, _, crit, _ = res
        stationnaire = "Oui" if p < 0.05 else "Non"
        return {
            "stationnaire": stationnaire,
            "adf_stat": round(stat, 4),
            "p_value": round(p, 4),
            "lags": int(lags),
            "crit_1":  round(crit["1%"], 4),
            "crit_5":  round(crit["5%"], 4),
            "crit_10": round(crit["10%"], 4),
        }
    except Exception as e:
        return {"stationnaire": "Erreur", "error": str(e)}

# ── Tendance linéaire OLS ─────────────────────────────────────────────────────
def linear_trend(x):
    x = np.array(x, dtype=float)
    mask = ~np.isnan(x)
    x = x[mask]
    if len(x) < 4:
        return {}
    t = np.arange(len(x), dtype=float)
    slope, intercept, r, p, se = sp_stats.linregress(t, x)
    return {
        "slope":     round(slope, 6),
        "intercept": round(intercept, 4),
        "r2":        round(r**2, 4),
        "p_value":   round(p, 6),
        "direction": "hausse" if slope > 0 and p < 0.05 else
                     "baisse" if slope < 0 and p < 0.05 else "neutre",
    }

# ── STL Décomposition ─────────────────────────────────────────────────────────
def stl_decompose(series, period=4, label=""):
    x = np.array(series, dtype=float)
    x = x[~np.isnan(x)]
    if len(x) < 2 * period + 1:
        return None
    try:
        stl = STL(x, period=period, robust=True)
        res = stl.fit()
        trend_slope = sp_stats.linregress(np.arange(len(res.trend)), res.trend)[0]
        return {
            "n": len(x),
            "period": period,
            "trend_mean":     round(float(res.trend.mean()), 4),
            "trend_slope":    round(trend_slope, 6),
            "trend_var_pct":  round(float(res.trend.var() / np.var(x) * 100), 2),
            "seasonal_amp":   round(float(res.seasonal.max() - res.seasonal.min()), 4),
            "seasonal_mean":  round(float(res.seasonal.mean()), 6),
            "seasonal_var_pct": round(float(res.seasonal.var() / np.var(x) * 100), 2),
            "resid_std":      round(float(res.resid.std()), 4),
            "resid_max_abs":  round(float(np.abs(res.resid).max()), 4),
            "resid_var_pct":  round(float(res.resid.var() / np.var(x) * 100), 2),
        }
    except Exception as e:
        return {"error": str(e)}

# ── ARIMA ─────────────────────────────────────────────────────────────────────
def fit_arima(series, label="", holdout=4, orders=[(1,1,1),(0,1,1),(1,1,0),(2,1,1),(1,0,1)]):
    x = np.array(series, dtype=float)
    x = x[~np.isnan(x)]
    if len(x) < 12:
        return None
    train = x[:-holdout]
    test  = x[-holdout:]

    # Sélection par AIC sur train
    best_aic, best_order, best_model = np.inf, None, None
    for order in orders:
        try:
            m = ARIMA(train, order=order).fit()
            if m.aic < best_aic:
                best_aic, best_order, best_model = m.aic, order, m
        except Exception:
            continue

    if best_model is None:
        return None

    # Prévision sur holdout
    fc_test = best_model.forecast(steps=holdout)
    rmse_ho = round(float(np.sqrt(np.mean((fc_test - test)**2))), 4)
    mape_ho = round(float(np.mean(np.abs((fc_test - test) / (test + 1e-9))) * 100), 2)

    # Ré-ajustement sur toutes les données pour prévision future
    try:
        full_model = ARIMA(x, order=best_order).fit()
        fc = full_model.get_forecast(steps=4)
        fc_mean = fc.predicted_mean
        fc_ci   = fc.conf_int(alpha=0.05)
        forecast = [
            {"step": i+1, "mean": round(fc_mean[i],4),
             "ci_low": round(fc_ci.iloc[i,0],4),
             "ci_high": round(fc_ci.iloc[i,1],4)}
            for i in range(4)
        ]
    except Exception:
        forecast = []

    return {
        "best_order": str(best_order),
        "aic":   round(best_aic, 2),
        "rmse_holdout": rmse_ho,
        "mape_holdout": mape_ho,
        "holdout_n": holdout,
        "forecast": forecast,
        "train_n":  len(train),
        "test_values": [round(float(v),4) for v in test],
        "fc_test_values": [round(float(v),4) for v in fc_test],
    }

# ── Corrélation croisée (CCF) ─────────────────────────────────────────────────
def cross_corr(x, y, max_lag=8, label_x="", label_y=""):
    x = np.array(x, dtype=float)
    y = np.array(y, dtype=float)
    n = min(len(x), len(y))
    x, y = x[:n], y[:n]
    # Normaliser
    xz = (x - x.mean()) / (x.std() + 1e-12)
    yz = (y - y.mean()) / (y.std() + 1e-12)
    rows = []
    for lag in range(-max_lag, max_lag + 1):
        if lag < 0:
            r = float(np.corrcoef(xz[:n+lag], yz[-lag:])[0,1])
        elif lag == 0:
            r = float(np.corrcoef(xz, yz)[0,1])
        else:
            r = float(np.corrcoef(xz[lag:], yz[:n-lag])[0,1])
        rows.append({"lag": lag, "ccf": round(r, 4)})
    return rows

# ── Anomalies Z-score ─────────────────────────────────────────────────────────
def detect_anomalies(series, dates, label, threshold=2.5):
    x = np.array(series, dtype=float)
    z = (x - np.nanmean(x)) / (np.nanstd(x) + 1e-12)
    anomalies = []
    for i, (zi, xi) in enumerate(zip(z, x)):
        if abs(zi) >= threshold:
            d = dates[i] if i < len(dates) else f"idx={i}"
            anomalies.append({"date": str(d)[:10], "valeur": round(float(xi),4),
                               "z_score": round(float(zi),3),
                               "direction": "PIC" if zi > 0 else "CREUX"})
    return anomalies

# ── Profil jour de la semaine ─────────────────────────────────────────────────
def weekday_profile(df, date_col, value_cols):
    df = df.copy()
    df[date_col] = pd.to_datetime(df[date_col], utc=True)
    df["weekday"] = df[date_col].dt.day_name()
    df["weekday_n"] = df[date_col].dt.dayofweek
    order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    result = {}
    for col in value_cols:
        if col not in df.columns:
            continue
        profile = df.groupby(["weekday","weekday_n"])[col].mean().reset_index()
        profile = profile.sort_values("weekday_n")
        result[col] = {row["weekday"]: round(row[col], 4) for _, row in profile.iterrows()}
    return result

# ─── CHARGEMENT DES DONNÉES ───────────────────────────────────────────────────
print("Chargement des donnees...")

bgp_ts_raw = load("bgp_timeseries")
dns_ts_raw = load("dns_timeseries")
em_dmarc   = load("email_dmarc")
em_dkim    = load("email_dkim")
em_spf     = load("email_spf")
em_spam    = load("email_spam")
em_spoof   = load("email_spoof")
em_malici  = load("email_malicious")
l3_proto   = load("attacks_l3_protocol")
l3_bit     = load("attacks_l3_bitrate")
l3_ip      = load("attacks_l3_ip_version")
l7_method  = load("attacks_l7_http_method")
l7_vert    = load("attacks_l7_vertical")
http_bot   = load("http_bot_class")
http_tls   = load("http_tls_version")
http_http  = load("http_http_version")
http_ipv   = load("http_ip_version")
http_dev   = load("http_device_type")
iqi_bw     = load("iqi_bandwidth")
iqi_dns    = load("iqi_dns")

# BGP timeseries : suppression dernière ligne (semaine partielle = valeur aberrante)
bgp_ts = bgp_ts_raw.iloc[:-1].copy()
bgp_ts["date"] = pd.to_datetime(bgp_ts["date"], utc=True)

dns_ts = dns_ts_raw.copy()
dns_ts["date"] = pd.to_datetime(dns_ts["date"], utc=True)

# Agréger HTTP/IQI en moyennes hebdomadaires globales
def global_weekly(df, date_col, value_cols):
    df = df.copy()
    df[date_col] = pd.to_datetime(df[date_col], utc=True)
    return df.groupby(date_col)[value_cols].mean().reset_index()

http_bot_wk  = global_weekly(http_bot,  "date", ["human","bot"])
http_tls_wk  = global_weekly(http_tls,  "date", ["TLS 1.3","TLS QUIC","TLS 1.2","TLS 1.1","TLS 1.0"])
http_http_wk = global_weekly(http_http, "date", ["HTTP/2","HTTP/1.x","HTTP/3"])
http_ipv_wk  = global_weekly(http_ipv,  "date", ["IPv6","IPv4"])
http_dev_wk  = global_weekly(http_dev,  "date", ["desktop","mobile","other"])
iqi_bw_wk    = global_weekly(iqi_bw,   "date", ["p25","p50","p75"])
iqi_dns_wk   = global_weekly(iqi_dns,  "date", ["p25","p50","p75"])

print("Analyse en cours...")

# ─── CONSTRUCTION DU CATALOGUE DE SÉRIES ─────────────────────────────────────
# (nom, série pandas, dates pandas, label rapport, période STL)

SERIES_CATALOGUE = [
    # BGP & DNS
    ("bgp_volume",     bgp_ts["values"],        bgp_ts["date"],           "Volume BGP (routes/semaine)", 4),
    ("dns_qualite",    dns_ts["values"],         dns_ts["date"],           "Qualité DNS (score normalisé)", 4),
    # Email
    ("dmarc_pass",     em_dmarc["PASS"],         em_dmarc["date"],         "DMARC PASS (%)", 4),
    ("dmarc_fail",     em_dmarc["FAIL"],         em_dmarc["date"],         "DMARC FAIL (%)", 4),
    ("dkim_pass",      em_dkim["PASS"],          em_dkim["date"],          "DKIM PASS (%)", 4),
    ("dkim_fail",      em_dkim["FAIL"],          em_dkim["date"],          "DKIM FAIL (%)", 4),
    ("spf_pass",       em_spf["PASS"],           em_spf["date"],           "SPF PASS (%)", 4),
    ("spf_fail",       em_spf["FAIL"],           em_spf["date"],           "SPF FAIL (%)", 4),
    ("spam",           em_spam["SPAM"],          em_spam["date"],          "Taux SPAM (%)", 4),
    ("spoof",          em_spoof["SPOOF"],        em_spoof["date"],         "Taux SPOOF (%)", 4),
    ("malicieux",      em_malici["MALICIOUS"],   em_malici["date"],        "Taux Malicieux (%)", 4),
    # L3 attacks
    ("l3_udp",         l3_proto["UDP"],          l3_proto["date"],         "L3 UDP (%)", 4),
    ("l3_tcp",         l3_proto["TCP"],          l3_proto["date"],         "L3 TCP (%)", 4),
    ("l3_mega",        l3_bit["OVER_100_GBPS"],  l3_bit["date"],           "L3 >100 Gbps (%)", 4),
    ("l3_small",       l3_bit["UNDER_500_MBPS"], l3_bit["date"],           "L3 <500 Mbps (%)", 4),
    ("l3_ipv4",        l3_ip["IPv4"],            l3_ip["date"],            "L3 IPv4 (%)", 4),
    # HTTP global
    ("http_bot",       http_bot_wk["bot"],       http_bot_wk["date"],      "Trafic Bot global (%)", 4),
    ("http_tls13",     http_tls_wk["TLS 1.3"],   http_tls_wk["date"],      "TLS 1.3 global (%)", 4),
    ("http_h3",        http_http_wk["HTTP/3"],   http_http_wk["date"],     "HTTP/3 global (%)", 4),
    ("http_ipv6",      http_ipv_wk["IPv6"],      http_ipv_wk["date"],      "IPv6 global (%)", 4),
    ("http_mobile",    http_dev_wk["mobile"],    http_dev_wk["date"],      "Mobile global (%)", 4),
    # IQI
    ("iqi_bw_med",     iqi_bw_wk["p50"],         iqi_bw_wk["date"],        "Bande passante médiane (Mbps)", 4),
    ("iqi_dns_med",    iqi_dns_wk["p50"],        iqi_dns_wk["date"],       "Latence DNS médiane (ms)", 4),
]

# ─── CALCUL DE TOUS LES TESTS ────────────────────────────────────────────────
RESULTS = {}
for key, serie, dates, label, period in SERIES_CATALOGUE:
    print(f"  >> {label}")
    vals = serie.values if hasattr(serie, "values") else np.array(serie)
    RESULTS[key] = {
        "label":    label,
        "n":        int(np.sum(~np.isnan(vals.astype(float)))),
        "mk":       mann_kendall(vals),
        "adf":      adf_test(vals),
        "trend":    linear_trend(vals),
        "stl":      stl_decompose(vals, period=period),
        "anomalies":detect_anomalies(vals, list(dates), label, threshold=2.5),
        "arima":    fit_arima(vals, label=label),
    }

# ─── CCF ENTRE SÉRIES CLÉS ───────────────────────────────────────────────────
print("  >> Corrélations croisées...")
# BGP vs DNS (mêmes 52 premières semaines)
bgp_vals = bgp_ts["values"].values[:52].astype(float)
dns_vals = dns_ts["values"].values[:52].astype(float)
ccf_bgp_dns = cross_corr(bgp_vals, dns_vals, max_lag=6, label_x="BGP", label_y="DNS")

# SPAM vs SPOOF
ccf_spam_spoof = cross_corr(
    em_spam["SPAM"].values, em_spoof["SPOOF"].values, max_lag=6,
    label_x="SPAM", label_y="SPOOF"
)

# DMARC_FAIL vs SPAM
ccf_dmarc_spam = cross_corr(
    em_dmarc["FAIL"].values, em_spam["SPAM"].values, max_lag=6,
    label_x="DMARC_FAIL", label_y="SPAM"
)

# L3 UDP vs TCP
ccf_udp_tcp = cross_corr(
    l3_proto["UDP"].values, l3_proto["TCP"].values, max_lag=6,
    label_x="UDP", label_y="TCP"
)

# TLS13 vs HTTP/3
ccf_tls_h3 = cross_corr(
    http_tls_wk["TLS 1.3"].values, http_http_wk["HTTP/3"].values, max_lag=6,
    label_x="TLS1.3", label_y="HTTP/3"
)

# ─── PROFIL JOUR DE SEMAINE L7 ───────────────────────────────────────────────
print("  >> Profil jour de semaine L7...")
l7_method["date"] = pd.to_datetime(l7_method["date"], utc=True)
l7_vert["date"]   = pd.to_datetime(l7_vert["date"],   utc=True)

wday_method = weekday_profile(l7_method, "date",
    [c for c in ["GET","POST","HEAD"] if c in l7_method.columns])
wday_vert   = weekday_profile(l7_vert, "date",
    [c for c in ["Computer and Electronics","Internet and Telecom","Finance"]
     if c in l7_vert.columns])

# ─── TEST DE GRANGER ─────────────────────────────────────────────────────────
print("  >> Test de Granger...")
def granger_test(x, y, max_lag=4):
    """Y est-il causé au sens de Granger par X ?"""
    x = np.array(x, dtype=float)
    y = np.array(y, dtype=float)
    n = min(len(x), len(y))
    xy = np.column_stack([y[:n], x[:n]])
    results = {}
    try:
        gr = grangercausalitytests(xy, maxlag=max_lag, verbose=False)
        for lag in range(1, max_lag + 1):
            p_f  = round(gr[lag][0]["ssr_ftest"][1], 4)
            p_chi= round(gr[lag][0]["ssr_chi2test"][1], 4)
            results[lag] = {"p_ftest": p_f, "p_chi2": p_chi,
                            "significant": p_f < 0.05}
    except Exception as e:
        results["error"] = str(e)
    return results

granger_bgp_dns  = granger_test(bgp_vals, dns_vals, max_lag=4)
granger_spam_spoof = granger_test(
    em_spam["SPAM"].values[:52], em_spoof["SPOOF"].values[:52], max_lag=4)
granger_dmarc_spam = granger_test(
    em_dmarc["FAIL"].values[:52], em_spam["SPAM"].values[:52], max_lag=4)

print("  >> Analyse L7 anomalies...")
# Anomalies L7 (daily)
l7_method_dates = pd.to_datetime(l7_method["date"], utc=True).dt.strftime("%Y-%m-%d").tolist()
anom_l7_get  = detect_anomalies(l7_method["GET"].values,  l7_method_dates, "L7 GET", threshold=2.5)
anom_l7_post = detect_anomalies(l7_method["POST"].values, l7_method_dates, "L7 POST", threshold=2.5)

# ─── GÉNÉRATION DU RAPPORT ───────────────────────────────────────────────────

R = []
def w(line=""):
    R.append(line)

w("# Rapport Phase C — Analyse Temporelle (Séries Chronologiques)")
w(f"**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  ")
w(f"**Auteur :** Issakha Thiam  ")
w(f"**Généré le :** {NOW}")
w()

# ─── 1. RÉSUMÉ DES TENDANCES ─────────────────────────────────────────────────
w("---")
w("## 1. Résumé Exécutif — Tendances Détectées")
w()
w("> **Légende p-value :** \\*\\*\\* p<0,001 | \\*\\* p<0,01 | \\* p<0,05 | n.s. non significatif")
w()
w("| Série | N | Tendance (MK) | Tau | p-value | Pente OLS | R² | Stationnaire (ADF) |")
w("|---|---:|---|---:|---:|---:|---:|---|")
for key, serie, dates, label, period in SERIES_CATALOGUE:
    r = RESULTS[key]
    mk  = r["mk"]
    tr  = r["trend"]
    adf = r["adf"]
    icon = {"hausse": "↑", "baisse": "↓", "neutre": "→"}.get(mk.get("trend",""),"?")
    sig  = stars(mk.get("p_value", 1))
    slope_str = fmt(tr.get("slope", np.nan), 6) if tr else "N/D"
    r2_str    = fmt(tr.get("r2", np.nan), 4)    if tr else "N/D"
    stat_str  = adf.get("stationnaire", "N/D")
    w(f"| {label} | {r['n']} | {icon} **{mk.get('trend','?')}** {sig} | "
      f"{fmt(mk.get('tau',np.nan),4)} | {fmt(mk.get('p_value',np.nan),4)} | "
      f"{slope_str} | {r2_str} | {stat_str} |")
w()

# ─── 2. BGP & DNS ─────────────────────────────────────────────────────────────
w("---")
w("## 2. BGP Timeseries & DNS Timeseries")
w()

for key, label in [("bgp_volume","BGP Volume (routes)"), ("dns_qualite","DNS Qualité (score normalisé)")]:
    r = RESULTS[key]
    w(f"### 2.{'1' if key=='bgp_volume' else '2'} {label}")
    w()
    # Données brutes
    serie_data = bgp_ts["values"] if key == "bgp_volume" else dns_ts["values"]
    dates_data = bgp_ts["date"]   if key == "bgp_volume" else dns_ts["date"]
    w("**Série temporelle complète (valeurs hebdomadaires) :**")
    w()
    w("| Semaine | Date | Valeur | Z-score |")
    w("|---:|---|---:|---:|")
    vals_arr = serie_data.values.astype(float)
    mean_v = np.nanmean(vals_arr)
    std_v  = np.nanstd(vals_arr)
    for i, (d, v) in enumerate(zip(dates_data, serie_data), 1):
        z = round((v - mean_v) / (std_v + 1e-12), 2)
        flag = " ⚠️" if abs(z) >= 2.5 else ""
        w(f"| S{i:02d} | {str(d)[:10]} | {v:,.4f} | {z}{flag} |")
    w()

    # ADF
    adf = r["adf"]
    w("**Test de stationnarité (ADF — Augmented Dickey-Fuller) :**")
    w()
    w("| Paramètre | Valeur |")
    w("|---|---|")
    w(f"| Statistique ADF | {fmt(adf.get('adf_stat',np.nan),4)} |")
    w(f"| p-value | {fmt(adf.get('p_value',np.nan),4)} {stars(adf.get('p_value',1))} |")
    w(f"| Lags retenus | {adf.get('lags','N/D')} |")
    w(f"| Seuil critique 1% | {fmt(adf.get('crit_1',np.nan),4)} |")
    w(f"| Seuil critique 5% | {fmt(adf.get('crit_5',np.nan),4)} |")
    w(f"| Seuil critique 10% | {fmt(adf.get('crit_10',np.nan),4)} |")
    w(f"| **Conclusion** | **Série {'stationnaire' if adf.get('stationnaire')=='Oui' else 'non stationnaire'}** |")
    w()

    # Mann-Kendall
    mk = r["mk"]
    w("**Test de Mann-Kendall (tendance monotone) :**")
    w()
    w("| Paramètre | Valeur |")
    w("|---|---|")
    w(f"| Statistique S | {mk.get('S','N/D')} |")
    w(f"| Tau de Kendall | {fmt(mk.get('tau',np.nan),4)} |")
    w(f"| Z normalisé | {fmt(mk.get('z',np.nan),4)} |")
    w(f"| p-value | {fmt(mk.get('p_value',np.nan),6)} {stars(mk.get('p_value',1))} |")
    w(f"| **Tendance** | **{mk.get('trend','N/D').upper()}** |")
    w()

    # STL
    stl = r["stl"]
    if stl and "error" not in stl:
        w(f"**Décomposition STL (période={stl['period']} semaines) :**")
        w()
        w("| Composante | Statistique | Valeur | Variance expliquée |")
        w("|---|---|---:|---:|")
        w(f"| Tendance | Moyenne | {fmt(stl['trend_mean'],4)} | {stl['trend_var_pct']}% |")
        w(f"| Tendance | Pente | {fmt(stl['trend_slope'],6)} | — |")
        w(f"| Saisonnalité | Amplitude | {fmt(stl['seasonal_amp'],4)} | {stl['seasonal_var_pct']}% |")
        w(f"| Saisonnalité | Moyenne | {fmt(stl['seasonal_mean'],6)} | — |")
        w(f"| Résidus | Écart-type | {fmt(stl['resid_std'],4)} | {stl['resid_var_pct']}% |")
        w(f"| Résidus | Max |résidu| | {fmt(stl['resid_max_abs'],4)} | — |")
        w()

    # Anomalies
    anom = r["anomalies"]
    w(f"**Anomalies détectées (|Z| ≥ 2,5) :**")
    w()
    if anom:
        w("| Date | Valeur | Z-score | Type |")
        w("|---|---:|---:|---|")
        for a in anom:
            w(f"| {a['date']} | {a['valeur']:,} | {a['z_score']} | **{a['direction']}** |")
    else:
        w("_Aucune anomalie détectée._")
    w()

    # ARIMA
    ar = r["arima"]
    if ar:
        w(f"**Modèle ARIMA (sélection par AIC, hold-out = {ar['holdout_n']} semaines) :**")
        w()
        w("| Paramètre | Valeur |")
        w("|---|---|")
        w(f"| Ordre sélectionné ARIMA(p,d,q) | {ar['best_order']} |")
        w(f"| AIC (train) | {ar['aic']} |")
        w(f"| RMSE hold-out | {ar['rmse_holdout']} |")
        w(f"| MAPE hold-out | {ar['mape_holdout']}% |")
        w(f"| Valeurs réelles (hold-out) | {ar['test_values']} |")
        w(f"| Valeurs prévues (hold-out) | {ar['fc_test_values']} |")
        w()
        if ar["forecast"]:
            w("**Prévisions +4 semaines (IC 95%) :**")
            w()
            w("| Horizon | Prévision | IC bas 95% | IC haut 95% |")
            w("|---|---:|---:|---:|")
            for fc in ar["forecast"]:
                w(f"| S+{fc['step']} | {fc['mean']:,} | {fc['ci_low']:,} | {fc['ci_high']:,} |")
        w()

# ─── 3. SÉCURITÉ EMAIL ────────────────────────────────────────────────────────
w("---")
w("## 3. Sécurité Email — Analyse Temporelle")
w()

email_series = [
    ("dmarc_pass","DMARC PASS"), ("dmarc_fail","DMARC FAIL"),
    ("dkim_pass","DKIM PASS"),   ("dkim_fail","DKIM FAIL"),
    ("spf_pass","SPF PASS"),     ("spf_fail","SPF FAIL"),
    ("spam","SPAM"),             ("spoof","SPOOF"),
    ("malicieux","Malicieux"),
]

# Tableau synthétique des séries email
w("### 3.1 Synthèse Tests Statistiques — Email")
w()
w("| Série | Moy. | Médiane | Éc.-type | CV% | Tendance MK | Tau | p-value | Pente OLS | R² | ADF stat. |")
w("|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---|")

for key, lbl in email_series:
    r = RESULTS[key]
    mk  = r["mk"]
    tr  = r["trend"]
    adf = r["adf"]
    # recalculer la série
    series_map = {
        "dmarc_pass": em_dmarc["PASS"], "dmarc_fail": em_dmarc["FAIL"],
        "dkim_pass":  em_dkim["PASS"],  "dkim_fail":  em_dkim["FAIL"],
        "spf_pass":   em_spf["PASS"],   "spf_fail":   em_spf["FAIL"],
        "spam":       em_spam["SPAM"],  "spoof":      em_spoof["SPOOF"],
        "malicieux":  em_malici["MALICIOUS"],
    }
    s = series_map[key].dropna()
    cv = round(s.std()/s.mean()*100, 2) if s.mean() != 0 else np.nan
    icon = {"hausse":"↑","baisse":"↓","neutre":"→"}.get(mk.get("trend",""),"?")
    sig  = stars(mk.get("p_value",1))
    w(f"| **{lbl}** | {s.mean():.3f} | {s.median():.3f} | {s.std():.3f} | {cv} | "
      f"{icon} {mk.get('trend','?')} {sig} | {fmt(mk.get('tau',np.nan),4)} | "
      f"{fmt(mk.get('p_value',np.nan),4)} | {fmt(tr.get('slope',np.nan),5) if tr else 'N/D'} | "
      f"{fmt(tr.get('r2',np.nan),4) if tr else 'N/D'} | "
      f"{adf.get('stationnaire','N/D')} |")
w()

# Séries hebdomadaires SPAM et SPOOF (valeurs brutes)
w("### 3.2 Valeurs Hebdomadaires : Spam et Spoofing")
w()
w("| Semaine | Date | SPAM % | SPOOF % | Malicieux % |")
w("|---:|---|---:|---:|---:|")
for i, (d, sp, spo, mal) in enumerate(zip(
    em_spam["date"], em_spam["SPAM"], em_spoof["SPOOF"], em_malici["MALICIOUS"]), 1):
    w(f"| S{i:02d} | {str(d)[:10]} | {sp:.3f} | {spo:.3f} | {mal:.3f} |")
w()

# Séries hebdomadaires DMARC/DKIM/SPF PASS
w("### 3.3 Valeurs Hebdomadaires : DMARC / DKIM / SPF")
w()
w("| Semaine | Date | DMARC PASS | DMARC FAIL | DKIM PASS | DKIM FAIL | SPF PASS | SPF FAIL |")
w("|---:|---|---:|---:|---:|---:|---:|---:|")
for i, (d, dp, df_, kp, kf, sp, sf) in enumerate(zip(
    em_dmarc["date"], em_dmarc["PASS"], em_dmarc["FAIL"],
    em_dkim["PASS"], em_dkim["FAIL"],
    em_spf["PASS"], em_spf["FAIL"]), 1):
    w(f"| S{i:02d} | {str(d)[:10]} | {dp:.3f} | {df_:.3f} | {kp:.3f} | {kf:.3f} | {sp:.3f} | {sf:.3f} |")
w()

# STL Email
w("### 3.4 Décomposition STL Email (période = 4 semaines)")
w()
w("| Série | Var. Tendance | Pente Tendance | Amplitude Saisonnière | Var. Saisonnière | Écart Résidus |")
w("|---|---:|---:|---:|---:|---:|")
for key, lbl in email_series:
    stl = RESULTS[key]["stl"]
    if stl and "error" not in stl:
        w(f"| {lbl} | {stl['trend_var_pct']}% | {fmt(stl['trend_slope'],5)} | "
          f"{fmt(stl['seasonal_amp'],4)} | {stl['seasonal_var_pct']}% | {fmt(stl['resid_std'],4)} |")
w()

# Anomalies email
w("### 3.5 Anomalies Email (|Z| ≥ 2,5)")
w()
for key, lbl in email_series:
    anom = RESULTS[key]["anomalies"]
    if anom:
        w(f"**{lbl} :**")
        w()
        w("| Date | Valeur | Z-score | Type |")
        w("|---|---:|---:|---|")
        for a in anom:
            w(f"| {a['date']} | {a['valeur']} | {a['z_score']} | **{a['direction']}** |")
        w()
w("_Séries sans anomalies : non affichées._")
w()

# ─── 4. ATTAQUES L3 ───────────────────────────────────────────────────────────
w("---")
w("## 4. Attaques L3 — Analyse Temporelle (52 semaines)")
w()

l3_series_map = {
    "l3_udp":  (l3_proto["UDP"],          l3_proto["date"],  "UDP"),
    "l3_tcp":  (l3_proto["TCP"],          l3_proto["date"],  "TCP"),
    "l3_mega": (l3_bit["OVER_100_GBPS"],  l3_bit["date"],    ">100 Gbps"),
    "l3_small":(l3_bit["UNDER_500_MBPS"], l3_bit["date"],    "<500 Mbps"),
    "l3_ipv4": (l3_ip["IPv4"],            l3_ip["date"],     "IPv4"),
}

w("### 4.1 Synthèse Tests Statistiques — L3")
w()
w("| Variable | Moy. | Médiane | CV% | Tendance MK | Tau | p-value | R² OLS | ADF stat. |")
w("|---|---:|---:|---:|---|---:|---:|---:|---|")
for key in ["l3_udp","l3_tcp","l3_mega","l3_small","l3_ipv4"]:
    serie, dates, lbl = l3_series_map[key]
    r  = RESULTS[key]
    mk = r["mk"]
    tr = r["trend"]
    adf= r["adf"]
    s  = serie.dropna()
    cv = round(s.std()/s.mean()*100,2) if s.mean() != 0 else np.nan
    icon = {"hausse":"↑","baisse":"↓","neutre":"→"}.get(mk.get("trend",""),"?")
    w(f"| **{lbl}** | {s.mean():.3f} | {s.median():.3f} | {cv} | "
      f"{icon} {mk.get('trend','?')} {stars(mk.get('p_value',1))} | "
      f"{fmt(mk.get('tau',np.nan),4)} | {fmt(mk.get('p_value',np.nan),4)} | "
      f"{fmt(tr.get('r2',np.nan),4) if tr else 'N/D'} | {adf.get('stationnaire','N/D')} |")
w()

w("### 4.2 Valeurs Hebdomadaires L3 (protocoles)")
w()
w("| S | Date | UDP% | TCP% | GRE% | ICMP% | <500Mbps% | >100Gbps% | IPv4% | IPv6% |")
w("|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|")
for i, row in l3_proto.iterrows():
    d  = str(row["date"])[:10]
    udp= row.get("UDP", np.nan)
    tcp= row.get("TCP", np.nan)
    gre= row.get("GRE", np.nan)
    icmp=row.get("ICMP",np.nan)
    small = l3_bit["UNDER_500_MBPS"].iloc[i] if i < len(l3_bit) else np.nan
    mega  = l3_bit["OVER_100_GBPS"].iloc[i]  if i < len(l3_bit) else np.nan
    ipv4  = l3_ip["IPv4"].iloc[i]  if i < len(l3_ip) else np.nan
    ipv6  = l3_ip["IPv6"].iloc[i]  if i < len(l3_ip) else np.nan
    n = i + 1
    w(f"| S{n:02d} | {d} | {udp:.2f} | {tcp:.2f} | {gre:.3f} | {icmp:.3f} | {small:.2f} | {mega:.4f} | {ipv4:.3f} | {ipv6:.3f} |")
w()

# ─── 5. ATTAQUES L7 ───────────────────────────────────────────────────────────
w("---")
w("## 5. Attaques L7 — Analyse Temporelle (85 jours)")
w()

w("### 5.1 Valeurs Journalières — Méthodes HTTP d'Attaque")
w()
method_cols = [c for c in ["GET","POST","HEAD","OPTIONS","PATCH","DELETE","PUT"] if c in l7_method.columns]
header = "| Jour | Date | " + " | ".join(f"{c}%" for c in method_cols) + " |"
sep    = "|---:|---|" + "".join("---:|" for _ in method_cols)
w(header); w(sep)
for i, row in l7_method.iterrows():
    vals_str = " | ".join(f"{row[c]:.3f}" if not pd.isna(row.get(c)) else "N/D" for c in method_cols)
    w(f"| J{i+1:02d} | {str(row['date'])[:10]} | {vals_str} |")
w()

w("### 5.2 Profil Jour de la Semaine — Méthodes HTTP L7")
w()
w("| Méthode | Lundi | Mardi | Mercredi | Jeudi | Vendredi | Samedi | Dimanche | Amplitude |")
w("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
days_order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
for col, profile in wday_method.items():
    vals = [profile.get(d, np.nan) for d in days_order]
    vals_str = " | ".join(f"{v:.4f}" if not np.isnan(v) else "N/D" for v in vals)
    amplitude = round(max(v for v in vals if not np.isnan(v)) - min(v for v in vals if not np.isnan(v)), 4)
    w(f"| **{col}** | {vals_str} | {amplitude} |")
w()

w("### 5.3 Profil Jour de la Semaine — Secteurs Ciblés")
w()
w("| Secteur | Lundi | Mardi | Mercredi | Jeudi | Vendredi | Samedi | Dimanche | Amplitude |")
w("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
for col, profile in wday_vert.items():
    vals = [profile.get(d, np.nan) for d in days_order]
    vals_str = " | ".join(f"{v:.4f}" if not np.isnan(v) else "N/D" for v in vals)
    try:
        amplitude = round(max(v for v in vals if not np.isnan(v)) - min(v for v in vals if not np.isnan(v)), 4)
    except ValueError:
        amplitude = np.nan
    w(f"| {col[:30]} | {vals_str} | {amplitude} |")
w()

w("### 5.4 Anomalies L7 (|Z| ≥ 2,5)")
w()
for lbl, anom in [("GET", anom_l7_get), ("POST", anom_l7_post)]:
    if anom:
        w(f"**Méthode {lbl} :**")
        w()
        w("| Date | Valeur % | Z-score | Type |")
        w("|---|---:|---:|---|")
        for a in anom:
            w(f"| {a['date']} | {a['valeur']} | {a['z_score']} | **{a['direction']}** |")
        w()
w()

w("### 5.5 Tendances Linéaires — Méthodes L7")
w()
w("| Méthode | Pente/jour | R² | p-value | Tendance |")
w("|---|---:|---:|---:|---|")
for col in method_cols:
    if col in l7_method.columns:
        tr = linear_trend(l7_method[col].values)
        if tr:
            icon = {"hausse":"↑","baisse":"↓","neutre":"→"}.get(tr.get("direction",""),"?")
            w(f"| {col} | {fmt(tr.get('slope',np.nan),6)} | {fmt(tr.get('r2',np.nan),4)} | "
              f"{fmt(tr.get('p_value',np.nan),4)} {stars(tr.get('p_value',1))} | {icon} {tr.get('direction','')} |")
w()

# ─── 6. MÉTRIQUES HTTP/IQI GLOBALES ──────────────────────────────────────────
w("---")
w("## 6. Métriques HTTP & IQI — Tendances Hebdomadaires Globales")
w()

http_global_series = [
    ("http_bot",    "Trafic Bot global (%)"),
    ("http_tls13",  "TLS 1.3 global (%)"),
    ("http_h3",     "HTTP/3 global (%)"),
    ("http_ipv6",   "IPv6 global (%)"),
    ("http_mobile", "Mobile global (%)"),
    ("iqi_bw_med",  "BW médiane (Mbps)"),
    ("iqi_dns_med", "Latence DNS médiane (ms)"),
]

w("### 6.1 Synthèse Tests — HTTP & IQI Globaux")
w()
w("| Série | Moy. | Médiane | CV% | Tendance MK | Tau | p-value | R² OLS | ADF stat. |")
w("|---|---:|---:|---:|---|---:|---:|---:|---|")

data_map_global = {
    "http_bot":    http_bot_wk["bot"],
    "http_tls13":  http_tls_wk["TLS 1.3"],
    "http_h3":     http_http_wk["HTTP/3"],
    "http_ipv6":   http_ipv_wk["IPv6"],
    "http_mobile": http_dev_wk["mobile"],
    "iqi_bw_med":  iqi_bw_wk["p50"],
    "iqi_dns_med": iqi_dns_wk["p50"],
}
for key, lbl in http_global_series:
    r   = RESULTS[key]
    mk  = r["mk"]
    tr  = r["trend"]
    adf = r["adf"]
    s   = data_map_global[key].dropna()
    cv  = round(s.std()/s.mean()*100,2) if s.mean() != 0 else np.nan
    icon= {"hausse":"↑","baisse":"↓","neutre":"→"}.get(mk.get("trend",""),"?")
    w(f"| **{lbl}** | {s.mean():.4f} | {s.median():.4f} | {cv} | "
      f"{icon} {mk.get('trend','?')} {stars(mk.get('p_value',1))} | "
      f"{fmt(mk.get('tau',np.nan),4)} | {fmt(mk.get('p_value',np.nan),4)} | "
      f"{fmt(tr.get('r2',np.nan),4) if tr else 'N/D'} | {adf.get('stationnaire','N/D')} |")
w()

w("### 6.2 Valeurs Hebdomadaires — HTTP & IQI Globaux")
w()
w("| S | Date | Bot% | TLS1.3% | HTTP/3% | IPv6% | Mobile% | BW p50 (Mbps) | DNS p50 (ms) |")
w("|---:|---|---:|---:|---:|---:|---:|---:|---:|")
for i, row in http_bot_wk.iterrows():
    d    = str(row["date"])[:10]
    bot  = row.get("bot", np.nan)
    tls  = http_tls_wk["TLS 1.3"].iloc[i]  if i < len(http_tls_wk) else np.nan
    h3   = http_http_wk["HTTP/3"].iloc[i]   if i < len(http_http_wk) else np.nan
    ipv6 = http_ipv_wk["IPv6"].iloc[i]      if i < len(http_ipv_wk) else np.nan
    mob  = http_dev_wk["mobile"].iloc[i]    if i < len(http_dev_wk) else np.nan
    bw   = iqi_bw_wk["p50"].iloc[i]         if i < len(iqi_bw_wk) else np.nan
    dns_ = iqi_dns_wk["p50"].iloc[i]        if i < len(iqi_dns_wk) else np.nan
    n = i + 1
    w(f"| S{n:02d} | {d} | {bot:.3f} | {tls:.3f} | {h3:.3f} | {ipv6:.3f} | {mob:.3f} | {bw:.3f} | {dns_:.3f} |")
w()

# ─── 7. CORRÉLATIONS CROISÉES ─────────────────────────────────────────────────
w("---")
w("## 7. Corrélations Croisées (CCF) entre Séries")
w()
w("> La CCF mesure la corrélation entre deux séries avec un décalage (lag) entre elles.  ")
w("> Un lag positif signifie que X est décalé vers le passé par rapport à Y.")
w()

for title, ccf_data, descr in [
    ("BGP Volume → DNS Qualité", ccf_bgp_dns,
     "X = Volume BGP (t-lag) prédit-il Y = Qualité DNS (t) ?"),
    ("SPAM → SPOOF", ccf_spam_spoof,
     "Le taux de SPAM précède-t-il le taux de SPOOF ?"),
    ("DMARC FAIL → SPAM", ccf_dmarc_spam,
     "Le taux d'échec DMARC précède-t-il l'augmentation du SPAM ?"),
    ("L3 UDP → TCP", ccf_udp_tcp,
     "La part UDP est-elle liée à la part TCP décalée ?"),
    ("TLS 1.3 → HTTP/3", ccf_tls_h3,
     "L'adoption TLS 1.3 précède-t-elle l'adoption HTTP/3 ?"),
]:
    w(f"### {title}")
    w(f"*{descr}*")
    w()
    w("| Lag | CCF | Interprétation |")
    w("|---:|---:|---|")
    for row in ccf_data:
        lag, ccf_val = row["lag"], row["ccf"]
        intpr = ""
        if abs(ccf_val) >= 0.5:
            intpr = "**Forte**"
        elif abs(ccf_val) >= 0.3:
            intpr = "Modérée"
        else:
            intpr = "Faible"
        if lag == 0:
            intpr += " (synchrone)"
        elif lag < 0:
            intpr += f" (X décalé -{abs(lag)} période[s])"
        else:
            intpr += f" (Y décalé +{lag} période[s])"
        w(f"| {lag:+d} | {ccf_val:.4f} | {intpr} |")
    w()

# ─── 8. TEST DE GRANGER ────────────────────────────────────────────────────────
w("---")
w("## 8. Test de Causalité de Granger")
w()
w("> H0 : X ne cause pas Y au sens de Granger. Si p < 0,05 : on rejette H0 → X contient de l'information prédictive sur Y.")
w()

for title, gr_data, descr in [
    ("BGP Volume → DNS Qualité", granger_bgp_dns,
     "Le volume BGP (t-k) aide-t-il à prévoir la qualité DNS (t) ?"),
    ("SPAM → SPOOF",             granger_spam_spoof,
     "Le taux de SPAM (t-k) aide-t-il à prévoir le SPOOF (t) ?"),
    ("DMARC FAIL → SPAM",        granger_dmarc_spam,
     "Le taux d'échec DMARC (t-k) aide-t-il à prévoir le SPAM (t) ?"),
]:
    w(f"### {title}")
    w(f"*{descr}*")
    w()
    if "error" in gr_data:
        w(f"_Erreur : {gr_data['error']}_")
    else:
        w("| Lag | p-value F-test | p-value Chi2 | Résultat |")
        w("|---:|---:|---:|---|")
        for lag, res in gr_data.items():
            if isinstance(res, dict):
                sig = "**Rejet H0** (causalité détectée)" if res["significant"] else "Non significatif"
                w(f"| {lag} | {res['p_ftest']} {stars(res['p_ftest'])} | "
                  f"{res['p_chi2']} {stars(res['p_chi2'])} | {sig} |")
    w()

# ─── 9. ARIMA — TOUTES SÉRIES ─────────────────────────────────────────────────
w("---")
w("## 9. Modélisation ARIMA — Récapitulatif Toutes Séries")
w()
w("| Série | N | Ordre ARIMA | AIC | RMSE hold-out | MAPE hold-out |")
w("|---|---:|---|---:|---:|---:|")
for key, serie, dates, label, period in SERIES_CATALOGUE:
    ar = RESULTS[key]["arima"]
    if ar:
        w(f"| {label} | {ar['train_n']+ar['holdout_n']} | {ar['best_order']} | "
          f"{ar['aic']} | {ar['rmse_holdout']} | {ar['mape_holdout']}% |")
    else:
        w(f"| {label} | — | N/D | — | — | — |")
w()

# ─── 10. SYNTHÈSE ─────────────────────────────────────────────────────────────
w("---")
w("## 10. Synthèse — Findings Temporels Clés")
w()

w("### 10.1 Tendances Significatives")
w()
w("| Série | Trend | Tau MK | R² OLS | Interprétation |")
w("|---|---|---:|---:|---|")
for key, serie, dates, label, period in SERIES_CATALOGUE:
    r  = RESULTS[key]
    mk = r["mk"]
    tr = r["trend"]
    if mk.get("p_value", 1) < 0.05:
        icon = "↑ Hausse" if mk["trend"] == "hausse" else "↓ Baisse"
        r2   = fmt(tr.get("r2", np.nan), 4) if tr else "N/D"
        tau  = fmt(mk.get("tau", np.nan), 4)
        sig  = stars(mk.get("p_value", 1))
        w(f"| {label} | **{icon}** {sig} | {tau} | {r2} | — |")
w()

w("### 10.2 Stationnarité")
w()
w("| Série | Stationnaire | ADF stat | p-value | Conclusion |")
w("|---|---|---:|---:|---|")
for key, serie, dates, label, period in SERIES_CATALOGUE:
    adf = RESULTS[key]["adf"]
    stat = adf.get("stationnaire","N/D")
    icon = "✅" if stat == "Oui" else ("⚠️" if stat == "Non" else "?")
    w(f"| {label} | {icon} {stat} | {fmt(adf.get('adf_stat',np.nan),4)} | "
      f"{fmt(adf.get('p_value',np.nan),4)} {stars(adf.get('p_value',1))} | "
      f"{'Pas de racine unitaire' if stat=='Oui' else 'Racine unitaire détectée — différenciation nécessaire'} |")
w()

w("### 10.3 Anomalies Notables (toutes séries)")
w()
w("| Série | Date | Z-score | Type | Impact potentiel |")
w("|---|---|---:|---|---|")
for key, serie, dates, label, period in SERIES_CATALOGUE:
    for a in RESULTS[key]["anomalies"]:
        w(f"| {label} | {a['date']} | {a['z_score']} | **{a['direction']}** | À investiguer |")
w()

# ─── PIED DE PAGE ─────────────────────────────────────────────────────────────
w("---")
w(f"*Rapport généré automatiquement par `phase_C_temporel.py` le {NOW}.*  ")
w(f"*Méthodes : Mann-Kendall, ADF, OLS, STL (statsmodels), ARIMA, CCF, Granger.*  ")
w(f"*Prochaine étape : Phase D — Analyse géographique (rankings pays, choroplèthes).*")

# ─── ÉCRITURE ─────────────────────────────────────────────────────────────────
report_path = BASE / "rapport_phase_C.md"
with open(report_path, "w", encoding="utf-8") as f:
    f.write("\n".join(R))

print(f"\nRapport ecrit : {report_path}")
print(f"Taille : {round(report_path.stat().st_size / 1024, 1)} Ko")
print(f"Lignes : {len(R)}")
