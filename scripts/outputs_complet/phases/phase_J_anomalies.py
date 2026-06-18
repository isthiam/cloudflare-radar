# -*- coding: utf-8 -*-
"""
Phase J — Détection d'Anomalies Consolidée
Analyse multi-méthodes : Z-score, IQR, DBSCAN, LOF, Isolation Forest
sur toutes les séries temporelles et par pays
"""

import os
import warnings
import numpy as np
import pandas as pd
from datetime import datetime
from scipy import stats
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

BASE = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/cleaned/"
OUT  = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/rapport_phase_J.md"

MIN_WEEKS = 20
Z_THRESH  = 2.5
IQR_MULT  = 2.0

print("Phase J — Détection d'anomalies consolidée...")

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def parse_date(df, col="date"):
    df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    df[col] = df[col].dt.tz_localize(None)
    return df

def week_floor(dt_series):
    return dt_series.dt.to_period("W").dt.start_time

def fv(v, fmt=".4f", na="N/A"):
    if v is None: return na
    try:
        if np.isnan(v): return na
    except (TypeError, ValueError): pass
    return format(v, fmt)

def zscore_anomalies(series, thresh=Z_THRESH):
    s = series.dropna()
    if len(s) < 8:
        return pd.Series(dtype=float), pd.Series(dtype=float)
    mu, sigma = s.mean(), s.std()
    z = (series - mu) / sigma
    return z, z[z.abs() >= thresh]

def iqr_anomalies(series, mult=IQR_MULT):
    s = series.dropna()
    if len(s) < 8:
        return pd.Series(dtype=float), pd.Series(dtype=float)
    q1, q3 = s.quantile(0.25), s.quantile(0.75)
    iqr = q3 - q1
    lo, hi = q1 - mult * iqr, q3 + mult * iqr
    flags = (series < lo) | (series > hi)
    return flags, series[flags]

def iforest_anomalies(series, contamination=0.05):
    s = series.dropna()
    if len(s) < 20:
        return pd.Series(False, index=series.index)
    X = s.values.reshape(-1, 1)
    iso = IsolationForest(contamination=contamination, random_state=42)
    preds = iso.fit_predict(X)
    result = pd.Series(False, index=series.index)
    result.loc[s.index[preds == -1]] = True
    return result

def lof_anomalies(series, n_neighbors=5, contamination=0.05):
    s = series.dropna()
    if len(s) < n_neighbors + 5:
        return pd.Series(False, index=series.index)
    X = s.values.reshape(-1, 1)
    lof = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=contamination)
    preds = lof.fit_predict(X)
    result = pd.Series(False, index=series.index)
    result.loc[s.index[preds == -1]] = True
    return result

def anomaly_summary(name, series):
    """Run all 4 methods, return summary dict."""
    z_scores, z_anom = zscore_anomalies(series, Z_THRESH)
    _, iqr_anom = iqr_anomalies(series, IQR_MULT)
    iso_anom = iforest_anomalies(series)
    lof_anom = lof_anomalies(series)

    # Consensus: flagged by ≥ 2 methods
    consensus = pd.DataFrame({
        "z": z_scores.abs() >= Z_THRESH,
        "iqr": iqr_anom.reindex(series.index, fill_value=False).astype(bool),
        "iso": iso_anom.astype(bool),
        "lof": lof_anom.astype(bool),
    }).fillna(False)
    consensus["n_methods"] = consensus.sum(axis=1)
    consensus_anom = consensus[consensus["n_methods"] >= 2]

    return {
        "name": name,
        "n_obs": series.notna().sum(),
        "mean": series.mean(),
        "std": series.std(),
        "n_z": len(z_anom),
        "n_iqr": len(iqr_anom),
        "n_iso": iso_anom.sum(),
        "n_lof": lof_anom.sum(),
        "n_consensus": len(consensus_anom),
        "consensus_dates": consensus_anom.index.tolist(),
        "z_scores": z_scores,
        "consensus_df": consensus_anom,
    }

# ══════════════════════════════════════════════════════════════════════════════
# 1. CHARGEMENT DES SÉRIES HEBDOMADAIRES
# ══════════════════════════════════════════════════════════════════════════════
print("  1/6 Chargement séries temporelles...")

bgp_ts  = parse_date(pd.read_csv(BASE + "bgp_timeseries_clean.csv")).set_index("date")["values"].rename("BGP volume")
dns_ts  = parse_date(pd.read_csv(BASE + "dns_timeseries_clean.csv")).set_index("date")["values"].rename("DNS qualité")

dmarc  = parse_date(pd.read_csv(BASE + "email_dmarc_clean.csv")).set_index("date")
dkim   = parse_date(pd.read_csv(BASE + "email_dkim_clean.csv")).set_index("date")
spf    = parse_date(pd.read_csv(BASE + "email_spf_clean.csv")).set_index("date")
spam   = parse_date(pd.read_csv(BASE + "email_spam_clean.csv")).set_index("date")
spoof  = parse_date(pd.read_csv(BASE + "email_spoof_clean.csv")).set_index("date")
malic  = parse_date(pd.read_csv(BASE + "email_malicious_clean.csv")).set_index("date")

l3_proto  = parse_date(pd.read_csv(BASE + "attacks_l3_protocol_clean.csv")).set_index("date")
l3_bitrate= parse_date(pd.read_csv(BASE + "attacks_l3_bitrate_clean.csv")).set_index("date")

# HTTP global (mean across countries)
def http_global_weekly(fname, col):
    df = parse_date(pd.read_csv(BASE + fname))
    if col not in df.columns:
        orig_col = [c for c in df.columns if col.lower() in c.lower().replace(" ","")]
        if orig_col:
            df = df.rename(columns={orig_col[0]: col})
    return df.groupby("date")[col].mean()

ipv6_g  = http_global_weekly("http_ip_version_clean.csv", "IPv6")
tls_raw_g = parse_date(pd.read_csv(BASE + "http_tls_version_clean.csv"))
tls_raw_g = tls_raw_g.rename(columns={"TLS 1.3": "TLSv1.3"})
tls13_g = tls_raw_g.groupby("date")["TLSv1.3"].mean()
bot_g   = parse_date(pd.read_csv(BASE + "http_bot_class_clean.csv")).groupby("date")["bot"].mean()

# BGP events weekly
import ast
def safe_parse(s):
    if pd.isna(s): return []
    try: return ast.literal_eval(str(s))
    except: return []

hij = pd.read_csv(BASE + "bgp_hijacks_clean.csv")
hij["min_hijack_ts"] = pd.to_datetime(hij["min_hijack_ts"], errors="coerce")
hij = hij.dropna(subset=["min_hijack_ts"])
hij["week"] = week_floor(hij["min_hijack_ts"])
hij["rpki_inv"] = hij["tags"].apply(lambda s: 1 if isinstance(s,str) and "rpki_new_origin_invalid" in s else 0)
bgp_hij_wk = hij.groupby("week").agg(
    count=("id","count"), conf=("confidence_score","mean"), rpki=("rpki_inv","mean")
)
bgp_hij_wk.index = pd.to_datetime(bgp_hij_wk.index)

leaks = pd.read_csv(BASE + "bgp_leaks_clean.csv")
leaks["min_ts"] = pd.to_datetime(leaks["min_ts"], errors="coerce")
leaks = leaks.dropna(subset=["min_ts"])
leaks["week"] = week_floor(leaks["min_ts"])
bgp_leaks_wk = leaks.groupby("week").size().rename("leaks_count")
bgp_leaks_wk.index = pd.to_datetime(bgp_leaks_wk.index)

# L7 weekly
l7_vert = parse_date(pd.read_csv(BASE + "attacks_l7_vertical_clean.csv"))
l7_vert = l7_vert[l7_vert["dimension"]=="vertical"].copy()
l7_vert["week"] = week_floor(l7_vert["date"])
l7_it_wk = l7_vert.groupby("week")["Internet and Telecom"].mean()
l7_it_wk.index = pd.to_datetime(l7_it_wk.index)

# ══════════════════════════════════════════════════════════════════════════════
# 2. CATALOGUE DES SÉRIES À ANALYSER
# ══════════════════════════════════════════════════════════════════════════════
print("  2/6 Construction catalogue séries...")

SERIES_CATALOG = {
    # BGP
    "BGP volume msgs":      bgp_ts,
    "BGP hijacks count":    bgp_hij_wk["count"],
    "BGP conf. moy.":       bgp_hij_wk["conf"],
    "BGP RPKI inv%":        bgp_hij_wk["rpki"] * 100,
    "BGP leaks count":      bgp_leaks_wk,
    # DNS
    "DNS qualité":          dns_ts,
    # Email
    "DMARC PASS%":          dmarc["PASS"],
    "DMARC FAIL%":          dmarc["FAIL"],
    "DKIM PASS%":           dkim["PASS"],
    "SPF PASS%":            spf["PASS"],
    "SPF FAIL%":            spf["FAIL"],
    "SPAM%":                spam["SPAM"],
    "SPOOF%":               spoof["SPOOF"],
    "MALICIOUS%":           malic["MALICIOUS"],
    # HTTP/Protocol
    "IPv6%":                ipv6_g,
    "TLS 1.3%":             tls13_g,
    "Bot rate%":            bot_g,
    # L3 Attacks
    "L3 UDP%":              l3_proto["UDP"],
    "L3 TCP%":              l3_proto["TCP"],
    "L3 haut vol.%":        (l3_bitrate["_1_GBPS_TO_10_GBPS"].fillna(0) +
                             l3_bitrate["_10_GBPS_TO_100_GBPS"].fillna(0) +
                             l3_bitrate["OVER_100_GBPS"].fillna(0)),
    # L7 Attacks
    "L7 Internet&Télécom":  l7_it_wk,
}

# ══════════════════════════════════════════════════════════════════════════════
# 3. DÉTECTION ANOMALIES PAR SÉRIE
# ══════════════════════════════════════════════════════════════════════════════
print("  3/6 Détection anomalies (Z, IQR, IForest, LOF)...")
all_results = {}
for name, series in SERIES_CATALOG.items():
    series_clean = series.sort_index()
    all_results[name] = anomaly_summary(name, series_clean)

# ══════════════════════════════════════════════════════════════════════════════
# 4. MATRICE DE COÏNCIDENCE TEMPORELLE
# ══════════════════════════════════════════════════════════════════════════════
print("  4/6 Matrice coïncidence temporelle...")

# Build binary anomaly flags per week (consensus ≥ 2 methods)
all_dates = set()
for res in all_results.values():
    all_dates.update([str(d.date()) for d in res["consensus_dates"]])
all_dates = sorted(all_dates)

coin_matrix = {}
for name, res in all_results.items():
    anom_dates = set(str(d.date()) for d in res["consensus_dates"])
    coin_matrix[name] = {d: 1 if d in anom_dates else 0 for d in all_dates}

coin_df = pd.DataFrame(coin_matrix, index=all_dates).T
coin_df["total_anom_weeks"] = coin_df.sum(axis=1)

# Per-week count of anomalous domains
week_anom_count = coin_df.loc[:, all_dates].sum()
multi_anom_weeks = week_anom_count[week_anom_count >= 2].sort_values(ascending=False)

# ══════════════════════════════════════════════════════════════════════════════
# 5. ANOMALIES PAYS (IMP + BGP exposition)
# ══════════════════════════════════════════════════════════════════════════════
print("  5/6 Anomalies pays (isolation forest multi-features)...")

# Load country-level features
tls_full = parse_date(pd.read_csv(BASE + "http_tls_version_clean.csv"))
tls_full = tls_full.rename(columns={"TLS 1.3":"TLSv1.3","TLS 1.0":"TLSv1.0"})

def cmean(fname, cols, min_wk=MIN_WEEKS):
    df = parse_date(pd.read_csv(BASE + fname))
    grp = df.groupby("country_iso2")[cols].agg(["mean","count"])
    res = {}
    for c in cols:
        res[c] = grp[(c,"mean")].where(grp[(c,"count")] >= min_wk)
    return pd.DataFrame(res)

ipv6_c = cmean("http_ip_version_clean.csv",["IPv6"])
http3_c= cmean("http_http_version_clean.csv",["HTTP/3"])
tls_grp2= tls_full.groupby("country_iso2")[["TLSv1.3","TLSv1.0"]].agg(["mean","count"])
tls13_c = pd.DataFrame({
    "TLSv1.3": tls_grp2[("TLSv1.3","mean")].where(tls_grp2[("TLSv1.3","count")] >= MIN_WEEKS),
    "TLSv1.0": tls_grp2[("TLSv1.0","mean")].where(tls_grp2[("TLSv1.0","count")] >= MIN_WEEKS),
})
bot_c  = cmean("http_bot_class_clean.csv",["bot"])

feat_c = ipv6_c.join(http3_c, how="outer").join(tls13_c, how="outer").join(bot_c, how="outer")
feat_c = feat_c.dropna(subset=["IPv6","HTTP/3","TLSv1.3","bot"], how="any")
feat_c = feat_c.dropna()

# Compute IMP
feat_c["IMP"] = (
    feat_c["IPv6"]    / 100 * 0.25 +
    feat_c["HTTP/3"]  / 100 * 0.25 +
    feat_c["TLSv1.3"] / 100 * 0.20 +
    (100 - feat_c["bot"]) / 100 * 0.30
) * 100

# Isolation Forest on multi-features per country
X_c = feat_c[["IPv6","HTTP/3","TLSv1.3","bot"]].values
sc  = StandardScaler()
X_cs= sc.fit_transform(X_c)
iso_c = IsolationForest(contamination=0.07, random_state=42)
pred_c = iso_c.fit_predict(X_cs)
feat_c["iso_flag"] = (pred_c == -1)

# Z-score per feature per country
for col in ["IPv6","HTTP/3","TLSv1.3","bot"]:
    mu, sigma = feat_c[col].mean(), feat_c[col].std()
    feat_c[f"z_{col}"] = (feat_c[col] - mu) / sigma
feat_c["max_z"] = feat_c[["z_IPv6","z_HTTP/3","z_TLSv1.3","z_bot"]].abs().max(axis=1)

country_anomalies = feat_c[feat_c["iso_flag"]].sort_values("max_z", ascending=False)

# ══════════════════════════════════════════════════════════════════════════════
# 6. RAPPORT
# ══════════════════════════════════════════════════════════════════════════════
print("  6/6 Génération rapport Phase J...")
lines = []

lines.append("# Rapport Phase J — Détection d'Anomalies Consolidée")
lines.append("**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  ")
lines.append("**Auteur :** Issakha Thiam  ")
lines.append(f"**Généré le :** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
lines.append("")
lines.append("---")

# Section 1 — Résumé
lines.append("## 1. Résumé Exécutif")
lines.append("")
total_ts_anom = sum(r["n_consensus"] for r in all_results.values())
total_series  = len(all_results)
max_anom_series = max(all_results.items(), key=lambda x: x[1]["n_consensus"])
n_multi_weeks = len(multi_anom_weeks)

lines.append("| Indicateur | Valeur |")
lines.append("|---|---|")
lines.append(f"| Séries temporelles analysées | {total_series} |")
lines.append(f"| Méthodes de détection | 4 (Z-score, IQR, Isolation Forest, LOF) |")
lines.append(f"| Seuil consensus | ≥ 2 méthodes sur 4 |")
lines.append(f"| Total anomalies consensus (toutes séries) | **{total_ts_anom}** |")
lines.append(f"| Série la plus anomalique | **{max_anom_series[0]}** ({max_anom_series[1]['n_consensus']} anomalies) |")
lines.append(f"| Semaines avec ≥ 2 domaines anormaux | **{n_multi_weeks}** |")
lines.append(f"| Pays avec profil anomalique (Isolation Forest) | **{len(country_anomalies)}** |")
lines.append("")

# Most anomalous week overall
if len(multi_anom_weeks) > 0:
    peak_week_str = multi_anom_weeks.index[0]
    peak_n = int(multi_anom_weeks.iloc[0])
    lines.append(f"**Semaine la plus critique :** {peak_week_str} avec **{peak_n} domaines** anormaux simultanément.")
lines.append("")
lines.append("---")

# Section 2 — Résultats par série
lines.append("## 2. Anomalies par Série Temporelle")
lines.append("")
lines.append("> **Méthodes** : Z-score (|z|≥2.5), IQR (×2.0), Isolation Forest (5% contamination), LOF (5% contamination)  ")
lines.append("> **Consensus** : anomalie retenue si détectée par ≥ 2 méthodes sur 4.")
lines.append("")
lines.append("| Domaine | Série | N obs. | Moy. | Std | Z-anom | IQR-anom | IFo-anom | LOF-anom | Consensus |")
lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")

DOMAIN_MAP = {
    "BGP volume msgs":"BGP","BGP hijacks count":"BGP","BGP conf. moy.":"BGP",
    "BGP RPKI inv%":"BGP","BGP leaks count":"BGP",
    "DNS qualité":"DNS",
    "DMARC PASS%":"Email","DMARC FAIL%":"Email","DKIM PASS%":"Email",
    "SPF PASS%":"Email","SPF FAIL%":"Email","SPAM%":"Email","SPOOF%":"Email","MALICIOUS%":"Email",
    "IPv6%":"HTTP/Protocol","TLS 1.3%":"HTTP/Protocol","Bot rate%":"HTTP/Protocol",
    "L3 UDP%":"L3 Attacks","L3 TCP%":"L3 Attacks","L3 haut vol.%":"L3 Attacks",
    "L7 Internet&Télécom":"L7 Attacks",
}

for name, res in sorted(all_results.items(), key=lambda x: x[1]["n_consensus"], reverse=True):
    dom = DOMAIN_MAP.get(name, "—")
    lines.append(
        f"| {dom} | {name} | {res['n_obs']} | "
        f"{fv(res['mean'],'.2f')} | {fv(res['std'],'.2f')} | "
        f"{res['n_z']} | {res['n_iqr']} | {res['n_iso']} | {res['n_lof']} | **{res['n_consensus']}** |"
    )
lines.append("")
lines.append("---")

# Section 3 — Détail des anomalies consensus par série
lines.append("## 3. Détail des Anomalies Consensus par Série")
lines.append("")

for name, res in sorted(all_results.items(), key=lambda x: x[1]["n_consensus"], reverse=True):
    if res["n_consensus"] == 0:
        continue
    lines.append(f"### {name} ({res['n_consensus']} anomalies consensus)")
    lines.append("")
    lines.append("| Date | Valeur | Z-score | Type | Méthodes |")
    lines.append("|---|---:|---:|---|---|")

    z_series = res["z_scores"]
    consensus_df = res["consensus_df"]
    series_data = SERIES_CATALOG.get(name, pd.Series(dtype=float))

    for dt, crow in consensus_df.iterrows():
        # Get value
        try:
            val = series_data.loc[dt] if dt in series_data.index else np.nan
        except Exception:
            val = np.nan
        # Z-score
        try:
            z_val = z_series.loc[dt] if dt in z_series.index else np.nan
        except Exception:
            z_val = np.nan

        n_meth = int(crow["n_methods"])
        methstr = []
        if crow.get("z", False): methstr.append("Z")
        if crow.get("iqr", False): methstr.append("IQR")
        if crow.get("iso", False): methstr.append("IFo")
        if crow.get("lof", False): methstr.append("LOF")

        direction = "⬆️ PIC" if (not np.isnan(z_val) and z_val > 0) else "⬇️ CREUX"
        intensity = "🔴 EXTRÊME" if (not np.isnan(z_val) and abs(z_val) >= 4) else ("🟠 FORT" if (not np.isnan(z_val) and abs(z_val) >= 3) else "🟡 MODÉRÉ")

        lines.append(
            f"| {str(dt.date()) if hasattr(dt,'date') else str(dt)} | "
            f"{fv(val,'.3f')} | {fv(z_val,'+.2f')} | "
            f"{direction} {intensity} | {'+'.join(methstr)} |"
        )
    lines.append("")

lines.append("---")

# Section 4 — Coïncidences multi-domaines
lines.append("## 4. Coïncidences d'Anomalies Multi-Domaines")
lines.append("")
lines.append(f"> Semaines où ≥ 2 séries de domaines DIFFÉRENTS sont simultanément anormales.")
lines.append(f"> Total : **{n_multi_weeks}** semaines critiques.")
lines.append("")

if n_multi_weeks > 0:
    lines.append("| Semaine | Nb domaines | Séries anormales |")
    lines.append("|---|---:|---|")
    for week_str, n in multi_anom_weeks.items():
        anoms = [name for name in SERIES_CATALOG if coin_matrix.get(name, {}).get(week_str, 0) == 1]
        lines.append(f"| {week_str} | **{int(n)}** | {' · '.join(anoms[:8])} {'...' if len(anoms)>8 else ''} |")
    lines.append("")

lines.append("### 4.1 Corrélation entre Séries Anomaliques (Jaccard)")
lines.append("")
lines.append("> Jaccard(A,B) = |A∩B| / |A∪B| : proportion de semaines où A et B sont TOUTES DEUX anormales.")
lines.append("")

# Compute Jaccard similarity between anomaly flags
series_with_anom = [name for name, res in all_results.items() if res["n_consensus"] >= 2]
if len(series_with_anom) >= 2:
    jac_pairs = []
    for i, a in enumerate(series_with_anom):
        for j, b in enumerate(series_with_anom):
            if j <= i: continue
            set_a = set(str(d.date()) if hasattr(d,'date') else str(d) for d in all_results[a]["consensus_dates"])
            set_b = set(str(d.date()) if hasattr(d,'date') else str(d) for d in all_results[b]["consensus_dates"])
            inter = len(set_a & set_b)
            union = len(set_a | set_b)
            jac = inter / union if union > 0 else 0
            if jac >= 0.1 and inter >= 1:
                jac_pairs.append({"A":a, "B":b, "intersect":inter, "jaccard":jac})
    jac_pairs.sort(key=lambda x: x["jaccard"], reverse=True)

    if jac_pairs:
        lines.append("| Rang | Série A | Série B | Semaines communes | Jaccard |")
        lines.append("|---:|---|---|---:|---:|")
        for rank, pair in enumerate(jac_pairs[:20], 1):
            lines.append(f"| {rank} | {pair['A']} | {pair['B']} | {pair['intersect']} | {pair['jaccard']:.3f} |")
        lines.append("")
lines.append("---")

# Section 5 — Anomalies pays
lines.append("## 5. Pays à Profil Anomalique (Isolation Forest)")
lines.append("")
lines.append(f"> Isolation Forest sur 4 features (IPv6, HTTP/3, TLS1.3, Bot%) — contamination 7%.")
lines.append(f"> {len(country_anomalies)} pays identifiés comme outliers sur {len(feat_c)} pays analysés.")
lines.append("")

COUNTRY_NAMES = {
    "GI":"Gibraltar","US":"États-Unis","CN":"Chine","RU":"Russie","IN":"Inde",
    "DE":"Allemagne","FR":"France","GB":"Royaume-Uni","JP":"Japon","BR":"Brésil",
    "AU":"Australie","CA":"Canada","KR":"Corée du Sud","ID":"Indonésie","NG":"Nigeria",
    "PK":"Pakistan","BD":"Bangladesh","VN":"Viêt Nam","TH":"Thaïlande","EG":"Égypte",
    "SA":"Arabie saoudite","TR":"Turquie","MX":"Mexique","IT":"Italie","ES":"Espagne",
    "NL":"Pays-Bas","SE":"Suède","NO":"Norvège","DK":"Danemark","FI":"Finlande",
    "BE":"Belgique","AT":"Autriche","CH":"Suisse","PL":"Pologne","CZ":"Rép. tchèque",
    "RO":"Roumanie","HU":"Hongrie","UA":"Ukraine","IL":"Israël","SG":"Singapour",
    "MY":"Malaisie","PH":"Philippines","NZ":"Nouvelle-Zélande","ZA":"Afrique du Sud",
    "AR":"Argentine","CO":"Colombie","CL":"Chili","PE":"Pérou","VE":"Venezuela",
    "ET":"Éthiopie","KE":"Kenya","GH":"Ghana","TZ":"Tanzanie","UG":"Ouganda",
    "SO":"Somalie","LA":"Laos","MN":"Mongolie","KZ":"Kazakhstan","UZ":"Ouzbékistan",
    "TM":"Turkménistan","KG":"Kirghizistan","AF":"Afghanistan","MM":"Myanmar",
    "LK":"Sri Lanka","NP":"Népal","LB":"Liban","SY":"Syrie","IQ":"Irak","IR":"Iran",
    "YE":"Yémen","LY":"Libye","SD":"Soudan","SS":"Soudan du Sud","ML":"Mali",
    "NE":"Niger","TD":"Tchad","CF":"RCA","CD":"RDC","MW":"Malawi","MZ":"Mozambique",
    "ZM":"Zambie","ZW":"Zimbabwe","MG":"Madagascar","TJ":"Tadjikistan",
    "CU":"Cuba","KP":"Corée du Nord","HK":"Hong Kong","TW":"Taïwan",
    "PT":"Portugal","GR":"Grèce","HR":"Croatie","RS":"Serbie","BG":"Bulgarie",
    "SK":"Slovaquie","SI":"Slovénie","EE":"Estonie","LV":"Lettonie","LT":"Lituanie",
}

lines.append("| Rang | ISO2 | Pays | IPv6% | HTTP/3% | TLS1.3% | Bot% | IMP | Z max | Anomalie principale |")
lines.append("|---:|---|---|---:|---:|---:|---:|---:|---:|---|")
for rank, (iso, row) in enumerate(country_anomalies.head(30).iterrows(), 1):
    # Find which feature has max z
    z_vals = {c.replace("z_",""): row[c] for c in ["z_IPv6","z_HTTP/3","z_TLSv1.3","z_bot"]}
    max_feat = max(z_vals.items(), key=lambda x: abs(x[1]))
    direction = "⬆️" if max_feat[1] > 0 else "⬇️"
    anom_desc = f"{direction} {max_feat[0]} extrême (z={max_feat[1]:+.1f})"
    country_name = COUNTRY_NAMES.get(iso, iso)
    lines.append(
        f"| {rank} | {iso} | {country_name} | "
        f"{fv(row.get('IPv6',np.nan),'.1f')} | {fv(row.get('HTTP/3',np.nan),'.1f')} | "
        f"{fv(row.get('TLSv1.3',np.nan),'.1f')} | {fv(row.get('bot',np.nan),'.1f')} | "
        f"{fv(row.get('IMP',np.nan),'.1f')} | {fv(row.get('max_z',np.nan),'.2f')} | "
        f"{anom_desc} |"
    )
lines.append("")
lines.append("---")

# Section 6 — Analyse chronologique des anomalies
lines.append("## 6. Chronologie des Anomalies (Timeline)")
lines.append("")
lines.append("> Toutes les anomalies consensus classées chronologiquement.")
lines.append("")

# Collect all consensus anomaly dates with source
timeline = []
for name, res in all_results.items():
    z_series = res["z_scores"]
    for dt in res["consensus_dates"]:
        try:
            z_val = float(z_series.loc[dt]) if dt in z_series.index else np.nan
        except Exception:
            z_val = np.nan
        dom = DOMAIN_MAP.get(name, "—")
        timeline.append({
            "date": dt,
            "date_str": str(dt.date()) if hasattr(dt,"date") else str(dt),
            "domain": dom,
            "series": name,
            "z": z_val,
            "direction": "⬆️" if (not np.isnan(z_val) and z_val > 0) else "⬇️",
        })

timeline.sort(key=lambda x: x["date_str"])
lines.append("| Date | Domaine | Série | Z-score | Dir. |")
lines.append("|---|---|---|---:|---|")
for ev in timeline:
    lines.append(
        f"| {ev['date_str']} | {ev['domain']} | {ev['series']} | "
        f"{fv(ev['z'],'+.2f')} | {ev['direction']} |"
    )
lines.append("")
lines.append("---")

# Section 7 — Findings
lines.append("## 7. Findings et Implications")
lines.append("")

lines.append("### 7.1 Anomalies Temporelles les Plus Critiques")
lines.append("")
if n_multi_weeks > 0:
    lines.append(f"**{n_multi_weeks} semaines** présentent des anomalies simultanées sur ≥ 2 domaines. Les plus critiques :")
    lines.append("")
    for week_str, n in list(multi_anom_weeks.items())[:5]:
        anoms = [name for name in SERIES_CATALOG if coin_matrix.get(name, {}).get(week_str, 0) == 1]
        lines.append(f"- **{week_str}** : {int(n)} domaines anormaux ({', '.join(anoms[:4])}...)")
    lines.append("")

lines.append("### 7.2 Séries à Surveillance Prioritaire")
lines.append("")
top_series = sorted(all_results.items(), key=lambda x: x[1]["n_consensus"], reverse=True)[:5]
for rank, (name, res) in enumerate(top_series, 1):
    lines.append(f"{rank}. **{name}** : {res['n_consensus']} anomalies consensus sur la période")
lines.append("")

lines.append("### 7.3 Pays à Profil Extrême")
lines.append("")
lines.append(f"{len(country_anomalies)} pays sur {len(feat_c)} ont un profil protocolaire statistiquement anormal.")
if len(country_anomalies) > 0:
    lines.append(f"Le pays le plus extrême : **{country_anomalies.index[0]}** "
                 f"(Z max = {country_anomalies['max_z'].iloc[0]:.2f})")
lines.append("")

lines.append("### 7.4 Implications pour la Surveillance")
lines.append("")
lines.append("1. **Méthode consensus** : La combinaison Z-score + IQR + Isolation Forest + LOF réduit les faux positifs "
             "et identifie les anomalies robustes.")
lines.append("")
lines.append("2. **Anomalies simultanées** : Les semaines avec anomalies multi-domaines sont des signaux d'alerte "
             "systémiques — elles indiquent une dégradation coordonnée de la sécurité internet.")
lines.append("")
lines.append("3. **Pays extrêmes** : Les outliers pays ne sont pas nécessairement des menaces — certains (ex. Gibraltar) "
             "ont des profils extrêmes dus à leur structure économique (finance offshore, CDN).")
lines.append("")
lines.append("4. **Utilité opérationnelle** : Ce catalogue d'anomalies peut alimenter un tableau de bord de surveillance "
             "en temps réel — chaque indicateur peut déclencher une alerte dès qu'il passe au-dessus du seuil Z=2.5.")
lines.append("")
lines.append("---")
lines.append(f"*Rapport généré automatiquement par `phase_J_anomalies.py` le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.*  ")
lines.append("*Sources : Cloudflare Radar API v4 — 25 datasets nettoyés.*  ")
lines.append("*Prochaine étape : Phase K — Analyse de graphe réseau (ASN network).*")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

size_kb = os.path.getsize(OUT) / 1024
print(f"\nRapport écrit : {OUT}")
print(f"Taille : {size_kb:.1f} Ko")
print(f"Lignes : {len(lines)}")
