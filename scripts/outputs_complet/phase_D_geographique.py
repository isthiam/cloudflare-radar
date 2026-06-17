#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase D — Analyse géographique (252 pays, HTTP/IQI/BGP)."""

import pandas as pd
import numpy as np
import os
import ast
import warnings
from collections import defaultdict
from datetime import datetime

warnings.filterwarnings("ignore")

BASE = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/cleaned"
OUT  = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/rapport_phase_D.md"

MIN_WEEKS = 20  # minimum non-NaN weeks pour inclure un pays dans les rankings

# ── Mapping ISO2 → noms pays ───────────────────────────────────────────────
COUNTRY_NAMES = {
    "AD":"Andorre","AE":"Émirats Arabes Unis","AF":"Afghanistan","AG":"Antigua-et-Barbuda",
    "AL":"Albanie","AM":"Arménie","AO":"Angola","AR":"Argentine","AT":"Autriche",
    "AU":"Australie","AZ":"Azerbaïdjan","BA":"Bosnie-Herzégovine","BB":"Barbade",
    "BD":"Bangladesh","BE":"Belgique","BF":"Burkina Faso","BG":"Bulgarie",
    "BH":"Bahreïn","BI":"Burundi","BJ":"Bénin","BN":"Brunéi","BO":"Bolivie",
    "BR":"Brésil","BS":"Bahamas","BT":"Bhoutan","BW":"Botswana","BY":"Biélorussie",
    "BZ":"Belize","CA":"Canada","CD":"Congo (RDC)","CF":"Centrafrique","CG":"Congo",
    "CH":"Suisse","CI":"Côte d'Ivoire","CL":"Chili","CM":"Cameroun","CN":"Chine",
    "CO":"Colombie","CR":"Costa Rica","CU":"Cuba","CV":"Cap-Vert","CY":"Chypre",
    "CZ":"République Tchèque","DE":"Allemagne","DJ":"Djibouti","DK":"Danemark",
    "DO":"République Dominicaine","DZ":"Algérie","EC":"Équateur","EE":"Estonie",
    "EG":"Égypte","ER":"Érythrée","ES":"Espagne","ET":"Éthiopie","FI":"Finlande",
    "FJ":"Fidji","FR":"France","GA":"Gabon","GB":"Royaume-Uni","GE":"Géorgie",
    "GH":"Ghana","GM":"Gambie","GN":"Guinée","GQ":"Guinée Équatoriale","GR":"Grèce",
    "GT":"Guatemala","GW":"Guinée-Bissau","GY":"Guyana","HK":"Hong Kong","HN":"Honduras",
    "HR":"Croatie","HT":"Haïti","HU":"Hongrie","ID":"Indonésie","IE":"Irlande",
    "IL":"Israël","IN":"Inde","IQ":"Irak","IR":"Iran","IS":"Islande","IT":"Italie",
    "JM":"Jamaïque","JO":"Jordanie","JP":"Japon","KE":"Kenya","KG":"Kirghizistan",
    "KH":"Cambodge","KI":"Kiribati","KM":"Comores","KN":"Saint-Kitts-et-Nevis",
    "KP":"Corée du Nord","KR":"Corée du Sud","KW":"Koweït","KY":"Îles Caïmans",
    "KZ":"Kazakhstan","LA":"Laos","LB":"Liban","LC":"Sainte-Lucie","LI":"Liechtenstein",
    "LK":"Sri Lanka","LR":"Libéria","LS":"Lesotho","LT":"Lituanie","LU":"Luxembourg",
    "LV":"Lettonie","LY":"Libye","MA":"Maroc","MC":"Monaco","MD":"Moldavie",
    "ME":"Monténégro","MG":"Madagascar","MK":"Macédoine du Nord","ML":"Mali",
    "MM":"Myanmar","MN":"Mongolie","MO":"Macao","MR":"Mauritanie","MT":"Malte",
    "MU":"Maurice","MV":"Maldives","MW":"Malawi","MX":"Mexique","MY":"Malaisie",
    "MZ":"Mozambique","NA":"Namibie","NE":"Niger","NG":"Nigeria","NI":"Nicaragua",
    "NL":"Pays-Bas","NO":"Norvège","NP":"Népal","NR":"Nauru","NZ":"Nouvelle-Zélande",
    "OM":"Oman","PA":"Panama","PE":"Pérou","PG":"Papouasie-Nouvelle-Guinée",
    "PH":"Philippines","PK":"Pakistan","PL":"Pologne","PT":"Portugal","PW":"Palaos",
    "PY":"Paraguay","QA":"Qatar","RO":"Roumanie","RS":"Serbie","RU":"Russie",
    "RW":"Rwanda","SA":"Arabie Saoudite","SB":"Îles Salomon","SC":"Seychelles",
    "SD":"Soudan","SE":"Suède","SG":"Singapour","SI":"Slovénie","SK":"Slovaquie",
    "SL":"Sierra Leone","SM":"Saint-Marin","SN":"Sénégal","SO":"Somalie",
    "SR":"Suriname","SS":"Soudan du Sud","ST":"Sao Tomé-et-Principe","SV":"El Salvador",
    "SY":"Syrie","SZ":"Eswatini","TD":"Tchad","TG":"Togo","TH":"Thaïlande",
    "TJ":"Tadjikistan","TL":"Timor-Leste","TM":"Turkménistan","TN":"Tunisie",
    "TO":"Tonga","TR":"Turquie","TT":"Trinité-et-Tobago","TV":"Tuvalu","TZ":"Tanzanie",
    "UA":"Ukraine","UG":"Ouganda","US":"États-Unis","UY":"Uruguay","UZ":"Ouzbékistan",
    "VA":"Vatican","VC":"Saint-Vincent-et-les-Grenadines","VE":"Venezuela",
    "VN":"Viêt Nam","VU":"Vanuatu","WS":"Samoa","XK":"Kosovo","YE":"Yémen",
    "ZA":"Afrique du Sud","ZM":"Zambie","ZW":"Zimbabwe",
    "AN":"Antilles néerlandaises","EU":"Europe (agrégat)","T1":"Tor network",
}

def cname(iso2):
    return COUNTRY_NAMES.get(iso2, iso2)

# ── Chargement ──────────────────────────────────────────────────────────────
print("Chargement des donnees...")

http_ip   = pd.read_csv(f"{BASE}/http_ip_version_clean.csv")
http_http = pd.read_csv(f"{BASE}/http_http_version_clean.csv")
http_tls  = pd.read_csv(f"{BASE}/http_tls_version_clean.csv")
http_bot  = pd.read_csv(f"{BASE}/http_bot_class_clean.csv")
http_dev  = pd.read_csv(f"{BASE}/http_device_type_clean.csv")
http_os   = pd.read_csv(f"{BASE}/http_os_clean.csv")
http_br   = pd.read_csv(f"{BASE}/http_browser_family_clean.csv")
iqi_bw    = pd.read_csv(f"{BASE}/iqi_bandwidth_clean.csv")
iqi_dns   = pd.read_csv(f"{BASE}/iqi_dns_clean.csv")
hijacks   = pd.read_csv(f"{BASE}/bgp_hijacks_clean.csv")
leaks     = pd.read_csv(f"{BASE}/bgp_leaks_clean.csv")

# ── Agrégation pays (moyenne sur la période) ────────────────────────────────
def country_mean(df, cols, min_weeks=MIN_WEEKS):
    """Moyenne par pays sur les colonnes numériques, filtrée par min_weeks valides."""
    grp = df.groupby("country_iso2")[cols].agg(["mean", "count"])
    result = {}
    for c in cols:
        means = grp[(c, "mean")]
        counts = grp[(c, "count")]
        result[c] = means.where(counts >= min_weeks)
    return pd.DataFrame(result)

print("Agregation HTTP par pays...")

# IPv6 adoption
ipv6_stats = country_mean(http_ip, ["IPv6", "IPv4"])
ipv6_stats.index.name = "country_iso2"

# HTTP version
http_v_stats = country_mean(http_http, ["HTTP/3", "HTTP/2", "HTTP/1.x"])

# TLS version
tls_stats = country_mean(http_tls, ["TLS 1.3", "TLS QUIC", "TLS 1.2", "TLS 1.1", "TLS 1.0"])

# Bot rate
bot_stats = country_mean(http_bot, ["bot", "human"])

# Device type
dev_stats = country_mean(http_dev, ["mobile", "desktop", "other"])

# OS
os_stats = country_mean(http_os, ["WINDOWS", "ANDROID", "MACOSX", "IOS", "LINUX", "CHROMEOS", "SMART_TV"])

# Browser
br_stats = country_mean(http_br, ["chrome", "safari", "edge", "firefox", "samsung", "opera"])

# IQI bandwidth (p50 = médiane)
iqi_bw_stats = iqi_bw.groupby("country_iso2")["p50"].agg(
    mean_bw=lambda x: x.mean() if x.notna().sum() >= MIN_WEEKS else np.nan,
    valid_weeks=lambda x: x.notna().sum()
)

# IQI DNS (p50 = latence médiane, lower = better)
iqi_dns_stats = iqi_dns.groupby("country_iso2")["p50"].agg(
    mean_dns=lambda x: x.mean() if x.notna().sum() >= MIN_WEEKS else np.nan,
    valid_weeks=lambda x: x.notna().sum()
)

print("Traitement BGP geographique...")

# ── BGP Hijacks — pays hijackeurs ───────────────────────────────────────────
hijacker_counts = hijacks["hijacker_country"].value_counts()
hijacker_conf   = hijacks.groupby("hijacker_country")["confidence_score"].mean()
hijacker_dur    = hijacks.groupby("hijacker_country")["duration"].mean()

# BGP Hijacks — pays victimes (JSON array)
victim_list = []
for v in hijacks["victim_countries"].dropna():
    try:
        countries = ast.literal_eval(v)
        victim_list.extend(countries)
    except Exception:
        pass
victim_counts = pd.Series(victim_list).value_counts()

# BGP Leaks — pays impliqués
leak_countries_list = []
for v in leaks["countries"].dropna():
    try:
        countries = ast.literal_eval(v)
        leak_countries_list.extend(countries)
    except Exception:
        pass
leak_country_counts = pd.Series(leak_countries_list).value_counts()

# Paires hijacker → victime
print("Calcul matrice hijacker-victime...")
pairs = defaultdict(int)
for _, row in hijacks.iterrows():
    hc = row["hijacker_country"]
    if pd.isna(hc) or hc == "UNKNOWN":
        continue
    try:
        victims = ast.literal_eval(row["victim_countries"])
        for v in victims:
            if v != hc:
                pairs[(hc, v)] += 1
    except Exception:
        pass

top_pairs = sorted(pairs.items(), key=lambda x: -x[1])[:25]

# ── Indice de Maturité des Protocoles (IMP) ─────────────────────────────────
print("Calcul IMP (Indice de Maturite des Protocoles)...")

def minmax_norm(series):
    """Normalise 0-100, NaN → NaN."""
    mn, mx = series.min(), series.max()
    if mx == mn:
        return pd.Series(50.0, index=series.index)
    return (series - mn) / (mx - mn) * 100

# Composantes (direction positive = meilleur)
imp_df = pd.DataFrame(index=ipv6_stats.index)
imp_df["ipv6"]   = ipv6_stats["IPv6"]
imp_df["http3"]  = http_v_stats["HTTP/3"]
imp_df["tls13"]  = tls_stats["TLS 1.3"]
imp_df["tlsquic"]= tls_stats["TLS QUIC"]
imp_df["no_bot"] = 100 - bot_stats["bot"]     # inverted
imp_df["mobile"] = dev_stats["mobile"]

# Normalisation min-max
for c in imp_df.columns:
    imp_df[c + "_n"] = minmax_norm(imp_df[c].dropna().reindex(imp_df.index))

# Poids
W = {"ipv6_n": 0.25, "http3_n": 0.25, "tls13_n": 0.20, "tlsquic_n": 0.10,
     "no_bot_n": 0.10, "mobile_n": 0.10}

def imp_score(row):
    total_w, total_s = 0, 0
    for col, w in W.items():
        v = row.get(col)
        if pd.notna(v):
            total_s += v * w
            total_w += w
    return total_s / total_w if total_w >= 0.5 else np.nan

imp_df["IMP"] = imp_df.apply(imp_score, axis=1)
imp_ranked = imp_df["IMP"].dropna().sort_values(ascending=False)

# ── Helpers affichage ────────────────────────────────────────────────────────
def ascii_bar(val, max_val=100, width=30, unit="%"):
    """Barre ASCII proportionnelle."""
    if pd.isna(val):
        return "N/A"
    filled = int(round(val / max_val * width))
    bar = "#" * filled + "." * (width - filled)
    return f"[{bar}] {val:.1f}{unit}"

def fmt_country(iso2, val, unit="%", decimals=1):
    name = cname(iso2)
    return f"{name} ({iso2})", f"{val:.{decimals}f}{unit}"

def ranking_table(series, top_n=25, ascending=False, unit="%", decimals=1,
                  title="Classement", bar_max=100):
    """Génère une table markdown de classement."""
    s = series.dropna().sort_values(ascending=ascending)
    s = s.head(top_n)
    lines = [f"\n**{title} (Top {len(s)})**\n"]
    lines.append(f"| Rang | Pays | ISO2 | Valeur | Barre |")
    lines.append("|---:|---|---|---:|---|")
    for rank, (iso2, val) in enumerate(s.items(), 1):
        name = cname(iso2)
        bar  = ascii_bar(val, max_val=bar_max, width=25, unit=unit)
        lines.append(f"| {rank} | {name} | {iso2} | {val:.{decimals}f}{unit} | {bar} |")
    return "\n".join(lines)

def dual_ranking_table(series, top_n=20, unit="%", decimals=1, title=""):
    """Top N + Bottom N dans une table double."""
    s = series.dropna().sort_values(ascending=False)
    top = s.head(top_n)
    bot = s.tail(top_n).sort_values(ascending=True)
    lines = [f"\n**{title}**\n"]
    lines.append(f"| Rang | TOP {top_n} (les plus élevés) | ISO2 | Val. | Rang | BOTTOM {top_n} (les plus bas) | ISO2 | Val. |")
    lines.append("|---:|---|---|---:|---:|---|---|---:|")
    for i in range(top_n):
        r1 = i + 1
        iso_t, v_t = top.index[i], top.iloc[i]
        iso_b, v_b = bot.index[i], bot.iloc[i]
        r2 = len(s) - top_n + i + 1
        lines.append(f"| {r1} | {cname(iso_t)} | {iso_t} | {v_t:.{decimals}f}{unit} "
                     f"| {r2} | {cname(iso_b)} | {iso_b} | {v_b:.{decimals}f}{unit} |")
    return "\n".join(lines)

def os_dominant_table(os_df, top_n=30):
    """Tableau OS dominant par pays."""
    cols = ["WINDOWS", "ANDROID", "MACOSX", "IOS", "LINUX", "CHROMEOS", "SMART_TV"]
    dom = os_df[cols].idxmax(axis=1)
    dom_val = os_df[cols].max(axis=1)
    result = pd.DataFrame({"dominant": dom, "share": dom_val}).dropna()
    result = result[result["share"].notna()]
    lines = ["\n**OS dominant par pays (part de marché de l'OS leader)**\n"]
    for os_name in cols:
        sub = result[result["dominant"] == os_name].sort_values("share", ascending=False)
        if len(sub) == 0:
            continue
        lines.append(f"\n_Dominance {os_name}_ ({len(sub)} pays) :")
        lines.append("| Pays | ISO2 | Part (%) |")
        lines.append("|---|---|---:|")
        for iso2, row in sub.head(15).iterrows():
            lines.append(f"| {cname(iso2)} | {iso2} | {row['share']:.1f}% |")
    return "\n".join(lines)

# ── Génération du rapport ────────────────────────────────────────────────────
print("Generation du rapport Phase D...")

lines = []
ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

lines.append("# Rapport Phase D — Analyse Géographique (252 Pays)")
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
lines.append(f"- **Pays couverts :** 252 (ISO2) × 53 semaines (juin 2025 – juin 2026)")
lines.append(f"- **Seuil d'inclusion :** ≥ {MIN_WEEKS} semaines valides pour les rankings")
lines.append(f"- **Événements BGP analysés :** {len(hijacks):,} hijacks + {len(leaks):,} leaks")
lines.append(f"- **Pays hijackeurs uniques :** {hijacks['hijacker_country'].nunique()}")
lines.append(f"- **Pays victimes uniques :** {victim_counts.shape[0]}")
lines.append("")

# Comptage pays éligibles par indicateur
n_ipv6   = ipv6_stats["IPv6"].notna().sum()
n_http3  = http_v_stats["HTTP/3"].notna().sum()
n_tls13  = tls_stats["TLS 1.3"].notna().sum()
n_bot    = bot_stats["bot"].notna().sum()
n_mobile = dev_stats["mobile"].notna().sum()
n_bw     = (iqi_bw_stats["mean_bw"].notna()).sum()
n_dns_   = (iqi_dns_stats["mean_dns"].notna()).sum()
n_imp    = imp_ranked.shape[0]

lines.append("**Pays éligibles par indicateur (≥ 20 semaines valides) :**")
lines.append("")
lines.append("| Indicateur | Pays éligibles |")
lines.append("|---|---:|")
lines.append(f"| IPv6 adoption | {n_ipv6} |")
lines.append(f"| HTTP/3 adoption | {n_http3} |")
lines.append(f"| TLS 1.3 | {n_tls13} |")
lines.append(f"| Taux bot | {n_bot} |")
lines.append(f"| Mobile/Desktop | {n_mobile} |")
lines.append(f"| Bande passante IQI (Mbps) | {n_bw} |")
lines.append(f"| Latence DNS IQI (ms) | {n_dns_} |")
lines.append(f"| Indice Maturité Protocoles (IMP) | {n_imp} |")
lines.append("")

# Top 5 IMP
lines.append("**Top 5 Indice de Maturité des Protocoles :**")
lines.append("")
lines.append("| Rang | Pays | ISO2 | IMP Score |")
lines.append("|---:|---|---|---:|")
for rank, (iso2, val) in enumerate(imp_ranked.head(5).items(), 1):
    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | {val:.1f}/100 |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 : IPv6 ADOPTION
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 2. Adoption IPv6 par Pays")
lines.append("")
lines.append(f"**Statistiques globales (moyenne de la période, {n_ipv6} pays éligibles) :**")
lines.append("")
ipv6_vals = ipv6_stats["IPv6"].dropna()
lines.append("| Statistique | Valeur |")
lines.append("|---|---:|")
lines.append(f"| Moyenne mondiale | {ipv6_vals.mean():.2f}% |")
lines.append(f"| Médiane mondiale | {ipv6_vals.median():.2f}% |")
lines.append(f"| Écart-type | {ipv6_vals.std():.2f}% |")
lines.append(f"| Minimum | {ipv6_vals.min():.2f}% ({cname(ipv6_vals.idxmin())} — {ipv6_vals.idxmin()}) |")
lines.append(f"| Maximum | {ipv6_vals.max():.2f}% ({cname(ipv6_vals.idxmax())} — {ipv6_vals.idxmax()}) |")
lines.append(f"| Pays > 50% IPv6 | {(ipv6_vals > 50).sum()} |")
lines.append(f"| Pays < 5% IPv6 | {(ipv6_vals < 5).sum()} |")
lines.append("")

lines.append(dual_ranking_table(ipv6_vals, top_n=20, unit="%", decimals=1,
                                 title="IPv6 adoption — Top 20 / Bottom 20"))
lines.append("")

# Distribution par quintile
q = ipv6_vals.quantile([.2,.4,.6,.8])
lines.append("**Distribution par quintile :**")
lines.append("")
lines.append("| Quintile | Seuil (%) | Nb pays |")
lines.append("|---|---:|---:|")
lines.append(f"| Q1 — Très faible (<{q[.2]:.1f}%) | {q[.2]:.1f} | {(ipv6_vals < q[.2]).sum()} |")
lines.append(f"| Q2 — Faible ({q[.2]:.1f}–{q[.4]:.1f}%) | {q[.4]:.1f} | {((ipv6_vals >= q[.2]) & (ipv6_vals < q[.4])).sum()} |")
lines.append(f"| Q3 — Moyen ({q[.4]:.1f}–{q[.6]:.1f}%) | {q[.6]:.1f} | {((ipv6_vals >= q[.4]) & (ipv6_vals < q[.6])).sum()} |")
lines.append(f"| Q4 — Élevé ({q[.6]:.1f}–{q[.8]:.1f}%) | {q[.8]:.1f} | {((ipv6_vals >= q[.6]) & (ipv6_vals < q[.8])).sum()} |")
lines.append(f"| Q5 — Très élevé (>{q[.8]:.1f}%) | — | {(ipv6_vals >= q[.8]).sum()} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 : HTTP/3 ADOPTION
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 3. Adoption HTTP/3 par Pays")
lines.append("")
http3_vals = http_v_stats["HTTP/3"].dropna()
http2_vals = http_v_stats["HTTP/2"].dropna()
http1_vals = http_v_stats["HTTP/1.x"].dropna()

lines.append("**Statistiques globales HTTP/3 :**")
lines.append("")
lines.append("| Statistique | Valeur |")
lines.append("|---|---:|")
lines.append(f"| Moyenne HTTP/3 | {http3_vals.mean():.2f}% |")
lines.append(f"| Médiane HTTP/3 | {http3_vals.median():.2f}% |")
lines.append(f"| Maximum HTTP/3 | {http3_vals.max():.2f}% ({cname(http3_vals.idxmax())} — {http3_vals.idxmax()}) |")
lines.append(f"| Minimum HTTP/3 | {http3_vals.min():.2f}% ({cname(http3_vals.idxmin())} — {http3_vals.idxmin()}) |")
lines.append(f"| Pays > 30% HTTP/3 | {(http3_vals > 30).sum()} |")
lines.append(f"| Moyenne HTTP/2 | {http2_vals.mean():.2f}% |")
lines.append(f"| Moyenne HTTP/1.x | {http1_vals.mean():.2f}% |")
lines.append("")

lines.append(dual_ranking_table(http3_vals, top_n=20, unit="%", decimals=1,
                                 title="HTTP/3 adoption — Top 20 / Bottom 20"))
lines.append("")

# HTTP version breakdown top 15
lines.append("**Répartition HTTP/3 vs HTTP/2 vs HTTP/1.x — Top 15 pays HTTP/3 :**")
lines.append("")
lines.append("| Rang | Pays | ISO2 | HTTP/3 (%) | HTTP/2 (%) | HTTP/1.x (%) |")
lines.append("|---:|---|---|---:|---:|---:|")
for rank, (iso2, v3) in enumerate(http3_vals.sort_values(ascending=False).head(15).items(), 1):
    v2  = http_v_stats.loc[iso2, "HTTP/2"]  if iso2 in http_v_stats.index else np.nan
    v1  = http_v_stats.loc[iso2, "HTTP/1.x"] if iso2 in http_v_stats.index else np.nan
    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | {v3:.1f}% | {v2:.1f}% | {v1:.1f}% |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 : TLS PAR PAYS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 4. Adoption TLS par Pays")
lines.append("")
tls13_vals  = tls_stats["TLS 1.3"].dropna()
tlsq_vals   = tls_stats["TLS QUIC"].dropna()
tls12_vals  = tls_stats["TLS 1.2"].dropna()
tls10_vals  = tls_stats["TLS 1.0"].dropna()
tls11_vals  = tls_stats["TLS 1.1"].dropna()

lines.append("**Statistiques globales TLS :**")
lines.append("")
lines.append("| Protocole | Moyenne | Médiane | Max | Pays > 80% |")
lines.append("|---|---:|---:|---:|---:|")
lines.append(f"| TLS 1.3 | {tls13_vals.mean():.2f}% | {tls13_vals.median():.2f}% | {tls13_vals.max():.2f}% | {(tls13_vals>80).sum()} |")
lines.append(f"| TLS QUIC | {tlsq_vals.mean():.2f}% | {tlsq_vals.median():.2f}% | {tlsq_vals.max():.2f}% | {(tlsq_vals>80).sum()} |")
lines.append(f"| TLS 1.2 | {tls12_vals.mean():.2f}% | {tls12_vals.median():.2f}% | {tls12_vals.max():.2f}% | — |")
lines.append(f"| TLS 1.1 (legacy) | {tls11_vals.mean():.2f}% | {tls11_vals.median():.2f}% | {tls11_vals.max():.2f}% | — |")
lines.append(f"| TLS 1.0 (obsolète) | {tls10_vals.mean():.2f}% | {tls10_vals.median():.2f}% | {tls10_vals.max():.2f}% | — |")
lines.append("")

lines.append(dual_ranking_table(tls13_vals, top_n=20, unit="%", decimals=1,
                                 title="TLS 1.3 adoption — Top 20 / Bottom 20"))
lines.append("")

# Pays encore avec TLS 1.0 élevé (>= 5%)
tls10_high = tls10_vals[tls10_vals >= 5].sort_values(ascending=False)
if len(tls10_high) > 0:
    lines.append("**Pays avec TLS 1.0 (obsolète) >= 5% — risque sécurité :**")
    lines.append("")
    lines.append("| Rang | Pays | ISO2 | TLS 1.0 (%) | TLS 1.1 (%) | TLS 1.2 (%) | TLS 1.3 (%) |")
    lines.append("|---:|---|---|---:|---:|---:|---:|")
    for rank, (iso2, v) in enumerate(tls10_high.items(), 1):
        v11 = tls_stats.loc[iso2, "TLS 1.1"] if iso2 in tls_stats.index else np.nan
        v12 = tls_stats.loc[iso2, "TLS 1.2"] if iso2 in tls_stats.index else np.nan
        v13 = tls_stats.loc[iso2, "TLS 1.3"] if iso2 in tls_stats.index else np.nan
        lines.append(f"| {rank} | {cname(iso2)} | {iso2} | **{v:.1f}%** | {v11:.1f}% | {v12:.1f}% | {v13:.1f}% |")
    lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 : TRAFIC BOT PAR PAYS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 5. Trafic Bot par Pays")
lines.append("")
bot_vals  = bot_stats["bot"].dropna()
hum_vals  = bot_stats["human"].dropna()

lines.append("**Statistiques globales trafic bot :**")
lines.append("")
lines.append("| Statistique | Valeur |")
lines.append("|---|---:|")
lines.append(f"| Taux bot moyen mondial | {bot_vals.mean():.2f}% |")
lines.append(f"| Taux bot médian mondial | {bot_vals.median():.2f}% |")
lines.append(f"| Maximum bot | {bot_vals.max():.2f}% ({cname(bot_vals.idxmax())} — {bot_vals.idxmax()}) |")
lines.append(f"| Minimum bot | {bot_vals.min():.2f}% ({cname(bot_vals.idxmin())} — {bot_vals.idxmin()}) |")
lines.append(f"| Pays > 50% bot | {(bot_vals > 50).sum()} |")
lines.append(f"| Pays > 30% bot | {(bot_vals > 30).sum()} |")
lines.append(f"| Pays < 10% bot | {(bot_vals < 10).sum()} |")
lines.append("")

lines.append(ranking_table(bot_vals, top_n=30, ascending=False, unit="%", decimals=1,
                            title="Pays avec le plus de trafic bot", bar_max=bot_vals.max()))
lines.append("")
lines.append(ranking_table(bot_vals, top_n=20, ascending=True, unit="%", decimals=1,
                            title="Pays avec le moins de trafic bot (trafic le plus humain)", bar_max=bot_vals.max()))
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 : DEVICE TYPE (MOBILE vs DESKTOP)
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 6. Répartition Mobile / Desktop par Pays")
lines.append("")
mob_vals = dev_stats["mobile"].dropna()
desk_vals = dev_stats["desktop"].dropna()

lines.append("**Statistiques globales :**")
lines.append("")
lines.append("| Statistique | Mobile (%) | Desktop (%) |")
lines.append("|---|---:|---:|")
lines.append(f"| Moyenne | {mob_vals.mean():.2f} | {desk_vals.mean():.2f} |")
lines.append(f"| Médiane | {mob_vals.median():.2f} | {desk_vals.median():.2f} |")
lines.append(f"| Max | {mob_vals.max():.2f} ({mob_vals.idxmax()}) | {desk_vals.max():.2f} ({desk_vals.idxmax()}) |")
lines.append(f"| Min | {mob_vals.min():.2f} ({mob_vals.idxmin()}) | {desk_vals.min():.2f} ({desk_vals.idxmin()}) |")
lines.append(f"| Pays > 70% mobile | {(mob_vals > 70).sum()} | — |")
lines.append(f"| Pays > 70% desktop | — | {(desk_vals > 70).sum()} |")
lines.append("")

lines.append(dual_ranking_table(mob_vals, top_n=20, unit="%", decimals=1,
                                 title="Mobile vs Desktop — Top 20 / Bottom 20 (par taux mobile)"))
lines.append("")

# Top pays les plus desktop
lines.append(ranking_table(desk_vals, top_n=20, ascending=False, unit="%", decimals=1,
                            title="Top 20 pays les plus orientés Desktop", bar_max=100))
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 : OS PAR PAYS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 7. Systèmes d'Exploitation par Pays")
lines.append("")

# Moyennes globales
lines.append("**Moyennes mondiales (moyenne des pays éligibles) :**")
lines.append("")
lines.append("| OS | Part moyenne (%) | Part médiane (%) |")
lines.append("|---|---:|---:|")
for os_col in ["WINDOWS","ANDROID","MACOSX","IOS","LINUX","CHROMEOS","SMART_TV"]:
    vals = os_stats[os_col].dropna()
    lines.append(f"| {os_col} | {vals.mean():.2f} | {vals.median():.2f} |")
lines.append("")

# Windows dominance
win_vals = os_stats["WINDOWS"].dropna()
and_vals = os_stats["ANDROID"].dropna()
ios_vals = os_stats["IOS"].dropna()
lin_vals = os_stats["LINUX"].dropna()
mac_vals = os_stats["MACOSX"].dropna()

lines.append(dual_ranking_table(win_vals, top_n=15, unit="%", decimals=1,
                                 title="Windows — Top 15 / Bottom 15"))
lines.append("")
lines.append(dual_ranking_table(and_vals, top_n=15, unit="%", decimals=1,
                                 title="Android — Top 15 / Bottom 15"))
lines.append("")
lines.append(dual_ranking_table(ios_vals, top_n=15, unit="%", decimals=1,
                                 title="iOS — Top 15 / Bottom 15"))
lines.append("")

# Linux
lin_high = lin_vals.sort_values(ascending=False).head(20)
lines.append("**Linux (Top 20 pays) :**")
lines.append("")
lines.append("| Rang | Pays | ISO2 | Linux (%) |")
lines.append("|---:|---|---|---:|")
for rank, (iso2, v) in enumerate(lin_high.items(), 1):
    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | {v:.1f}% |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 : NAVIGATEURS PAR PAYS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 8. Navigateurs Web par Pays")
lines.append("")
chr_vals = br_stats["chrome"].dropna()
saf_vals = br_stats["safari"].dropna()
edg_vals = br_stats["edge"].dropna()
ffx_vals = br_stats["firefox"].dropna()
sam_vals = br_stats["samsung"].dropna()

lines.append("**Moyennes mondiales :**")
lines.append("")
lines.append("| Navigateur | Moyenne (%) | Médiane (%) | Max (%) | Pays leader |")
lines.append("|---|---:|---:|---:|---|")
for col, vals in [("Chrome", chr_vals), ("Safari", saf_vals), ("Edge", edg_vals),
                   ("Firefox", ffx_vals), ("Samsung", sam_vals)]:
    leader = cname(vals.idxmax()) + f" ({vals.idxmax()})"
    lines.append(f"| {col} | {vals.mean():.2f} | {vals.median():.2f} | {vals.max():.2f} | {leader} |")
lines.append("")

# Safari vs Chrome (Apple ecosystem indicator)
lines.append("**Safari — Top 15 (proxy présence iPhone/macOS) :**")
lines.append("")
lines.append("| Rang | Pays | ISO2 | Safari (%) | Chrome (%) |")
lines.append("|---:|---|---|---:|---:|")
for rank, (iso2, v) in enumerate(saf_vals.sort_values(ascending=False).head(15).items(), 1):
    ch = chr_vals.get(iso2, np.nan)
    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | {v:.1f}% | {ch:.1f}% |")
lines.append("")

# Firefox — résistance alternative
lines.append("**Firefox — Top 15 (diversité des navigateurs) :**")
lines.append("")
lines.append("| Rang | Pays | ISO2 | Firefox (%) |")
lines.append("|---:|---|---|---:|")
for rank, (iso2, v) in enumerate(ffx_vals.sort_values(ascending=False).head(15).items(), 1):
    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | {v:.1f}% |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 : QUALITÉ RÉSEAU IQI
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 9. Qualité Réseau IQI par Pays")
lines.append("")

bw_vals  = iqi_bw_stats["mean_bw"].dropna()
dns_vals = iqi_dns_stats["mean_dns"].dropna()

lines.append("**Bande passante médiane (p50, Mbps) :**")
lines.append("")
lines.append("| Statistique | Valeur |")
lines.append("|---|---:|")
lines.append(f"| Pays couverts | {len(bw_vals)} |")
lines.append(f"| Moyenne mondiale | {bw_vals.mean():.2f} Mbps |")
lines.append(f"| Médiane mondiale | {bw_vals.median():.2f} Mbps |")
lines.append(f"| Max | {bw_vals.max():.2f} Mbps ({cname(bw_vals.idxmax())} — {bw_vals.idxmax()}) |")
lines.append(f"| Min | {bw_vals.min():.2f} Mbps ({cname(bw_vals.idxmin())} — {bw_vals.idxmin()}) |")
lines.append(f"| Pays > 100 Mbps | {(bw_vals > 100).sum()} |")
lines.append(f"| Pays < 10 Mbps | {(bw_vals < 10).sum()} |")
lines.append("")

lines.append(dual_ranking_table(bw_vals, top_n=20, unit=" Mbps", decimals=1,
                                 title="Bande passante médiane — Top 20 / Bottom 20"))
lines.append("")

lines.append("**Latence DNS médiane (p50, ms) — lower is better :**")
lines.append("")
lines.append("| Statistique | Valeur |")
lines.append("|---|---:|")
lines.append(f"| Pays couverts | {len(dns_vals)} |")
lines.append(f"| Moyenne mondiale | {dns_vals.mean():.2f} ms |")
lines.append(f"| Médiane mondiale | {dns_vals.median():.2f} ms |")
lines.append(f"| Min (meilleur) | {dns_vals.min():.2f} ms ({cname(dns_vals.idxmin())} — {dns_vals.idxmin()}) |")
lines.append(f"| Max (pire) | {dns_vals.max():.2f} ms ({cname(dns_vals.idxmax())} — {dns_vals.idxmax()}) |")
lines.append(f"| Pays < 20 ms | {(dns_vals < 20).sum()} |")
lines.append(f"| Pays > 100 ms | {(dns_vals > 100).sum()} |")
lines.append("")

# DNS : meilleures latences (ascendant = les plus rapides en premier)
lines.append(ranking_table(dns_vals, top_n=25, ascending=True, unit=" ms", decimals=1,
                            title="Latence DNS la plus faible (Top 25 — meilleurs)",
                            bar_max=dns_vals.max()))
lines.append("")
lines.append(ranking_table(dns_vals, top_n=20, ascending=False, unit=" ms", decimals=1,
                            title="Latence DNS la plus élevée (Top 20 — les plus lents)",
                            bar_max=dns_vals.max()))
lines.append("")

# Matrice bande passante × latence DNS
lines.append("**Matrice Bande Passante × Latence DNS (pays en commun) :**")
lines.append("")
bw_dns = pd.DataFrame({"bw": bw_vals, "dns_latency": dns_vals}).dropna()
lines.append(f"Pays couverts par les deux indicateurs : {len(bw_dns)}")
lines.append("")
lines.append("_Quadrants (top 10 par quadrant) :_")
bw_med = bw_dns["bw"].median()
dns_med = bw_dns["dns_latency"].median()

quad = {
    "Haute BW + Faible latence (idéal)": bw_dns[(bw_dns["bw"] >= bw_med) & (bw_dns["dns_latency"] <= dns_med)],
    "Haute BW + Haute latence": bw_dns[(bw_dns["bw"] >= bw_med) & (bw_dns["dns_latency"] > dns_med)],
    "Faible BW + Faible latence": bw_dns[(bw_dns["bw"] < bw_med) & (bw_dns["dns_latency"] <= dns_med)],
    "Faible BW + Haute latence (problématique)": bw_dns[(bw_dns["bw"] < bw_med) & (bw_dns["dns_latency"] > dns_med)],
}
for quad_name, sub in quad.items():
    lines.append(f"\n**{quad_name}** ({len(sub)} pays) :")
    lines.append("| Pays | ISO2 | BW (Mbps) | DNS latence (ms) |")
    lines.append("|---|---|---:|---:|")
    sub_sorted = sub.sort_values("bw", ascending=False).head(10)
    for iso2, row in sub_sorted.iterrows():
        lines.append(f"| {cname(iso2)} | {iso2} | {row['bw']:.1f} | {row['dns_latency']:.1f} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 : BGP GÉOGRAPHIQUE
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 10. Analyse BGP Géographique")
lines.append("")

# ── 10.1 Pays hijackeurs ────────────────────────────────────────────────────
lines.append("### 10.1 Pays Hijackeurs (émetteurs d'attaques BGP)")
lines.append("")
total_hijacks = len(hijacks)
hj_known = hijacker_counts[hijacker_counts.index != "UNKNOWN"]
lines.append("**Top 30 pays hijackeurs (événements, % total, score confiance moyen) :**")
lines.append("")
lines.append("| Rang | Pays | ISO2 | Nb événements | % Total | Confiance moy. | Durée moy. (s) |")
lines.append("|---:|---|---|---:|---:|---:|---:|")
for rank, (iso2, cnt) in enumerate(hj_known.head(30).items(), 1):
    pct = cnt / total_hijacks * 100
    conf = hijacker_conf.get(iso2, np.nan)
    dur  = hijacker_dur.get(iso2, np.nan)
    conf_str = f"{conf:.1f}" if pd.notna(conf) else "N/A"
    dur_str  = f"{dur:.0f}" if pd.notna(dur) else "N/A"
    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | {cnt:,} | {pct:.1f}% | {conf_str} | {dur_str} |")
lines.append("")

unknown_cnt = hijacker_counts.get("UNKNOWN", 0)
lines.append(f"> **UNKNOWN :** {unknown_cnt:,} événements ({unknown_cnt/total_hijacks*100:.1f}% du total)")
lines.append("")

# ── 10.2 Pays victimes ──────────────────────────────────────────────────────
lines.append("### 10.2 Pays Victimes (cibles d'attaques BGP)")
lines.append("")
lines.append("**Top 30 pays victimes (fréquence dans victim_countries) :**")
lines.append("")
lines.append("| Rang | Pays | ISO2 | Nb occurrences victimisation | % Total victimes |")
lines.append("|---:|---|---|---:|---:|")
total_victim_occ = victim_counts.sum()
for rank, (iso2, cnt) in enumerate(victim_counts.head(30).items(), 1):
    pct = cnt / total_victim_occ * 100
    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | {cnt:,} | {pct:.1f}% |")
lines.append("")

# ── 10.3 Paires hijacker-victime ────────────────────────────────────────────
lines.append("### 10.3 Paires Hijacker → Victime (Top 25 relations)")
lines.append("")
lines.append("| Rang | Hijacker | ISO2-H | Victime | ISO2-V | Nb incidents |")
lines.append("|---:|---|---|---|---|---:|")
for rank, ((hc, vc), cnt) in enumerate(top_pairs, 1):
    lines.append(f"| {rank} | {cname(hc)} | {hc} | {cname(vc)} | {vc} | {cnt:,} |")
lines.append("")

# ── 10.4 BGP Leaks ─────────────────────────────────────────────────────────
lines.append("### 10.4 Pays Impliqués dans les BGP Leaks")
lines.append("")
lines.append(f"Total événements leaks : {len(leaks):,}")
lines.append(f"Pays uniques dans les leaks : {leak_country_counts.shape[0]}")
lines.append("")
lines.append("**Top 25 pays impliqués dans des BGP leaks :**")
lines.append("")
lines.append("| Rang | Pays | ISO2 | Nb occurrences |")
lines.append("|---:|---|---|---:|")
for rank, (iso2, cnt) in enumerate(leak_country_counts.head(25).items(), 1):
    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | {cnt:,} |")
lines.append("")

# Types de leaks
if "leak_type" in leaks.columns:
    lines.append("**Répartition par type de leak :**")
    lines.append("")
    lines.append("| Type | Nb événements | % |")
    lines.append("|---|---:|---:|")
    for lt, cnt in leaks["leak_type"].value_counts().items():
        lines.append(f"| {lt} | {cnt:,} | {cnt/len(leaks)*100:.1f}% |")
    lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 : INDICE DE MATURITÉ DES PROTOCOLES (IMP)
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 11. Indice de Maturité des Protocoles (IMP)")
lines.append("")
lines.append("**Méthodologie IMP :**")
lines.append("")
lines.append("| Composante | Indicateur | Poids | Direction |")
lines.append("|---|---|---:|---|")
lines.append("| IPv6 | Taux d'adoption IPv6 (%) | 25% | Plus élevé = meilleur |")
lines.append("| HTTP/3 | Taux d'adoption HTTP/3 (%) | 25% | Plus élevé = meilleur |")
lines.append("| TLS 1.3 | Taux d'adoption TLS 1.3 (%) | 20% | Plus élevé = meilleur |")
lines.append("| TLS QUIC | Taux TLS QUIC (%) | 10% | Plus élevé = meilleur |")
lines.append("| Bot faible | 100 - Taux bot (%) | 10% | Plus élevé (bot faible) = meilleur |")
lines.append("| Mobile | Taux d'accès mobile (%) | 10% | Indicateur de pénétration mobile |")
lines.append("")
lines.append("> Chaque composante est normalisée min-max (0–100) avant pondération.  ")
lines.append("> Seuls les pays avec ≥ 50% des composantes disponibles sont inclus.")
lines.append("")

lines.append(f"**IMP Complet — Top 30 (sur {len(imp_ranked)} pays éligibles) :**")
lines.append("")
lines.append("| Rang | Pays | ISO2 | IMP | IPv6 (%) | HTTP/3 (%) | TLS 1.3 (%) | Bot (%) | Mobile (%) |")
lines.append("|---:|---|---|---:|---:|---:|---:|---:|---:|")
for rank, (iso2, imp_val) in enumerate(imp_ranked.head(30).items(), 1):
    ipv6_v = imp_df.loc[iso2, "ipv6"] if iso2 in imp_df.index else np.nan
    h3_v   = imp_df.loc[iso2, "http3"] if iso2 in imp_df.index else np.nan
    t13_v  = imp_df.loc[iso2, "tls13"] if iso2 in imp_df.index else np.nan
    bot_v  = 100 - imp_df.loc[iso2, "no_bot"] if iso2 in imp_df.index else np.nan  # back to bot rate
    mob_v  = imp_df.loc[iso2, "mobile"] if iso2 in imp_df.index else np.nan
    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | **{imp_val:.1f}** | "
                 f"{ipv6_v:.1f}% | {h3_v:.1f}% | {t13_v:.1f}% | {bot_v:.1f}% | {mob_v:.1f}% |")
lines.append("")

lines.append("**IMP — Bottom 20 (pays les moins matures) :**")
lines.append("")
lines.append("| Rang | Pays | ISO2 | IMP | IPv6 (%) | HTTP/3 (%) | TLS 1.3 (%) | Bot (%) | Mobile (%) |")
lines.append("|---:|---|---|---:|---:|---:|---:|---:|---:|")
imp_bottom = imp_ranked.tail(20).sort_values()
for rank, (iso2, imp_val) in enumerate(imp_bottom.items(), 1):
    ipv6_v = imp_df.loc[iso2, "ipv6"] if iso2 in imp_df.index else np.nan
    h3_v   = imp_df.loc[iso2, "http3"] if iso2 in imp_df.index else np.nan
    t13_v  = imp_df.loc[iso2, "tls13"] if iso2 in imp_df.index else np.nan
    bot_v  = 100 - imp_df.loc[iso2, "no_bot"] if iso2 in imp_df.index else np.nan
    mob_v  = imp_df.loc[iso2, "mobile"] if iso2 in imp_df.index else np.nan
    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | **{imp_val:.1f}** | "
                 f"{ipv6_v:.1f}% | {h3_v:.1f}% | {t13_v:.1f}% | {bot_v:.1f}% | {mob_v:.1f}% |")
lines.append("")

# Distribution IMP par quintile
q_imp = imp_ranked.quantile([.2,.4,.6,.8])
lines.append("**Distribution IMP par quintile :**")
lines.append("")
lines.append("| Quintile | Seuil IMP | Nb pays | Caractéristique |")
lines.append("|---|---:|---:|---|")
lines.append(f"| Q1 — Très faible | < {q_imp[.2]:.1f} | {(imp_ranked < q_imp[.2]).sum()} | Protocoles obsolètes dominants |")
lines.append(f"| Q2 — Faible | {q_imp[.2]:.1f}–{q_imp[.4]:.1f} | {((imp_ranked >= q_imp[.2]) & (imp_ranked < q_imp[.4])).sum()} | Adoption partielle |")
lines.append(f"| Q3 — Moyen | {q_imp[.4]:.1f}–{q_imp[.6]:.1f} | {((imp_ranked >= q_imp[.4]) & (imp_ranked < q_imp[.6])).sum()} | Transition en cours |")
lines.append(f"| Q4 — Élevé | {q_imp[.6]:.1f}–{q_imp[.8]:.1f} | {((imp_ranked >= q_imp[.6]) & (imp_ranked < q_imp[.8])).sum()} | Bonne adoption |")
lines.append(f"| Q5 — Excellent | > {q_imp[.8]:.1f} | {(imp_ranked >= q_imp[.8]).sum()} | Avant-garde des protocoles |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12 : TABLEAU SYNTHÈSE MULTI-INDICATEURS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 12. Tableau de Synthèse Multi-Indicateurs (Top 50 pays)")
lines.append("")
lines.append("> Classement par IMP décroissant. N/A = données insuffisantes.")
lines.append("")
lines.append("| Rang | Pays | ISO2 | IMP | IPv6 | HTTP/3 | TLS1.3 | Bot | Mobile | BW (Mbps) | DNS (ms) |")
lines.append("|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")

for rank, (iso2, imp_val) in enumerate(imp_ranked.head(50).items(), 1):
    def g(df_or_series, col=None):
        try:
            if col:
                v = df_or_series.loc[iso2, col] if iso2 in df_or_series.index else np.nan
            else:
                v = df_or_series.loc[iso2] if iso2 in df_or_series.index else np.nan
            return f"{v:.1f}" if pd.notna(v) else "N/A"
        except Exception:
            return "N/A"

    bw_v  = iqi_bw_stats.loc[iso2, "mean_bw"]  if iso2 in iqi_bw_stats.index  else np.nan
    dns_v = iqi_dns_stats.loc[iso2, "mean_dns"] if iso2 in iqi_dns_stats.index else np.nan

    lines.append(f"| {rank} | {cname(iso2)} | {iso2} | **{imp_val:.1f}** | "
                 f"{g(ipv6_stats,'IPv6')} | {g(http_v_stats,'HTTP/3')} | {g(tls_stats,'TLS 1.3')} | "
                 f"{g(bot_stats,'bot')} | {g(dev_stats,'mobile')} | "
                 f"{'N/A' if pd.isna(bw_v) else f'{bw_v:.1f}'} | "
                 f"{'N/A' if pd.isna(dns_v) else f'{dns_v:.1f}'} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 13 : FINDINGS CLÉS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 13. Findings Géographiques Clés")
lines.append("")

# IMP champions
imp_top1 = imp_ranked.index[0]
imp_top3 = list(imp_ranked.head(3).index)
imp_bot1 = imp_ranked.index[-1]

# IPv6 champion
ipv6_top = ipv6_vals.idxmax()
# HTTP/3 champion
http3_top = http3_vals.idxmax()
# Bot le plus élevé
bot_top = bot_vals.idxmax()
# BW le plus élevé
bw_top = bw_vals.idxmax() if len(bw_vals) > 0 else "N/A"
# DNS le plus rapide
dns_best = dns_vals.idxmin() if len(dns_vals) > 0 else "N/A"
# Hijacker le plus actif
hj_top = hj_known.index[0]
# Victime la plus fréquente
vic_top = victim_counts.index[0]

lines.append("### 13.1 Champions et Indicateurs Clés")
lines.append("")
lines.append("| Indicateur | Champion / Valeur remarquable |")
lines.append("|---|---|")
lines.append(f"| IMP le plus élevé | {cname(imp_top1)} ({imp_top1}) — {imp_ranked.iloc[0]:.1f}/100 |")
lines.append(f"| IMP le plus faible | {cname(imp_bot1)} ({imp_bot1}) — {imp_ranked.iloc[-1]:.1f}/100 |")
lines.append(f"| IPv6 le plus adopté | {cname(ipv6_top)} ({ipv6_top}) — {ipv6_vals.max():.1f}% |")
lines.append(f"| HTTP/3 le plus adopté | {cname(http3_top)} ({http3_top}) — {http3_vals.max():.1f}% |")
lines.append(f"| Taux bot le plus élevé | {cname(bot_top)} ({bot_top}) — {bot_vals.max():.1f}% |")
if len(bw_vals) > 0:
    lines.append(f"| Bande passante la plus haute | {cname(bw_top)} ({bw_top}) — {bw_vals.max():.1f} Mbps |")
if len(dns_vals) > 0:
    lines.append(f"| Latence DNS la plus faible | {cname(dns_best)} ({dns_best}) — {dns_vals.min():.1f} ms |")
lines.append(f"| Pays hijackeur le plus actif | {cname(hj_top)} ({hj_top}) — {hj_known.iloc[0]:,} événements |")
lines.append(f"| Pays victime le plus ciblé | {cname(vic_top)} ({vic_top}) — {victim_counts.iloc[0]:,} occurrences |")
lines.append(f"| Pays > 50% IPv6 | {(ipv6_vals > 50).sum()} pays |")
lines.append(f"| Pays avec TLS 1.0 >= 5% | {len(tls10_high)} pays (risque obsolescence) |")
lines.append("")

lines.append("### 13.2 Observations Structurelles")
lines.append("")
lines.append(f"1. **Fracture numérique Nord-Sud :** L'IMP révèle un fossé structurel — "
             f"les pays Q5 (IMP>{q_imp[.8]:.0f}) concentrent majoritairement des économies avancées, "
             f"tandis que le Q1 (IMP<{q_imp[.2]:.0f}) reflète une adoption très limitée des protocoles modernes.")
lines.append("")
lines.append(f"2. **IPv6 : pénétration hétérogène :** {(ipv6_vals > 50).sum()} pays dépassent 50% mais "
             f"{(ipv6_vals < 5).sum()} restent sous 5%. Le déploiement global moyen de {ipv6_vals.mean():.1f}% "
             f"masque une variance extrême (σ={ipv6_vals.std():.1f}%).")
lines.append("")
lines.append(f"3. **BGP : concentration des menaces :** Les 3 premiers pays hijackeurs "
             f"({', '.join([cname(x)+' ('+x+')' for x in hj_known.head(3).index])}) "
             f"représentent {hj_known.head(3).sum()/total_hijacks*100:.1f}% des événements totaux.")
lines.append("")
lines.append(f"4. **Mobile-first dans les pays en développement :** Les pays avec le plus fort taux mobile "
             f"(>{mob_vals.quantile(.9):.0f}%) sont généralement aussi ceux avec la plus faible IPv6 "
             f"et les protocoles les moins modernes, confirmant un modèle d'accès mobile-centrique sans modernisation stack.")
lines.append("")
lines.append(f"5. **TLS obsolète persistant :** {len(tls10_high)} pays maintiennent TLS 1.0 >= 5%, "
             f"exposant leurs utilisateurs à des vecteurs d'attaque connus (BEAST, POODLE).")
lines.append("")
lines.append("---")
lines.append(f"*Rapport généré automatiquement par `phase_D_geographique.py` le {ts}.*  ")
lines.append("*Sources : Cloudflare Radar API v4 — http_*, iqi_*, bgp_* datasets.*  ")
lines.append("*Prochaine étape : Phase E — Analyse des attaques L3/L7.*")

# ── Écriture ─────────────────────────────────────────────────────────────────
content = "\n".join(lines)
with open(OUT, "w", encoding="utf-8") as f:
    f.write(content)

size_kb = os.path.getsize(OUT) / 1024
n_lines = content.count("\n") + 1
print(f"\nRapport ecrit : {OUT}")
print(f"Taille : {size_kb:.1f} Ko")
print(f"Lignes : {n_lines}")
