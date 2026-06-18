#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase G — Analyse détaillée BGP Hijacks & Leaks (ASN, pays, RPKI/IRR, temporel)."""

import pandas as pd
import numpy as np
import ast
import os
import warnings
from datetime import datetime
from collections import defaultdict, Counter
from scipy import stats

warnings.filterwarnings("ignore")

BASE = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/cleaned"
OUT  = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/rapport_phase_G.md"

COUNTRY_NAMES = {
    "AD":"Andorre","AE":"EAU","AF":"Afghanistan","AG":"Antigua","AL":"Albanie",
    "AM":"Arménie","AO":"Angola","AR":"Argentine","AT":"Autriche","AU":"Australie",
    "AZ":"Azerbaïdjan","BA":"Bosnie","BB":"Barbade","BD":"Bangladesh","BE":"Belgique",
    "BF":"Burkina Faso","BG":"Bulgarie","BH":"Bahreïn","BI":"Burundi","BJ":"Bénin",
    "BN":"Brunéi","BO":"Bolivie","BR":"Brésil","BT":"Bhoutan","BW":"Botswana",
    "BY":"Biélorussie","BZ":"Belize","CA":"Canada","CD":"Congo RDC","CF":"Centrafrique",
    "CG":"Congo","CH":"Suisse","CI":"Côte d'Ivoire","CL":"Chili","CM":"Cameroun",
    "CN":"Chine","CO":"Colombie","CR":"Costa Rica","CU":"Cuba","CV":"Cap-Vert",
    "CY":"Chypre","CZ":"Rép. Tchèque","DE":"Allemagne","DK":"Danemark",
    "DO":"Rép. Dominicaine","DZ":"Algérie","EC":"Équateur","EE":"Estonie",
    "EG":"Égypte","ES":"Espagne","ET":"Éthiopie","FI":"Finlande","FJ":"Fidji",
    "FR":"France","GA":"Gabon","GB":"Royaume-Uni","GE":"Géorgie","GH":"Ghana",
    "GR":"Grèce","GT":"Guatemala","HK":"Hong Kong","HN":"Honduras","HR":"Croatie",
    "HT":"Haïti","HU":"Hongrie","ID":"Indonésie","IE":"Irlande","IL":"Israël",
    "IN":"Inde","IQ":"Irak","IR":"Iran","IS":"Islande","IT":"Italie",
    "JM":"Jamaïque","JO":"Jordanie","JP":"Japon","KE":"Kenya","KG":"Kirghizistan",
    "KH":"Cambodge","KR":"Corée du Sud","KW":"Koweït","KZ":"Kazakhstan",
    "LA":"Laos","LB":"Liban","LK":"Sri Lanka","LR":"Libéria","LT":"Lituanie",
    "LU":"Luxembourg","LV":"Lettonie","LY":"Libye","MA":"Maroc","MD":"Moldavie",
    "MG":"Madagascar","MM":"Myanmar","MN":"Mongolie","MO":"Macao","MT":"Malte",
    "MU":"Maurice","MX":"Mexique","MY":"Malaisie","MZ":"Mozambique","NA":"Namibie",
    "NG":"Nigeria","NL":"Pays-Bas","NO":"Norvège","NP":"Népal","NZ":"Nouvelle-Zélande",
    "OM":"Oman","PA":"Panama","PE":"Pérou","PH":"Philippines","PK":"Pakistan",
    "PL":"Pologne","PT":"Portugal","PY":"Paraguay","QA":"Qatar","RO":"Roumanie",
    "RS":"Serbie","RU":"Russie","RW":"Rwanda","SA":"Arabie Saoudite","SD":"Soudan",
    "SE":"Suède","SG":"Singapour","SI":"Slovénie","SK":"Slovaquie","SN":"Sénégal",
    "SO":"Somalie","SR":"Suriname","SY":"Syrie","TH":"Thaïlande","TJ":"Tadjikistan",
    "TM":"Turkménistan","TN":"Tunisie","TR":"Turquie","TT":"Trinité-et-Tobago",
    "TZ":"Tanzanie","UA":"Ukraine","UG":"Ouganda","US":"États-Unis","UY":"Uruguay",
    "UZ":"Ouzbékistan","VE":"Venezuela","VN":"Viêt Nam","YE":"Yémen",
    "ZA":"Afrique du Sud","ZM":"Zambie","ZW":"Zimbabwe","UNKNOWN":"Inconnu",
}

def cn(iso2):
    return COUNTRY_NAMES.get(str(iso2), str(iso2))

def safe_parse(s):
    if pd.isna(s):
        return []
    try:
        return ast.literal_eval(str(s))
    except Exception:
        return []

# ── Chargement ──────────────────────────────────────────────────────────────
print("Chargement des donnees BGP...")

h = pd.read_csv(f"{BASE}/bgp_hijacks_clean.csv")
l = pd.read_csv(f"{BASE}/bgp_leaks_clean.csv")

h["min_hijack_ts"] = pd.to_datetime(h["min_hijack_ts"], errors="coerce", utc=True)
h["max_hijack_ts"] = pd.to_datetime(h["max_hijack_ts"], errors="coerce", utc=True)
h["duration_h"]    = h["duration"] / 3600
h["duration_d"]    = h["duration"] / 86400

l["min_ts"] = pd.to_datetime(l["min_ts"], errors="coerce", utc=True)
l["max_ts"] = pd.to_datetime(l["max_ts"], errors="coerce", utc=True)
l["duration_h"] = (l["max_ts"] - l["min_ts"]).dt.total_seconds() / 3600

h["week"]  = h["min_hijack_ts"].dt.to_period("W")
h["month"] = h["min_hijack_ts"].dt.to_period("M")
l["week"]  = l["min_ts"].dt.to_period("W")
l["month"] = l["min_ts"].dt.to_period("M")

# ── Parsing tags ─────────────────────────────────────────────────────────────
print("Parsing tags BGP...")
tag_records = []
for _, row in h.iterrows():
    tags = safe_parse(row["tags"])
    for t in tags:
        tag_records.append({"event_id": row["id"], "tag": t.get("name",""), "score": t.get("score",0)})
tags_df = pd.DataFrame(tag_records)
tag_counts = tags_df["tag"].value_counts()
tag_score_mean = tags_df.groupby("tag")["score"].mean()

# RPKI / IRR flags per event
rpki_inv_events = set(tags_df[tags_df["tag"] == "rpki_new_origin_invalid"]["event_id"])
rpki_val_events = set(tags_df[tags_df["tag"] == "rpki_old_origin_valid"]["event_id"])
irr_inv_events  = set(tags_df[tags_df["tag"] == "irr_new_origin_invalid"]["event_id"])
bogon_events    = set(tags_df[tags_df["tag"] == "bogon_old_origin"]["event_id"])

h["rpki_invalid"] = h["id"].isin(rpki_inv_events)
h["rpki_valid"]   = h["id"].isin(rpki_val_events)
h["irr_invalid"]  = h["id"].isin(irr_inv_events)
h["is_bogon"]     = h["id"].isin(bogon_events)

# ── Parsing listes JSON ──────────────────────────────────────────────────────
print("Parsing victim ASNs et countries...")
victim_asn_list, victim_country_list = [], []
for _, row in h.iterrows():
    for asn in safe_parse(row["victim_asns"]):
        victim_asn_list.append(asn)
    for c in safe_parse(row["victim_countries"]):
        victim_country_list.append(c)

victim_asn_counts     = Counter(victim_asn_list)
victim_country_counts = Counter(victim_country_list)

# Paires hijacker_country → victim_country
print("Calcul paires pays hijacker/victime...")
hv_pairs = defaultdict(int)
for _, row in h.iterrows():
    hc = row["hijacker_country"]
    if pd.isna(hc) or hc == "UNKNOWN":
        continue
    for vc in safe_parse(row["victim_countries"]):
        if vc != hc:
            hv_pairs[(hc, vc)] += 1
top_hv_pairs = sorted(hv_pairs.items(), key=lambda x: -x[1])[:30]

# Paires hijacker_ASN → victim_ASN (top)
print("Calcul paires ASN hijacker/victime...")
ha_pairs = defaultdict(int)
for _, row in h.iterrows():
    hasn = row["hijacker_asn"]
    for vasn in safe_parse(row["victim_asns"]):
        if vasn != hasn:
            ha_pairs[(int(hasn), int(vasn))] += 1
top_ha_pairs = sorted(ha_pairs.items(), key=lambda x: -x[1])[:25]

# ── Analyse des leaks ────────────────────────────────────────────────────────
print("Analyse BGP leaks...")

leak_country_list = []
for _, row in l.iterrows():
    for c in safe_parse(row["countries"]):
        leak_country_list.append(c)
leak_country_counts = Counter(leak_country_list)

# leak_seg : extraire les ASNs intermédiaires (le "noeud de fuite" est le 2e)
leak_middle_asns = []
leak_origin_asns = []
leak_provider_asns = []
for _, row in l.iterrows():
    seg = safe_parse(row["leak_seg"])
    if len(seg) >= 3:
        leak_origin_asns.append(seg[0])     # origine
        leak_middle_asns.append(seg[1])     # le noeud qui fuit
        leak_provider_asns.append(seg[-1])  # upstream
    elif len(seg) == 2:
        leak_origin_asns.append(seg[0])
        leak_middle_asns.append(seg[1])

leak_asn_counts    = l["leak_asn"].value_counts()
leak_middle_counts = Counter(leak_middle_asns)
leak_origin_counts = Counter(leak_origin_asns)

# ── Agrégations temporelles ───────────────────────────────────────────────────
h_weekly = h.groupby("week").agg(
    n_events     = ("id", "count"),
    avg_conf     = ("confidence_score", "mean"),
    avg_dur_h    = ("duration_h", "mean"),
    med_dur_h    = ("duration_h", "median"),
    max_dur_h    = ("duration_h", "max"),
    avg_prefixes = ("prefixes_count", "mean"),
    max_prefixes = ("prefixes_count", "max"),
    rpki_inv_pct = ("rpki_invalid", lambda x: x.mean()*100),
    irr_inv_pct  = ("irr_invalid",  lambda x: x.mean()*100),
    bogon_pct    = ("is_bogon",     lambda x: x.mean()*100),
).reset_index()

l_weekly = l.groupby("week").agg(
    n_events   = ("id", "count"),
    avg_seg    = ("leak_seg_len", "mean"),
    avg_count  = ("leak_count", "mean"),
    avg_prefix = ("prefix_count", "mean"),
    avg_peers  = ("peer_count", "mean"),
).reset_index()

h_monthly = h.groupby("month").agg(
    n_events     = ("id","count"),
    avg_conf     = ("confidence_score","mean"),
    avg_dur_h    = ("duration_h","mean"),
    high_conf_n  = ("confidence_score", lambda x: (x >= 8).sum()),
    rpki_inv_pct = ("rpki_invalid", lambda x: x.mean()*100),
    irr_inv_pct  = ("irr_invalid",  lambda x: x.mean()*100),
).reset_index()

l_monthly = l.groupby("month").agg(
    n_events  = ("id","count"),
    avg_seg   = ("leak_seg_len","mean"),
    finished_pct = ("finished", lambda x: x.mean()*100),
).reset_index()

# ── Sévérité des hijacks ─────────────────────────────────────────────────────
# Score sévérité = confidence_score * log1p(prefixes_count) * log1p(duration_h+1)
h["severity"] = (
    h["confidence_score"] *
    np.log1p(h["prefixes_count"]) *
    np.log1p(h["duration_h"].clip(lower=0))
)
# Catégories de sévérité
h["severity_cat"] = pd.cut(
    h["severity"],
    bins=[-np.inf, 2, 5, 10, 20, np.inf],
    labels=["Négligeable","Faible","Modérée","Élevée","Critique"]
)

sev_counts = h["severity_cat"].value_counts()
high_sev   = h[h["confidence_score"] >= 8]

# Distribution confidence_score
conf_dist = h["confidence_score"].value_counts().sort_index()

# ── Top hijacker ASNs ────────────────────────────────────────────────────────
top_hijacker_asns = h.groupby("hijacker_asn").agg(
    n_events   = ("id", "count"),
    avg_conf   = ("confidence_score", "mean"),
    avg_dur_h  = ("duration_h", "mean"),
    med_pref   = ("prefixes_count", "median"),
    country    = ("hijacker_country", lambda x: x.mode().iloc[0] if len(x) > 0 else "?"),
).sort_values("n_events", ascending=False).head(30)

# Top hijacker countries
top_hijacker_countries = h[h["hijacker_country"] != "UNKNOWN"].groupby("hijacker_country").agg(
    n_events    = ("id","count"),
    avg_conf    = ("confidence_score","mean"),
    avg_dur_h   = ("duration_h","mean"),
    high_conf_n = ("confidence_score", lambda x: (x>=8).sum()),
    rpki_inv_pct= ("rpki_invalid", lambda x: x.mean()*100),
).sort_values("n_events", ascending=False)

# ── GÉNÉRATION DU RAPPORT ────────────────────────────────────────────────────
print("Generation du rapport Phase G...")

ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
lines = []

lines.append("# Rapport Phase G — Analyse BGP Hijacks & Leaks")
lines.append("**Cloudflare Radar Dataset — Déc. 2025 / Juin 2026**  ")
lines.append("**Auteur :** Issakha Thiam  ")
lines.append(f"**Généré le :** {ts}")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 : RÉSUMÉ EXÉCUTIF
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 1. Résumé Exécutif")
lines.append("")
lines.append("| Jeu de données | Période | Événements | Pays hijackeurs | ASNs hijackeurs |")
lines.append("|---|---|---:|---:|---:|")
lines.append(f"| BGP Hijacks | 2025-12-04 → 2026-06-09 | {len(h):,} | "
             f"{h[h['hijacker_country']!='UNKNOWN']['hijacker_country'].nunique()} | "
             f"{h['hijacker_asn'].nunique():,} |")
lines.append(f"| BGP Leaks   | 2026-03-02 → 2026-06-09 | {len(l):,} | "
             f"{len(set(leak_country_list))} | {l['leak_asn'].nunique():,} |")
lines.append("")
lines.append("**Métriques clés :**")
lines.append("")
lines.append("| Indicateur | Valeur |")
lines.append("|---|---|")
lines.append(f"| Durée moyenne d'un hijack | {h['duration_h'].mean():.1f} h (médiane : {h['duration_h'].median():.1f} h) |")
lines.append(f"| Durée maximale d'un hijack | {h['duration_h'].max():.1f} h = {h['duration_d'].max():.0f} jours |")
lines.append(f"| Confidence score moyen | {h['confidence_score'].mean():.2f} / 12 |")
lines.append(f"| Hijacks confiance élevée (≥ 8) | {(h['confidence_score']>=8).sum():,} ({(h['confidence_score']>=8).mean()*100:.1f}%) |")
lines.append(f"| Hijacks avec RPKI invalide | {h['rpki_invalid'].sum():,} ({h['rpki_invalid'].mean()*100:.1f}%) |")
lines.append(f"| Hijacks avec IRR invalide | {h['irr_invalid'].sum():,} ({h['irr_invalid'].mean()*100:.1f}%) |")
lines.append(f"| Hijacks bogon prefix | {h['is_bogon'].sum():,} ({h['is_bogon'].mean()*100:.1f}%) |")
lines.append(f"| Préfixes max hijackés (1 event) | {h['prefixes_count'].max():,} |")
lines.append(f"| ASNs victimes uniques | {len(set(victim_asn_list)):,} |")
lines.append(f"| Pays victimes uniques | {len(set(victim_country_list))} |")
lines.append(f"| Leaks encore actifs | {(~l['finished']).sum():,} ({(~l['finished']).mean()*100:.1f}%) |")
lines.append(f"| Longueur moyenne leak_seg | {l['leak_seg_len'].mean():.2f} ASNs |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 : BGP HIJACKS — VUE D'ENSEMBLE
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 2. BGP Hijacks — Vue d'Ensemble")
lines.append("")

lines.append("### 2.1 Distribution du Score de Confiance")
lines.append("")
lines.append("> Score Cloudflare : 1=très faible, 4=faible, 8=probable, 10=fort, 12=certain.")
lines.append("")
lines.append("| Score | Nb événements | % Total | Interprétation | Barre |")
lines.append("|---:|---:|---:|---|---|")
interpretations = {1:"Très faible — probable faux positif", 2:"Faible", 4:"Modéré",
                   5:"Modéré+", 6:"Probable", 7:"Probable+", 8:"Fort — hijack probable",
                   10:"Très fort", 12:"Certain — hijack confirmé"}
total_h = len(h)
for score, cnt in conf_dist.items():
    pct = cnt / total_h * 100
    interp = interpretations.get(score, "")
    bar = "#" * int(pct/2) + "." * (50 - int(pct/2))
    lines.append(f"| {score} | {cnt:,} | {pct:.1f}% | {interp} | [{bar[:30]}] |")
lines.append("")

lines.append("### 2.2 Statistiques Descriptives — Durée des Hijacks")
lines.append("")
lines.append("| Statistique | Durée (heures) | Durée (jours) |")
lines.append("|---|---:|---:|")
for stat, func in [("Minimum","min"),("P25","quantile(.25)"),("Médiane","median"),
                   ("Moyenne","mean"),("P75","quantile(.75)"),("P90","quantile(.9)"),
                   ("P95","quantile(.95)"),("Maximum","max")]:
    if "quantile" in func:
        q = float(func.split("(")[1].rstrip(")"))
        vh = h["duration_h"].quantile(q)
    else:
        vh = getattr(h["duration_h"], func)()
    lines.append(f"| {stat} | {vh:.2f} | {vh/24:.2f} |")
lines.append("")

lines.append("### 2.3 Distribution de Sévérité")
lines.append("")
lines.append("> Sévérité = confidence_score × log(1+prefixes) × log(1+durée_h)")
lines.append("")
lines.append("| Catégorie | Nb | % | Conf. moy. | Préf. moy. | Durée moy. (h) |")
lines.append("|---|---:|---:|---:|---:|---:|")
for cat in ["Critique","Élevée","Modérée","Faible","Négligeable"]:
    sub = h[h["severity_cat"] == cat]
    if len(sub) == 0:
        continue
    lines.append(f"| **{cat}** | {len(sub):,} | {len(sub)/total_h*100:.1f}% | "
                 f"{sub['confidence_score'].mean():.1f} | "
                 f"{sub['prefixes_count'].mean():.1f} | "
                 f"{sub['duration_h'].mean():.1f} |")
lines.append("")

lines.append("### 2.4 Statistiques des Préfixes Hijackés")
lines.append("")
lines.append("| Statistique | Préfixes | Victimes ASNs | Victimes pays |")
lines.append("|---|---:|---:|---:|")
for stat, func in [("Min","min"),("Médiane","median"),("Moyenne","mean"),
                   ("Max","max"),("Std","std")]:
    vp = getattr(h["prefixes_count"], func)()
    va = getattr(h["victim_asns_count"], func)()
    vc = getattr(h["victim_countries_count"], func)()
    lines.append(f"| {stat} | {vp:.2f} | {va:.2f} | {vc:.2f} |")
lines.append("")
lines.append(f"**Top événement par préfixes :** {h['prefixes_count'].max():,} préfixes en 1 seul hijack")
lines.append(f"**Top événement victimes ASNs :** {h['victim_asns_count'].max():,} ASNs victimes en 1 seul hijack")
lines.append(f"**Top événement victimes pays :** {h['victim_countries_count'].max():,} pays victimes en 1 seul hijack")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 : TAGS IRR & RPKI
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 3. Analyse Tags IRR & RPKI")
lines.append("")
lines.append("> **IRR** (Internet Routing Registry) : base de données de routage.  ")
lines.append("> **RPKI** (Resource Public Key Infrastructure) : validation cryptographique des origines AS.  ")
lines.append("> Un préfixe RPKI-invalid dans le nouveau hijack indique une violation ROA (Route Origin Authorization).")
lines.append("")

lines.append("### 3.1 Fréquence des Tags (toutes occurrences)")
lines.append("")
lines.append("| Rang | Tag | Nb occurrences | % événements | Score moyen | Signification |")
lines.append("|---:|---|---:|---:|---:|---|")
tag_meanings = {
    "irr_new_origin_invalid":   "Nouveau noeud non enregistré en IRR",
    "rpki_new_origin_invalid":  "⚠️ RPKI ROA violation — attaque probable",
    "irr_old_origin_valid":     "Ancien noeud enregistré en IRR (légitime)",
    "rpki_old_origin_valid":    "Ancien noeud validé RPKI (légitime)",
    "rpki_new_origin_unknown":  "RPKI inconnu pour nouveau noeud",
    "rpki_old_origin_unknown":  "RPKI inconnu pour ancien noeud",
    "irr_old_origin_invalid":   "Ancien noeud invalide IRR",
    "irr_old_origin_unknown":   "Ancien noeud inconnu IRR",
    "irr_new_origin_unknown":   "Nouveau noeud inconnu IRR",
    "irr_new_origin_valid":     "Nouveau noeud valide IRR (mais change)",
    "asrel_new_origin_provider": "Fournisseur AS devient origine",
    "asrel_sibling_origins":    "ASNs frères — même organisation",
    "rpki_old_origin_invalid":  "Ancien noeud RPKI invalide",
    "bogon_old_origin":         "🚨 Adresse bogon en ancien préfixe",
    "asrel_new_origin_customer":"Client AS devient origine",
    "asrel_new_origin_peer":    "Pair AS devient origine",
}
for rank, (tag, cnt) in enumerate(tag_counts.head(20).items(), 1):
    pct_events = cnt / total_h * 100
    score_m = tag_score_mean.get(tag, 0)
    meaning = tag_meanings.get(tag, "—")
    lines.append(f"| {rank} | `{tag}` | {cnt:,} | {pct_events:.1f}% | {score_m:.1f} | {meaning} |")
lines.append("")

lines.append("### 3.2 Couverture RPKI vs IRR")
lines.append("")
lines.append("| Indicateur | Nb événements | % du total |")
lines.append("|---|---:|---:|")
lines.append(f"| RPKI new origin INVALID (violation ROA) | {h['rpki_invalid'].sum():,} | {h['rpki_invalid'].mean()*100:.1f}% |")
lines.append(f"| IRR new origin INVALID | {h['irr_invalid'].sum():,} | {h['irr_invalid'].mean()*100:.1f}% |")
lines.append(f"| RPKI old origin VALID (origine légitime connue) | {h['rpki_valid'].sum():,} | {h['rpki_valid'].mean()*100:.1f}% |")
lines.append(f"| Bogon prefix détecté | {h['is_bogon'].sum():,} | {h['is_bogon'].mean()*100:.1f}% |")
lines.append(f"| RPKI ET IRR tous deux invalides | "
             f"{(h['rpki_invalid'] & h['irr_invalid']).sum():,} | "
             f"{(h['rpki_invalid'] & h['irr_invalid']).mean()*100:.1f}% |")
lines.append("")

lines.append("### 3.3 Analyse des Hijacks Haute Confiance (score ≥ 8)")
lines.append("")
hc_h = h[h["confidence_score"] >= 8]
lines.append(f"**{len(hc_h):,} événements ({len(hc_h)/total_h*100:.1f}%) à confiance ≥ 8**")
lines.append("")
lines.append("| Statistique | Valeur |")
lines.append("|---|---|")
lines.append(f"| Durée moyenne | {hc_h['duration_h'].mean():.1f} h |")
lines.append(f"| Préfixes moyens | {hc_h['prefixes_count'].mean():.1f} |")
lines.append(f"| Victimes ASNs moyennes | {hc_h['victim_asns_count'].mean():.1f} |")
lines.append(f"| Victimes pays moyennes | {hc_h['victim_countries_count'].mean():.1f} |")
lines.append(f"| RPKI invalide | {hc_h['rpki_invalid'].mean()*100:.1f}% |")
lines.append(f"| IRR invalide | {hc_h['irr_invalid'].mean()*100:.1f}% |")
lines.append(f"| Top pays hijackeur | {hc_h['hijacker_country'].value_counts().index[0]} ({hc_h['hijacker_country'].value_counts().iloc[0]:,}) |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 : TOP ASNs HIJACKEURS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 4. Top ASNs Hijackeurs")
lines.append("")
lines.append("### 4.1 Top 30 ASNs Hijackeurs par Volume")
lines.append("")
lines.append("| Rang | ASN hijackeur | Pays | Nb events | % total | Conf. moy. | Dur. moy. (h) | Préf. méd. |")
lines.append("|---:|---:|---|---:|---:|---:|---:|---:|")
for rank, (asn, row) in enumerate(top_hijacker_asns.iterrows(), 1):
    pct = row["n_events"] / total_h * 100
    country = cn(row["country"])
    lines.append(f"| {rank} | AS{asn} | {country} | {int(row['n_events']):,} | {pct:.2f}% | "
                 f"{row['avg_conf']:.1f} | {row['avg_dur_h']:.1f} | {row['med_pref']:.0f} |")
lines.append("")

lines.append("### 4.2 ASNs Hijackeurs avec Haute Confiance (score ≥ 8, Top 20)")
lines.append("")
hc_asn = h[h["confidence_score"] >= 8].groupby("hijacker_asn").agg(
    n_events = ("id","count"),
    avg_conf = ("confidence_score","mean"),
    country  = ("hijacker_country", lambda x: x.mode().iloc[0]),
    avg_pref = ("prefixes_count","mean"),
).sort_values("n_events", ascending=False).head(20)
lines.append("| Rang | ASN | Pays | Nb events haute conf. | Conf. moy. | Préf. moy. |")
lines.append("|---:|---:|---|---:|---:|---:|")
for rank, (asn, row) in enumerate(hc_asn.iterrows(), 1):
    lines.append(f"| {rank} | AS{asn} | {cn(row['country'])} | {int(row['n_events']):,} | "
                 f"{row['avg_conf']:.1f} | {row['avg_pref']:.1f} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 : TOP PAYS HIJACKEURS & VICTIMES
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 5. Analyse Géographique BGP Hijacks")
lines.append("")

lines.append("### 5.1 Top 30 Pays Hijackeurs")
lines.append("")
lines.append("| Rang | Pays | ISO2 | Nb events | % | Conf. moy. | Dur. moy. (h) | Conf≥8 | RPKI inv% |")
lines.append("|---:|---|---|---:|---:|---:|---:|---:|---:|")
for rank, (iso2, row) in enumerate(top_hijacker_countries.head(30).iterrows(), 1):
    pct = row["n_events"] / total_h * 100
    lines.append(f"| {rank} | {cn(iso2)} | {iso2} | {int(row['n_events']):,} | {pct:.1f}% | "
                 f"{row['avg_conf']:.1f} | {row['avg_dur_h']:.1f} | "
                 f"{int(row['high_conf_n']):,} | {row['rpki_inv_pct']:.1f}% |")
lines.append("")

lines.append("### 5.2 Top 30 Pays Victimes")
lines.append("")
total_victim_occ = sum(victim_country_counts.values())
lines.append("| Rang | Pays | ISO2 | Nb occurrences | % victimisations |")
lines.append("|---:|---|---|---:|---:|")
for rank, (iso2, cnt) in enumerate(victim_country_counts.most_common(30), 1):
    pct = cnt / total_victim_occ * 100
    lines.append(f"| {rank} | {cn(iso2)} | {iso2} | {cnt:,} | {pct:.1f}% |")
lines.append("")

lines.append("### 5.3 Top 30 Paires Hijacker → Victime (pays)")
lines.append("")
lines.append("| Rang | Pays hijackeur | ISO2-H | Pays victime | ISO2-V | Nb incidents |")
lines.append("|---:|---|---|---|---|---:|")
for rank, ((hc, vc), cnt) in enumerate(top_hv_pairs, 1):
    lines.append(f"| {rank} | {cn(hc)} | {hc} | {cn(vc)} | {vc} | {cnt:,} |")
lines.append("")

lines.append("### 5.4 Top 25 Paires Hijacker → Victime (ASNs)")
lines.append("")
lines.append("| Rang | ASN hijackeur | ASN victime | Nb incidents |")
lines.append("|---:|---:|---:|---:|")
for rank, ((hasn, vasn), cnt) in enumerate(top_ha_pairs, 1):
    lines.append(f"| {rank} | AS{hasn} | AS{vasn} | {cnt:,} |")
lines.append("")

lines.append("### 5.5 Top 30 ASNs Victimes")
lines.append("")
lines.append("| Rang | ASN victime | Nb occurrences |")
lines.append("|---:|---:|---:|")
for rank, (asn, cnt) in enumerate(victim_asn_counts.most_common(30), 1):
    lines.append(f"| {rank} | AS{asn} | {cnt:,} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 : ÉVOLUTION TEMPORELLE BGP HIJACKS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 6. Évolution Temporelle — BGP Hijacks")
lines.append("")

lines.append("### 6.1 Évolution Mensuelle")
lines.append("")
lines.append("| Mois | Nb events | Conf. moy. | Dur. moy. (h) | Conf≥8 | RPKI inv% | IRR inv% |")
lines.append("|---|---:|---:|---:|---:|---:|---:|")
for _, row in h_monthly.iterrows():
    lines.append(f"| {row['month']} | {int(row['n_events']):,} | {row['avg_conf']:.2f} | "
                 f"{row['avg_dur_h']:.1f} | {int(row['high_conf_n']):,} | "
                 f"{row['rpki_inv_pct']:.1f}% | {row['irr_inv_pct']:.1f}% |")
lines.append("")

lines.append("### 6.2 Évolution Hebdomadaire (toutes semaines)")
lines.append("")
lines.append("| Semaine | Nb events | Conf. moy. | Dur. méd. (h) | Dur. moy. (h) | Préf. moy. | RPKI inv% |")
lines.append("|---|---:|---:|---:|---:|---:|---:|")
for _, row in h_weekly.iterrows():
    lines.append(f"| {row['week']} | {int(row['n_events']):,} | {row['avg_conf']:.2f} | "
                 f"{row['med_dur_h']:.1f} | {row['avg_dur_h']:.1f} | "
                 f"{row['avg_prefixes']:.1f} | {row['rpki_inv_pct']:.1f}% |")
lines.append("")

# Anomalies hebdomadaires
weekly_events = h_weekly["n_events"]
z_we = (weekly_events - weekly_events.mean()) / weekly_events.std()
anom_weeks = [(i, r["week"], int(r["n_events"]), round(z_we.iloc[i], 2))
              for i, r in h_weekly.iterrows() if abs(z_we.iloc[i]) >= 2.0]
if anom_weeks:
    lines.append("### 6.3 Semaines Anormales (|Z| ≥ 2,0)")
    lines.append("")
    lines.append("| Semaine | Nb events | Z-score | Type |")
    lines.append("|---|---:|---:|---|")
    for _, week, cnt, z in anom_weeks:
        t = "PIC" if z > 0 else "CREUX"
        lines.append(f"| {week} | {cnt:,} | {z:.2f} | **{t}** ⚠️ |")
    lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 : BGP LEAKS — VUE D'ENSEMBLE
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 7. BGP Leaks — Vue d'Ensemble")
lines.append("")
lines.append(f"> **{len(l):,} événements de fuite BGP** sur la période 2026-03-02 → 2026-06-09  ")
lines.append(f"> Tous de type 1 (BGP type 1 leak : valley-free violation).")
lines.append("")

lines.append("### 7.1 Statistiques Descriptives — Leaks")
lines.append("")
lines.append("| Statistique | Leak count | Prefix count | Peer count | Origin count | Seg len | Durée (h) |")
lines.append("|---|---:|---:|---:|---:|---:|---:|")
for stat, func in [("Min","min"),("P25","quantile(.25)"),("Médiane","median"),
                   ("Moyenne","mean"),("P75","quantile(.75)"),("Max","max"),("Std","std")]:
    def gv(col, f):
        if "quantile" in f:
            q = float(f.split("(")[1].rstrip(")"))
            return l[col].quantile(q)
        return getattr(l[col], f)()
    lc = gv("leak_count", func)
    pc = gv("prefix_count", func)
    pe = gv("peer_count", func)
    oc = gv("origin_count", func)
    sl = gv("leak_seg_len", func)
    dh = gv("duration_h", func)
    lines.append(f"| {stat} | {lc:.1f} | {pc:.1f} | {pe:.1f} | {oc:.1f} | {sl:.2f} | {dh:.1f} |")
lines.append("")

lines.append(f"**Leaks encore actifs (non terminés) : {(~l['finished']).sum():,} "
             f"({(~l['finished']).mean()*100:.1f}%)**")
lines.append("")

lines.append("### 7.2 Top 30 ASNs Fuiteurs (leak_asn)")
lines.append("")
lines.append("| Rang | ASN fuiteur | Nb événements | % total | Leaks actifs |")
lines.append("|---:|---:|---:|---:|---:|")
for rank, (asn, cnt) in enumerate(leak_asn_counts.head(30).items(), 1):
    pct = cnt / len(l) * 100
    active = l[(l["leak_asn"] == asn) & (~l["finished"])].shape[0]
    lines.append(f"| {rank} | AS{asn} | {cnt:,} | {pct:.2f}% | {active} |")
lines.append("")

lines.append("### 7.3 Top 25 ASNs Noeud de Fuite (middle de leak_seg)")
lines.append("")
lines.append("| Rang | ASN middle | Nb occurrences |")
lines.append("|---:|---:|---:|")
for rank, (asn, cnt) in enumerate(Counter(leak_middle_asns).most_common(25), 1):
    lines.append(f"| {rank} | AS{asn} | {cnt:,} |")
lines.append("")

lines.append("### 7.4 Top 20 ASNs Origine dans les Leaks")
lines.append("")
lines.append("| Rang | ASN origine | Nb occurrences |")
lines.append("|---:|---:|---:|")
for rank, (asn, cnt) in enumerate(Counter(leak_origin_asns).most_common(20), 1):
    lines.append(f"| {rank} | AS{asn} | {cnt:,} |")
lines.append("")

lines.append("### 7.5 Top 25 Pays Impliqués dans les Leaks")
lines.append("")
total_lc = sum(leak_country_counts.values())
lines.append("| Rang | Pays | ISO2 | Nb occurrences | % |")
lines.append("|---:|---|---|---:|---:|")
for rank, (iso2, cnt) in enumerate(leak_country_counts.most_common(25), 1):
    pct = cnt / total_lc * 100
    lines.append(f"| {rank} | {cn(iso2)} | {iso2} | {cnt:,} | {pct:.1f}% |")
lines.append("")

lines.append("### 7.6 Longueur des Chemins de Fuite (leak_seg_len)")
lines.append("")
seg_dist = l["leak_seg_len"].value_counts().sort_index()
lines.append("| Longueur chemin | Nb événements | % |")
lines.append("|---:|---:|---:|")
for seg_len, cnt in seg_dist.items():
    lines.append(f"| {seg_len} ASNs | {cnt:,} | {cnt/len(l)*100:.1f}% |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 : ÉVOLUTION TEMPORELLE BGP LEAKS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 8. Évolution Temporelle — BGP Leaks")
lines.append("")

lines.append("### 8.1 Évolution Mensuelle")
lines.append("")
lines.append("| Mois | Nb events | Durée moy. seg | Finished % |")
lines.append("|---|---:|---:|---:|")
for _, row in l_monthly.iterrows():
    lines.append(f"| {row['month']} | {int(row['n_events']):,} | "
                 f"{row['avg_seg']:.2f} ASNs | {row['finished_pct']:.1f}% |")
lines.append("")

lines.append("### 8.2 Évolution Hebdomadaire")
lines.append("")
lines.append("| Semaine | Nb events | Dur. seg moy. | Leak count moy. | Préfixes moy. | Pairs moy. |")
lines.append("|---|---:|---:|---:|---:|---:|")
for _, row in l_weekly.iterrows():
    lines.append(f"| {row['week']} | {int(row['n_events']):,} | {row['avg_seg']:.2f} | "
                 f"{row['avg_count']:.1f} | {row['avg_prefix']:.1f} | {row['avg_peers']:.1f} |")
lines.append("")

# Anomalies
lw_events = l_weekly["n_events"]
if lw_events.std() > 0:
    z_lw = (lw_events - lw_events.mean()) / lw_events.std()
    anom_lw = [(i, r["week"], int(r["n_events"]), round(z_lw.iloc[i], 2))
               for i, r in l_weekly.iterrows() if abs(z_lw.iloc[i]) >= 2.0]
    if anom_lw:
        lines.append("### 8.3 Semaines Anormales Leaks (|Z| ≥ 2,0)")
        lines.append("")
        lines.append("| Semaine | Nb events | Z-score | Type |")
        lines.append("|---|---:|---:|---|")
        for _, week, cnt, z in anom_lw:
            t = "PIC" if z > 0 else "CREUX"
            lines.append(f"| {week} | {cnt:,} | {z:.2f} | **{t}** ⚠️ |")
        lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 : ANALYSE CROISÉE HIJACKS × LEAKS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 9. Analyse Croisée — Hijacks × Leaks (période commune mars–juin 2026)")
lines.append("")

# Période commune
h_common = h[h["min_hijack_ts"] >= pd.Timestamp("2026-03-02", tz="UTC")]
l_common  = l.copy()

# Hijacks vs leaks sur période commune
lines.append("| Indicateur | Hijacks (mars–juin) | Leaks (mars–juin) |")
lines.append("|---|---:|---:|")
lines.append(f"| Nb événements | {len(h_common):,} | {len(l_common):,} |")
lines.append(f"| Pays uniques impliqués | {h_common['hijacker_country'].nunique()} | {len(set(leak_country_list))} |")
lines.append(f"| ASNs uniques | {h_common['hijacker_asn'].nunique():,} | {l_common['leak_asn'].nunique():,} |")
lines.append(f"| Conf./score moy. | {h_common['confidence_score'].mean():.2f} | — |")
lines.append(f"| Durée moy. (h) | {h_common['duration_h'].mean():.1f} | {l_common['duration_h'].mean():.1f} |")
lines.append("")

# ASNs présents dans les deux (hijackeurs ET fuiteurs)
hijack_asns = set(h["hijacker_asn"].unique())
leak_asns   = set(l["leak_asn"].unique())
overlap_asns = hijack_asns & leak_asns
lines.append(f"**ASNs présents dans hijacks ET leaks (même ASN joue les deux rôles) : {len(overlap_asns):,}**")
if overlap_asns:
    sample = sorted(list(overlap_asns))[:15]
    lines.append(f"Exemples : {', '.join([f'AS{a}' for a in sample])}")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 : CORRÉLATIONS ET PATTERNS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 10. Corrélations Intra-BGP et Patterns")
lines.append("")

lines.append("### 10.1 Corrélation Confidence Score × Métriques")
lines.append("")
for col, label in [("duration_h","Durée (h)"),("prefixes_count","Nb préfixes"),
                    ("victim_asns_count","Nb victimes ASNs"),("victim_countries_count","Nb victimes pays"),
                    ("peer_asns_count","Nb pairs"),("tags_total_score","Score tags"),
                    ("hijack_msgs_count","Nb messages")]:
    r, p = stats.spearmanr(h["confidence_score"], h[col])
    sig = "✅" if abs(p) < 0.05 else ""
    lines.append(f"- **Confidence × {label}** : r_Spearman = {r:.4f}, p = {p:.4f} {sig}")
lines.append("")

lines.append("### 10.2 Corrélation Durée × Préfixes")
lines.append("")
r_dp, p_dp = stats.spearmanr(h["duration_h"], h["prefixes_count"])
r_dc, p_dc = stats.spearmanr(h["duration_h"], h["confidence_score"])
r_pc, p_pc = stats.spearmanr(h["prefixes_count"], h["confidence_score"])
lines.append(f"- Durée × Préfixes : r = {r_dp:.4f}, p = {p_dp:.4f}")
lines.append(f"- Durée × Confidence : r = {r_dc:.4f}, p = {p_dc:.4f}")
lines.append(f"- Préfixes × Confidence : r = {r_pc:.4f}, p = {p_pc:.4f}")
lines.append("")

lines.append("### 10.3 Patterns Temporels (heure de début des hijacks)")
lines.append("")
h["hour"] = h["min_hijack_ts"].dt.hour
hour_dist = h.groupby("hour").agg(n=("id","count"), avg_conf=("confidence_score","mean"))
lines.append("| Heure UTC | Nb events | Conf. moy. |")
lines.append("|---:|---:|---:|")
for hour, row in hour_dist.iterrows():
    lines.append(f"| {int(hour):02d}:00 | {int(row['n']):,} | {row['avg_conf']:.2f} |")
lines.append("")
lines.append("---")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 : FINDINGS ET IMPLICATIONS
# ══════════════════════════════════════════════════════════════════════════════
lines.append("## 11. Findings et Implications Sécurité Routage")
lines.append("")

lines.append("### 11.1 Résumé Statistique Global")
lines.append("")
lines.append("| Indicateur | BGP Hijacks | BGP Leaks |")
lines.append("|---|---|---|")
lines.append(f"| Période couverte | Déc. 2025 – Juin 2026 | Mars 2026 – Juin 2026 |")
lines.append(f"| Nb total événements | {len(h):,} | {len(l):,} |")
lines.append(f"| Taux résolution | {h['is_stale'].mean()*100:.1f}% résolus | {l['finished'].mean()*100:.1f}% terminés |")
lines.append(f"| Durée médiane | {h['duration_h'].median():.1f} h | {l['duration_h'].median():.1f} h |")
lines.append(f"| Pays origine | {h['hijacker_country'].nunique()} pays | {len(set(leak_country_list))} pays impliqués |")
lines.append(f"| Top pays offensif | {top_hijacker_countries.index[0]} "
             f"({int(top_hijacker_countries.iloc[0]['n_events']):,} events) | "
             f"{list(leak_country_counts.most_common(1))[0][0]} "
             f"({list(leak_country_counts.most_common(1))[0][1]:,} occ.) |")
lines.append("")

lines.append("### 11.2 Observations Clés")
lines.append("")
us_h = top_hijacker_countries.loc["US","n_events"] if "US" in top_hijacker_countries.index else 0
cn_h = top_hijacker_countries.loc["CN","n_events"] if "CN" in top_hijacker_countries.index else 0
ru_h = top_hijacker_countries.loc["RU","n_events"] if "RU" in top_hijacker_countries.index else 0
top3_pct = (us_h + cn_h + ru_h) / total_h * 100

lines.append(f"1. **Concentration géographique des menaces :** US + CN + RU représentent "
             f"{top3_pct:.1f}% des hijacks. Cependant, les hijacks attribués aux USA peuvent "
             f"refléter des compromissions d'ASNs hébergés aux USA plutôt que des acteurs étatiques.")
lines.append("")
lines.append(f"2. **RPKI : déploiement insuffisant.** {h['rpki_invalid'].mean()*100:.1f}% des "
             f"hijacks violent des ROAs RPKI — ce qui signifie que {100-h['rpki_invalid'].mean()*100:.1f}% "
             f"des hijacks n'auraient PAS été détectés par RPKI seul. La couverture ROV (Route Origin "
             f"Validation) reste largement incomplète sur l'internet mondial.")
lines.append("")
lines.append(f"3. **Durées hétérogènes : de quelques secondes à {h['duration_d'].max():.0f} jours.** "
             f"La médiane de {h['duration_h'].median():.1f}h indique que la majorité des hijacks "
             f"sont résolus rapidement, mais les événements extrêmes (>100h) peuvent avoir des impacts durables.")
lines.append("")
lines.append(f"4. **Leaks BGP type 1 (valley-free) omniprésents.** Les {len(l):,} leaks identifiés "
             f"sur 3 mois indiquent un problème structurel de politique de filtrage BGP. "
             f"AS199310 (AS{leak_asn_counts.index[0]}) est le fuiteur le plus actif avec "
             f"{int(leak_asn_counts.iloc[0]):,} événements.")
lines.append("")
lines.append(f"5. **Hijacks à large portée.** Un seul événement peut toucher jusqu'à "
             f"{h['prefixes_count'].max():,} préfixes et {h['victim_countries_count'].max()} pays "
             f"simultanément — soulignant la vulnérabilité systémique du routage BGP sans RPKI/ROV.")
lines.append("")
lines.append(f"6. **Chevauchement hijacks/leaks : {len(overlap_asns):,} ASNs actifs dans les deux.** "
             f"La présence d'ASNs communs dans les hijacks ET les leaks peut indiquer soit "
             f"des réseaux compromis, soit des opérateurs sans politique de sécurité BGP robuste.")
lines.append("")
lines.append(f"7. **Vigilance sur les leaks non terminés.** {(~l['finished']).sum():,} leaks "
             f"({(~l['finished']).mean()*100:.1f}%) restent actifs à la fin de la période — "
             f"trafic potentiellement détourné en cours.")
lines.append("")
lines.append("---")
lines.append(f"*Rapport généré automatiquement par `phase_G_bgp.py` le {ts}.*  ")
lines.append("*Sources : Cloudflare Radar API v4 — bgp_hijacks, bgp_leaks datasets.*  ")
lines.append("*Prochaine étape : Phase H — Corrélations croisées inter-domaines.*")

# ── Écriture ─────────────────────────────────────────────────────────────────
content = "\n".join(lines)
with open(OUT, "w", encoding="utf-8") as f:
    f.write(content)

size_kb = os.path.getsize(OUT) / 1024
n_lines = content.count("\n") + 1
print(f"\nRapport ecrit : {OUT}")
print(f"Taille : {size_kb:.1f} Ko")
print(f"Lignes : {n_lines}")
