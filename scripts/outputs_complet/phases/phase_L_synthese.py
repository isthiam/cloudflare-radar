# -*- coding: utf-8 -*-
"""
Phase L — Synthèse Finale et Dashboard
Consolidation de toutes les phases A→K, indicateurs clés, recommandations
"""

import os
import ast
import warnings
import numpy as np
import pandas as pd
from datetime import datetime
from scipy import stats

warnings.filterwarnings("ignore")

BASE    = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/cleaned/"
REPORTS = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/"
OUT     = REPORTS + "rapport_phase_L_synthese.md"

print("Phase L — Synthèse finale...")

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def parse_date(df, col="date"):
    df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    df[col] = df[col].dt.tz_localize(None)
    return df

def fv(v, fmt=".2f", na="N/A"):
    if v is None: return na
    try:
        if np.isnan(v): return na
    except (TypeError, ValueError): pass
    return format(v, fmt)

def mann_kendall_tau(series):
    s = series.dropna().values
    n = len(s)
    if n < 5: return np.nan, np.nan
    tau, p = stats.kendalltau(np.arange(n), s)
    return tau, p

def safe_parse(s):
    if pd.isna(s): return []
    try: return ast.literal_eval(str(s))
    except: return []

def week_floor(dt_series):
    return dt_series.dt.to_period("W").dt.start_time

def trend_symbol(tau, p):
    if p is None or np.isnan(p) or p > 0.05: return "→ stable"
    if tau > 0.3: return "↑↑ forte hausse"
    if tau > 0.1: return "↑ hausse modérée"
    if tau < -0.3: return "↓↓ forte baisse"
    if tau < -0.1: return "↓ baisse modérée"
    return "→ stable"

# ══════════════════════════════════════════════════════════════════════════════
# 1. RECHARGEMENT DES INDICATEURS CLÉS
# ══════════════════════════════════════════════════════════════════════════════
print("  1/4 Rechargement indicateurs clés...")

# BGP
hij = pd.read_csv(BASE + "bgp_hijacks_clean.csv")
hij["min_hijack_ts"] = pd.to_datetime(hij["min_hijack_ts"], errors="coerce")
hij = hij.dropna(subset=["min_hijack_ts"])
leaks = pd.read_csv(BASE + "bgp_leaks_clean.csv")
leaks["min_ts"] = pd.to_datetime(leaks["min_ts"], errors="coerce")
leaks = leaks.dropna(subset=["min_ts"])

# Duration
if "max_hijack_ts" in hij.columns:
    hij["max_hijack_ts"] = pd.to_datetime(hij["max_hijack_ts"], errors="coerce")
    hij["duration_h"] = (hij["max_hijack_ts"] - hij["min_hijack_ts"]).dt.total_seconds() / 3600
    hij["duration_h"] = hij["duration_h"].clip(lower=0)

# BGP weekly
hij["week"] = week_floor(hij["min_hijack_ts"])
hij["rpki_inv"] = hij["tags"].apply(lambda s: 1 if isinstance(s,str) and "rpki_new_origin_invalid" in s else 0)
bgp_hij_wk = hij.groupby("week").agg(
    count=("id","count"), conf=("confidence_score","mean"), rpki=("rpki_inv","mean")
)
bgp_hij_wk.index = pd.to_datetime(bgp_hij_wk.index)

# DNS
dns_ts = parse_date(pd.read_csv(BASE + "dns_timeseries_clean.csv")).set_index("date")["values"]

# Email
dmarc = parse_date(pd.read_csv(BASE + "email_dmarc_clean.csv")).set_index("date")
dkim  = parse_date(pd.read_csv(BASE + "email_dkim_clean.csv")).set_index("date")
spf   = parse_date(pd.read_csv(BASE + "email_spf_clean.csv")).set_index("date")
spam  = parse_date(pd.read_csv(BASE + "email_spam_clean.csv")).set_index("date")
spoof = parse_date(pd.read_csv(BASE + "email_spoof_clean.csv")).set_index("date")
malic = parse_date(pd.read_csv(BASE + "email_malicious_clean.csv")).set_index("date")

ISE = (dmarc["PASS"]*0.35 + dkim["PASS"]*0.35 + spf["PASS"]*0.30) - \
      (spam["SPAM"] + spoof["SPOOF"] + malic["MALICIOUS"])/3 * 0.5

# L3 attacks
l3_proto  = parse_date(pd.read_csv(BASE + "attacks_l3_protocol_clean.csv")).set_index("date")
l3_bitrate= parse_date(pd.read_csv(BASE + "attacks_l3_bitrate_clean.csv")).set_index("date")
l3_high   = l3_bitrate["_1_GBPS_TO_10_GBPS"].fillna(0) + l3_bitrate["_10_GBPS_TO_100_GBPS"].fillna(0) + l3_bitrate["OVER_100_GBPS"].fillna(0)

# HTTP global
def http_g(fname, col, rename=None):
    df = parse_date(pd.read_csv(BASE + fname))
    if rename: df = df.rename(columns=rename)
    return df.groupby("date")[col].mean()

ipv6_g   = http_g("http_ip_version_clean.csv", "IPv6")
http3_g  = http_g("http_http_version_clean.csv", "HTTP/3")
tls_raw  = parse_date(pd.read_csv(BASE + "http_tls_version_clean.csv"))
tls_raw  = tls_raw.rename(columns={"TLS 1.3":"TLS13"})
tls13_g  = tls_raw.groupby("date")["TLS13"].mean()
bot_g    = http_g("http_bot_class_clean.csv", "bot")

# L7 attacks
l7_vert = parse_date(pd.read_csv(BASE + "attacks_l7_vertical_clean.csv"))
l7_vert = l7_vert[l7_vert["dimension"]=="vertical"]
l7_it   = l7_vert.groupby("date")["Internet and Telecom"].mean()

# ══════════════════════════════════════════════════════════════════════════════
# 2. CALCUL INDICATEURS SYNTHÈSE
# ══════════════════════════════════════════════════════════════════════════════
print("  2/4 Calcul indicateurs synthèse...")

KPI = {}

# BGP
KPI["bgp_n_hijacks"]     = len(hij)
KPI["bgp_n_leaks"]       = len(leaks)
KPI["bgp_conf_mean"]     = hij["confidence_score"].mean()
KPI["bgp_rpki_inv_pct"]  = hij["rpki_inv"].mean() * 100
KPI["bgp_dur_median_h"]  = hij["duration_h"].median() if "duration_h" in hij.columns else np.nan
KPI["bgp_dur_max_h"]     = hij["duration_h"].max()    if "duration_h" in hij.columns else np.nan
KPI["bgp_n_hijack_countries"] = 141
KPI["bgp_n_victim_countries"] = 174
KPI["bgp_n_hijack_asns"]      = 2219
KPI["bgp_dual_role_asns"]     = 302

# DNS
KPI["dns_mean"]  = float(dns_ts.mean())
KPI["dns_tau"], KPI["dns_p"] = mann_kendall_tau(dns_ts)

# Email
KPI["dmarc_pass_mean"] = float(dmarc["PASS"].mean())
KPI["dkim_pass_mean"]  = float(dkim["PASS"].mean())
KPI["spf_pass_mean"]   = float(spf["PASS"].mean())
KPI["spf_fail_mean"]   = float(spf["FAIL"].mean())
KPI["spam_mean"]       = float(spam["SPAM"].mean())
KPI["spoof_mean"]      = float(spoof["SPOOF"].mean())
KPI["malicious_mean"]  = float(malic["MALICIOUS"].mean())
KPI["ISE_mean"]        = float(ISE.mean())
KPI["ISE_min"]         = float(ISE.min())
KPI["spoof_tau"], KPI["spoof_p"]     = mann_kendall_tau(spoof["SPOOF"])
KPI["malicious_tau"], KPI["malic_p"] = mann_kendall_tau(malic["MALICIOUS"])
KPI["spam_tau"], KPI["spam_p"]       = mann_kendall_tau(spam["SPAM"])

# HTTP/Protocol
KPI["ipv6_mean"]  = float(ipv6_g.mean())
KPI["http3_mean"] = float(http3_g.mean())
KPI["tls13_mean"] = float(tls13_g.mean())
KPI["bot_mean"]   = float(bot_g.mean())
KPI["ipv6_tau"], KPI["ipv6_p"]   = mann_kendall_tau(ipv6_g)
KPI["http3_tau"], KPI["http3_p"] = mann_kendall_tau(http3_g)

# L3
KPI["l3_udp_mean"]  = float(l3_proto["UDP"].mean())
KPI["l3_high_mean"] = float(l3_high.mean())
KPI["l3_udp_tau"], KPI["l3_udp_p"] = mann_kendall_tau(l3_proto["UDP"])

# L7
KPI["l7_it_mean"] = float(l7_it.mean())

# Phase I clusters
KPI["n_countries_analyzed"] = 247
KPI["n_clusters"]           = 4
KPI["imp_global_mean"]      = 43.8
KPI["imp_max"]              = 58.1
KPI["imp_min"]              = 21.8

# Phase J anomalies
KPI["n_ts_analyzed"]    = 21
KPI["n_anom_consensus"] = 42
KPI["n_multi_weeks"]    = 10
KPI["peak_week"]        = "2026-05-18"

# Phase K graph
KPI["g_asn_nodes"]     = 5287
KPI["g_asn_edges"]     = 5697
KPI["g_leak_nodes"]    = 2703
KPI["g_dual_role"]     = 302

# ══════════════════════════════════════════════════════════════════════════════
# 3. RAPPORT SYNTHÈSE
# ══════════════════════════════════════════════════════════════════════════════
print("  3/4 Génération rapport synthèse...")
lines = []

lines.append("# Rapport Phase L — Synthèse Finale")
lines.append("## Analyse Complète de la Sécurité Internet (Cloudflare Radar)")
lines.append("")
lines.append("**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  ")
lines.append("**Auteur :** Issakha Thiam  ")
lines.append(f"**Généré le :** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
lines.append("")
lines.append("---")

# ══ SECTION 0 — Vue d'ensemble
lines.append("## 0. Vue d'Ensemble du Projet")
lines.append("")
lines.append("| Aspect | Valeur |")
lines.append("|---|---|")
lines.append("| Dataset source | Cloudflare Radar API v4 |")
lines.append("| Période couverte | Juin 2025 – Juin 2026 (53 semaines) |")
lines.append("| Fichiers analysés | 25 CSV nettoyés |")
lines.append("| Lignes de données | ~2.9M |")
lines.append("| Pays couverts | 252 (HTTP/IQI) · 174 victimes BGP · 247 (clustering) |")
lines.append("| Phases d'analyse | A → L (12 phases) |")
lines.append("| Scripts Python | 9 scripts de ~300-400 lignes chacun |")
lines.append("| Rapports générés | 9 rapports Markdown (phases C → K) |")
lines.append("")
lines.append("---")

# ══ SECTION 1 — Dashboard KPI
lines.append("## 1. Dashboard — Indicateurs Clés de Performance (KPIs)")
lines.append("")
lines.append("### 1.1 Sécurité du Routage BGP")
lines.append("")
lines.append("| KPI | Valeur | Tendance | Risque |")
lines.append("|---|---|---|---|")
lines.append(f"| Hijacks BGP analysés | {int(KPI['bgp_n_hijacks']):,} | — | ⚠️ |")
lines.append(f"| Leaks BGP analysés | {int(KPI['bgp_n_leaks']):,} | — | ⚠️ |")
lines.append(f"| Confiance moy. hijacks | {fv(KPI['bgp_conf_mean'],'.1f')}/12 | — | 🟡 |")
lines.append(f"| Hijacks avec RPKI invalide | {fv(KPI['bgp_rpki_inv_pct'],'.1f')}% | — | 🔴 Critique |")
lines.append(f"| Durée médiane hijack | {fv(KPI['bgp_dur_median_h'],'.1f')} h | — | 🟡 |")
lines.append(f"| Durée max hijack | {fv(KPI['bgp_dur_max_h'],'.0f')} h = {fv(KPI['bgp_dur_max_h']/24,'.0f')} jours | — | 🔴 |")
lines.append(f"| Pays hijackeurs | {int(KPI['bgp_n_hijack_countries'])} | — | 🟡 |")
lines.append(f"| ASNs à double rôle (hij+leak) | {int(KPI['bgp_dual_role_asns'])} | — | ⚠️ |")
lines.append("")

lines.append("### 1.2 Qualité DNS")
lines.append("")
lines.append("| KPI | Valeur | Tendance | Risque |")
lines.append("|---|---|---|---|")
lines.append(f"| DNS qualité (IQI p50 moyen) | {fv(KPI['dns_mean'],'.4f')} | {trend_symbol(KPI['dns_tau'], KPI['dns_p'])} (τ={fv(KPI['dns_tau'],'.2f')}) | 🟢 En amélioration |")
lines.append("")

lines.append("### 1.3 Sécurité Email")
lines.append("")
lines.append("| KPI | Valeur | Tendance | Risque |")
lines.append("|---|---|---|---|")
lines.append(f"| DMARC PASS% | {fv(KPI['dmarc_pass_mean'],'.1f')}% | → stable | 🟢 |")
lines.append(f"| DKIM PASS% | {fv(KPI['dkim_pass_mean'],'.1f')}% | ↑ hausse modérée | 🟢 |")
lines.append(f"| SPF PASS% | {fv(KPI['spf_pass_mean'],'.1f')}% | ↑ hausse forte | 🟢 |")
lines.append(f"| SPF FAIL% | {fv(KPI['spf_fail_mean'],'.1f')}% | ↓ baisse | 🟡 |")
lines.append(f"| SPAM% | {fv(KPI['spam_mean'],'.1f')}% | {trend_symbol(KPI['spam_tau'], KPI['spam_p'])} (τ={fv(KPI['spam_tau'],'.2f')}) | 🟡 |")
lines.append(f"| SPOOF% | {fv(KPI['spoof_mean'],'.1f')}% | {trend_symbol(KPI['spoof_tau'], KPI['spoof_p'])} (τ={fv(KPI['spoof_tau'],'.2f')}) | 🔴 CRITIQUE |")
lines.append(f"| MALICIOUS% | {fv(KPI['malicious_mean'],'.1f')}% | {trend_symbol(KPI['malicious_tau'], KPI['malic_p'])} (τ={fv(KPI['malicious_tau'],'.2f')}) | 🔴 CRITIQUE |")
lines.append(f"| ISE (index global) | {fv(KPI['ISE_mean'],'.1f')}/100 | ↓ légère dégradation | 🟡 |")
lines.append(f"| ISE minimum observé | {fv(KPI['ISE_min'],'.1f')}/100 (semaine {KPI['peak_week']}) | — | 🔴 |")
lines.append("")

lines.append("### 1.4 Maturité Protocolaire (HTTP)")
lines.append("")
lines.append("| KPI | Valeur | Tendance | Risque |")
lines.append("|---|---|---|---|")
lines.append(f"| IPv6 adoption globale | {fv(KPI['ipv6_mean'],'.1f')}% | {trend_symbol(KPI['ipv6_tau'], KPI['ipv6_p'])} (τ={fv(KPI['ipv6_tau'],'.2f')}) | 🟡 |")
lines.append(f"| HTTP/3 adoption | {fv(KPI['http3_mean'],'.1f')}% | {trend_symbol(KPI['http3_tau'], KPI['http3_p'])} (τ={fv(KPI['http3_tau'],'.2f')}) | 🟡 |")
lines.append(f"| TLS 1.3 adoption | {fv(KPI['tls13_mean'],'.1f')}% | → stable | 🟢 |")
lines.append(f"| Bot rate globale | {fv(KPI['bot_mean'],'.1f')}% | ↑ hausse modérée | 🟡 |")
lines.append(f"| IMP pays moyen | {fv(KPI['imp_global_mean'],'.1f')}/100 | — | 🟡 |")
lines.append(f"| IMP pays max/min | {fv(KPI['imp_max'],'.1f')} / {fv(KPI['imp_min'],'.1f')} | — | — |")
lines.append("")

lines.append("### 1.5 Attaques L3/L7")
lines.append("")
lines.append("| KPI | Valeur | Tendance | Risque |")
lines.append("|---|---|---|---|")
lines.append(f"| L3 UDP% moyen | {fv(KPI['l3_udp_mean'],'.1f')}% | {trend_symbol(KPI['l3_udp_tau'], KPI['l3_udp_p'])} (τ={fv(KPI['l3_udp_tau'],'.2f')}) | 🟡 |")
lines.append(f"| L3 attaques haut volume (>1 Gbps)% | {fv(KPI['l3_high_mean'],'.1f')}% | ↑ hausse | 🟠 |")
lines.append(f"| L7 Internet&Télécom% | {fv(KPI['l7_it_mean'],'.1f')}% | ↑ hausse forte | 🔴 |")
lines.append("")

lines.append("### 1.6 Anomalies & Graphe Réseau")
lines.append("")
lines.append("| KPI | Valeur |")
lines.append("|---|---|")
lines.append(f"| Séries analysées (Phase J) | {int(KPI['n_ts_analyzed'])} |")
lines.append(f"| Anomalies consensus (≥2 méthodes) | **{int(KPI['n_anom_consensus'])}** |")
lines.append(f"| Semaines multi-domaines anormales | **{int(KPI['n_multi_weeks'])}** |")
lines.append(f"| Semaine la plus critique | **{KPI['peak_week']}** (6 domaines anormaux) |")
lines.append(f"| Nœuds graphe BGP (ASNs) | {int(KPI['g_asn_nodes']):,} |")
lines.append(f"| Arêtes graphe BGP | {int(KPI['g_asn_edges']):,} |")
lines.append(f"| Pays analysés (clustering) | {int(KPI['n_countries_analyzed'])} |")
lines.append(f"| Clusters géographiques | {int(KPI['n_clusters'])} |")
lines.append("")
lines.append("---")

# ══ SECTION 2 — Synthèse par phase
lines.append("## 2. Synthèse des Résultats par Phase")
lines.append("")

PHASE_SUMMARIES = {
    "C — Analyse Temporelle": [
        f"53 semaines (juin 2025 – juin 2026), 23 séries analysées",
        f"DNS qualité : forte hausse τ=+0.85 (R²=0.92) — tendance structurelle",
        f"SPOOF : forte hausse τ=+0.63 · MALICIOUS : τ=+0.73 — dégradation email",
        f"Anomalie S50 (2026-05-18) : pics simultanés DMARC FAIL + SPF FAIL + SPOOF + MALICIOUS",
        f"Mobile : τ=-0.75 (baisse) · IPv6 : τ=+0.54 (hausse)",
    ],
    "D — Analyse Géographique": [
        f"252 pays analysés, filtre MIN_WEEKS=20",
        f"IPv6 : moy. 19.9% (σ=19.3%), 17 pays >50%, 72 pays <5%",
        f"HTTP/3 : Laos leader (40.4%) — paradoxe pays émergents",
        f"Bot max : Gibraltar (90.7%) — infrastructure financière offshore",
        f"IMP #1 : Sri Lanka (64.9), Grèce (64.5), Inde (64.3)",
        f"BGP : US+CN+RU = 38.8% hijacks ; US = top hijackeur ET victime",
        f"7 pays avec TLS 1.0 ≥ 5% (vulnérabilités BEAST/POODLE)",
    ],
    "E — Attaques L3/L7": [
        f"L3 (53 semaines) : UDP 74% moy., hausse τ=+0.23",
        f"57.1% attaques <500 Mbps ; attaques 1-10 Gbps en hausse τ=+0.33",
        f"L3 IPv4 : 99.73% (botnets évitent IPv6)",
        f"L7 (85 jours) : Computer & Electronics (22.8%) + Internet & Telecom (22.4%) = 45% cibles",
        f"Internet & Telecom en hausse forte τ=+0.50",
        f"GET flood 82% mais en baisse ; POST en hausse τ=+0.43",
    ],
    "F — Sécurité Email": [
        f"DMARC PASS 87.9% stable · DKIM PASS 89.4% hausse τ=+0.25",
        f"SPF PASS 79.0% hausse τ=+0.37 · SPF FAIL 16.3% (le plus élevé)",
        f"SPAM 6.2% baisse τ=-0.44 · SPOOF 17.2% hausse τ=+0.63 · MALICIOUS 10.8% hausse τ=+0.73",
        f"ISE : 80.1/100 moy., légère baisse τ=-0.22",
        f"Anomalie S50 (2026-05-18) : ISE=68.4 (Z=-4.06) — pire semaine",
        f"Causalité Granger SPOOF→MALICIOUS confirmée (p<0.05)",
    ],
    "G — BGP Hijacks & Leaks": [
        f"20,000 hijacks (déc.2025–juin 2026) · 19,999 leaks (mars–juin 2026)",
        f"RPKI invalide : 56.3% des hijacks, IRR invalide : 76.5%",
        f"Durée médiane hijack : 1.9h · max : 2533h = 106 jours",
        f"Top pays hijackeur : US (23.5%) · Top victime : US (26.4%)",
        f"Sévérité critique : 18.7% des events (conf≥9, préf. moy. 11.5, durée 47h)",
        f"302 ASNs jouant les deux rôles (hijackeur + leaker)",
        f"582 leaks encore actifs (2.9%) à la fin de la période",
    ],
    "H — Corrélations Inter-Domaines": [
        f"29 variables × 29 : 40 paires inter-domaines significatives (p<0.05)",
        f"4 causalités Granger inter-domaines confirmées sur 10 testées",
        f"Corrélation #1 : SPOOF% ↔ IVC (r=0.85)",
        f"BGP RPKI inv% ↔ L7 Internet&Télécom (r=0.74)",
        f"DNS qualité ↔ MALICIOUS% (r=0.82) — découverte majeure",
        f"IVC global moy. : vulnérabilité composite en hausse sur période commune",
    ],
    "I — Clustering Géographique": [
        f"247 pays, 7 features protocolaires, k=4 clusters (silhouette=0.55 pour k=2)",
        f"Cluster Matures & Sécurisés : 111 pays, IMP 46.1/100, HTTP/3 29.9%",
        f"Cluster En développement avancé : 62 pays, IMP 43.1/100",
        f"Cluster Vulnérables intermédiaires : 59 pays, IMP 41.9%, IPv6 8.7%",
        f"Cluster Sous-équipés & à risque : 15 pays, IMP 37.6%, bot 60.0%",
        f"Inde #1 IMP parmi les grands pays (58.1/100)",
    ],
    "J — Détection d'Anomalies": [
        f"21 séries, 4 méthodes (Z-score, IQR, Isolation Forest, LOF)",
        f"42 anomalies consensus total · 10 semaines multi-domaines",
        f"Semaine 2026-05-18 : 6 domaines anormaux simultanément (pic historique)",
        f"Série la plus anomalique : SPOOF% (4 anomalies)",
        f"18 pays à profil protocolaire extrême (Isolation Forest)",
    ],
    "K — Graphe Réseau ASN": [
        f"Graphe hijacks : 5,287 nœuds, 5,697 arêtes, densité 0.000204",
        f"886 composantes connexes — structure très fragmentée",
        f"1,014 ASNs jouant les deux rôles (hijackeur + victime)",
        f"73.3% des hijackeurs : out-degree = 1 (attaque ponctuelle)",
        f"Graphe leaks : 2,703 nœuds, 5,795 arêtes, 1,848 leakers distincts",
        f"302 ASNs actifs à la fois dans hijacks ET leaks (infrastructure à risque)",
    ],
}

for phase, bullets in PHASE_SUMMARIES.items():
    lines.append(f"### Phase {phase}")
    lines.append("")
    for b in bullets:
        lines.append(f"- {b}")
    lines.append("")

lines.append("---")

# ══ SECTION 3 — Findings transversaux
lines.append("## 3. Findings Transversaux Majeurs")
lines.append("")

FINDINGS = [
    ("🔴 CRITIQUE", "Semaine 2026-05-18 : Crise Multi-Domaines",
     "La semaine du 18 mai 2026 est la plus critique de la période : 6 domaines anormaux simultanément "
     "(SPOOF, DMARC FAIL, SPF FAIL, SPAM, BGP volume, L3 haut vol.). "
     "L'ISE atteint son minimum (68.4/100, Z=-4.06). "
     "Aucune causalité unique n'a été identifiée — il s'agit d'une convergence de menaces."),

    ("🔴 CRITIQUE", "SPOOF% et MALICIOUS% en hausse structurelle",
     "Le spoofing email (τ=+0.63) et les emails malicieux (τ=+0.73) suivent des tendances à la hausse "
     "statistiquement significatives sur 53 semaines. La causalité Granger SPOOF→MALICIOUS est confirmée. "
     "Le spoofing email est précurseur des emails malicieux avec un délai de 1-2 semaines."),

    ("🔴 CRITIQUE", "RPKI insuffisamment déployé : 56.3% des hijacks violent des ROAs",
     "56.3% des 20,000 hijacks BGP violent des ROAs RPKI — signifiant que 43.7% des hijacks "
     "AURAIENT ECHAPPÉ à une détection RPKI seule. L'adoption du ROV (Route Origin Validation) "
     "reste incomplète et urgente."),

    ("🟠 ÉLEVÉ", "DNS qualité en forte hausse mais corrélée aux menaces email",
     "La DNS qualité (IQI) montre une forte hausse (τ=+0.85, R²=0.92) — signe d'une meilleure "
     "résolution DNS mondiale. Paradoxalement, elle est fortement corrélée à SPOOF% (r=0.74) et "
     "MALICIOUS% (r=0.82), suggérant que les acteurs malveillants utilisent de meilleures "
     "infrastructures DNS pour leurs opérations."),

    ("🟠 ÉLEVÉ", "L7 Internet & Télécom : cible prioritaire en hausse",
     "Le secteur Internet & Télécom représente 22.4% des cibles L7 et est en forte hausse (τ=+0.50). "
     "Combiné avec le secteur Informatique (22.8%), ces deux secteurs concentrent 45% des attaques L7."),

    ("🟡 MODÉRÉ", "BGP : Réseau très fragmenté, acteurs concentrés",
     "Le graphe BGP est extrêmement creux (densité 0.0002) avec 886 composantes connexes. "
     "Cependant, 73.3% des hijackeurs n'attaquent qu'une seule cible (out-degree=1) — "
     "majorité d'opportunistes, non de campagnes systématiques. Seuls 4 ASNs (0.2%) sont hyperactifs (≥50 victimes)."),

    ("🟡 MODÉRÉ", "Fracture numérique protocolaire : IMP 21.8 → 58.1/100",
     "L'écart d'IMP entre le pays le plus mature (Sri Lanka 58.1) et le moins avancé (21.8) "
     "révèle une fracture numérique systémique. 15 pays forment un cluster 'sous-équipé' "
     "(bot rate 60%, HTTP/3 5%) qui nécessite un accompagnement infrastructurel urgent."),

    ("🟡 MODÉRÉ", "IPv6 en hausse mais inégale : 17 pays >50%, 72 pays <5%",
     "IPv6 progresse globalement (τ=+0.54) mais avec une variance extrême. "
     "Le paradoxe HTTP/3 des pays émergents (Laos 40.4%, Somalie 38.7%) révèle "
     "l'adoption de stacks réseau mobiles modernes sans infrastructure IPv6 mature."),

    ("🟢 POSITIF", "Amélioration globale de la DNS qualité",
     "La DNS qualité suit une tendance à la hausse forte (τ=+0.85) sur toute la période — "
     "le meilleur signal positif du dataset. Cela indique un investissement continu "
     "des opérateurs dans la qualité de résolution DNS mondiale."),

    ("🟢 POSITIF", "SPF et DKIM en amélioration",
     "SPF PASS% (τ=+0.37) et DKIM PASS% (τ=+0.25) progressent — "
     "signe que les opérateurs email adoptent progressivement les standards anti-spoofing. "
     "Néanmoins, le SPF FAIL reste à 16.3% (trop élevé) et le SPOOF% augmente malgré ces progrès."),
]

for i, (level, title, detail) in enumerate(FINDINGS, 1):
    lines.append(f"### F{i}. {level} — {title}")
    lines.append("")
    lines.append(detail)
    lines.append("")

lines.append("---")

# ══ SECTION 4 — Recommandations
lines.append("## 4. Recommandations Stratégiques")
lines.append("")

RECS = [
    ("R1", "Déploiement RPKI/ROV en priorité absolue",
     "56.3% des hijacks BGP violent des ROAs RPKI mais ne sont pas bloqués par les ISPs. "
     "La mise en place du Route Origin Validation (ROV) chez les opérateurs tier-1 et tier-2 "
     "réduirait mécaniquement plus de la moitié des hijacks détectés. Rejoindre MANRS "
     "(Mutually Agreed Norms for Routing Security) devrait être une priorité gouvernementale.",
     "Court terme", "🔴"),

    ("R2", "Renforcement anti-spoofing email : DMARC enforcement",
     "Le SPOOF% (17.2%) en hausse structurelle (τ=+0.63) et la causalité Granger SPOOF→MALICIOUS "
     "indiquent que le spoofing est un vecteur d'entrée pour les emails malicieux. "
     "Passer de DMARC p=none à DMARC p=reject pour les domaines critiques. "
     "SPF FAIL à 16.3% doit être réduit par une meilleure gouvernance des enregistrements DNS.",
     "Court terme", "🔴"),

    ("R3", "Surveillance renforcée post-2026-05-18",
     "La semaine du 18 mai 2026 a montré que des crises multi-domaines simultanées sont possibles. "
     "Mettre en place un système d'alerte précoce basé sur l'IVC (Index de Vulnérabilité Composite) "
     "avec seuil d'alerte à IVC>70/100 et notification automatique.",
     "Court terme", "🟠"),

    ("R4", "Accélération IPv6 dans les pays à faible adoption",
     "72 pays ont moins de 5% d'IPv6 — cette fragmentation crée des obstacles à la transition "
     "vers des protocoles modernes. Les gouvernements devraient imposer des mandats IPv6 "
     "pour les fournisseurs d'accès internet financés par des fonds publics.",
     "Moyen terme", "🟡"),

    ("R5", "Sécurisation des ASNs à double rôle (hijackeurs + leakers)",
     "302 ASNs sont actifs à la fois dans des hijacks et des leaks — "
     "indicateur de mauvaise hygiène BGP. Ces ASNs devraient faire l'objet "
     "d'audits de configuration et de formation BGP (RIPE NCC, LACNIC, AFRINIC).",
     "Moyen terme", "🟡"),

    ("R6", "Monitoring L7 Internet & Télécom",
     "Le secteur Internet & Télécom est la cible principale et en forte hausse (τ=+0.50). "
     "Les opérateurs de ce secteur devraient déployer des protections anti-DDoS L7 "
     "(WAF, rate-limiting) et participer aux CERT sectoriels.",
     "Moyen terme", "🟡"),

    ("R7", "Programme d'accompagnement des pays en cluster 'Sous-équipés'",
     "15 pays forment un cluster avec bot rate 60%, HTTP/3 5% et IMP 37.6/100. "
     "Ces pays nécessitent un accompagnement technique pour moderniser leur pile réseau "
     "(IPv6, TLS 1.3, filtrage bot) — potentiellement via l'aide au développement numérique.",
     "Long terme", "🟢"),
]

lines.append("| Rec. | Titre | Horizon | Priorité |")
lines.append("|---|---|---|---|")
for rec_id, title, _, horizon, prio in RECS:
    lines.append(f"| {rec_id} | {title} | {horizon} | {prio} |")
lines.append("")

for rec_id, title, detail, horizon, prio in RECS:
    lines.append(f"### {rec_id} — {title}")
    lines.append(f"> Horizon : {horizon} | Priorité : {prio}")
    lines.append("")
    lines.append(detail)
    lines.append("")

lines.append("---")

# ══ SECTION 5 — Index des rapports
lines.append("## 5. Index des Rapports Générés")
lines.append("")
lines.append("| Phase | Fichier | Taille | Contenu |")
lines.append("|---|---|---|---|")

RAPPORT_INDEX = [
    ("C", "rapport_phase_C.md", "~53 Ko", "Analyse temporelle (23 séries, Mann-Kendall, ADF, STL, ARIMA)"),
    ("D", "rapport_phase_D.md", "~45 Ko", "Géographie (252 pays, HHI, IMP, top/bottom pays)"),
    ("E", "rapport_phase_E.md", "~54 Ko", "Attaques L3/L7 (protocoles, tailles, secteurs, méthodes HTTP)"),
    ("F", "rapport_phase_F.md", "~39 Ko", "Sécurité email (DMARC/DKIM/SPF/SPAM/SPOOF/MALICIOUS, ISE, Granger)"),
    ("G", "rapport_phase_G.md", "~29 Ko", "BGP hijacks & leaks (RPKI/IRR, ASN top, géographie, temporel)"),
    ("H", "rapport_phase_H.md", "~30 Ko", "Corrélations inter-domaines (29×29, Granger, CCF, IVC)"),
    ("I", "rapport_phase_I.md", "~33 Ko", "Clustering géographique (247 pays, PCA, k-means k=4)"),
    ("J", "rapport_phase_J.md", "~17 Ko", "Détection anomalies (Z, IQR, IForest, LOF, 21 séries)"),
    ("K", "rapport_phase_K.md", "~18 Ko", "Graphe réseau ASN (5287 nœuds, PageRank, Betweenness, HITS)"),
    ("L", "rapport_phase_L_synthese.md", "~30 Ko", "Synthèse finale (KPIs, findings, recommandations)"),
]

for phase, fname, size, content in RAPPORT_INDEX:
    lines.append(f"| Phase {phase} | `{fname}` | {size} | {content} |")
lines.append("")

# ══ SECTION 6 — Méthodes
lines.append("## 6. Méthodes Statistiques Utilisées")
lines.append("")
lines.append("| Méthode | Phase(s) | Objectif |")
lines.append("|---|---|---|")
METHODS = [
    ("Mann-Kendall τ", "C, H, L", "Détection de tendances monotones non-paramétriques"),
    ("ADF (Augmented Dickey-Fuller)", "C", "Test de stationnarité des séries temporelles"),
    ("OLS (régression linéaire)", "C", "Quantification de la tendance (pente, R²)"),
    ("STL (Seasonal-Trend Decomposition)", "C", "Décomposition tendance/saisonnalité/résidu"),
    ("ARIMA (AIC selection)", "C", "Modélisation et prévision à court terme"),
    ("CCF (Cross-Correlation Function)", "C, F, H", "Lag optimal entre deux séries"),
    ("Granger Causality (F-test)", "C, F, H", "Test de causalité temporelle inter-séries"),
    ("Z-score (|z|≥2.5)", "C, J", "Détection d'anomalies univariées"),
    ("IQR (×2.0)", "J", "Détection d'anomalies robuste aux queues"),
    ("Isolation Forest", "I, J", "Détection d'anomalies multi-variées"),
    ("Local Outlier Factor (LOF)", "J", "Détection d'outliers basée sur densité locale"),
    ("Spearman ρ", "H", "Corrélation non-paramétrique inter-séries"),
    ("Herfindahl-Hirschman Index (HHI)", "D", "Concentration géographique des protocoles"),
    ("PCA (Analyse en Composantes Principales)", "I", "Réduction dimensionnelle features pays"),
    ("K-Means Clustering", "I", "Segmentation pays par profil protocolaire"),
    ("Silhouette Score", "I", "Sélection du nombre optimal de clusters"),
    ("PageRank", "K", "Influence des ASNs dans le graphe de hijack"),
    ("Betweenness Centrality", "K", "ASNs pivot dans le graphe de routage"),
    ("HITS (Hubs & Authorities)", "K", "Identification hijackeurs systématiques vs victimes structurelles"),
]
for m, p, o in METHODS:
    lines.append(f"| {m} | {p} | {o} |")
lines.append("")

lines.append("---")
lines.append("## 7. Conclusion")
lines.append("")
lines.append("Cette étude de la sécurité internet sur 53 semaines (juin 2025 – juin 2026) via Cloudflare Radar "
             "révèle un **écosystème internet sous tension croissante** :")
lines.append("")
lines.append("**Sur les menaces :** Le routage BGP reste vulnérable (56% des hijacks violent les ROAs RPKI), "
             "le spoofing email progresse structurellement (+63% en tendance), et les attaques L7 ciblent "
             "de plus en plus les opérateurs télécom. La semaine du 18 mai 2026 constitue un épisode de "
             "crise multi-dimensionnelle sans précédent dans le dataset.")
lines.append("")
lines.append("**Sur les défenses :** La qualité DNS s'améliore fortement (+85% en tendance), "
             "les protocoles de messagerie (SPF, DKIM) progressent modestement, "
             "et l'adoption IPv6 continue sa hausse. Ces signes positifs restent insuffisants "
             "face à la dynamique offensive.")
lines.append("")
lines.append("**Sur les inégalités :** La fracture entre pays matures (IMP 58/100) et "
             "pays sous-équipés (IMP 22/100) est systémique. 72 pays ont moins de 5% d'IPv6 "
             "et 15 pays forment un cluster à risque élevé nécessitant un accompagnement international.")
lines.append("")
lines.append("La priorité absolue est l'accélération du déploiement RPKI/ROV et le renforcement "
             "de l'application DMARC, deux mesures à fort impact et faible coût d'implémentation "
             "pour les opérateurs disposant des ressources nécessaires.")
lines.append("")
lines.append("---")
lines.append(f"*Rapport de synthèse généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} par `phase_L_synthese.py`.*  ")
lines.append("*Projet : Analyse de sécurité internet — Cloudflare Radar API v4.*  ")
lines.append("*Issakha Thiam — Issakha.THIAM@uca.fr*")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

size_kb = os.path.getsize(OUT) / 1024
print(f"\nRapport écrit : {OUT}")
print(f"Taille : {size_kb:.1f} Ko")
print(f"Lignes : {len(lines)}")
