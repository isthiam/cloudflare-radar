"""
Phase B — Statistiques Descriptives Globales
Cloudflare Radar Dataset — Juin 2025 / Juin 2026
Auteur    : Issakha Thiam
"""

import pandas as pd
import numpy as np
import warnings
from pathlib import Path
from datetime import datetime

warnings.filterwarnings("ignore")
pd.set_option("display.float_format", "{:.4f}".format)

BASE   = Path(r"E:\Webscraping\cloudflare_radar_vulnerabilite\scripts\outputs_complet")
CLEAN  = BASE / "cleaned"
NOW    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ─── UTILITAIRES ─────────────────────────────────────────────────────────────

def load(name):
    return pd.read_csv(CLEAN / f"{name}_clean.csv", low_memory=False)

def full_stats(series, label=None):
    s = series.dropna()
    if len(s) == 0:
        return {}
    cv = round(float(s.std() / s.mean() * 100), 2) if s.mean() != 0 else np.nan
    return {
        "variable": label or series.name,
        "n":        len(s),
        "n_na":     int(series.isna().sum()),
        "mean":     round(float(s.mean()), 4),
        "median":   round(float(s.median()), 4),
        "std":      round(float(s.std()), 4),
        "cv_pct":   cv,
        "min":      round(float(s.min()), 4),
        "p5":       round(float(s.quantile(0.05)), 4),
        "p25":      round(float(s.quantile(0.25)), 4),
        "p75":      round(float(s.quantile(0.75)), 4),
        "p95":      round(float(s.quantile(0.95)), 4),
        "max":      round(float(s.max()), 4),
        "skew":     round(float(s.skew()), 4),
        "kurt":     round(float(s.kurt()), 4),
    }

def stats_table(rows):
    """Retourne une liste de lignes markdown pour un tableau de stats complet."""
    header = (
        "| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |"
    )
    sep = "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    lines = [header, sep]
    for r in rows:
        if not r:
            continue
        lines.append(
            f"| `{r['variable']}` | {r['n']:,} | {r['n_na']:,} | {r['mean']} | {r['median']} "
            f"| {r['std']} | {r['cv_pct']} | {r['min']} | {r['p5']} | {r['p25']} "
            f"| {r['p75']} | {r['p95']} | {r['max']} | {r['skew']} | {r['kurt']} |"
        )
    return lines

def corr_table(df, cols, method="spearman"):
    """Matrice de corrélation Spearman en markdown."""
    existing = [c for c in cols if c in df.columns]
    if len(existing) < 2:
        return []
    c = df[existing].corr(method=method).round(3)
    lines = []
    header = "| |" + "".join(f" `{col}` |" for col in existing)
    sep    = "|---|" + "".join(" ---:|" for _ in existing)
    lines += [header, sep]
    for row_label in existing:
        vals = "".join(f" {c.loc[row_label, col]} |" for col in existing)
        lines.append(f"| `{row_label}` |{vals}")
    return lines

def pct_bar(value, total=100, width=20):
    """Mini barre ASCII proportionnelle."""
    filled = int(round(value / total * width))
    return "█" * filled + "░" * (width - filled)

def fmt(v, decimals=2):
    return f"{v:.{decimals}f}"

# ─── COLLECTE ────────────────────────────────────────────────────────────────

R = []   # lignes du rapport

def w(line=""):
    R.append(line)

# ═══════════════════════════════════════════════════════════════════════════════
w("# Rapport Phase B — Statistiques Descriptives Globales")
w(f"**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  ")
w(f"**Auteur :** Issakha Thiam  ")
w(f"**Généré le :** {NOW}  ")
w(f"**Données source :** répertoire `cleaned/` (25 fichiers CSV nettoyés — Phase A)")
w()

# ─── RÉSUMÉ EXÉCUTIF ─────────────────────────────────────────────────────────
w("---")
w("## 1. Résumé Exécutif — Chiffres Clés")
w()

# Pré-calcul de quelques indicateurs globaux
l3_proto   = load("attacks_l3_protocol")
l3_bitrate = load("attacks_l3_bitrate")
l7_method  = load("attacks_l7_http_method")
l7_vert    = load("attacks_l7_vertical")
em_dmarc   = load("email_dmarc")
em_dkim    = load("email_dkim")
em_spf     = load("email_spf")
em_spam    = load("email_spam")
em_spoof   = load("email_spoof")
em_malici  = load("email_malicious")
bgp_ts     = load("bgp_timeseries")
bgp_hij    = load("bgp_hijacks")
bgp_leak   = load("bgp_leaks")
dns_ts     = load("dns_timeseries")
http_bot   = load("http_bot_class")
http_brow  = load("http_browser_family")
http_dev   = load("http_device_type")
http_tls   = load("http_tls_version")
http_http  = load("http_http_version")
http_ipv   = load("http_ip_version")
http_os    = load("http_os")
iqi_bw     = load("iqi_bandwidth")
iqi_dns    = load("iqi_dns")

# Indicateurs clés
udp_mean   = round(l3_proto["UDP"].mean(), 1)
tcp_mean   = round(l3_proto["TCP"].mean(), 1)
get_mean   = round(l7_method["GET"].mean(), 1)
post_mean  = round(l7_method["POST"].mean(), 1)
dmarc_pass = round(em_dmarc["PASS"].mean(), 1)
dkim_pass  = round(em_dkim["PASS"].mean(), 1)
spf_pass   = round(em_spf["PASS"].mean(), 1)
spam_mean  = round(em_spam["SPAM"].mean(), 1)
malici_mean= round(em_malici["MALICIOUS"].mean(), 1)
spoof_mean = round(em_spoof["SPOOF"].mean(), 1)
bot_mean   = round(http_bot["bot"].mean(), 1)
chrome_m   = round(http_brow["chrome"].mean(), 1)
safari_m   = round(http_brow["safari"].mean(), 1)
mobile_m   = round(http_dev["mobile"].mean(), 1)
desktop_m  = round(http_dev["desktop"].mean(), 1)
tls13_m    = round(http_tls["TLS 1.3"].mean(), 1)
h2_m       = round(http_http["HTTP/2"].mean(), 1)
h3_m       = round(http_http["HTTP/3"].mean(), 1)
ipv6_m     = round(http_ipv["IPv6"].mean(), 1)
bw_median  = round(iqi_bw["p50"].median(), 1)
dns_median = round(iqi_dns["p50"].median(), 1)
n_hijacks  = len(bgp_hij)
n_leaks    = len(bgp_leak)
hij_dur_med= round(bgp_hij["duration"].median(), 0)
hij_conf_m = round(bgp_hij["confidence_score"].mean(), 2)
big_att    = round(l3_bitrate["OVER_100_GBPS"].mean(), 3)

w("### Attaques Réseau")
w(f"| Indicateur | Valeur |")
w(f"|---|---|")
w(f"| Protocole L3 dominant (52 semaines) | **UDP {udp_mean}%** vs TCP {tcp_mean}% |")
w(f"| Part des attaques L3 > 100 Gbps (moy.) | **{big_att}%** |")
w(f"| Méthode HTTP L7 dominante (85 jours) | **GET {get_mean}%** vs POST {post_mean}% |")
w(f"| Secteur le plus attaqué (L7) | **Informatique/Électronique** (~{round(l7_vert['Computer and Electronics'].mean(),1)}%) |")
w()

w("### Sécurité Email")
w(f"| Indicateur | Valeur |")
w(f"|---|---|")
w(f"| DMARC PASS (moy. annuelle) | **{dmarc_pass}%** |")
w(f"| DKIM PASS (moy. annuelle) | **{dkim_pass}%** |")
w(f"| SPF PASS (moy. annuelle) | **{spf_pass}%** |")
w(f"| Taux de spam (moy.) | **{spam_mean}%** |")
w(f"| Taux de spoofing (moy.) | **{spoof_mean}%** |")
w(f"| Taux malicieux (moy.) | **{malici_mean}%** |")
w()

w("### Infrastructure & Protocoles (253 pays, 52 semaines)")
w(f"| Indicateur | Valeur |")
w(f"|---|---|")
w(f"| Trafic bot global (moy. par pays) | **{bot_mean}%** |")
w(f"| Part IPv6 global (moy. par pays) | **{ipv6_m}%** |")
w(f"| Part TLS 1.3 global (moy. par pays) | **{tls13_m}%** |")
w(f"| Part HTTP/2 global (moy. par pays) | **{h2_m}%** |")
w(f"| Part HTTP/3 global (moy. par pays) | **{h3_m}%** |")
w(f"| Navigateur dominant : Chrome (moy.) | **{chrome_m}%** |")
w(f"| Navigateur n°2 : Safari (moy.) | **{safari_m}%** |")
w(f"| Appareil dominant : Mobile (moy.) | **{mobile_m}%** vs Desktop {desktop_m}% |")
w(f"| Bande passante médiane mondiale | **{bw_median} Mbps** (médiane des médianes pays) |")
w(f"| Latence DNS médiane mondiale | **{dns_median} ms** (médiane des médianes pays) |")
w()

w("### Incidents BGP")
w(f"| Indicateur | Valeur |")
w(f"|---|---|")
w(f"| Hijacks analysés | **{n_hijacks:,}** |")
w(f"| Leaks analysés | **{n_leaks:,}** |")
w(f"| Durée médiane d'un hijack | **{int(hij_dur_med)} secondes** |")
w(f"| Score de confiance moyen (hijacks) | **{hij_conf_m}/16** |")
w()

# ═══════════════════════════════════════════════════════════════════════════════
w("---")
w("## 2. Attaques Couche 3 (L3)")
w()

# B2.1 — Bitrate
w("### 2.1 Distribution de la Taille des Attaques L3 (bitrate)")
w(f"*52 semaines, granularité hebdomadaire. Valeurs en % du trafic d'attaque.*")
w()

bitrate_cols = ["UNDER_500_MBPS","_500_MBPS_TO_1_GBPS","_1_GBPS_TO_10_GBPS","_10_GBPS_TO_100_GBPS","OVER_100_GBPS"]
labels_bitrate = {
    "UNDER_500_MBPS":       "< 500 Mbps",
    "_500_MBPS_TO_1_GBPS":  "500 Mbps – 1 Gbps",
    "_1_GBPS_TO_10_GBPS":   "1 – 10 Gbps",
    "_10_GBPS_TO_100_GBPS": "10 – 100 Gbps",
    "OVER_100_GBPS":        "> 100 Gbps",
}
rows_br = [full_stats(l3_bitrate[c], labels_bitrate.get(c,c)) for c in bitrate_cols if c in l3_bitrate.columns]
R.extend(stats_table(rows_br))
w()

w("**Profil visuel (moyenne annuelle) :**")
w()
w("| Catégorie | Moy. % | Distribution |")
w("|---|---:|---|")
for c in bitrate_cols:
    if c in l3_bitrate.columns:
        m = l3_bitrate[c].mean()
        w(f"| {labels_bitrate.get(c,c)} | {m:.2f}% | `{pct_bar(m)}` |")
w()

# Observations
under_500 = l3_bitrate["UNDER_500_MBPS"].mean()
over_100  = l3_bitrate["OVER_100_GBPS"].mean()
over_100_max = l3_bitrate["OVER_100_GBPS"].max()
w(f"> **Observation :** {under_500:.1f}% des attaques L3 sont sous 500 Mbps (volumétrie limitée), "
  f"mais les méga-attaques (>100 Gbps) représentent en moyenne {over_100:.3f}% "
  f"(pic observé : {over_100_max:.3f}%). Les attaques 1–10 Gbps constituent la deuxième catégorie "
  f"({l3_bitrate['_1_GBPS_TO_10_GBPS'].mean():.1f}% en moyenne).")
w()

# B2.2 — Protocoles
w("### 2.2 Répartition Protocolaire des Attaques L3")
w(f"*52 semaines, granularité hebdomadaire. Valeurs en %.*")
w()

proto_cols = ["UDP","TCP","GRE","ICMP"]
rows_proto = [full_stats(l3_proto[c], c) for c in proto_cols if c in l3_proto.columns]
R.extend(stats_table(rows_proto))
w()

w("**Profil visuel (moyenne annuelle) :**")
w()
w("| Protocole | Moy. % | Min % | Max % | Distribution |")
w("|---|---:|---:|---:|---|")
for c in proto_cols:
    if c in l3_proto.columns:
        m = l3_proto[c].mean()
        mn = l3_proto[c].min()
        mx = l3_proto[c].max()
        w(f"| {c} | {m:.2f}% | {mn:.2f}% | {mx:.2f}% | `{pct_bar(m)}` |")
w()

w(f"> **Observation :** UDP domine massivement à {l3_proto['UDP'].mean():.1f}% (CV={round(l3_proto['UDP'].std()/l3_proto['UDP'].mean()*100,1)}%), "
  f"caractéristique des attaques volumétriques par réflexion/amplification. "
  f"TCP représente {l3_proto['TCP'].mean():.1f}% avec une variabilité notable (CV={round(l3_proto['TCP'].std()/l3_proto['TCP'].mean()*100,1)}%). "
  f"GRE ({l3_proto['GRE'].mean():.2f}%) et ICMP ({l3_proto['ICMP'].mean():.2f}%) restent marginaux.")
w()

# B2.3 — IP Version L3
w("### 2.3 Version IP dans les Attaques L3")
w()
l3_ip = load("attacks_l3_ip_version")
ipv4_mean = l3_ip["IPv4"].mean()
ipv6_mean = l3_ip["IPv6"].mean()

rows_ip3 = [full_stats(l3_ip[c], c) for c in ["IPv4","IPv6"] if c in l3_ip.columns]
R.extend(stats_table(rows_ip3))
w()
w(f"> **Observation :** IPv4 représente {ipv4_mean:.2f}% du vecteur d'attaque L3. "
  f"IPv6 (moy. {ipv6_mean:.2f}%) est très peu utilisé comme vecteur d'attaque, "
  f"alors qu'il représente {ipv6_m:.1f}% du trafic légitime par pays — "
  f"les attaquants restent principalement sur IPv4.")
w()

# ═══════════════════════════════════════════════════════════════════════════════
w("---")
w("## 3. Attaques Couche 7 (L7)")
w()

# B3.1 — Méthodes HTTP
w("### 3.1 Méthodes HTTP d'Attaque L7")
w(f"*85 jours (granularité quotidienne). Valeurs en %.*")
w()

http_method_cols = ["GET","POST","HEAD","OPTIONS","PATCH","DELETE","PUT","UNKNOWN","ACL"]
rows_hm = [full_stats(l7_method[c], c) for c in http_method_cols if c in l7_method.columns]
R.extend(stats_table(rows_hm))
w()

w("**Profil visuel (moyenne sur 85 jours) :**")
w()
w("| Méthode | Moy. % | Distribution |")
w("|---|---:|---|")
for c in http_method_cols:
    if c in l7_method.columns:
        m = l7_method[c].mean()
        if m > 0:
            w(f"| {c} | {m:.3f}% | `{pct_bar(m)}` |")
w()

w(f"> **Observation :** GET représente {l7_method['GET'].mean():.1f}% des requêtes DDoS L7 "
  f"(CV={round(l7_method['GET'].std()/l7_method['GET'].mean()*100,1)}%), "
  f"POST {l7_method['POST'].mean():.1f}%. "
  f"HEAD ({l7_method['HEAD'].mean():.2f}%) peut indiquer de la reconnaissance préalable. "
  f"Les méthodes destructives (PUT, DELETE, PATCH) représentent ensemble "
  f"{round(l7_method[['PUT','DELETE','PATCH']].sum(axis=1).mean(), 3):.3f}% — essentiellement négligeable.")
w()

# B3.2 — Versions HTTP L7
w("### 3.2 Versions HTTP dans les Attaques L7")
w()
l7_ver = load("attacks_l7_http_version")
http_ver_cols = ["HTTP/2","HTTP/1.x","HTTP/3"]
# colonnes réellement présentes avec données
existing_ver = [c for c in http_ver_cols if c in l7_ver.columns and l7_ver[c].notna().sum() > 0]
rows_hv = [full_stats(l7_ver[c], c) for c in existing_ver]
R.extend(stats_table(rows_hv))
w()

# Comparer avec trafic légitime
w("**Comparaison attaques L7 vs trafic légitime (HTTP par pays) :**")
w()
w("| Version HTTP | Attaques L7 (moy.) | Trafic légitime (moy. mondial) | Écart |")
w("|---|---:|---:|---:|")
for col, leg in [("HTTP/2", h2_m), ("HTTP/1.x", None), ("HTTP/3", h3_m)]:
    if col in l7_ver.columns and l7_ver[col].notna().sum() > 0:
        atk = round(l7_ver[col].mean(), 2)
        if leg is not None:
            ecart = round(atk - leg, 2)
            signe = "+" if ecart > 0 else ""
            w(f"| {col} | {atk}% | {leg}% | {signe}{ecart}% |")
        else:
            w(f"| {col} | {atk}% | N/D | — |")
w()

# B3.3 — Secteurs ciblés
w("### 3.3 Secteurs d'Activité Ciblés par les Attaques L7")
w(f"*85 jours. Répartition quotidienne des attaques par verticale.*")
w()

vert_cols = [
    "Computer and Electronics","Internet and Telecom","other",
    "Shopping & General Merchandise","Finance","Gambling",
    "News, Media, and Publications","Business and Industry",
    "Professional Services","Art, Entertainment & Recreation"
]
existing_vert = [c for c in vert_cols if c in l7_vert.columns and l7_vert[c].notna().sum() > 0]
rows_vt = [full_stats(l7_vert[c], c) for c in existing_vert]
R.extend(stats_table(rows_vt))
w()

# Ranking
w("**Ranking des secteurs (% moyen d'attaques reçues) :**")
w()
w("| Rang | Secteur | Moy. % | Min % | Max % | Distribution |")
w("|---:|---|---:|---:|---:|---|")
means_v = {c: l7_vert[c].mean() for c in existing_vert}
for rank, (c, m) in enumerate(sorted(means_v.items(), key=lambda x: -x[1]), 1):
    mn = l7_vert[c].min()
    mx = l7_vert[c].max()
    w(f"| {rank} | {c} | {m:.2f}% | {mn:.2f}% | {mx:.2f}% | `{pct_bar(m, total=30)}` |")
w()

# ═══════════════════════════════════════════════════════════════════════════════
w("---")
w("## 4. Sécurité Email")
w()

# B4.1 — DMARC
w("### 4.1 DMARC (Domain-based Message Authentication)")
w(f"*53 semaines. Valeurs en %.*")
w()
rows_dm = [full_stats(em_dmarc[c], f"DMARC {c}") for c in ["PASS","NONE","FAIL"] if c in em_dmarc.columns]
R.extend(stats_table(rows_dm))
w()

# B4.2 — DKIM
w("### 4.2 DKIM (DomainKeys Identified Mail)")
w()
rows_dk = [full_stats(em_dkim[c], f"DKIM {c}") for c in ["PASS","NONE","FAIL"] if c in em_dkim.columns]
R.extend(stats_table(rows_dk))
w()

# B4.3 — SPF
w("### 4.3 SPF (Sender Policy Framework)")
w()
rows_spf = [full_stats(em_spf[c], f"SPF {c}") for c in ["PASS","NONE","FAIL"] if c in em_spf.columns]
R.extend(stats_table(rows_spf))
w()

# Tableau comparatif DMARC / DKIM / SPF
w("### 4.4 Tableau Comparatif DMARC / DKIM / SPF")
w()
w("| Protocole | PASS moy. | PASS min | PASS max | FAIL moy. | FAIL max | NONE moy. |")
w("|---|---:|---:|---:|---:|---:|---:|")
for name_em, df_em in [("DMARC", em_dmarc), ("DKIM", em_dkim), ("SPF", em_spf)]:
    p_m = round(df_em["PASS"].mean(), 2)
    p_mn = round(df_em["PASS"].min(), 2)
    p_mx = round(df_em["PASS"].max(), 2)
    f_m = round(df_em["FAIL"].mean(), 2)
    f_mx = round(df_em["FAIL"].max(), 2)
    n_m = round(df_em["NONE"].mean(), 2)
    w(f"| **{name_em}** | **{p_m}%** | {p_mn}% | {p_mx}% | {f_m}% | {f_mx}% | {n_m}% |")
w()

# B4.5 — Spam, Spoofing, Malicieux
w("### 4.5 Spam, Spoofing et Courrier Malicieux")
w()
w("| Indicateur | N° positif (moy.) | N° positif (min) | N° positif (max) | Éc.-type | CV% |")
w("|---|---:|---:|---:|---:|---:|")
for label, df_e, col_pos in [
    ("Spam",      em_spam,   "SPAM"),
    ("Spoofing",  em_spoof,  "SPOOF"),
    ("Malicieux", em_malici, "MALICIOUS"),
]:
    s = df_e[col_pos]
    cv = round(s.std()/s.mean()*100, 1)
    w(f"| **{label}** | {s.mean():.2f}% | {s.min():.2f}% | {s.max():.2f}% | {s.std():.3f} | {cv}% |")
w()

# Matrice de corrélation email
w("### 4.6 Matrice de Corrélation (Spearman) entre Indicateurs Email")
w()
em_combined = pd.DataFrame({
    "DMARC_FAIL": em_dmarc["FAIL"],
    "DKIM_FAIL":  em_dkim["FAIL"],
    "SPF_FAIL":   em_spf["FAIL"],
    "SPAM":       em_spam["SPAM"],
    "SPOOF":      em_spoof["SPOOF"],
    "MALICIEUX":  em_malici["MALICIOUS"],
})
R.extend(corr_table(em_combined, list(em_combined.columns)))
w()
w("> **Lecture :** valeurs proches de 1 = corrélation positive forte, -1 = corrélation inverse forte.")
w()

# ═══════════════════════════════════════════════════════════════════════════════
w("---")
w("## 5. BGP (Border Gateway Protocol)")
w()

# B5.1 — Timeseries
w("### 5.1 BGP Timeseries — Volume Hebdomadaire de Routes")
w()
rows_bgpts = [full_stats(bgp_ts["values"], "Volume BGP (routes)")]
R.extend(stats_table(rows_bgpts))
w()
bgp_min_ts = pd.to_datetime(bgp_ts["date"]).min()
bgp_max_ts = pd.to_datetime(bgp_ts["date"]).max()
bgp_val_mn = bgp_ts["values"].min()
bgp_val_mx = bgp_ts["values"].max()
bgp_val_m  = bgp_ts["values"].mean()
bgp_trend  = round(bgp_ts["values"].iloc[-1] / bgp_ts["values"].iloc[0] * 100 - 100, 1)
w(f"> **Couverture :** {bgp_min_ts.date()} → {bgp_max_ts.date()} ({len(bgp_ts)} semaines)  ")
w(f"> **Volume :** moyenne {bgp_val_m:,.0f} | min {bgp_val_mn:,.0f} | max {bgp_val_mx:,.0f}  ")
w(f"> **Tendance :** variation semaine 1 → semaine 53 : **{'+' if bgp_trend>0 else ''}{bgp_trend}%**")
w()

# B5.2 — Hijacks
w("### 5.2 BGP Hijacks — Statistiques Descriptives (20 000 événements)")
w()
bij_numeric_cols = [
    "duration","hijack_msgs_count","peer_ip_count","on_going_count",
    "confidence_score","peer_asns_count","prefixes_count",
    "victim_asns_count","victim_countries_count","tags_total_score","tags_count"
]
rows_bh = [full_stats(bgp_hij[c], c) for c in bij_numeric_cols if c in bgp_hij.columns]
R.extend(stats_table(rows_bh))
w()

# Durée : catégorisation
bgp_hij["duration_cat"] = pd.cut(
    bgp_hij["duration"],
    bins=[-1, 0, 60, 3600, 86400, float("inf")],
    labels=["Instantané (0s)", "< 1 min", "1 min – 1h", "1h – 24h", "> 24h"]
)
dur_dist = bgp_hij["duration_cat"].value_counts().sort_index()
w("**Distribution de la durée des hijacks :**")
w()
w("| Catégorie | Nombre | % | Barre |")
w("|---|---:|---:|---|")
total_bij = len(bgp_hij)
for cat, cnt in dur_dist.items():
    pct = round(100 * cnt / total_bij, 2)
    w(f"| {cat} | {cnt:,} | {pct}% | `{pct_bar(pct, total=100, width=15)}` |")
w()

# Confidence score distribution
bgp_hij["conf_cat"] = pd.cut(
    bgp_hij["confidence_score"],
    bins=[-1, 3, 7, float("inf")],
    labels=["Faible (0–3)","Modérée (4–7)","Élevée (8+)"]
)
conf_dist = bgp_hij["conf_cat"].value_counts().sort_index()
w("**Distribution du score de confiance (0 = incertain, 16+ = très confiant) :**")
w()
w("| Niveau | Nombre | % |")
w("|---|---:|---:|")
for cat, cnt in conf_dist.items():
    pct = round(100 * cnt / total_bij, 2)
    w(f"| {cat} | {cnt:,} | {pct}% |")
w()

# Top pays hijackeurs
top_hijack_ctry = bgp_hij["hijacker_country"].value_counts().head(15)
w("**Top 15 pays d'origine des hijacks :**")
w()
w("| Rang | Pays | Nombre | % |")
w("|---:|---|---:|---:|")
for rank, (ctry, cnt) in enumerate(top_hijack_ctry.items(), 1):
    pct = round(100 * cnt / total_bij, 2)
    w(f"| {rank} | {ctry} | {cnt:,} | {pct}% |")
w()

# B5.3 — Leaks
w("### 5.3 BGP Leaks — Statistiques Descriptives (19 999 événements)")
w()
bl_numeric_cols = [
    "leak_count","peer_count","prefix_count","origin_count",
    "leak_seg_len","countries_count"
]
rows_bl = [full_stats(bgp_leak[c], c) for c in bl_numeric_cols if c in bgp_leak.columns]
R.extend(stats_table(rows_bl))
w()

# Finished vs On-going
if "finished" in bgp_leak.columns:
    fin_vals = bgp_leak["finished"].map({True: "Terminé", False: "En cours", "True": "Terminé", "False": "En cours"})
    fin_dist = fin_vals.value_counts()
    w("**Statut des événements de leak :**")
    w()
    w("| Statut | Nombre | % |")
    w("|---|---:|---:|")
    for st, cnt in fin_dist.items():
        pct = round(100 * cnt / len(bgp_leak), 2)
        w(f"| {st} | {cnt:,} | {pct}% |")
    w()

# Leak type
if "leak_type" in bgp_leak.columns:
    lt_dist = bgp_leak["leak_type"].value_counts()
    w("**Types de leak :**")
    w()
    w("| Type | Nombre | % |")
    w("|---|---:|---:|")
    for lt, cnt in lt_dist.items():
        pct = round(100 * cnt / len(bgp_leak), 2)
        w(f"| {lt} | {cnt:,} | {pct}% |")
    w()

# Top ASNs leak
top_leak_asn = bgp_leak["leak_asn"].value_counts().head(15)
w("**Top 15 ASNs à l'origine des leaks :**")
w()
w("| Rang | ASN | Nombre de leaks |")
w("|---:|---|---:|")
for rank, (asn, cnt) in enumerate(top_leak_asn.items(), 1):
    w(f"| {rank} | AS{int(asn)} | {cnt:,} |")
w()

# ═══════════════════════════════════════════════════════════════════════════════
w("---")
w("## 6. DNS Timeseries")
w()

rows_dns = [full_stats(dns_ts["values"], "Métrique DNS")]
R.extend(stats_table(rows_dns))
w()
dns_min_ts = pd.to_datetime(dns_ts["date"]).min()
dns_max_ts = pd.to_datetime(dns_ts["date"]).max()
dns_trend  = round(dns_ts["values"].iloc[-1] / dns_ts["values"].iloc[0] * 100 - 100, 2)
w(f"> **Couverture :** {dns_min_ts.date()} → {dns_max_ts.date()} ({len(dns_ts)} semaines)  ")
w(f"> **Plage :** {dns_ts['values'].min():.4f} – {dns_ts['values'].max():.4f} (ratio normalisé 0-1)  ")
w(f"> **Tendance :** variation S1 → S52 : **{'+' if dns_trend>0 else ''}{dns_trend}%**  ")
w(f"> **Interprétation :** métrique Cloudflare normalisée — valeur proche de 1 = qualité/volume optimal.")
w()

# ═══════════════════════════════════════════════════════════════════════════════
w("---")
w("## 7. Métriques HTTP par Pays (253 pays × 53 semaines)")
w()
w("> **Note :** les statistiques ci-dessous portent sur l'ensemble des observations pays×semaine "
  f"(~13 000 lignes par fichier, données {http_bot['country_iso2'].nunique()} pays distincts).")
w()

# B7.1 — Bot vs Humain
w("### 7.1 Trafic Bot vs Humain")
w()
rows_bot = [
    full_stats(http_bot["human"], "Trafic humain"),
    full_stats(http_bot["bot"],   "Trafic bot"),
]
R.extend(stats_table(rows_bot))
w()
w(f"> **Observation :** le trafic bot varie de {http_bot['bot'].min():.1f}% à {http_bot['bot'].max():.1f}% selon les pays et semaines "
  f"(CV = {round(http_bot['bot'].std()/http_bot['bot'].mean()*100,1)}%). "
  f"La distribution est fortement asymétrique (skew = {round(http_bot['bot'].skew(),2)}) : "
  f"la plupart des pays ont peu de bots mais quelques-uns ont des pics élevés.")
w()

# B7.2 — Navigateurs
w("### 7.2 Parts de Marché des Navigateurs")
w()
brow_cols = ["chrome","safari","edge","firefox","samsung","opera","ucbrowser","yandex","brave","coccoc"]
rows_brow = [full_stats(http_brow[c], c.capitalize()) for c in brow_cols if c in http_brow.columns]
R.extend(stats_table(rows_brow))
w()

w("**Ranking (moyenne mondiale, toutes observations) :**")
w()
w("| Rang | Navigateur | Moy. % | Médiane % | Barre |")
w("|---:|---|---:|---:|---|")
brow_means = {c: http_brow[c].mean() for c in brow_cols if c in http_brow.columns}
for rank, (c, m) in enumerate(sorted(brow_means.items(), key=lambda x: -x[1]), 1):
    med = http_brow[c].median()
    w(f"| {rank} | {c.capitalize()} | {m:.2f}% | {med:.2f}% | `{pct_bar(m)}` |")
w()

# B7.3 — OS
w("### 7.3 Systèmes d'Exploitation")
w()
os_cols = ["WINDOWS","ANDROID","MACOSX","IOS","LINUX","CHROMEOS","SMART_TV"]
rows_os = [full_stats(http_os[c], c) for c in os_cols if c in http_os.columns]
R.extend(stats_table(rows_os))
w()

w("**Ranking (moyenne mondiale) :**")
w()
w("| Rang | OS | Moy. % | Médiane % | Barre |")
w("|---:|---|---:|---:|---|")
os_means = {c: http_os[c].mean() for c in os_cols if c in http_os.columns}
for rank, (c, m) in enumerate(sorted(os_means.items(), key=lambda x: -x[1]), 1):
    med = http_os[c].median()
    w(f"| {rank} | {c} | {m:.2f}% | {med:.2f}% | `{pct_bar(m)}` |")
w()

# B7.4 — Device type
w("### 7.4 Types d'Appareils")
w()
dev_cols = ["desktop","mobile","other"]
rows_dev = [full_stats(http_dev[c], c.capitalize()) for c in dev_cols if c in http_dev.columns]
R.extend(stats_table(rows_dev))
w()
mob_vs_desk = round(http_dev["mobile"].mean() / http_dev["desktop"].mean() * 100, 1)
w(f"> **Observation :** mobile représente {mobile_m:.1f}% du trafic mondial en moyenne "
  f"({mob_vs_desk}% du niveau desktop). La variabilité est très élevée selon les pays "
  f"(CV mobile = {round(http_dev['mobile'].std()/http_dev['mobile'].mean()*100,1)}%).")
w()

# B7.5 — IP Version
w("### 7.5 Adoption IPv6 par Pays")
w()
rows_ipv = [
    full_stats(http_ipv["IPv6"], "IPv6"),
    full_stats(http_ipv["IPv4"], "IPv4"),
]
R.extend(stats_table(rows_ipv))
w()

# Déciles IPv6 par pays
ipv6_country = http_ipv.groupby("country_iso2")["IPv6"].mean().sort_values(ascending=False)
w("**Top 20 pays avec le plus fort taux d'adoption IPv6 :**")
w()
w("| Rang | Pays | Taux IPv6 moy. % |")
w("|---:|---|---:|")
for rank, (ctry, val) in enumerate(ipv6_country.head(20).items(), 1):
    w(f"| {rank} | {ctry} | {val:.2f}% |")
w()
w("**Bottom 10 pays avec le plus faible taux d'adoption IPv6 :**")
w()
w("| Rang | Pays | Taux IPv6 moy. % |")
w("|---:|---|---:|")
bottom_ipv6 = ipv6_country[ipv6_country > 0].tail(10)
for rank, (ctry, val) in enumerate(bottom_ipv6.items(), 1):
    w(f"| {rank} | {ctry} | {val:.2f}% |")
w()

# B7.6 — TLS
w("### 7.6 Versions TLS")
w()
tls_cols = ["TLS 1.3","TLS QUIC","TLS 1.2","TLS 1.1","TLS 1.0"]
rows_tls = [full_stats(http_tls[c], c) for c in tls_cols if c in http_tls.columns]
R.extend(stats_table(rows_tls))
w()

# Legacy TLS
tls10_high = http_tls[http_tls["TLS 1.0"] > 5]["country_iso2"].nunique() if "TLS 1.0" in http_tls.columns else 0
tls11_high = http_tls[http_tls["TLS 1.1"] > 5]["country_iso2"].nunique() if "TLS 1.1" in http_tls.columns else 0
w(f"> **Protocoles obsolètes :** {tls10_high} pays présentent un taux TLS 1.0 > 5% sur au moins une semaine. "
  f"{tls11_high} pays présentent un taux TLS 1.1 > 5%. "
  f"TLS 1.3 (moy. {tls13_m}%) et QUIC (moy. {round(http_tls['TLS QUIC'].mean(),1)}%) dominent.")
w()

# B7.7 — HTTP Version
w("### 7.7 Versions HTTP")
w()
hv_cols = ["HTTP/2","HTTP/1.x","HTTP/3"]
rows_hv2 = [full_stats(http_http[c], c) for c in hv_cols if c in http_http.columns]
R.extend(stats_table(rows_hv2))
w()
w(f"> **Observation :** HTTP/2 domine ({h2_m}% moy.), HTTP/3 est déjà à {h3_m}% moy. "
  f"HTTP/1.x reste à {round(http_http['HTTP/1.x'].mean(),1)}% moy. mais avec une très forte variabilité "
  f"(CV = {round(http_http['HTTP/1.x'].std()/http_http['HTTP/1.x'].mean()*100,1)}%) — "
  f"certains pays ou semaines dépendent encore massivement du protocole legacy.")
w()

# ═══════════════════════════════════════════════════════════════════════════════
w("---")
w("## 8. Qualité Internet — IQI (253 pays × 53 semaines)")
w()

# B8.1 — Bande Passante
w("### 8.1 Bande Passante (IQI Bandwidth, Mbps)")
w()
bw_cols = ["p25","p50","p75"]
rows_bw = [full_stats(iqi_bw[c], f"BW {c}") for c in bw_cols if c in iqi_bw.columns]
R.extend(stats_table(rows_bw))
w()

# Top/Bottom pays par bande passante médiane
bw_country = iqi_bw.groupby("country_iso2")["p50"].mean().dropna().sort_values(ascending=False)
w("**Top 20 pays avec la meilleure bande passante médiane (Mbps) :**")
w()
w("| Rang | Pays | BW médiane moy. (Mbps) |")
w("|---:|---|---:|")
for rank, (ctry, val) in enumerate(bw_country.head(20).items(), 1):
    w(f"| {rank} | {ctry} | {val:.2f} |")
w()

w("**Bottom 15 pays avec la plus faible bande passante médiane (Mbps) :**")
w()
w("| Rang | Pays | BW médiane moy. (Mbps) |")
w("|---:|---|---:|")
bw_bottom = bw_country.dropna()
bw_bottom = bw_bottom[bw_bottom > 0].tail(15)
for rank, (ctry, val) in enumerate(bw_bottom.items(), 1):
    w(f"| {rank} | {ctry} | {val:.2f} |")
w()

# Pays sans données BW
n_no_bw = (iqi_bw.groupby("country_iso2")["p50"].mean().isna()).sum()
w(f"> **Couverture :** {len(bw_country)} pays ont des données de bande passante, "
  f"{n_no_bw} pays n'ont aucune donnée (territoires isolés, pas de présence Cloudflare).")
w()

# B8.2 — DNS Quality
w("### 8.2 Qualité DNS (IQI DNS, ms)")
w()
dns_iq_cols = ["p25","p50","p75"]
rows_dnsiq = [full_stats(iqi_dns[c], f"DNS {c}") for c in dns_iq_cols if c in iqi_dns.columns]
R.extend(stats_table(rows_dnsiq))
w()

dns_country = iqi_dns.groupby("country_iso2")["p50"].mean().dropna().sort_values()
w("**Top 20 pays avec la meilleure latence DNS (médiane la plus faible, ms) :**")
w()
w("| Rang | Pays | Latence DNS médiane moy. (ms) |")
w("|---:|---|---:|")
for rank, (ctry, val) in enumerate(dns_country.head(20).items(), 1):
    w(f"| {rank} | {ctry} | {val:.2f} |")
w()

w("**Top 15 pays avec la latence DNS la plus élevée (ms) :**")
w()
w("| Rang | Pays | Latence DNS médiane moy. (ms) |")
w("|---:|---|---:|")
for rank, (ctry, val) in enumerate(dns_country.tail(15).sort_values(ascending=False).items(), 1):
    w(f"| {rank} | {ctry} | {val:.2f} |")
w()

# Corrélation IQI bandwidth ~ DNS
common_ctry = set(bw_country.index) & set(dns_country.index)
bw_c = bw_country.reindex(list(common_ctry))
dns_c = dns_country.reindex(list(common_ctry))
corr_bw_dns = round(float(pd.Series(bw_c.values).corr(pd.Series(dns_c.values), method="spearman")), 3)
w(f"> **Corrélation Spearman bande passante ~ latence DNS (par pays) : {corr_bw_dns}**  ")
w(f"> {'Corrélation négative modérée à forte : les pays avec une meilleure bande passante ont tendance à avoir une latence DNS plus faible.' if corr_bw_dns < -0.3 else 'Relation faible entre bande passante et latence DNS.'}")
w()

# ═══════════════════════════════════════════════════════════════════════════════
w("---")
w("## 9. Synthèse — Faits Saillants et Findings Clés")
w()

w("### 9.1 Attaques Réseau")
w(f"- **L3 :** UDP représente **{udp_mean}%** du vecteur d'attaque (amplification/réflexion). "
  f"Les petites attaques (<500 Mbps) sont les plus fréquentes (**{under_500:.0f}%**) "
  f"mais les méga-attaques (>100 Gbps) existent (moy. {over_100:.3f}%, pic {over_100_max:.3f}%).")
w(f"- **L7 :** GET domine à **{get_mean}%**. L'Informatique/Électronique subit **{round(l7_vert['Computer and Electronics'].mean(),1)}%** "
  f"des attaques applicatives. HTTP/2 et HTTP/1.x sont les protocoles d'attaque principaux.")
w(f"- **IPv4 vs IPv6 :** les attaques L3 sont à **{ipv4_mean:.1f}%** IPv4, "
  f"soit bien plus que la part IPv4 dans le trafic légitime ({round(100-ipv6_m,1)}%) — "
  f"les attaquants évitent IPv6.")
w()

w("### 9.2 Sécurité Email")
w(f"- DMARC est le protocole le plus efficace : **{dmarc_pass}%** PASS, "
  f"mais SPF reste défaillant (**{round(em_spf['FAIL'].mean(),1)}%** FAIL), "
  f"ce qui laisse une surface d'attaque réelle.")
w(f"- **{spam_mean}%** du trafic email est du spam, **{spoof_mean}%** du spoofing, "
  f"**{malici_mean}%** malicieux — ces métriques sont corrélées entre elles.")
w()

w("### 9.3 Protocoles Web & Infrastructure")
w(f"- TLS 1.3 (**{tls13_m}% moy.**) est désormais dominant ; les protocoles obsolètes "
  f"(TLS 1.0/1.1) subsistent dans quelques pays à infrastructure vieillissante.")
w(f"- HTTP/3 atteint **{h3_m}% moy.** — adoption significative mais hétérogène (CV élevé).")
w(f"- IPv6 : **{ipv6_m}%** moy. mondial, mais la médiane est {round(http_ipv['IPv6'].median(),1)}% "
  f"— distribution très asymétrique (quelques pays très avancés tirent la moyenne vers le haut).")
w(f"- Chrome (**{chrome_m}%**) et Android (**{round(http_os['ANDROID'].mean(),1)}%**) "
  f"dominent le Web mondial ; le mobile (**{mobile_m}%**) talonne le desktop (**{desktop_m}%**).")
w()

w("### 9.4 BGP & Routage")
w(f"- **{int(hij_dur_med)}s** de durée médiane pour un hijack BGP — la plupart sont brefs "
  f"({round(bgp_hij[bgp_hij['duration']<60].shape[0]/len(bgp_hij)*100,1)}% < 1 minute).")
w(f"- Score de confiance moyen **{hij_conf_m}/16** — les événements à haute confiance (8+) "
  f"représentent {round(bgp_hij[bgp_hij['confidence_score']>=8].shape[0]/len(bgp_hij)*100,1)}% des hijacks.")
w(f"- Chaque hijack implique en moyenne "
  f"{round(bgp_hij['prefixes_count'].mean(),1)} préfixes IP et "
  f"{round(bgp_hij['peer_asns_count'].mean(),1)} ASNs pairs.")
w()

w("### 9.5 Qualité Internet Mondiale")
w(f"- Bande passante : médiane mondiale **{bw_median} Mbps** mais distribution log-normale "
  f"(skew = {round(iqi_bw['p50'].skew(),2)}) — forte inégalité entre pays.")
w(f"- Latence DNS : médiane mondiale **{dns_median} ms** avec des valeurs jusqu'à "
  f"{round(iqi_dns['p50'].max(),0):.0f} ms dans les pays les plus défavorisés.")
w(f"- **{n_no_bw}** pays sans données IQI : territoires isolés ou non couverts par Cloudflare.")
w()

# ─── PIED DE PAGE ─────────────────────────────────────────────────────────────
w("---")
w(f"*Rapport généré automatiquement par `phase_B_descriptif.py` le {NOW}.*  ")
w(f"*Prochaine étape : Phase C — Analyse temporelle (séries chronologiques, STL, ARIMA).*")

# ─── ÉCRITURE ─────────────────────────────────────────────────────────────────
report_path = BASE / "rapport_phase_B.md"
with open(report_path, "w", encoding="utf-8") as f:
    f.write("\n".join(R))

print(f"\nRapport ecrit : {report_path}")
print(f"Taille : {round(report_path.stat().st_size / 1024, 1)} Ko")
print(f"Lignes : {len(R)}")
