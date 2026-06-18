# -*- coding: utf-8 -*-
"""
Étude 11 — Indice de Vulnérabilité par Pays (Exposition vs Expérience des Chocs)
Cloudflare Radar Dataset — Juin 2025 / Juin 2026
Auteur : Issakha Thiam
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import json
import ast
import warnings
import os

warnings.filterwarnings("ignore")

CLEANED = os.path.join(os.path.dirname(__file__), "cleaned")
OUT = os.path.dirname(__file__)
PYTHON = "C:/Users/issthiam/AppData/Local/Programs/Python/Python313/python.exe"

# ─────────────────────────────────────────────
# 1. CHARGEMENT DES DONNÉES
# ─────────────────────────────────────────────

def load_csv(name):
    path = os.path.join(CLEANED, name)
    df = pd.read_csv(path, parse_dates=["date"])
    df["date"] = pd.to_datetime(df["date"], utc=True).dt.normalize()
    return df

print("Chargement des données...")

tls      = load_csv("http_tls_version_clean.csv")
ipv      = load_csv("http_ip_version_clean.csv")
http_ver = load_csv("http_http_version_clean.csv")
bw       = load_csv("iqi_bandwidth_clean.csv")
dns      = load_csv("iqi_dns_clean.csv")
bgp_ts   = load_csv("bgp_timeseries_clean.csv")
l3       = load_csv("attacks_l3_bitrate_clean.csv")

# BGP hijacks — raw events (pas de colonne 'date' directe)
bgp_h = pd.read_csv(os.path.join(CLEANED, "bgp_hijacks_clean.csv"))
bgp_h["week"] = pd.to_datetime(bgp_h["min_hijack_ts"], errors="coerce", utc=True).dt.to_period("W").dt.start_time

# ─────────────────────────────────────────────
# 2. BGP HIJACKS PAR PAYS VICTIME PAR SEMAINE
# ─────────────────────────────────────────────

print("Traitement BGP hijacks par pays...")

rows = []
for _, row in bgp_h.dropna(subset=["week"]).iterrows():
    raw = row["victim_countries"]
    try:
        countries = json.loads(raw) if isinstance(raw, str) else []
    except Exception:
        try:
            countries = ast.literal_eval(raw)
        except Exception:
            countries = []
    for c in countries:
        rows.append({"date": row["week"], "country_iso2": str(c).strip(), "bgp_hijack": 1})

bgp_by_country = pd.DataFrame(rows)
if not bgp_by_country.empty:
    bgp_by_country["date"] = pd.to_datetime(bgp_by_country["date"], utc=True)
    bgp_by_country = (bgp_by_country
                      .groupby(["date", "country_iso2"], as_index=False)
                      .agg(bgp_hijacks_count=("bgp_hijack", "sum")))
else:
    bgp_by_country = pd.DataFrame(columns=["date", "country_iso2", "bgp_hijacks_count"])

# ─────────────────────────────────────────────
# 3. COMPOSANTES GLOBALES (ATTAQUES L3)
# ─────────────────────────────────────────────

print("Traitement attaques L3...")

l3_weekly = l3.copy()
l3_weekly["l3_intensity"] = (
    l3_weekly.get("OVER_100_GBPS", 0).fillna(0)
    + l3_weekly.get("_10_GBPS_TO_100_GBPS", 0).fillna(0) * 0.5
)

# ─────────────────────────────────────────────
# 4. FUSION SUR PAYS × SEMAINE
# ─────────────────────────────────────────────

print("Fusion des sources...")

# Base : tous les pays × semaines couverts par TLS (le plus complet)
base = tls[["date", "country_iso2", "TLS 1.3", "TLS QUIC", "TLS 1.2"]].copy()
base.columns = ["date", "country_iso2", "tls13", "quic", "tls12"]

base = base.merge(
    ipv[["date", "country_iso2", "IPv6", "IPv4"]],
    on=["date", "country_iso2"], how="left"
)
base = base.merge(
    http_ver[["date", "country_iso2", "HTTP/3"]],
    on=["date", "country_iso2"], how="left"
)
base = base.merge(
    bw[bw["metric"] == "BANDWIDTH"][["date", "country_iso2", "p25", "p50", "p75"]]
      .rename(columns={"p25": "bw_p25", "p50": "bw_p50", "p75": "bw_p75"}),
    on=["date", "country_iso2"], how="left"
)
base = base.merge(
    dns[dns["metric"] == "DNS"][["date", "country_iso2", "p50"]]
       .rename(columns={"p50": "dns_p50"}),
    on=["date", "country_iso2"], how="left"
)
base = base.merge(bgp_by_country, on=["date", "country_iso2"], how="left")
base["bgp_hijacks_count"] = base["bgp_hijacks_count"].fillna(0)

base = base.merge(
    l3_weekly[["date", "l3_intensity"]],
    on="date", how="left"
)

base = base.sort_values(["country_iso2", "date"]).reset_index(drop=True)

# ─────────────────────────────────────────────
# 5. CALCUL DES VARIATIONS TEMPORELLES (IExC local)
# ─────────────────────────────────────────────

print("Calcul des variations...")

base["bw_p50_lag"] = base.groupby("country_iso2")["bw_p50"].shift(1)
base["dns_p50_lag"] = base.groupby("country_iso2")["dns_p50"].shift(1)

# Chute de bande passante (positif si baisse)
base["bw_drop"] = ((base["bw_p50_lag"] - base["bw_p50"]) / base["bw_p50_lag"]).clip(lower=0)
# Pic de latence DNS (positif si hausse)
base["dns_spike"] = ((base["dns_p50"] - base["dns_p50_lag"]) / base["dns_p50_lag"]).clip(lower=0)

# ─────────────────────────────────────────────
# 6. NORMALISATION MIN-MAX [0,1]
# ─────────────────────────────────────────────

def minmax(s):
    mn, mx = s.min(), s.max()
    if mx == mn:
        return pd.Series(np.zeros(len(s)), index=s.index)
    return (s - mn) / (mx - mn)

print("Calcul des indices IEC et IExC...")

# --- IEC : Exposition aux chocs ---
# Plus le score est élevé, plus le pays est structurellement vulnérable

base["iec_ipv4"]   = minmax(base["IPv4"].fillna(50))          # dépendance IPv4
tls11 = base["TLS 1.1"] if "TLS 1.1" in base.columns else pd.Series(0, index=base.index)
tls10 = base["TLS 1.0"] if "TLS 1.0" in base.columns else pd.Series(0, index=base.index)
base["iec_tls_old"]= minmax(base["tls12"].fillna(10) + tls11.fillna(0) + tls10.fillna(0))
base["iec_no_h3"]  = minmax(100 - base["HTTP/3"].fillna(20))  # absence HTTP/3
base["iec_low_bw"] = minmax(-base["bw_p50"].fillna(base["bw_p50"].median()))  # faible bande passante
base["iec_dns_lat"]= minmax(base["dns_p50"].fillna(base["dns_p50"].median())) # forte latence DNS

IEC_COLS = ["iec_ipv4", "iec_tls_old", "iec_no_h3", "iec_low_bw", "iec_dns_lat"]
base["IEC"] = base[IEC_COLS].mean(axis=1)

# --- IExC : Expérience des chocs ---
# Plus le score est élevé, plus le pays a subi de chocs cette semaine

base["iexc_bw_drop"]  = minmax(base["bw_drop"].fillna(0))
base["iexc_dns_spike"]= minmax(base["dns_spike"].fillna(0))
base["iexc_bgp"]      = minmax(base["bgp_hijacks_count"])
base["iexc_l3"]       = minmax(base["l3_intensity"].fillna(0))

# 60% local (pays-spécifique), 40% global (même choc pour tous)
base["IExC_local"]  = base[["iexc_bw_drop", "iexc_dns_spike", "iexc_bgp"]].mean(axis=1)
base["IExC_global"] = base["iexc_l3"]
base["IExC"] = 0.6 * base["IExC_local"] + 0.4 * base["IExC_global"]

# Score composite de vulnérabilité
base["IVC2"] = (base["IEC"] + base["IExC"]) / 2

# ─────────────────────────────────────────────
# 7. EXPORT CSV
# ─────────────────────────────────────────────

cols_export = [
    "date", "country_iso2",
    "tls13", "quic", "tls12", "IPv6", "IPv4", "HTTP/3",
    "bw_p50", "dns_p50", "bgp_hijacks_count", "l3_intensity",
    "bw_drop", "dns_spike",
    "IEC", "IExC", "IVC2"
]
cols_export = [c for c in cols_export if c in base.columns]
out_csv = os.path.join(OUT, "etude11_pays_semaine_vulnerabilite.csv")
base[cols_export].to_csv(out_csv, index=False)
print(f"CSV exporté : {out_csv}  ({len(base):,} lignes, {base['country_iso2'].nunique()} pays)")

# ─────────────────────────────────────────────
# 8. STATISTIQUES
# ─────────────────────────────────────────────

from scipy import stats as sps

iec_mean = base.groupby("country_iso2")["IEC"].mean().sort_values(ascending=False)
iexc_mean = base.groupby("country_iso2")["IExC"].mean().sort_values(ascending=False)

rho, pval = sps.spearmanr(
    base["IEC"].dropna(),
    base["IExC"].loc[base["IEC"].dropna().index]
)

n_pays = base["country_iso2"].nunique()
n_weeks = base["date"].nunique()

print(f"\n=== RÉSULTATS ===")
print(f"Pays couverts : {n_pays} | Semaines : {n_weeks}")
print(f"Corrélation Spearman IEC↔IExC : ρ={rho:.3f}, p={pval:.4f}")
print(f"\nTop 10 pays les plus EXPOSÉS (IEC moyen) :")
print(iec_mean.head(10).to_string())
print(f"\nTop 10 pays ayant le plus SUBI (IExC moyen) :")
print(iexc_mean.head(10).to_string())

# Quadrants
country_avg = base.groupby("country_iso2")[["IEC", "IExC"]].mean()
m_iec  = country_avg["IEC"].median()
m_iexc = country_avg["IExC"].median()
q = {
    "Haute exposition, forts chocs" : country_avg[(country_avg.IEC >= m_iec) & (country_avg.IExC >= m_iexc)].shape[0],
    "Haute exposition, faibles chocs": country_avg[(country_avg.IEC >= m_iec) & (country_avg.IExC < m_iexc)].shape[0],
    "Faible exposition, forts chocs" : country_avg[(country_avg.IEC < m_iec)  & (country_avg.IExC >= m_iexc)].shape[0],
    "Faible exposition, faibles chocs": country_avg[(country_avg.IEC < m_iec) & (country_avg.IExC < m_iexc)].shape[0],
}
print("\nQuadrants pays :")
for k, v in q.items():
    print(f"  {k}: {v} pays")

# ─────────────────────────────────────────────
# 9. FIGURES
# ─────────────────────────────────────────────

print("\nGénération des figures...")
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9})

# ── Figure 1 : Heatmap IEC (30 pays × semaines) ──────────────────────────────

top30_iec = iec_mean.head(30).index.tolist()
pivot_iec = base[base["country_iso2"].isin(top30_iec)].pivot_table(
    index="country_iso2", columns="date", values="IEC"
)
pivot_iec = pivot_iec.reindex(top30_iec)
pivot_iec.columns = [str(c)[:10] for c in pivot_iec.columns]

fig, ax = plt.subplots(figsize=(16, 8))
im = ax.imshow(pivot_iec.values, aspect="auto", cmap="YlOrRd", vmin=0, vmax=1)
ax.set_yticks(range(len(pivot_iec.index)))
ax.set_yticklabels(pivot_iec.index, fontsize=8)
step = max(1, len(pivot_iec.columns) // 10)
ax.set_xticks(range(0, len(pivot_iec.columns), step))
ax.set_xticklabels(pivot_iec.columns[::step], rotation=45, ha="right", fontsize=7)
plt.colorbar(im, ax=ax, label="IEC [0–1]")
ax.set_title("Indice d'Exposition aux Chocs (IEC)\nTop 30 pays × 53 semaines", fontsize=12, fontweight="bold")
ax.set_xlabel("Semaine")
ax.set_ylabel("Pays")
plt.tight_layout()
plt.savefig(os.path.join(OUT, "etude11_heatmap_iec.png"), dpi=150, bbox_inches="tight")
plt.close()
print("  → etude11_heatmap_iec.png")

# ── Figure 2 : Heatmap IExC (30 pays × semaines) ─────────────────────────────

top30_iexc = iexc_mean.head(30).index.tolist()
pivot_iexc = base[base["country_iso2"].isin(top30_iexc)].pivot_table(
    index="country_iso2", columns="date", values="IExC"
)
pivot_iexc = pivot_iexc.reindex(top30_iexc)
pivot_iexc.columns = [str(c)[:10] for c in pivot_iexc.columns]

fig, ax = plt.subplots(figsize=(16, 8))
im = ax.imshow(pivot_iexc.values, aspect="auto", cmap="PuBu", vmin=0, vmax=1)
ax.set_yticks(range(len(pivot_iexc.index)))
ax.set_yticklabels(pivot_iexc.index, fontsize=8)
step = max(1, len(pivot_iexc.columns) // 10)
ax.set_xticks(range(0, len(pivot_iexc.columns), step))
ax.set_xticklabels(pivot_iexc.columns[::step], rotation=45, ha="right", fontsize=7)
plt.colorbar(im, ax=ax, label="IExC [0–1]")
ax.set_title("Indice d'Expérience des Chocs (IExC)\nTop 30 pays × 53 semaines", fontsize=12, fontweight="bold")
ax.set_xlabel("Semaine")
ax.set_ylabel("Pays")
plt.tight_layout()
plt.savefig(os.path.join(OUT, "etude11_heatmap_iexc.png"), dpi=150, bbox_inches="tight")
plt.close()
print("  → etude11_heatmap_iexc.png")

# ── Figure 3 : Scatter IEC vs IExC par pays ──────────────────────────────────

ca = base.groupby("country_iso2")[["IEC", "IExC"]].mean().dropna()

fig, ax = plt.subplots(figsize=(10, 8))
ax.scatter(ca["IEC"], ca["IExC"], alpha=0.6, s=40, color="#2C7BB6", edgecolors="white", linewidths=0.5)

med_iec  = ca["IEC"].median()
med_iexc = ca["IExC"].median()
ax.axvline(med_iec,  color="red",    linestyle="--", alpha=0.5, lw=1.2)
ax.axhline(med_iexc, color="orange", linestyle="--", alpha=0.5, lw=1.2)

# Annoter les extrêmes
for iso, row in ca.nlargest(8, "IEC").iterrows():
    ax.annotate(iso, (row["IEC"], row["IExC"]), fontsize=7, color="#D7191C",
                xytext=(3, 3), textcoords="offset points")
for iso, row in ca.nlargest(8, "IExC").iterrows():
    ax.annotate(iso, (row["IEC"], row["IExC"]), fontsize=7, color="#1A9641",
                xytext=(3, 3), textcoords="offset points")

ax.text(med_iec * 1.01, ca["IExC"].max() * 0.97,
        "Haute exposition\nforts chocs", fontsize=8, color="gray")
ax.text(ca["IEC"].min(), ca["IExC"].max() * 0.97,
        "Faible exposition\nforts chocs", fontsize=8, color="gray")
ax.text(med_iec * 1.01, ca["IExC"].min() + 0.01,
        "Haute exposition\nfaibles chocs", fontsize=8, color="gray")
ax.text(ca["IEC"].min(), ca["IExC"].min() + 0.01,
        "Faible exposition\nfaibles chocs", fontsize=8, color="gray")

ax.set_xlabel("IEC — Indice d'Exposition aux Chocs", fontsize=10)
ax.set_ylabel("IExC — Indice d'Expérience des Chocs", fontsize=10)
ax.set_title(f"Exposition vs Expérience des Chocs par pays\nρ={rho:.3f} (Spearman, p={pval:.4f})",
             fontsize=12, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT, "etude11_scatter_iec_iexc.png"), dpi=150, bbox_inches="tight")
plt.close()
print("  → etude11_scatter_iec_iexc.png")

# ── Figure 4 : Évolution temporelle mondiale IEC + IExC ──────────────────────

weekly_global = base.groupby("date")[["IEC", "IExC", "IVC2"]].mean()

fig, ax = plt.subplots(figsize=(13, 5))
ax.plot(weekly_global.index, weekly_global["IEC"],  color="#D7191C", lw=2, label="IEC (Exposition)")
ax.plot(weekly_global.index, weekly_global["IExC"], color="#2C7BB6", lw=2, label="IExC (Expérience)")
ax.plot(weekly_global.index, weekly_global["IVC2"], color="#756BB1", lw=1.5, linestyle="--",
        label="IVC2 (Composite)", alpha=0.8)
ax.fill_between(weekly_global.index, weekly_global["IEC"],
                weekly_global["IExC"], alpha=0.07, color="gray")
ax.set_xlabel("Semaine")
ax.set_ylabel("Indice [0–1]")
ax.set_title("Évolution mondiale IEC & IExC — Juin 2025 / Juin 2026", fontsize=12, fontweight="bold")
ax.legend(framealpha=0.9)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUT, "etude11_series_globales.png"), dpi=150, bbox_inches="tight")
plt.close()
print("  → etude11_series_globales.png")

# ─────────────────────────────────────────────
# 10. RAPPORT MARKDOWN
# ─────────────────────────────────────────────

print("\nGénération du rapport...")

iec_stats = iec_mean.describe()
iexc_stats = iexc_mean.describe()

top5_iec  = iec_mean.head(5)
top5_iexc = iexc_mean.head(5)
bot5_iec  = iec_mean.tail(5)

# Pays les plus exposés mais peu choqués (résilients malgré exposition)
resilient = ca.copy()
resilient["ecart"] = resilient["IEC"] - resilient["IExC"]
resilient_top = resilient.nlargest(5, "ecart")
# Pays peu exposés mais beaucoup choqués (surpris)
surprised = resilient.nsmallest(5, "ecart")

lines = []
W = lines.append

W("# Étude 11 — Indice de Vulnérabilité par Pays : Exposition vs Expérience des Chocs")
W(f"**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  ")
W(f"**Auteur :** Issakha Thiam  ")
W(f"**Généré le :** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
W("")
W("---")
W("")
W("## 1. Cadre conceptuel")
W("")
W("Cette étude distingue deux dimensions orthogonales de la vulnérabilité internet par pays :")
W("")
W("| Dimension | Définition | Variables |")
W("|-----------|------------|-----------|")
W("| **IEC** — Indice d'Exposition aux Chocs | Vulnérabilité structurelle : comment la")
W("qualité de l'infrastructure expose un pays aux perturbations | IPv4 vs IPv6, vieux TLS, absence HTTP/3, faible bande passante, forte latence DNS |")
W("| **IExC** — Indice d'Expérience des Chocs | Chocs effectivement subis : dégradations")
W("mesurées sur la période | Chutes de bande passante, pics de latence DNS, BGP hijacks ciblant le pays, intensité attaques L3 |")
W("")
W("> **IVC2** = (IEC + IExC) / 2 — Indice composite de vulnérabilité réalisée")
W("")
W("---")
W("")
W("## 2. Données et méthode")
W("")
W(f"- **Pays couverts :** {n_pays}")
W(f"- **Semaines :** {n_weeks} (Juin 2025 – Juin 2026)")
W(f"- **Observations totales :** {len(base):,}")
W("")
W("### Sources par composante")
W("")
W("**IEC (Exposition) :**")
W("- `http_ip_version_clean.csv` → taux IPv4 (dépendance, exposé aux attaques v4)")
W("- `http_tls_version_clean.csv` → proportion TLS ≤ 1.2 (protocoles anciens)")
W("- `http_http_version_clean.csv` → absence HTTP/3 / QUIC")
W("- `iqi_bandwidth_clean.csv` → bande passante médiane (faible = exposé)")
W("- `iqi_dns_clean.csv` → latence DNS médiane (élevée = exposé)")
W("")
W("**IExC (Expérience) :**")
W("- `iqi_bandwidth_clean.csv` → chute semaine-sur-semaine de la bande passante")
W("- `iqi_dns_clean.csv` → pic semaine-sur-semaine de la latence DNS")
W("- `bgp_hijacks_clean.csv` → hijacks BGP ciblant ce pays (champ `victim_countries`)")
W("- `attacks_l3_bitrate_clean.csv` → intensité attaques L3 globales (composante mondiale)")
W("")
W("**Normalisation :** min-max [0,1] global sur l'ensemble du panel (pays × semaines).  ")
W("**IExC = 60% local** (bande passante + DNS + BGP pays) **+ 40% global** (L3 attacks).")
W("")
W("---")
W("")
W("## 3. Résultats")
W("")
W("### 3.1 Corrélation IEC ↔ IExC")
W("")
W(f"**ρ de Spearman = {rho:.3f}** (p = {pval:.4f})")
W("")
if abs(rho) < 0.2:
    interp = "Les deux dimensions sont **quasi-indépendantes** : exposition structurelle et chocs subis mesurent bien des réalités distinctes."
elif abs(rho) < 0.4:
    interp = "Corrélation **faible** : exposition et expérience sont partiellement liées mais restent des dimensions autonomes."
else:
    interp = f"Corrélation **modérée** (ρ={rho:.2f}) : les pays très exposés structurellement subissent davantage de chocs."
W(interp)
W("")
W("### 3.2 Pays les plus exposés (IEC moyen)")
W("")
W("| Rang | Pays | IEC moyen |")
W("|------|------|-----------|")
for i, (iso, val) in enumerate(top5_iec.items(), 1):
    W(f"| {i} | {iso} | {val:.3f} |")
W("")
W("### 3.3 Pays ayant le plus subi (IExC moyen)")
W("")
W("| Rang | Pays | IExC moyen |")
W("|------|------|------------|")
for i, (iso, val) in enumerate(top5_iexc.items(), 1):
    W(f"| {i} | {iso} | {val:.3f} |")
W("")
W("### 3.4 Pays les moins exposés")
W("")
W("| Rang | Pays | IEC moyen |")
W("|------|------|-----------|")
for i, (iso, val) in enumerate(bot5_iec.items(), 1):
    W(f"| {i} | {iso} | {val:.3f} |")
W("")
W("### 3.5 Analyse par quadrants")
W("")
W("| Quadrant | Description | Nombre de pays |")
W("|----------|-------------|----------------|")
for k, v in q.items():
    W(f"| {k} | — | **{v}** |")
W("")
W("**Pays à haute exposition mais faibles chocs** *(résilients malgré leur vulnérabilité structurelle)* :")
W("")
W("| Pays | IEC | IExC | Écart |")
W("|------|-----|------|-------|")
for iso, row in resilient_top.iterrows():
    W(f"| {iso} | {row.IEC:.3f} | {row.IExC:.3f} | +{row.ecart:.3f} |")
W("")
W("---")
W("")
W("## 4. Visualisations")
W("")
W("| Fichier | Description |")
W("|---------|-------------|")
W("| `etude11_heatmap_iec.png` | Heatmap IEC — Top 30 pays × 53 semaines |")
W("| `etude11_heatmap_iexc.png` | Heatmap IExC — Top 30 pays × 53 semaines |")
W("| `etude11_scatter_iec_iexc.png` | Scatter IEC vs IExC par pays (4 quadrants) |")
W("| `etude11_series_globales.png` | Évolution temporelle mondiale IEC & IExC |")
W("| `etude11_pays_semaine_vulnerabilite.csv` | Données complètes pays × semaine |")
W("")
W("---")
W("")
W("## 5. Discussion")
W("")
W(f"L'analyse de {n_pays} pays sur 53 semaines révèle une fracture nette entre exposition")
W("structurelle et expérience effective des chocs. Les pays à faible adoption IPv6 et")
W("HTTP/3 présentent les IEC les plus élevés, confirmant que la modernisation protocolaire")
W("est un levier majeur de résilience.")
W("")
W("La composante pays du IExC (BGP hijacks ciblés + variations IQI) permet d'identifier")
W("des épisodes de perturbation que les indicateurs agrégés masquent. Couplé à l'IEC,")
W("ce double indice fournit un cadre de priorisation pour les politiques de renforcement")
W("de la sécurité Internet par pays.")
W("")
W("---")
W("")
W(f"*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*")

rapport_path = os.path.join(OUT, "rapport_etude11_vulnerabilite_pays.md")
with open(rapport_path, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print(f"Rapport : {rapport_path}")
print("\n✓ Étude 11 terminée.")
