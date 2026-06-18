# -*- coding: utf-8 -*-
"""Étude 16 — Secteurs cibles L7 : tendances, saisonnalité et ciblage sectoriel"""
import pandas as pd, numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy import stats as sps
import warnings, os
warnings.filterwarnings("ignore")

CLEANED = os.path.join(os.path.dirname(__file__), "cleaned")
OUT = os.path.dirname(__file__)

def load(name):
    df = pd.read_csv(os.path.join(CLEANED, name), parse_dates=["date"])
    df["date"] = pd.to_datetime(df["date"], utc=True).dt.normalize()
    return df

print("Chargement...")
l7v  = load("attacks_l7_vertical_clean.csv")
l7m  = load("attacks_l7_http_method_clean.csv")
l3b  = load("attacks_l3_bitrate_clean.csv")

print("  Colonnes l7_vertical:", [c for c in l7v.columns if c not in ["date","dimension"]])
print("  Colonnes l7_method:  ", [c for c in l7m.columns if c not in ["date","dimension"]])

# ── Sélection des lignes verticales (dimension != NaN, pas de méthode HTTP) ─
# La CSV peut mélanger vertical et méthode selon la colonne dimension
# On garde les lignes du fichier l7_vertical
sectors_cols = [c for c in l7v.columns if c not in ["date","dimension","GET","POST","DELETE","HEAD","PUT","PATCH"]]
# Nettoyage : garder uniquement colonnes numériques non-méthode
num_cols = l7v.select_dtypes(include="number").columns.tolist()
# Secteurs candidats : colonnes numériques avec des valeurs >0
sector_candidates = []
for c in num_cols:
    if l7v[c].sum() > 0:
        sector_candidates.append(c)

print(f"  Secteurs détectés : {sector_candidates}")

if not sector_candidates:
    # Fallback : utiliser toutes les colonnes numériques
    sector_candidates = num_cols[:8]

SECTORS = sector_candidates

# ── Série temporelle par secteur ───────────────────────────────────────────
l7_ts = l7v.groupby("date")[SECTORS].sum()

# Part relative de chaque secteur
l7_ts_pct = l7_ts.div(l7_ts.sum(axis=1) + 1e-9, axis=0) * 100

# ── Top secteurs (cumulé sur la période) ──────────────────────────────────
sector_totals = l7_ts.sum().sort_values(ascending=False)
top_sectors = sector_totals.head(6).index.tolist()
print(f"  Top secteurs : {top_sectors}")

# ── Mann-Kendall tendance par secteur ─────────────────────────────────────
print("Mann-Kendall tendances secteurs...")
from scipy.stats import norm as sps_norm
def mk_test(x):
    x = x.dropna()
    if len(x)<8: return np.nan, np.nan
    n = len(x)
    s = sum(np.sign(x.iloc[j]-x.iloc[i]) for i in range(n-1) for j in range(i+1,n))
    var_s = n*(n-1)*(2*n+5)/18
    z = (s-1)/np.sqrt(var_s) if s>0 else ((s+1)/np.sqrt(var_s) if s<0 else 0)
    p = 2*(1-sps_norm.cdf(abs(z)))
    return float(z), float(p)

mk_sectors = {}
for sec in SECTORS:
    z, p = mk_test(l7_ts_pct[sec])
    mk_sectors[sec] = {"z":z,"p":p,"trend":"↑" if z>1.96 and p<0.05 else "↓" if z<-1.96 and p<0.05 else "="}
    print(f"  {sec}: z={z:.2f}  p={p:.4f}  {mk_sectors[sec]['trend']}")

# ── Figure 1 : stacked area chart secteurs ─────────────────────────────────
fig, ax = plt.subplots(figsize=(14,6))
colors_s = ["#1f77b4","#ff7f0e","#2ca02c","#d62728","#9467bd","#8c564b","#e377c2","#7f7f7f"]
ax.stackplot(l7_ts_pct.index, [l7_ts_pct[s] for s in top_sectors],
             labels=top_sectors, colors=colors_s[:len(top_sectors)], alpha=0.85)
ax.set_xlabel("Semaine"); ax.set_ylabel("Part des attaques (%)")
ax.set_title("Distribution des attaques L7 par secteur (stacked area)", fontsize=11, fontweight="bold")
ax.legend(loc="upper right", fontsize=7, ncol=2); ax.grid(True, alpha=0.2)
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude16_l7_secteurs_stacked.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 2 : séries temporelles individuelles top 6 ─────────────────────
fig, axes = plt.subplots(2, 3, figsize=(15,8))
for ax, sec in zip(axes.flat, top_sectors[:6]):
    s = l7_ts_pct[sec].dropna()
    ax.plot(s.index, s.values, lw=1.5, color=colors_s[top_sectors.index(sec)%len(colors_s)])
    ax.fill_between(s.index, s.values, alpha=0.2, color=colors_s[top_sectors.index(sec)%len(colors_s)])
    mk = mk_sectors.get(sec,{})
    ax.set_title(f"{sec}\nMK: z={mk.get('z',np.nan):.2f}  {mk.get('trend','?')}",
                 fontsize=8, fontweight="bold")
    ax.set_ylabel("Part (%)", fontsize=7); ax.grid(True, alpha=0.3)
    ax.tick_params(axis='x', labelsize=6)
plt.suptitle("Évolution temporelle des parts de secteurs ciblés (attaques L7)", fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude16_l7_secteurs_series.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 3 : méthodes HTTP utilisées ─────────────────────────────────────
method_cols = [c for c in l7m.select_dtypes("number").columns if l7m[c].sum()>0]
if method_cols:
    m_ts = l7m.groupby("date")[method_cols].sum()
    m_pct = m_ts.div(m_ts.sum(axis=1)+1e-9, axis=0)*100
    fig, ax = plt.subplots(figsize=(12,5))
    for col, color in zip(method_cols[:6], colors_s):
        ax.plot(m_pct.index, m_pct[col], label=col, lw=1.8, color=color)
    ax.set_xlabel("Semaine"); ax.set_ylabel("Part (%)")
    ax.set_title("Méthodes HTTP utilisées dans les attaques L7", fontsize=11, fontweight="bold")
    ax.legend(fontsize=8); ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT,"etude16_l7_methodes.png"), dpi=150, bbox_inches="tight")
    plt.close()

# ── Figure 4 : barplot part cumulée par secteur ────────────────────────────
fig, ax = plt.subplots(figsize=(10,5))
total_pct = l7_ts_pct.mean().sort_values(ascending=True)
ax.barh(range(len(total_pct)), total_pct.values,
        color=colors_s[:len(total_pct)])
ax.set_yticks(range(len(total_pct)))
ax.set_yticklabels(total_pct.index, fontsize=8)
ax.set_xlabel("Part moyenne sur la période (%)")
ax.set_title("Secteurs les plus ciblés par les attaques L7 (moyenne 53 semaines)", fontsize=11, fontweight="bold")
ax.grid(True, alpha=0.3, axis="x")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude16_l7_barplot.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Rapport ───────────────────────────────────────────────────────────────
lines = []
W = lines.append
W("# Étude 16 — Secteurs Cibles L7 : Tendances et Saisonnalité")
W(f"**Auteur :** Issakha Thiam  \n**Généré le :** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
W("---\n## 1. Questions de recherche\n")
W("Quels secteurs économiques sont les plus exposés aux attaques applicatives (L7) ? Ces ciblages évoluent-ils dans le temps ? Certains secteurs connaissent-ils une hausse significative des attaques ?\n")
W("## 2. Méthodes\n")
W("- Parts relatives par secteur par semaine\n- Mann-Kendall pour détecter des tendances monotones\n- Décomposition temporelle (stacked area + séries individuelles)\n")
W("## 3. Top secteurs ciblés\n")
W("| Secteur | Part moyenne | Tendance MK |")
W("|---------|-------------|-------------|")
for sec in sector_totals.index:
    avg = l7_ts_pct[sec].mean()
    mk = mk_sectors.get(sec,{})
    W(f"| {sec} | {avg:.1f}% | {mk.get('trend','?')} (z={mk.get('z',np.nan):.2f}) |")
W(f"\n---\n*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*")
with open(os.path.join(OUT,"rapport_etude16_secteurs_l7.md"),"w",encoding="utf-8") as f:
    f.write("\n".join(lines))
print("✓ Étude 16 terminée.")
