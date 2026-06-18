# -*- coding: utf-8 -*-
"""Étude 12 — Trajectoires de convergence des pays vers les standards de sécurité"""
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
tls = load("http_tls_version_clean.csv")
ipv = load("http_ip_version_clean.csv")
http3 = load("http_http_version_clean.csv")
bw = load("iqi_bandwidth_clean.csv")

# Construction du panel indicateurs par pays/semaine
panel = tls[["date","country_iso2","TLS 1.3"]].copy()
panel = panel.merge(ipv[["date","country_iso2","IPv6"]], on=["date","country_iso2"], how="left")
panel = panel.merge(http3[["date","country_iso2","HTTP/3"]], on=["date","country_iso2"], how="left")
panel = panel.merge(
    bw[bw["metric"]=="BANDWIDTH"][["date","country_iso2","p50"]].rename(columns={"p50":"bw_p50"}),
    on=["date","country_iso2"], how="left")
panel = panel.sort_values(["country_iso2","date"])

INDICATORS = ["TLS 1.3","IPv6","HTTP/3","bw_p50"]

# ── Mann-Kendall par pays par indicateur ─────────────────────────────────────
print("Mann-Kendall par pays...")

def mk_test(x):
    x = x.dropna()
    if len(x) < 8: return np.nan, np.nan
    n = len(x)
    s = sum(np.sign(x.iloc[j]-x.iloc[i]) for i in range(n-1) for j in range(i+1,n))
    var_s = n*(n-1)*(2*n+5)/18
    z = (s-1)/np.sqrt(var_s) if s>0 else ((s+1)/np.sqrt(var_s) if s<0 else 0)
    p = 2*(1-sps.norm.cdf(abs(z)))
    return float(z), float(p)

results = []
for iso, grp in panel.groupby("country_iso2"):
    row = {"country_iso2": iso}
    for ind in INDICATORS:
        z, p = mk_test(grp[ind])
        row[f"mk_z_{ind}"] = z
        row[f"mk_p_{ind}"] = p
        row[f"trend_{ind}"] = ("↑" if z>1.96 and p<0.05 else "↓" if z<-1.96 and p<0.05 else "=")
    results.append(row)
mk_df = pd.DataFrame(results)

# ── β-convergence (régression cross-section : Δvar ~ var_initiale) ───────────
print("β-convergence...")
beta_results = {}
for ind in INDICATORS:
    sub = panel.groupby("country_iso2")[ind].agg(["first","last"]).dropna()
    sub["delta"] = sub["last"] - sub["first"]
    sub = sub[sub["first"]>0]
    if len(sub) < 20: continue
    slope, intercept, r, p, se = sps.linregress(sub["first"], sub["delta"])
    beta_results[ind] = {"beta": slope, "r": r, "p": p, "n": len(sub)}

# ── σ-convergence (écart-type mondial par semaine) ───────────────────────────
sigma = panel.groupby("date")[INDICATORS].std()

# ── Stats synthèse ───────────────────────────────────────────────────────────
for ind in INDICATORS:
    col_trend = f"trend_{ind}"
    if col_trend in mk_df.columns:
        up = (mk_df[col_trend]=="↑").sum()
        down = (mk_df[col_trend]=="↓").sum()
        eq = (mk_df[col_trend]=="=").sum()
        print(f"  {ind}: ↑{up} ↓{down} ={eq}  | β={beta_results.get(ind,{}).get('beta',np.nan):.3f}")

# ── Export CSV ────────────────────────────────────────────────────────────────
mk_df.to_csv(os.path.join(OUT,"etude12_convergence_mk.csv"), index=False)

# ── Figure 1 : Heatmap tendances MK ──────────────────────────────────────────
trend_map = {"↑":1,"=":0,"↓":-1}
fig, axes = plt.subplots(1,4,figsize=(18,10))
for ax, ind in zip(axes, INDICATORS):
    col = f"trend_{ind}"
    vals = mk_df.set_index("country_iso2")[col].map(trend_map).fillna(0)
    vals = vals.sort_values(ascending=False)
    top = vals.head(40)
    ax.barh(range(len(top)), top.values,
            color=["#2ca02c" if v>0 else "#d62728" if v<0 else "#aec7e8" for v in top.values])
    ax.set_yticks(range(len(top)))
    ax.set_yticklabels(top.index, fontsize=6)
    ax.set_title(ind, fontsize=9, fontweight="bold")
    ax.axvline(0, color="black", lw=0.8)
    ax.set_xlim(-1.5,1.5)
    ax.set_xticks([-1,0,1])
    ax.set_xticklabels(["↓","=","↑"], fontsize=8)
plt.suptitle("Tendances Mann-Kendall par pays (53 semaines)\n↑ hausse significative · ↓ baisse · = stable",
             fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude12_mk_tendances.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 2 : β-convergence scatter ─────────────────────────────────────────
fig, axes = plt.subplots(2,2,figsize=(12,10))
for ax, ind in zip(axes.flat, INDICATORS):
    sub = panel.groupby("country_iso2")[ind].agg(["first","last"]).dropna()
    sub["delta"] = sub["last"] - sub["first"]
    sub = sub[sub["first"]>0]
    if len(sub) < 10:
        ax.set_visible(False); continue
    b = beta_results.get(ind,{})
    ax.scatter(sub["first"], sub["delta"], alpha=0.4, s=15, color="#5471b0")
    xs = np.linspace(sub["first"].min(), sub["first"].max(), 100)
    ys = b.get("beta",0)*xs + (sub["delta"].mean() - b.get("beta",0)*sub["first"].mean())
    ax.plot(xs, ys, "r-", lw=1.5)
    ax.axhline(0, color="gray", lw=0.8, linestyle="--")
    ax.set_xlabel(f"{ind} initial (%)", fontsize=8)
    ax.set_ylabel(f"Δ{ind} (52 semaines)", fontsize=8)
    sign = "convergence" if b.get("beta",0)<0 else "divergence"
    ax.set_title(f"{ind} — β={b.get('beta',np.nan):.3f} ({sign}, p={b.get('p',np.nan):.3f})",
                 fontsize=9, fontweight="bold")
plt.suptitle("β-convergence : les pays en retard rattrapent-ils les leaders ?", fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude12_beta_convergence.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 3 : σ-convergence (écart-type mondial) ────────────────────────────
fig, ax = plt.subplots(figsize=(12,5))
colors = ["#1f77b4","#ff7f0e","#2ca02c","#d62728"]
for ind, col in zip(INDICATORS, colors):
    s = sigma[ind].dropna()
    s_norm = s / s.iloc[0]
    ax.plot(s.index, s_norm, label=ind, color=col, lw=2)
ax.axhline(1, color="gray", lw=0.8, linestyle="--")
ax.set_xlabel("Semaine"); ax.set_ylabel("Écart-type mondial (normalisé à 1 en juin 2025)")
ax.set_title("σ-convergence : l'écart-type mondial diminue-t-il ?\n(< 1 = convergence, > 1 = divergence)",
             fontsize=11, fontweight="bold")
ax.legend(); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude12_sigma_convergence.png"), dpi=150, bbox_inches="tight")
plt.close()

print("Figures : etude12_mk_tendances.png, etude12_beta_convergence.png, etude12_sigma_convergence.png")

# ── Rapport ───────────────────────────────────────────────────────────────────
n_pays = mk_df["country_iso2"].nunique()
lines = []
W = lines.append
W("# Étude 12 — Trajectoires de Convergence des Pays vers les Standards de Sécurité")
W(f"**Auteur :** Issakha Thiam  \n**Généré le :** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
W("---\n## 1. Questions de recherche\n")
W("Les pays en retard technologique rattrapent-ils les leaders ? La dispersion mondiale des indicateurs de sécurité diminue-t-elle (σ-convergence) ? Les pays initialement faibles progressent-ils plus vite (β-convergence) ?\n")
W("## 2. Méthodes\n")
W("- **Mann-Kendall** : tendance monotone significative par pays par indicateur (H₀ : pas de tendance)\n- **β-convergence** : régression Δindicateur ~ indicateur_initial (pente négative = convergence)\n- **σ-convergence** : évolution de l'écart-type mondial sur 53 semaines\n")
W("## 3. Résultats Mann-Kendall\n")
W("| Indicateur | ↑ Hausse | = Stable | ↓ Baisse |")
W("|------------|----------|----------|---------|")
for ind in INDICATORS:
    col = f"trend_{ind}"
    if col in mk_df.columns:
        up = (mk_df[col]=="↑").sum()
        eq = (mk_df[col]=="=").sum()
        dn = (mk_df[col]=="↓").sum()
        W(f"| {ind} | {up} | {eq} | {dn} |")
W("\n## 4. β-convergence\n")
W("| Indicateur | β | r | p | Interprétation |")
W("|------------|---|---|---|----------------|")
for ind, b in beta_results.items():
    interp = "convergence" if b['beta']<0 else "divergence"
    W(f"| {ind} | {b['beta']:.3f} | {b['r']:.3f} | {b['p']:.4f} | **{interp}** |")
W("\n## 5. σ-convergence\n")
for ind in INDICATORS:
    s = sigma[ind].dropna()
    if len(s)>1:
        ratio = s.iloc[-1]/s.iloc[0]
        W(f"- **{ind}** : écart-type final / initial = {ratio:.3f} ({'convergence' if ratio<1 else 'divergence'})")
W(f"\n---\n*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*")
with open(os.path.join(OUT,"rapport_etude12_convergence_pays.md"),"w",encoding="utf-8") as f:
    f.write("\n".join(lines))
print("✓ Étude 12 terminée.")
