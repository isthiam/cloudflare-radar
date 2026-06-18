# -*- coding: utf-8 -*-
"""Étude 17 — Paradoxe de résilience : les pays vulnérables subissent-ils davantage les chocs ?
   Régression multiple : IExC ~ IEC + bot_ratio + IPv6 + bw_p50
   Hypothèse : IEC élevé → IExC élevé (vulnérabilité structurelle = plus d'impact)
   Paradoxe potentiel : corrélation faible (déjà vue dans étude 11 : ρ=0.020)
"""
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
# Charger les données IEC/IExC de l'étude 11
iec_file = os.path.join(OUT, "etude11_pays_semaine_vulnerabilite.csv")
if not os.path.exists(iec_file):
    raise FileNotFoundError(f"Fichier introuvable : {iec_file}\nExécutez d'abord etude11_vulnerabilite_pays.py")

panel = pd.read_csv(iec_file, parse_dates=["date"])

# ── Données auxiliaires ───────────────────────────────────────────────────
bot = load("http_bot_class_clean.csv")
bot_avg = bot.groupby("country_iso2")[["human","bot"]].mean()
bot_avg["bot_ratio"] = bot_avg["bot"]/(bot_avg["human"]+bot_avg["bot"]+1e-9)

ipv = load("http_ip_version_clean.csv")
ipv_avg = ipv.groupby("country_iso2")[["IPv6"]].mean()

bw = load("iqi_bandwidth_clean.csv")
bw_avg = bw[bw["metric"]=="BANDWIDTH"].groupby("country_iso2")[["p50"]].mean().rename(columns={"p50":"bw_p50"})

# ── Agrégation par pays (moyenne sur 53 semaines) ─────────────────────────
country_avg = panel.groupby("country_iso2")[["IEC","IExC","IVC2"]].mean()
country_avg = country_avg.join(bot_avg[["bot_ratio"]]).join(ipv_avg).join(bw_avg)
country_avg = country_avg.dropna(subset=["IEC","IExC"])
print(f"  {len(country_avg)} pays avec données IEC/IExC complètes")

# ── Régression OLS multiple : IExC ~ IEC + bot_ratio + IPv6 + bw_p50 ──────
print("\nRégression OLS : IExC ~ IEC + bot_ratio + IPv6 + bw_p50...")
regressors = [c for c in ["IEC","bot_ratio","IPv6","bw_p50"] if c in country_avg.columns]
sub = country_avg[["IExC"]+regressors].dropna()

from numpy.linalg import lstsq

X = np.column_stack([np.ones(len(sub))] + [sub[c] for c in regressors])
y = sub["IExC"].values
betas, _, _, _ = lstsq(X, y, rcond=None)

# Statistiques OLS manuelles
y_pred = X @ betas
ss_res = np.sum((y - y_pred)**2)
ss_tot = np.sum((y - y.mean())**2)
r2 = 1 - ss_res/ss_tot
n, k = len(y), len(betas)
se = np.sqrt(np.diag(np.linalg.inv(X.T @ X) * ss_res/(n-k)))
t_stats = betas / se
p_vals = 2*(1 - sps.t.cdf(np.abs(t_stats), df=n-k))

print(f"  R² = {r2:.4f}  n={n}")
reg_names = ["Intercept"] + regressors
for name, b, s, t, p in zip(reg_names, betas, se, t_stats, p_vals):
    sig = "***" if p<0.001 else "**" if p<0.01 else "*" if p<0.05 else ""
    print(f"  {name:20s}: β={b:.4f}  SE={s:.4f}  t={t:.3f}  p={p:.4f} {sig}")

# ── Corrélations bivariées ─────────────────────────────────────────────────
print("\nCorrélations Spearman IExC ~ explicatives...")
bivar = {}
for col in regressors:
    sub2 = country_avg[["IExC",col]].dropna()
    if len(sub2) < 20: continue
    r, p = sps.spearmanr(sub2["IExC"], sub2[col])
    bivar[col] = (r, p)
    print(f"  IExC ~ {col}: ρ={r:.3f}  p={p:.4f}")

# ── Quadrants IEC / IExC ──────────────────────────────────────────────────
m_iec  = country_avg["IEC"].median()
m_iexc = country_avg["IExC"].median()
def quadrant(row):
    if   row["IEC"]>=m_iec and row["IExC"]>=m_iexc: return "Vulnérable-Impacté"
    elif row["IEC"]< m_iec and row["IExC"]>=m_iexc: return "Résilient-Impacté"
    elif row["IEC"]>=m_iec and row["IExC"]< m_iexc: return "Vulnérable-Épargné"
    else:                                             return "Résilient-Épargné"
country_avg["quadrant"] = country_avg.apply(quadrant, axis=1)
quad_counts = country_avg["quadrant"].value_counts()
print("\nQuadrants IEC/IExC :")
for q, n_ in quad_counts.items():
    print(f"  {q}: {n_} pays")

# ── Figure 1 : scatter IEC vs IExC avec quadrants ─────────────────────────
fig, ax = plt.subplots(figsize=(10,8))
colors_q = {"Vulnérable-Impacté":"#d62728","Résilient-Impacté":"#ff7f0e",
            "Vulnérable-Épargné":"#9467bd","Résilient-Épargné":"#2ca02c"}
for quad, grp in country_avg.groupby("quadrant"):
    ax.scatter(grp["IEC"], grp["IExC"], label=f"{quad} (n={len(grp)})",
               color=colors_q[quad], alpha=0.7, s=25)
ax.axvline(m_iec,  color="gray", lw=1, linestyle="--")
ax.axhline(m_iexc, color="gray", lw=1, linestyle="--")
# Étiquettes top pays
top10 = country_avg.nlargest(5,"IExC").index.tolist() + country_avg.nlargest(5,"IEC").index.tolist()
for iso in set(top10):
    row = country_avg.loc[iso]
    ax.annotate(iso, (row["IEC"], row["IExC"]), fontsize=6, ha="left", va="bottom")
ax.set_xlabel("IEC — Exposition aux Chocs (structurelle)", fontsize=10)
ax.set_ylabel("IExC — Expérience des Chocs (réalisée)", fontsize=10)
r_sp, p_sp = sps.spearmanr(country_avg["IEC"], country_avg["IExC"])
ax.set_title(f"Paradoxe de résilience : IEC vs IExC (ρ={r_sp:.3f}, p={p_sp:.4f})\n"
             f"Corrélation faible = les pays structurellement vulnérables ne subissent pas plus de chocs",
             fontsize=10, fontweight="bold")
ax.legend(fontsize=8); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude17_paradoxe_iec_iexc.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 2 : régression partielle IExC ~ IEC ────────────────────────────
fig, ax = plt.subplots(figsize=(9,7))
ax.scatter(country_avg["IEC"], country_avg["IExC"], alpha=0.4, s=20, color="#5471b0")
# Droite de régression simple
slope, intercept, r, p, se_r = sps.linregress(country_avg["IEC"].dropna(),
    country_avg.loc[country_avg["IEC"].notna(),"IExC"])
xs = np.linspace(country_avg["IEC"].min(), country_avg["IEC"].max(), 100)
ax.plot(xs, slope*xs+intercept, "r-", lw=2)
ax.set_xlabel("IEC (Exposition structurelle)", fontsize=10)
ax.set_ylabel("IExC (Chocs réalisés)", fontsize=10)
ax.set_title(f"Régression IExC ~ IEC : β={slope:.4f}  r={r:.3f}  p={p:.4f}", fontsize=10, fontweight="bold")
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude17_regression_iec_iexc.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 3 : coefficients de régression multiple ─────────────────────────
fig, ax = plt.subplots(figsize=(8,5))
beta_vals = betas[1:]  # sans intercept
se_vals   = se[1:]
labels_r  = regressors
colors_r  = ["#d62728" if b>0 else "#2ca02c" for b in beta_vals]
ax.barh(range(len(beta_vals)), beta_vals, xerr=1.96*se_vals,
        color=colors_r, alpha=0.85, capsize=4)
ax.set_yticks(range(len(beta_vals)))
ax.set_yticklabels(labels_r, fontsize=9)
ax.axvline(0, color="black", lw=1)
ax.set_xlabel("Coefficient β (±1.96 SE)", fontsize=9)
ax.set_title(f"Régression OLS — IExC ~ explicatives  (R²={r2:.3f})", fontsize=10, fontweight="bold")
ax.grid(True, alpha=0.3, axis="x")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude17_ols_coefficients.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Rapport ───────────────────────────────────────────────────────────────
lines = []
W = lines.append
W("# Étude 17 — Paradoxe de Résilience : les Pays Vulnérables Subissent-ils Davantage les Chocs ?")
W(f"**Auteur :** Issakha Thiam  \n**Généré le :** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
W("---\n## 1. Hypothèse\n")
W("La vulnérabilité structurelle (IEC élevé) devrait entraîner plus de chocs réalisés (IExC élevé). Si cette corrélation est faible, on parle de **paradoxe de résilience** : certains pays structurellement fragiles n'expérimentent pas davantage de chocs — peut-être parce qu'ils génèrent moins de trafic et sont donc moins ciblés.\n")
W("## 2. Résultat principal\n")
W(f"- Corrélation Spearman IEC ~ IExC : **ρ={r_sp:.3f}**  p={p_sp:.4f}")
W(f"- Interprétation : {'Corrélation quasi-nulle — paradoxe de résilience confirmé' if abs(r_sp)<0.15 else 'Corrélation significative'}\n")
W("## 3. Régression OLS multiple\n")
W(f"**R² = {r2:.4f}**  (n={n})\n")
W("| Variable | β | SE | t | p | Sig |")
W("|----------|---|-----|---|---|-----|")
for name, b_, s_, t_, p_ in zip(reg_names, betas, se, t_stats, p_vals):
    sig = "***" if p_<0.001 else "**" if p_<0.01 else "*" if p_<0.05 else ""
    W(f"| {name} | {b_:.4f} | {s_:.4f} | {t_:.3f} | {p_:.4f} | {sig} |")
W("\n## 4. Quadrants IEC / IExC\n")
W("| Quadrant | Pays |")
W("|----------|------|")
for q, n_ in quad_counts.items():
    W(f"| {q} | {n_} |")
W(f"\n---\n*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*")
with open(os.path.join(OUT,"rapport_etude17_paradoxe_resilience.md"),"w",encoding="utf-8") as f:
    f.write("\n".join(lines))
print("✓ Étude 17 terminée.")
