# -*- coding: utf-8 -*-
"""Étude 13 — Trafic bot vs vulnérabilité : les pays vulnérables attirent-ils plus de bots ?"""
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
bot   = load("http_bot_class_clean.csv")
tls   = load("http_tls_version_clean.csv")
ipv   = load("http_ip_version_clean.csv")
http3 = load("http_http_version_clean.csv")
bw    = load("iqi_bandwidth_clean.csv")

# ── Ratio bot par pays (moyenne sur la période) ────────────────────────────
bot_avg = bot.groupby("country_iso2")[["human","bot"]].mean()
bot_avg["bot_ratio"] = bot_avg["bot"] / (bot_avg["human"] + bot_avg["bot"] + 1e-9)
bot_avg = bot_avg[["bot_ratio"]]

# ── Indicateurs de vulnérabilité par pays (moyenne) ────────────────────────
tls_avg  = tls.groupby("country_iso2")[["TLS 1.3"]].mean().rename(columns={"TLS 1.3":"tls13"})
ipv_avg  = ipv.groupby("country_iso2")[["IPv6"]].mean()
h3_avg   = http3.groupby("country_iso2")[["HTTP/3"]].mean()
bw_avg   = bw[bw["metric"]=="BANDWIDTH"].groupby("country_iso2")[["p50"]].mean().rename(columns={"p50":"bw_p50"})

base = bot_avg.join(tls_avg).join(ipv_avg).join(h3_avg).join(bw_avg).dropna(subset=["bot_ratio"])

# ── Corrélations de Spearman ────────────────────────────────────────────────
print("Corrélations Spearman...")
indicators = {"tls13":"TLS 1.3 (%)","IPv6":"IPv6 (%)","HTTP/3":"HTTP/3 (%)","bw_p50":"Bande passante médiane"}
corr_results = {}
for col, label in indicators.items():
    sub = base[["bot_ratio",col]].dropna()
    if len(sub) < 20: continue
    r, p = sps.spearmanr(sub["bot_ratio"], sub[col])
    corr_results[col] = {"label":label, "rho":r, "p":p, "n":len(sub)}
    print(f"  bot_ratio ~ {col}: ρ={r:.3f}  p={p:.4f}  n={len(sub)}")

# ── Évolution temporelle mondiale du ratio bot ──────────────────────────────
bot_ts = bot.groupby("date")[["human","bot"]].sum()
bot_ts["bot_ratio"] = bot_ts["bot"] / (bot_ts["human"] + bot_ts["bot"])

# ── Top/bottom pays par ratio bot ──────────────────────────────────────────
top20  = base["bot_ratio"].sort_values(ascending=False).head(20)
bot20  = base["bot_ratio"].sort_values().head(20)

# ── Figure 1 : scatter bot_ratio vs indicateurs ────────────────────────────
fig, axes = plt.subplots(2,2,figsize=(13,10))
for ax, (col, label) in zip(axes.flat, indicators.items()):
    sub = base[["bot_ratio",col]].dropna()
    b   = corr_results.get(col,{})
    ax.scatter(sub[col], sub["bot_ratio"]*100, alpha=0.4, s=15, color="#5471b0")
    ax.set_xlabel(label, fontsize=8)
    ax.set_ylabel("Ratio bot (%)", fontsize=8)
    sign = ("↓ moins de bots" if b.get("rho",0)<0 else "↑ plus de bots")
    ax.set_title(f"{label}\nρ={b.get('rho',np.nan):.3f}  p={b.get('p',np.nan):.3f}  ({sign})",
                 fontsize=9, fontweight="bold")
    ax.grid(True, alpha=0.3)
plt.suptitle("Trafic bot vs indicateurs de sécurité/qualité (252 pays)", fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude13_bot_scatter.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 2 : top/bottom 20 pays ──────────────────────────────────────────
fig, (ax1,ax2) = plt.subplots(1,2,figsize=(13,7))
ax1.barh(range(len(top20)), top20.values*100, color="#d62728")
ax1.set_yticks(range(len(top20))); ax1.set_yticklabels(top20.index, fontsize=7)
ax1.set_xlabel("Ratio bot (%)"); ax1.set_title("Top 20 — Pays les plus ciblés par bots", fontweight="bold", fontsize=9)
ax2.barh(range(len(bot20)), bot20.values*100, color="#2ca02c")
ax2.set_yticks(range(len(bot20))); ax2.set_yticklabels(bot20.index, fontsize=7)
ax2.set_xlabel("Ratio bot (%)"); ax2.set_title("Top 20 — Pays les moins ciblés par bots", fontweight="bold", fontsize=9)
plt.suptitle("Classement des pays par ratio trafic bot", fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude13_bot_classement.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 3 : série temporelle mondiale ───────────────────────────────────
fig, ax = plt.subplots(figsize=(12,5))
ax.plot(bot_ts.index, bot_ts["bot_ratio"]*100, color="#d62728", lw=2)
ax.fill_between(bot_ts.index, bot_ts["bot_ratio"]*100, alpha=0.2, color="#d62728")
ax.set_xlabel("Semaine"); ax.set_ylabel("Ratio bot mondial (%)")
ax.set_title("Évolution du ratio trafic bot mondial (juin 2025 – juin 2026)", fontsize=11, fontweight="bold")
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude13_bot_timeseries.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Export CSV ────────────────────────────────────────────────────────────
base.reset_index().to_csv(os.path.join(OUT,"etude13_bot_pays.csv"), index=False)

# ── Rapport ───────────────────────────────────────────────────────────────
lines = []
W = lines.append
W("# Étude 13 — Trafic Bot vs Vulnérabilité : les Pays Vulnérables Attirent-ils Plus de Bots ?")
W(f"**Auteur :** Issakha Thiam  \n**Généré le :** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
W("---\n## 1. Questions de recherche\n")
W("Les pays avec de faibles indicateurs de sécurité (TLS 1.3 bas, peu d'IPv6, peu d'HTTP/3, faible bande passante) sont-ils davantage exposés au trafic bot ? Le trafic bot est-il corrélé à la vulnérabilité structurelle ?\n")
W("## 2. Méthodes\n")
W("- Ratio bot = traffic bot / (humain + bot) par pays, moyenne sur 53 semaines\n- Corrélations de Spearman (non paramétriques, robustes aux outliers)\n- Séries temporelles du ratio mondial\n")
W("## 3. Résultats\n")
W("| Indicateur | ρ Spearman | p-value | Interprétation |")
W("|------------|-----------|---------|----------------|")
for col, b in corr_results.items():
    direction = "moins de bots si sécurité ↑" if b['rho']<0 else "plus de bots si sécurité ↑"
    W(f"| {b['label']} | {b['rho']:.3f} | {b['p']:.4f} | {direction} |")
W("\n## 4. Statistiques globales\n")
W(f"- Ratio bot mondial moyen : **{bot_ts['bot_ratio'].mean()*100:.1f}%**")
W(f"- Ratio bot max : **{bot_ts['bot_ratio'].max()*100:.1f}%** | min : **{bot_ts['bot_ratio'].min()*100:.1f}%**")
W(f"- Pays avec ratio bot le plus élevé : **{top20.index[0]}** ({top20.iloc[0]*100:.1f}%)")
W(f"\n---\n*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*")
with open(os.path.join(OUT,"rapport_etude13_bot_vulnerabilite.md"),"w",encoding="utf-8") as f:
    f.write("\n".join(lines))
print("✓ Étude 13 terminée.")
