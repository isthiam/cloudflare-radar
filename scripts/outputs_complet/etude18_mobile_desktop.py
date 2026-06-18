# -*- coding: utf-8 -*-
"""Étude 18 — Fracture mobile/desktop : les utilisateurs mobiles sont-ils moins bien protégés ?"""
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
dev   = load("http_device_type_clean.csv")
tls   = load("http_tls_version_clean.csv")
ipv   = load("http_ip_version_clean.csv")
http3 = load("http_http_version_clean.csv")
bw    = load("iqi_bandwidth_clean.csv")
bot   = load("http_bot_class_clean.csv")

# ── Part mobile par pays ────────────────────────────────────────────────────
dev_avg = dev.groupby("country_iso2")[["desktop","mobile","other"]].mean()
dev_avg["mobile_ratio"] = dev_avg["mobile"]/(dev_avg["desktop"]+dev_avg["mobile"]+dev_avg["other"]+1e-9)

# ── Indicateurs sécurité par pays ──────────────────────────────────────────
tls_avg  = tls.groupby("country_iso2")[["TLS 1.3"]].mean().rename(columns={"TLS 1.3":"tls13"})
ipv_avg  = ipv.groupby("country_iso2")[["IPv6"]].mean()
h3_avg   = http3.groupby("country_iso2")[["HTTP/3"]].mean()
bw_avg   = bw[bw["metric"]=="BANDWIDTH"].groupby("country_iso2")[["p50"]].mean().rename(columns={"p50":"bw_p50"})
bot_avg  = bot.groupby("country_iso2")[["human","bot"]].mean()
bot_avg["bot_ratio"] = bot_avg["bot"]/(bot_avg["human"]+bot_avg["bot"]+1e-9)

base = dev_avg.join(tls_avg).join(ipv_avg).join(h3_avg).join(bw_avg).join(bot_avg[["bot_ratio"]])

# ── Corrélations Spearman mobile_ratio ~ sécurité ─────────────────────────
print("Corrélations Spearman mobile_ratio ~ sécurité...")
indicators = {"tls13":"TLS 1.3","IPv6":"IPv6","HTTP/3":"HTTP/3","bw_p50":"BW médiane","bot_ratio":"Ratio bot"}
corr_results = {}
for col, label in indicators.items():
    sub = base[["mobile_ratio",col]].dropna()
    if len(sub)<20: continue
    r, p = sps.spearmanr(sub["mobile_ratio"], sub[col])
    corr_results[col] = {"label":label,"rho":r,"p":p,"n":len(sub)}
    print(f"  mobile_ratio ~ {col}: ρ={r:.3f}  p={p:.4f}  n={len(sub)}")

# ── Évolution temporelle mondiale ──────────────────────────────────────────
dev_ts = dev.groupby("date")[["desktop","mobile","other"]].mean()
dev_ts["mobile_ratio"] = dev_ts["mobile"]/(dev_ts["desktop"]+dev_ts["mobile"]+dev_ts["other"])

# ── Tertiles mobile : faible / moyen / fort ────────────────────────────────
q33 = base["mobile_ratio"].quantile(0.33)
q67 = base["mobile_ratio"].quantile(0.67)

def mobile_group(x):
    if x <= q33:   return "Faible mobile"
    elif x <= q67: return "Moyen mobile"
    else:          return "Fort mobile"

base["mobile_group"] = base["mobile_ratio"].apply(mobile_group)
groups = ["Faible mobile","Moyen mobile","Fort mobile"]

# ── Tests Kruskal-Wallis entre groupes ─────────────────────────────────────
print("\nTests Kruskal-Wallis par groupe mobile...")
kw_results = {}
for col, label in indicators.items():
    gdata = [base.loc[base["mobile_group"]==g, col].dropna().values for g in groups]
    gdata = [g for g in gdata if len(g)>=5]
    if len(gdata)<2: continue
    stat, p = sps.kruskal(*gdata)
    kw_results[col] = {"stat":stat,"p":p}
    print(f"  {label}: KW H={stat:.3f}  p={p:.4f}")

# ── Figure 1 : scatter mobile_ratio vs indicateurs ─────────────────────────
fig, axes = plt.subplots(2,3,figsize=(14,9))
colors_m = ["#1f77b4","#ff7f0e","#2ca02c","#d62728","#9467bd"]
for ax, (col, label), color in zip(axes.flat, indicators.items(), colors_m):
    sub = base[["mobile_ratio",col]].dropna()
    b   = corr_results.get(col,{})
    ax.scatter(sub["mobile_ratio"]*100, sub[col]*100 if col not in ["bw_p50"] else sub[col],
               alpha=0.4, s=15, color=color)
    ax.set_xlabel("Part mobile (%)", fontsize=8)
    ax.set_ylabel(label, fontsize=8)
    dir_ = ("↓ moins" if b.get("rho",0)<0 else "↑ plus")
    ax.set_title(f"{label}\nρ={b.get('rho',np.nan):.3f}  p={b.get('p',np.nan):.3f}  ({dir_})",
                 fontsize=9, fontweight="bold")
    ax.grid(True, alpha=0.3)
# Dernier axes : série temporelle mobile ratio
ax6 = axes.flat[5]
ax6.plot(dev_ts.index, dev_ts["mobile_ratio"]*100, color="#d62728", lw=2)
ax6.fill_between(dev_ts.index, dev_ts["mobile_ratio"]*100, alpha=0.2, color="#d62728")
ax6.set_xlabel("Semaine"); ax6.set_ylabel("Part mobile mondiale (%)")
ax6.set_title("Évolution mondiale ratio mobile", fontsize=9, fontweight="bold")
ax6.grid(True, alpha=0.3)
plt.suptitle("Fracture mobile/desktop : impact sur les indicateurs de sécurité", fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude18_mobile_scatter.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 2 : boxplot indicateurs par groupe mobile ─────────────────────
fig, axes = plt.subplots(2,3,figsize=(14,9))
for ax, (col, label), color in zip(axes.flat, indicators.items(), colors_m):
    data = [base.loc[base["mobile_group"]==g, col].dropna()*100
            if col not in ["bw_p50"] else
            base.loc[base["mobile_group"]==g, col].dropna()
            for g in groups]
    bp = ax.boxplot(data, patch_artist=True, labels=groups)
    for patch, c in zip(bp["boxes"], ["#2ca02c","#ff7f0e","#d62728"]):
        patch.set_facecolor(c); patch.set_alpha(0.7)
    kw = kw_results.get(col,{})
    ax.set_title(f"{label}\nKW p={kw.get('p',np.nan):.4f}", fontsize=9, fontweight="bold")
    ax.set_ylabel(label, fontsize=7); ax.grid(True, alpha=0.3, axis="y")
    ax.tick_params(axis='x', labelsize=7)
axes.flat[5].set_visible(False)
plt.suptitle("Indicateurs de sécurité par niveau d'utilisation mobile (tertiles)",
             fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude18_mobile_boxplot.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 3 : Top 20 pays les plus mobiles vs indicateurs clés ────────────
top20_mobile = base.nlargest(20,"mobile_ratio")
fig, (ax1, ax2) = plt.subplots(1,2,figsize=(14,6))
ax1.barh(range(20), top20_mobile["mobile_ratio"].values*100, color="#d62728", alpha=0.8)
ax1.set_yticks(range(20)); ax1.set_yticklabels(top20_mobile.index, fontsize=7)
ax1.set_xlabel("Part mobile (%)"); ax1.set_title("Top 20 pays les plus mobiles", fontweight="bold", fontsize=9)
ax2.barh(range(20), top20_mobile["tls13"].values*100, color="#1f77b4", alpha=0.8)
ax2.set_yticks(range(20)); ax2.set_yticklabels(top20_mobile.index, fontsize=7)
ax2.set_xlabel("TLS 1.3 (%)"); ax2.set_title("TLS 1.3 des pays les plus mobiles", fontweight="bold", fontsize=9)
plt.suptitle("Pays fortement mobiles : niveau de TLS 1.3", fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude18_mobile_top20.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Export CSV ────────────────────────────────────────────────────────────
base.reset_index().to_csv(os.path.join(OUT,"etude18_mobile_pays.csv"), index=False)

# ── Rapport ───────────────────────────────────────────────────────────────
lines = []
W = lines.append
W("# Étude 18 — Fracture Mobile/Desktop : les Utilisateurs Mobiles Sont-ils Moins Bien Protégés ?")
W(f"**Auteur :** Issakha Thiam  \n**Généré le :** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
W("---\n## 1. Questions de recherche\n")
W("Les pays avec une forte proportion d'utilisateurs mobiles adoptent-ils moins les protocoles modernes (TLS 1.3, IPv6, HTTP/3) ? La 'mobilisation' du trafic est-elle associée à une moindre sécurité ou, au contraire, à une adoption accélérée via les navigateurs mobiles ?\n")
W("## 2. Méthodes\n")
W("- Part mobile = mobile / (desktop + mobile + other) par pays, moyenne 53 semaines\n- Corrélations de Spearman entre part mobile et indicateurs de sécurité\n- Tests Kruskal-Wallis entre tertiles de part mobile\n")
W("## 3. Corrélations clés\n")
W("| Indicateur | ρ Spearman | p-value | Interprétation |")
W("|------------|-----------|---------|----------------|")
for col, b in corr_results.items():
    direction = "mobile → moins sécurisé" if b['rho']<-0.1 else "mobile → plus sécurisé" if b['rho']>0.1 else "pas d'effet clair"
    W(f"| {b['label']} | {b['rho']:.3f} | {b['p']:.4f} | {direction} |")
W("\n## 4. Tests Kruskal-Wallis (tertiles mobile)\n")
W("| Indicateur | H | p-value |")
W("|------------|---|---------|")
for col, kw in kw_results.items():
    W(f"| {indicators[col]} | {kw['stat']:.3f} | {kw['p']:.4f} |")
W("\n## 5. Part mobile mondiale\n")
W(f"- Moyenne : **{dev_ts['mobile_ratio'].mean()*100:.1f}%**")
W(f"- Tendance : {'↑ hausse' if dev_ts['mobile_ratio'].iloc[-1]>dev_ts['mobile_ratio'].iloc[0] else '↓ baisse'}")
W(f"\n---\n*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*")
with open(os.path.join(OUT,"rapport_etude18_mobile_desktop.md"),"w",encoding="utf-8") as f:
    f.write("\n".join(lines))
print("✓ Étude 18 terminée.")
