# -*- coding: utf-8 -*-
"""Étude 14 — OS legacy et sécurité : Windows/Android vieux = moins sécurisé ?"""
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
os_df  = load("http_os_clean.csv")
tls    = load("http_tls_version_clean.csv")
ipv    = load("http_ip_version_clean.csv")
http3  = load("http_http_version_clean.csv")
bw     = load("iqi_bandwidth_clean.csv")

# Colonnes OS disponibles
OS_COLS = [c for c in os_df.columns if c not in ["date","country_iso2"]]
print(f"  OS détectés : {OS_COLS}")

# ── Part Windows (proxy OS legacy desktop) & Android (mobile) par pays ─────
os_avg = os_df.groupby("country_iso2")[OS_COLS].mean()

# Indice legacy = WINDOWS + ANDROID (parts dominantes mais potentiellement moins à jour)
# Indice moderne = MACOSX + IOS + CHROMEOS (mieux patchés)
win_col  = "WINDOWS"   if "WINDOWS"   in OS_COLS else None
and_col  = "ANDROID"   if "ANDROID"   in OS_COLS else None
mac_col  = "MACOSX"    if "MACOSX"    in OS_COLS else None
ios_col  = "IOS"       if "IOS"       in OS_COLS else None
cros_col = "CHROMEOS"  if "CHROMEOS"  in OS_COLS else None
linux_col= "LINUX"     if "LINUX"     in OS_COLS else None
stv_col  = "SMART_TV"  if "SMART_TV"  in OS_COLS else None

# ── Indicateurs sécurité moyens par pays ────────────────────────────────────
tls_avg  = tls.groupby("country_iso2")[["TLS 1.3"]].mean().rename(columns={"TLS 1.3":"tls13"})
ipv_avg  = ipv.groupby("country_iso2")[["IPv6"]].mean()
h3_avg   = http3.groupby("country_iso2")[["HTTP/3"]].mean()
bw_avg   = bw[bw["metric"]=="BANDWIDTH"].groupby("country_iso2")[["p50"]].mean().rename(columns={"p50":"bw_p50"})

base = os_avg.join(tls_avg).join(ipv_avg).join(h3_avg).join(bw_avg)

# ── Corrélations Spearman OS ~ sécurité ────────────────────────────────────
print("Corrélations Spearman OS ~ sécurité...")
sec_indicators = {"tls13":"TLS 1.3","IPv6":"IPv6","HTTP/3":"HTTP/3","bw_p50":"BW médiane"}
corr_matrix = {}
for os_col in OS_COLS:
    corr_matrix[os_col] = {}
    for sec_col, sec_label in sec_indicators.items():
        sub = base[[os_col, sec_col]].dropna()
        if len(sub) < 20:
            corr_matrix[os_col][sec_col] = (np.nan, np.nan, 0)
            continue
        r, p = sps.spearmanr(sub[os_col], sub[sec_col])
        corr_matrix[os_col][sec_col] = (r, p, len(sub))
        if abs(r) > 0.2:
            print(f"  {os_col} ~ {sec_col}: ρ={r:.3f}  p={p:.4f}")

# ── Série temporelle mondiale OS ────────────────────────────────────────────
os_ts = os_df.groupby("date")[OS_COLS].mean()

# ── Figure 1 : heatmap corrélations OS ~ sécurité ──────────────────────────
rho_matrix = pd.DataFrame({
    os_col: {sec_col: corr_matrix[os_col][sec_col][0] for sec_col in sec_indicators}
    for os_col in OS_COLS
}).T

fig, ax = plt.subplots(figsize=(10,6))
im = ax.imshow(rho_matrix.values, cmap="RdYlGn", vmin=-1, vmax=1, aspect="auto")
ax.set_xticks(range(len(sec_indicators)))
ax.set_xticklabels(list(sec_indicators.values()), fontsize=9)
ax.set_yticks(range(len(OS_COLS)))
ax.set_yticklabels(OS_COLS, fontsize=9)
plt.colorbar(im, ax=ax, label="ρ Spearman")
for i in range(len(OS_COLS)):
    for j in range(len(sec_indicators)):
        v = rho_matrix.values[i,j]
        if not np.isnan(v):
            ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=8,
                    color="black" if abs(v)<0.5 else "white")
ax.set_title("Corrélation ρ Spearman : OS vs Indicateurs de Sécurité (par pays)", fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude14_os_corr_heatmap.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 2 : Série temporelle mondiale OS ────────────────────────────────
fig, ax = plt.subplots(figsize=(13,5))
colors_os = ["#1f77b4","#ff7f0e","#2ca02c","#d62728","#9467bd","#8c564b","#e377c2"]
for col, color in zip(OS_COLS, colors_os):
    ax.plot(os_ts.index, os_ts[col]*100, label=col, color=color, lw=1.8)
ax.set_xlabel("Semaine"); ax.set_ylabel("Part mondiale (%)")
ax.set_title("Évolution mondiale des parts d'OS (juin 2025 – juin 2026)", fontsize=11, fontweight="bold")
ax.legend(loc="upper right", fontsize=8, ncol=2); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude14_os_timeseries.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 3 : scatter Windows ~ TLS 1.3 (relation clé) ────────────────────
if win_col and "tls13" in base.columns:
    sub = base[[win_col,"tls13"]].dropna()
    fig, ax = plt.subplots(figsize=(8,6))
    ax.scatter(sub[win_col]*100, sub["tls13"]*100, alpha=0.5, s=20, color="#1f77b4")
    slope, intercept, r, p, se = sps.linregress(sub[win_col], sub["tls13"])
    xs = np.linspace(sub[win_col].min(), sub[win_col].max(), 100)
    ax.plot(xs*100, (slope*xs+intercept)*100, "r-", lw=2)
    ax.set_xlabel("Part Windows (%)", fontsize=10)
    ax.set_ylabel("TLS 1.3 (%)", fontsize=10)
    ax.set_title(f"Windows vs TLS 1.3 — r={r:.3f}  p={p:.4f}", fontsize=11, fontweight="bold")
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT,"etude14_windows_tls.png"), dpi=150, bbox_inches="tight")
    plt.close()

# ── Export CSV ────────────────────────────────────────────────────────────
base.reset_index().to_csv(os.path.join(OUT,"etude14_os_pays.csv"), index=False)

# ── Rapport ───────────────────────────────────────────────────────────────
lines = []
W = lines.append
W("# Étude 14 — OS Legacy et Sécurité : Windows/Android = Moins Sécurisé ?")
W(f"**Auteur :** Issakha Thiam  \n**Généré le :** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
W("---\n## 1. Questions de recherche\n")
W("Les pays avec une forte prévalence de Windows ou Android adoptent-ils moins les protocoles modernes (TLS 1.3, IPv6, HTTP/3) ? Existe-t-il un 'effet OS' sur la sécurité internet ?\n")
W("## 2. Méthodes\n")
W("- Parts moyennes de chaque OS par pays sur 53 semaines\n- Corrélations de Spearman entre parts OS et indicateurs de sécurité\n- Régression linéaire Windows ~ TLS 1.3 (relation clé)\n")
W("## 3. Matrice de corrélations Spearman\n")
W("| OS | TLS 1.3 | IPv6 | HTTP/3 | BW médiane |")
W("|-----|---------|------|--------|------------|")
for os_col in OS_COLS:
    row_vals = []
    for sec_col in sec_indicators:
        r, p, n = corr_matrix[os_col][sec_col]
        if np.isnan(r):
            row_vals.append("—")
        else:
            sig = "**" if p < 0.05 else ""
            row_vals.append(f"{sig}{r:.3f}{sig}")
    W(f"| {os_col} | {' | '.join(row_vals)} |")
W("\n*Gras = p<0.05*\n")
W("## 4. Tendances mondiales\n")
for col in OS_COLS:
    s = os_ts[col]
    trend = "↑" if s.iloc[-1] > s.iloc[0] else "↓"
    W(f"- **{col}** : {s.mean()*100:.1f}% en moyenne  {trend}")
W(f"\n---\n*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*")
with open(os.path.join(OUT,"rapport_etude14_os_legacy.md"),"w",encoding="utf-8") as f:
    f.write("\n".join(lines))
print("✓ Étude 14 terminée.")
