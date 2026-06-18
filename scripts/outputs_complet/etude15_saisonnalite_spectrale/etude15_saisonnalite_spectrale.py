# -*- coding: utf-8 -*-
"""Étude 15 — Saisonnalité spectrale : FFT + décomposition STL des indicateurs globaux"""
import pandas as pd, numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy import stats as sps
from scipy.fft import rfft, rfftfreq
import warnings, os
warnings.filterwarnings("ignore")

CLEANED = os.path.join(os.path.dirname(__file__), "..", "cleaned")
OUT = os.path.dirname(__file__)

def load(name):
    df = pd.read_csv(os.path.join(CLEANED, name), parse_dates=["date"])
    df["date"] = pd.to_datetime(df["date"], utc=True).dt.normalize()
    return df

print("Chargement...")
tls   = load("http_tls_version_clean.csv")
ipv   = load("http_ip_version_clean.csv")
http3 = load("http_http_version_clean.csv")
bw    = load("iqi_bandwidth_clean.csv")
bot   = load("http_bot_class_clean.csv")
atk   = load("attacks_l3_bitrate_clean.csv")
bgp   = load("bgp_timeseries_clean.csv")
email_sp = load("email_spam_clean.csv")

# ── Séries temporelles mondiales (moyenne pondérée = toutes entrées confondues) ─
tls_ts   = tls.groupby("date")["TLS 1.3"].mean()
ipv_ts   = ipv.groupby("date")["IPv6"].mean()
h3_ts    = http3.groupby("date")["HTTP/3"].mean()
bw_ts    = bw[bw["metric"]=="BANDWIDTH"].groupby("date")["p50"].mean()
bot_ts   = bot.groupby("date")[["human","bot"]].sum()
bot_ts["ratio"] = bot_ts["bot"]/(bot_ts["human"]+bot_ts["bot"])

# BGP total_routes série globale si disponible
if "total_routes" in bgp.columns:
    bgp_ts = bgp.groupby("date")["total_routes"].mean()
else:
    bgp_ts = bgp.groupby("date")[bgp.select_dtypes("number").columns[0]].mean()

# Spam
spam_ts = None
if "SPAM" in email_sp.columns:
    spam_ts = email_sp.groupby("date")["SPAM"].mean()

SERIES = {
    "TLS 1.3 (%)":      tls_ts * 100,
    "IPv6 (%)":         ipv_ts * 100,
    "HTTP/3 (%)":       h3_ts  * 100,
    "BW médiane":       bw_ts,
    "Ratio bot (%)":    bot_ts["ratio"] * 100,
    "BGP routes":       bgp_ts,
}
if spam_ts is not None:
    SERIES["Spam (%)"] = spam_ts * 100

# ── Fonction FFT ─────────────────────────────────────────────────────────────
def fft_analysis(series):
    s = series.dropna()
    if len(s) < 8:
        return pd.DataFrame()
    n  = len(s)
    dt = 1  # 1 semaine
    yf = np.abs(rfft(s.values - s.values.mean()))
    xf = rfftfreq(n, d=dt)
    periods = np.where(xf > 0, 1.0/xf, np.nan)
    df = pd.DataFrame({"freq":xf, "period_weeks":periods, "amplitude":yf})
    df = df[df["freq"] > 0].sort_values("amplitude", ascending=False)
    return df.head(10)

# ── STL-like décomposition manuelle (trend + residual) ─────────────────────
def moving_avg(s, w=4):
    return s.rolling(window=w, center=True).mean()

# ── Calcul FFT pour toutes les séries ─────────────────────────────────────
print("Analyse FFT...")
fft_results = {}
for name, s in SERIES.items():
    df = fft_analysis(s)
    if not df.empty:
        top = df.iloc[0]
        print(f"  {name}: période dominante = {top['period_weeks']:.1f} sem (amp={top['amplitude']:.2f})")
        fft_results[name] = df

# ── Figure 1 : spectres FFT (amplitude vs période) ─────────────────────────
n_series = len(SERIES)
fig, axes = plt.subplots(2, 4, figsize=(18, 8))
axes = axes.flat
colors = ["#1f77b4","#ff7f0e","#2ca02c","#d62728","#9467bd","#8c564b","#e377c2"]
for i, (name, s) in enumerate(SERIES.items()):
    ax = axes[i]
    df = fft_results.get(name)
    if df is None or df.empty:
        ax.set_visible(False); continue
    # Spectrogramme en barres (périodes 2–30 sem)
    sub = df[(df["period_weeks"]>=2) & (df["period_weeks"]<=53)].copy()
    ax.bar(sub["period_weeks"], sub["amplitude"], width=0.8, color=colors[i%len(colors)], alpha=0.8)
    ax.axvline(4,  color="gray", lw=0.8, linestyle="--", alpha=0.5, label="4 sem")
    ax.axvline(13, color="gray", lw=0.8, linestyle=":", alpha=0.5, label="13 sem")
    ax.axvline(26, color="gray", lw=0.8, linestyle="-.", alpha=0.5, label="26 sem")
    ax.set_xlabel("Période (semaines)", fontsize=7)
    ax.set_ylabel("Amplitude FFT", fontsize=7)
    ax.set_title(name, fontsize=9, fontweight="bold")
    ax.set_xlim(0, 55)
    ax.grid(True, alpha=0.3)
for j in range(i+1, 8):
    axes[j].set_visible(False)
plt.suptitle("Spectres FFT des indicateurs internet mondiaux\n(lignes pointillées : 4, 13, 26 semaines)",
             fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude15_fft_spectres.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 2 : séries + tendance lissée (MA4) ─────────────────────────────
fig, axes = plt.subplots(3, 3, figsize=(16, 10))
axes = axes.flat
for i, (name, s) in enumerate(SERIES.items()):
    ax = axes[i]
    s_clean = s.dropna()
    trend = moving_avg(s_clean, w=4)
    ax.plot(s_clean.index, s_clean.values, color=colors[i%len(colors)], lw=1, alpha=0.5, label="Brut")
    ax.plot(trend.index, trend.values, color=colors[i%len(colors)], lw=2.5, label="MA(4)")
    ax.set_title(name, fontsize=9, fontweight="bold")
    ax.legend(fontsize=6); ax.grid(True, alpha=0.3)
    ax.tick_params(axis='x', labelsize=6)
for j in range(i+1, 9):
    axes[j].set_visible(False)
plt.suptitle("Séries temporelles mondiales + tendance lissée (MA4 semaines)", fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude15_series_tendance.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Figure 3 : résidus (saisonnalité) ─────────────────────────────────────
fig, axes = plt.subplots(2, 4, figsize=(18, 7))
axes = axes.flat
for i, (name, s) in enumerate(SERIES.items()):
    ax = axes[i]
    s_clean = s.dropna()
    trend = moving_avg(s_clean, w=4)
    residual = s_clean - trend
    ax.plot(residual.index, residual.values, color=colors[i%len(colors)], lw=1.2)
    ax.axhline(0, color="black", lw=0.8)
    ax.fill_between(residual.index, residual.values, alpha=0.2, color=colors[i%len(colors)])
    ax.set_title(f"{name} — Résidus", fontsize=8, fontweight="bold")
    ax.grid(True, alpha=0.3); ax.tick_params(axis='x', labelsize=6)
for j in range(i+1, 8):
    axes[j].set_visible(False)
plt.suptitle("Composante saisonnière / irrégulière (série − MA4)", fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(OUT,"etude15_residus_saisonniers.png"), dpi=150, bbox_inches="tight")
plt.close()

# ── Rapport ───────────────────────────────────────────────────────────────
lines = []
W = lines.append
W("# Étude 15 — Saisonnalité Spectrale des Indicateurs Internet Mondiaux")
W(f"**Auteur :** Issakha Thiam  \n**Généré le :** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
W("---\n## 1. Questions de recherche\n")
W("Existe-t-il des cycles réguliers (hebdomadaires, mensuels, trimestriels) dans les indicateurs de sécurité internet ? Le trafic bot, les attaques L3, ou le spam présentent-ils une saisonnalité structurelle ?\n")
W("## 2. Méthodes\n")
W("- **FFT (Transformée de Fourier rapide)** : décomposition spectrale des séries temporelles mondiales\n- **Moyenne mobile MA(4)** : extraction de la tendance (équivalent décomposition additive)\n- Résidus = série originale − tendance (composante saisonnière + bruit)\n")
W("## 3. Périodes dominantes\n")
W("| Indicateur | Période dominante (sem) | Amplitude |")
W("|------------|------------------------|-----------|")
for name, df in fft_results.items():
    top = df.iloc[0]
    W(f"| {name} | {top['period_weeks']:.1f} | {top['amplitude']:.2f} |")
W("\n## 4. Interprétation\n")
W("- Une période de **4 semaines** indique un cycle mensuel\n- Une période de **13 semaines** correspond à un cycle trimestriel\n- Une période de **26 semaines** suggère une saisonnalité semi-annuelle\n")
W(f"\n---\n*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*")
with open(os.path.join(OUT,"rapport_etude15_saisonnalite_spectrale.md"),"w",encoding="utf-8") as f:
    f.write("\n".join(lines))
print("Figures : etude15_fft_spectres.png, etude15_series_tendance.png, etude15_residus_saisonniers.png")
print("✓ Étude 15 terminée.")
