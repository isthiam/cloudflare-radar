# etude3_weekends.py — Analyse week-ends et jours fériés (données L7 quotidiennes)
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')
from scipy.stats import mannwhitneyu, kruskal

BASE = r'E:\Webscraping\cloudflare_radar_vulnerabilite\scripts\outputs_complet\cleaned'

df = pd.read_csv(f'{BASE}/attacks_l7_vertical_clean.csv', encoding='utf-8', parse_dates=['date'])
df['date'] = pd.to_datetime(df['date']).dt.tz_localize(None)

# Filtrer uniquement dimension=vertical
df = df[df['dimension'] == 'vertical'].copy()
print(f"Données L7 : {len(df)} lignes, {df['date'].nunique()} jours")
print("Colonnes :", list(df.columns))

# Colonnes sectorielles
secteurs = [c for c in df.columns if c not in ['date', 'dimension']]
secteurs_num = [c for c in secteurs if df[c].dtype in [np.float64, np.int64]]
print(f"Secteurs numériques : {secteurs_num}")

# Les colonnes sont des distributions en % (somme = 100)
# Score "secteurs vulnérables week-end" : Finance, Gambling, Art/Entertainment
weekend_sensitive = [c for c in secteurs_num if any(k in c for k in ['Finance','Gambling','Art','Entertainment','Shopping'])]
weekday_heavy = [c for c in secteurs_num if any(k in c for k in ['Business','Professional','Internet','Telecom'])]
print(f"Secteurs 'week-end sensibles' : {weekend_sensitive}")
print(f"Secteurs 'jour ouvré dominants' : {weekday_heavy}")

df['score_we_sensitive'] = df[weekend_sensitive].sum(axis=1, skipna=True) if weekend_sensitive else df[secteurs_num[0]]
df['score_wd_heavy'] = df[weekday_heavy].sum(axis=1, skipna=True) if weekday_heavy else df[secteurs_num[1]]
# Indice de diversité Shannon
from scipy.stats import entropy as sh_entropy
def shannon_div(row):
    vals = row[secteurs_num].fillna(0).values
    vals = vals[vals > 0] / 100
    return sh_entropy(vals, base=2) if len(vals) > 0 else 0
df['shannon_entropy'] = df.apply(shannon_div, axis=1)
df['score_total'] = df['score_we_sensitive']  # proxy principal

# Variables temporelles
df['dow'] = df['date'].dt.dayofweek  # 0=lundi, 6=dimanche
df['dow_name'] = df['date'].dt.day_name(locale=None)
df['is_weekend'] = df['dow'].isin([5, 6])

# Jours fériés 2026
jours_feries_2026 = pd.to_datetime([
    '2026-01-01', '2026-04-06', '2026-05-01', '2026-05-08',
    '2026-05-14', '2026-05-25', '2026-07-14', '2026-08-15',
    '2026-11-01', '2026-11-11', '2026-12-25'
])
# Jours fériés 2025
jours_feries_2025 = pd.to_datetime([
    '2025-01-01', '2025-04-21', '2025-05-01', '2025-05-08',
    '2025-05-29', '2025-06-09', '2025-07-14', '2025-08-15',
    '2025-11-01', '2025-11-11', '2025-12-25'
])
all_feries = list(jours_feries_2026) + list(jours_feries_2025)
df['is_ferie'] = df['date'].isin([d.date() for d in all_feries]) | df['date'].dt.date.astype(str).isin([str(d.date()) for d in all_feries])
df['is_special'] = df['is_weekend'] | df['is_ferie']

# Statistiques
wd = df[~df['is_weekend']]['score_total'].dropna()
we = df[df['is_weekend']]['score_total'].dropna()
fe = df[df['is_ferie']]['score_total'].dropna()

print(f"\nScore moyen jours ouvrés  : {wd.mean():.2f} ± {wd.std():.2f}")
print(f"Score moyen week-ends     : {we.mean():.2f} ± {we.std():.2f}")
print(f"Ratio WE/JO : {we.mean()/wd.mean():.3f}")

# Mann-Whitney U
stat_mw, p_mw = mannwhitneyu(we, wd, alternative='two-sided')
print(f"\nMann-Whitney U (WE vs JO): U={stat_mw:.1f}  p={p_mw:.4f}")

# Effect size Cohen d
pooled_std = np.sqrt((we.std()**2 + wd.std()**2) / 2)
cohen_d = (we.mean() - wd.mean()) / pooled_std if pooled_std > 0 else 0
print(f"Effect size Cohen d = {cohen_d:.3f}")

# Kruskal-Wallis par jour
groups = [df[df['dow'] == d]['score_total'].dropna().values for d in range(7)]
groups = [g for g in groups if len(g) > 0]
if len(groups) >= 3:
    stat_kw, p_kw = kruskal(*groups)
    print(f"Kruskal-Wallis (7 jours): H={stat_kw:.2f}  p={p_kw:.4f}")
else:
    stat_kw, p_kw = 0, 1

# Jours fériés
if len(fe) >= 2 and len(wd) >= 2:
    stat_fe, p_fe = mannwhitneyu(fe, wd, alternative='two-sided')
    print(f"Mann-Whitney U (fériés vs JO): U={stat_fe:.1f}  p={p_fe:.4f}")

# Par secteur
print("\n=== Ratio WE/JO par secteur ===")
for sec in secteurs_num:
    s_wd = df[~df['is_weekend']][sec].mean()
    s_we = df[df['is_weekend']][sec].mean()
    ratio = s_we / s_wd if s_wd > 0 else 1
    print(f"  {sec[:35]:<35} WE={s_we:.1f}  JO={s_wd:.1f}  ratio={ratio:.3f}")

# Moyenne par jour de semaine
dow_means = df.groupby('dow_name')['score_total'].agg(['mean','std','count'])
dow_order = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday']
dow_means = dow_means.reindex([d for d in dow_order if d in dow_means.index])
print("\nMoyenne par jour :")
print(dow_means.round(2))

# --- Figure 1 : Boxplot par jour ---
fig, ax = plt.subplots(figsize=(12, 6))
dow_data = [df[df['dow'] == d]['score_total'].dropna().values for d in range(7)]
jours_fr = ['Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi', 'Dimanche']
colors_box = ['#4C72B0']*5 + ['#DD8452', '#DD8452']
bp = ax.boxplot(dow_data, labels=jours_fr, patch_artist=True, notch=False)
for patch, color in zip(bp['boxes'], colors_box):
    patch.set_facecolor(color)
    patch.set_alpha(0.7)
ax.set_title('Distribution des attaques L7 par jour de la semaine (Mars-Juin 2026)', fontsize=13)
ax.set_ylabel('Score total d\'attaques (%)', fontsize=11)
ax.set_xlabel('Jour de la semaine', fontsize=11)
ax.grid(True, alpha=0.3, axis='y')
ax.text(0.98, 0.97, f'WE vs JO: p={p_mw:.3f}\nd={cohen_d:.3f}',
        transform=ax.transAxes, ha='right', va='top', fontsize=9,
        bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
plt.tight_layout()
plt.savefig('etude3_boxplot.png', dpi=150, bbox_inches='tight')
plt.close()

# --- Figure 2 : Série temporelle avec annotations WE ---
fig, ax = plt.subplots(figsize=(14, 5))
ax.plot(df['date'], df['score_total'], color='#4C72B0', linewidth=0.8, alpha=0.7)
we_dates = df[df['is_weekend']]['date']
ax.scatter(df[df['is_weekend']]['date'], df[df['is_weekend']]['score_total'],
           color='#DD8452', s=20, alpha=0.8, label='Week-end', zorder=5)
ax.set_title('Attaques L7 quotidiennes (85 jours) — week-ends en orange', fontsize=12)
ax.set_ylabel('Score total (%)', fontsize=10)
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('etude3_timeline.png', dpi=150, bbox_inches='tight')
plt.close()

print("\nGraphiques sauvegardés : etude3_boxplot.png, etude3_timeline.png")
print(f"\n=== RÉSUMÉ ÉTUDE 3 ===")
print(f"Jours analysés : {len(df)}")
print(f"Week-ends : {we.mean():.2f}  Jours ouvrés : {wd.mean():.2f}  Ratio : {we.mean()/wd.mean():.3f}")
print(f"Mann-Whitney p = {p_mw:.4f}  Cohen d = {cohen_d:.3f}")
print(f"Kruskal-Wallis H = {stat_kw:.2f}  p = {p_kw:.4f}")
