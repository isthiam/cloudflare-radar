# etude7_browsers.py — Impact des mises à jour navigateurs sur TLS/HTTP3
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')
from scipy.stats import mannwhitneyu, spearmanr

BASE = r'E:\Webscraping\cloudflare_radar_vulnerabilite\scripts\outputs_complet\cleaned'

# Dates releases Chrome (cycle 4 semaines environ)
chrome_releases = [
    {'version': 125, 'date': '2025-06-04', 'tls_related': False, 'http3_related': False},
    {'version': 126, 'date': '2025-06-25', 'tls_related': False, 'http3_related': True},
    {'version': 127, 'date': '2025-07-23', 'tls_related': False, 'http3_related': True},
    {'version': 128, 'date': '2025-08-20', 'tls_related': True,  'http3_related': False},
    {'version': 129, 'date': '2025-09-17', 'tls_related': True,  'http3_related': False},
    {'version': 130, 'date': '2025-10-15', 'tls_related': True,  'http3_related': False},
    {'version': 131, 'date': '2025-11-12', 'tls_related': True,  'http3_related': False},
    {'version': 132, 'date': '2026-01-14', 'tls_related': True,  'http3_related': False},
    {'version': 133, 'date': '2026-02-04', 'tls_related': False, 'http3_related': True},
    {'version': 134, 'date': '2026-03-04', 'tls_related': False, 'http3_related': True},
    {'version': 135, 'date': '2026-04-01', 'tls_related': True,  'http3_related': False},
    {'version': 136, 'date': '2026-04-29', 'tls_related': False, 'http3_related': True},
    {'version': 137, 'date': '2026-05-27', 'tls_related': True,  'http3_related': False},
]
firefox_releases = [
    {'version': 127, 'date': '2025-06-10', 'tls_related': True,  'http3_related': False},
    {'version': 128, 'date': '2025-07-09', 'tls_related': False, 'http3_related': True},
    {'version': 129, 'date': '2025-08-06', 'tls_related': True,  'http3_related': False},
    {'version': 130, 'date': '2025-09-03', 'tls_related': True,  'http3_related': False},
    {'version': 131, 'date': '2025-10-01', 'tls_related': True,  'http3_related': False},
    {'version': 132, 'date': '2025-10-29', 'tls_related': False, 'http3_related': True},
    {'version': 133, 'date': '2025-11-26', 'tls_related': True,  'http3_related': False},
    {'version': 134, 'date': '2026-01-07', 'tls_related': True,  'http3_related': False},
    {'version': 135, 'date': '2026-02-04', 'tls_related': False, 'http3_related': True},
    {'version': 136, 'date': '2026-03-04', 'tls_related': True,  'http3_related': False},
    {'version': 137, 'date': '2026-04-01', 'tls_related': True,  'http3_related': False},
    {'version': 138, 'date': '2026-04-29', 'tls_related': False, 'http3_related': True},
    {'version': 139, 'date': '2026-05-27', 'tls_related': True,  'http3_related': False},
]
chrome_df = pd.DataFrame(chrome_releases)
chrome_df['date'] = pd.to_datetime(chrome_df['date'])
firefox_df = pd.DataFrame(firefox_releases)
firefox_df['date'] = pd.to_datetime(firefox_df['date'])

# Charge données TLS et HTTP3
tls = pd.read_csv(f'{BASE}/http_tls_version_clean.csv', encoding='utf-8', parse_dates=['date'])
tls['date'] = pd.to_datetime(tls['date']).dt.tz_localize(None)
http = pd.read_csv(f'{BASE}/http_http_version_clean.csv', encoding='utf-8', parse_dates=['date'])
http['date'] = pd.to_datetime(http['date']).dt.tz_localize(None)

# Agrégation globale par semaine
dates_all = tls['date'].sort_values().unique()
tls13_g  = tls.groupby('date')['TLS 1.3'].mean()
tlsq_g   = tls.groupby('date')['TLS QUIC'].mean()
tls12_g  = tls.groupby('date')['TLS 1.2'].mean()
http3_g  = http.groupby('date')['HTTP/3'].mean()

ts = pd.DataFrame({'tls13': tls13_g, 'tlsquic': tlsq_g, 'tls12': tls12_g, 'http3': http3_g})
ts = ts.sort_index().interpolate()
dates_ts = ts.index
print(f"Série temporelle : {len(ts)} semaines")
print(f"TLS 1.3 : {ts['tls13'].mean():.1f}%  HTTP/3 : {ts['http3'].mean():.1f}%")

def find_closest_week(release_date, dates_idx):
    diffs = np.abs((dates_idx - pd.Timestamp(release_date)).total_seconds())
    return int(np.argmin(diffs))

# Aligner les releases sur les semaines
for df_rel, name in [(chrome_df, 'chrome'), (firefox_df, 'firefox')]:
    df_rel['week_idx'] = df_rel['date'].apply(lambda d: find_closest_week(d, dates_ts))

# Event study : variation TLS 1.3 dans les 4 semaines suivant une release TLS-related
WINDOW = 4
effects_chrome_tls = []
effects_chrome_h3  = []
effects_ff_tls     = []

for _, row in chrome_df.iterrows():
    idx = row['week_idx']
    if idx + WINDOW < len(ts):
        post = ts['tls13'].iloc[idx+1:idx+WINDOW+1].mean()
        pre  = ts['tls13'].iloc[max(0,idx-WINDOW):idx].mean()
        delta = post - pre
        if row['tls_related']:
            effects_chrome_tls.append(delta)
        if row['http3_related']:
            h3_post = ts['http3'].iloc[idx+1:idx+WINDOW+1].mean()
            h3_pre  = ts['http3'].iloc[max(0,idx-WINDOW):idx].mean()
            effects_chrome_h3.append(h3_post - h3_pre)

for _, row in firefox_df.iterrows():
    idx = row['week_idx']
    if idx + WINDOW < len(ts) and row['tls_related']:
        post = ts['tls13'].iloc[idx+1:idx+WINDOW+1].mean()
        pre  = ts['tls13'].iloc[max(0,idx-WINDOW):idx].mean()
        effects_ff_tls.append(post - pre)

print(f"\nEffet moyen Chrome (TLS-related) sur TLS 1.3 : {np.mean(effects_chrome_tls):.3f}% pts")
print(f"Effet moyen Chrome (HTTP3-related) sur HTTP/3 : {np.mean(effects_chrome_h3):.3f}% pts")
print(f"Effet moyen Firefox (TLS-related) sur TLS 1.3 : {np.mean(effects_ff_tls):.3f}% pts")

# Mann-Whitney : semaines post-release TLS vs ordinaires
all_tls_rel_weeks = set()
for _, row in chrome_df.iterrows():
    if row['tls_related']:
        all_tls_rel_weeks.update(range(row['week_idx']+1, min(len(ts), row['week_idx']+5)))
for _, row in firefox_df.iterrows():
    if row['tls_related']:
        all_tls_rel_weeks.update(range(row['week_idx']+1, min(len(ts), row['week_idx']+5)))

delta_ts = ts['tls13'].diff().fillna(0).values
post_vals = delta_ts[sorted(all_tls_rel_weeks)]
other_vals = np.delete(delta_ts, sorted(all_tls_rel_weeks))
if len(post_vals) >= 3:
    mw_stat, mw_p = mannwhitneyu(post_vals, other_vals, alternative='two-sided')
    print(f"\nMann-Whitney (post-release vs ordinaire) : U={mw_stat:.1f}  p={mw_p:.4f}")

# Figure 1 : TLS 1.3 avec marqueurs Chrome
fig, ax = plt.subplots(figsize=(14, 6))
ax.plot(dates_ts, ts['tls13'].values, color='#1F77B4', linewidth=1.8, label='TLS 1.3 mondial (%)')
ax.fill_between(dates_ts, ts['tls13'].values, alpha=0.15, color='#1F77B4')

tls_chrome = chrome_df[chrome_df['tls_related']]
for _, row in tls_chrome.iterrows():
    idx = row['week_idx']
    if idx < len(dates_ts):
        ax.axvline(x=dates_ts[idx], color='#D62728', linestyle='--', alpha=0.5, linewidth=1)
        ax.annotate(f"C{row['version']}", (dates_ts[idx], ts['tls13'].iloc[idx]),
                    xytext=(0, 8), textcoords='offset points', fontsize=7, color='#D62728',
                    ha='center')

ax.set_ylabel('TLS 1.3 (%)', fontsize=11)
ax.set_title('Adoption TLS 1.3 mondiale avec releases Chrome liées TLS (2025-2026)', fontsize=12)
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('etude7_tls_timeline.png', dpi=150, bbox_inches='tight')
plt.close()

# Figure 2 : HTTP/3 avec Firefox
fig, ax = plt.subplots(figsize=(14, 5))
ax.plot(dates_ts, ts['http3'].values, color='#2CA02C', linewidth=1.8, label='HTTP/3 mondial (%)')
h3_ff = firefox_df[firefox_df['http3_related']]
for _, row in h3_ff.iterrows():
    idx = row['week_idx']
    if idx < len(dates_ts):
        ax.axvline(x=dates_ts[idx], color='#FF7F0E', linestyle='--', alpha=0.5, linewidth=1)
        ax.annotate(f"FF{row['version']}", (dates_ts[idx], ts['http3'].iloc[idx]),
                    xytext=(0, 6), textcoords='offset points', fontsize=7, color='#FF7F0E', ha='center')
ax.set_ylabel('HTTP/3 (%)', fontsize=11)
ax.set_title('Adoption HTTP/3 mondiale avec releases Firefox HTTP3-related', fontsize=12)
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('etude7_http3_browsers.png', dpi=150, bbox_inches='tight')
plt.close()

# Tendances globales
from scipy.stats import linregress
x_t = np.arange(len(ts))
slope_tls, _, r_tls, _, _ = linregress(x_t, ts['tls13'].values)
slope_h3, _, r_h3, _, _   = linregress(x_t, ts['http3'].values)
print(f"\nTendance TLS 1.3 : +{slope_tls*52:.2f}%/an  R²={r_tls**2:.3f}")
print(f"Tendance HTTP/3  : +{slope_h3*52:.2f}%/an  R²={r_h3**2:.3f}")

print("\nFichiers : etude7_tls_timeline.png, etude7_http3_browsers.png")
print(f"\n=== RÉSUMÉ ===")
print(f"Effet moyen Chrome TLS-release sur TLS 1.3 : {np.mean(effects_chrome_tls):+.3f}%pts")
print(f"Effet moyen Chrome HTTP3-release sur HTTP/3 : {np.mean(effects_chrome_h3):+.3f}%pts")
print(f"Tendance TLS 1.3 : {slope_tls*52:+.2f}%/an  |  Tendance HTTP/3 : {slope_h3*52:+.2f}%/an")
