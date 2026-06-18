# etude1_geopolitique.py — Géopolitique de la sécurité internet par région
import pandas as pd
import numpy as np
import matplotlib
import os; os.chdir(os.path.dirname(os.path.abspath(__file__)))

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')
from scipy.stats import kruskal, f_oneway

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cleaned')

REGIONS = {
    'FR':'EU-West','DE':'EU-West','GB':'EU-West','ES':'EU-West','IT':'EU-West',
    'NL':'EU-West','BE':'EU-West','AT':'EU-West','CH':'EU-West','SE':'EU-West',
    'NO':'EU-West','DK':'EU-West','FI':'EU-West','PT':'EU-West','IE':'EU-West',
    'LU':'EU-West','MT':'EU-West','CY':'EU-West','GR':'EU-West','LI':'EU-West',
    'PL':'EU-East','RO':'EU-East','HU':'EU-East','CZ':'EU-East','SK':'EU-East',
    'BG':'EU-East','HR':'EU-East','RS':'EU-East','UA':'EU-East','BY':'EU-East',
    'RU':'EU-East','LT':'EU-East','LV':'EU-East','EE':'EU-East','SI':'EU-East',
    'US':'NA','CA':'NA','MX':'NA',
    'BR':'LATAM','AR':'LATAM','CL':'LATAM','CO':'LATAM','PE':'LATAM','VE':'LATAM',
    'EC':'LATAM','BO':'LATAM','PY':'LATAM','UY':'LATAM','CR':'LATAM','PA':'LATAM',
    'JP':'APAC-Dev','AU':'APAC-Dev','NZ':'APAC-Dev','SG':'APAC-Dev','KR':'APAC-Dev',
    'HK':'APAC-Dev','TW':'APAC-Dev',
    'CN':'APAC-Em','IN':'APAC-Em','TH':'APAC-Em','VN':'APAC-Em','PH':'APAC-Em',
    'ID':'APAC-Em','MY':'APAC-Em','BD':'APAC-Em','PK':'APAC-Em','MM':'APAC-Em',
    'SA':'MENA','AE':'MENA','IL':'MENA','TR':'MENA','EG':'MENA','IR':'MENA',
    'IQ':'MENA','JO':'MENA','LB':'MENA','QA':'MENA','KW':'MENA','BH':'MENA',
    'ZA':'Africa','NG':'Africa','KE':'Africa','GH':'Africa','ET':'Africa',
    'TZ':'Africa','UG':'Africa','DZ':'Africa','MA':'Africa','TN':'Africa',
    'SN':'Africa','CI':'Africa','CM':'Africa','AO':'Africa','MZ':'Africa',
}

def load(name):
    df = pd.read_csv(f'{BASE}/{name}', encoding='utf-8', parse_dates=['date'])
    df['date'] = pd.to_datetime(df['date']).dt.tz_localize(None)
    return df

tls = load('http_tls_version_clean.csv')
ipv = load('http_ip_version_clean.csv')
http = load('http_http_version_clean.csv')
iqi = load('iqi_bandwidth_clean.csv')

# Agrégation par pays (moyenne sur 53 semaines)
tls13 = tls.groupby('country_iso2')['TLS 1.3'].mean()
ipv6  = ipv.groupby('country_iso2')['IPv6'].mean()
http3 = http.groupby('country_iso2')['HTTP/3'].mean()

# IQI : p50 uniquement (BANDWIDTH)
iqi_bw = iqi[iqi['metric'] == 'BANDWIDTH'].copy()
iqi_med = iqi_bw.groupby('country_iso2')['p50'].mean()

# Fusion
pays = pd.DataFrame({
    'tls13': tls13,
    'ipv6': ipv6,
    'http3': http3,
    'iqi_p50': iqi_med
}).reset_index()
pays.columns = ['country', 'tls13', 'ipv6', 'http3', 'iqi_p50']
pays['region'] = pays['country'].map(REGIONS).fillna('Other')
pays = pays.dropna(subset=['tls13'])

print(f"Pays analysés : {len(pays)}")
print(f"Régions : {pays['region'].value_counts().to_dict()}")

# Statistiques par région
reg = pays.groupby('region').agg(
    n=('tls13','count'),
    tls13_mean=('tls13','mean'), tls13_std=('tls13','std'),
    ipv6_mean=('ipv6','mean'),
    http3_mean=('http3','mean'),
    iqi_mean=('iqi_p50','mean')
).round(2)
print("\n=== Statistiques par région ===")
print(reg.to_string())

# ANOVA et Kruskal-Wallis sur TLS 1.3
regions_list = [g for _, g in pays.groupby('region')['tls13'] if len(g) >= 3]
if len(regions_list) >= 2:
    F_an, p_an = f_oneway(*regions_list)
    H_kw, p_kw = kruskal(*regions_list)
    print(f"\nANOVA TLS 1.3: F={F_an:.2f}  p={p_an:.4f}")
    print(f"Kruskal-Wallis: H={H_kw:.2f}  p={p_kw:.4f}")

# Top/Bottom 15
pays_sorted = pays.sort_values('tls13', ascending=False)
print("\nTop 15 pays (TLS 1.3):")
print(pays_sorted[['country','region','tls13','ipv6','http3']].head(15).to_string(index=False))
print("\nBottom 15 pays (TLS 1.3):")
print(pays_sorted[['country','region','tls13','ipv6','http3']].tail(15).to_string(index=False))

# Sauvegarde
pays.to_csv('etude1_pays.csv', index=False, encoding='utf-8')
reg.reset_index().to_csv('etude1_regions.csv', index=False, encoding='utf-8')

# --- Figure : Boxplot TLS 1.3 par région ---
reg_order = reg['tls13_mean'].sort_values(ascending=False).index.tolist()
fig, ax = plt.subplots(figsize=(13, 6))
data_plot = [pays[pays['region'] == r]['tls13'].dropna().values for r in reg_order]
bp = ax.boxplot(data_plot, labels=reg_order, patch_artist=True, notch=False)
palette = ['#1F77B4','#FF7F0E','#2CA02C','#D62728','#9467BD','#8C564B','#E377C2','#7F7F7F']
for patch, color in zip(bp['boxes'], palette[:len(reg_order)]):
    patch.set_facecolor(color)
    patch.set_alpha(0.7)
ax.set_title('Distribution de l\'adoption TLS 1.3 par région (2025-2026)', fontsize=13)
ax.set_ylabel('TLS 1.3 (%)', fontsize=11)
ax.set_xlabel('Région', fontsize=11)
ax.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig('etude1_regions_boxplot.png', dpi=150, bbox_inches='tight')
plt.close()

# --- Figure 2 : Heatmap métriques × régions ---
fig, ax = plt.subplots(figsize=(10, 5))
metrics = ['tls13_mean','ipv6_mean','http3_mean']
reg2 = reg[metrics].dropna()
im = ax.imshow(reg2.values.T, aspect='auto', cmap='YlOrRd')
ax.set_xticks(range(len(reg2)))
ax.set_xticklabels(reg2.index, rotation=30, ha='right', fontsize=10)
ax.set_yticks(range(len(metrics)))
ax.set_yticklabels(['TLS 1.3 (%)', 'IPv6 (%)', 'HTTP/3 (%)'], fontsize=10)
for i in range(len(reg2)):
    for j, m in enumerate(metrics):
        v = reg2.iloc[i][m]
        ax.text(i, j, f'{v:.1f}', ha='center', va='center', fontsize=9,
                color='white' if v > 50 else 'black')
plt.colorbar(im, ax=ax)
ax.set_title('Métriques de sécurité protocolaire par région', fontsize=12)
plt.tight_layout()
plt.savefig('etude1_heatmap.png', dpi=150, bbox_inches='tight')
plt.close()

print("\nGraphiques : etude1_regions_boxplot.png, etude1_heatmap.png")
print(f"\n=== RÉSUMÉ ===")
print(f"ANOVA: F={F_an:.2f} p={p_an:.4f}  |  KW: H={H_kw:.2f} p={p_kw:.4f}")
print(f"Meilleure région TLS 1.3: {reg['tls13_mean'].idxmax()} ({reg['tls13_mean'].max():.1f}%)")
print(f"Plus faible: {reg['tls13_mean'].idxmin()} ({reg['tls13_mean'].min():.1f}%)")
