# etude8_inegalites.py — Fracture numérique de sécurité (Nord-Sud)
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')
from scipy.stats import spearmanr, kruskal
import requests

BASE = r'E:\Webscraping\cloudflare_radar_vulnerabilite\scripts\outputs_complet\cleaned'

GDP_FALLBACK = {
    'US':76329,'CA':53247,'GB':45295,'DE':48717,'FR':43510,'AU':65099,
    'JP':33805,'CH':93259,'NL':57024,'SE':57682,'DK':67790,'NO':101374,
    'SG':65641,'HK':50400,'AT':54810,'BE':51247,'FI':52945,'IE':98259,
    'NZ':46960,'KR':33147,'IL':51342,'AE':47957,'SA':25637,'QA':83891,
    'TW':35510,'IT':34776,'ES':32110,'PT':24505,'CZ':27290,'PL':20585,
    'GR':21580,'HU':20010,'SK':22714,'CL':16510,'MX':10046,'AR':10462,
    'BR':9673,'CO':6635,'TR':10674,'ZA':6192,'RU':12195,'CN':12720,
    'TH':7009,'MY':13352,'BG':15093,'RO':16017,'IN':2392,'PH':3622,
    'VN':4163,'ID':4798,'NG':2184,'KE':1942,'ET':925,'EG':3699,
    'MA':3864,'PK':1488,'BD':2688,'TZ':1190,'UG':906,'GH':2363,
}

INCOME_FALLBACK = {
    'US':'HIC','CA':'HIC','GB':'HIC','DE':'HIC','FR':'HIC','AU':'HIC',
    'JP':'HIC','CH':'HIC','NL':'HIC','SE':'HIC','DK':'HIC','NO':'HIC',
    'SG':'HIC','HK':'HIC','AT':'HIC','BE':'HIC','FI':'HIC','IE':'HIC',
    'NZ':'HIC','KR':'HIC','IL':'HIC','AE':'HIC','SA':'HIC','QA':'HIC',
    'TW':'HIC','IT':'HIC','ES':'HIC','PT':'HIC','CZ':'HIC','PL':'HIC',
    'GR':'HIC','HU':'HIC','SK':'HIC','CL':'UMC','MX':'UMC','AR':'UMC',
    'BR':'UMC','CO':'UMC','TR':'UMC','ZA':'UMC','RU':'UMC','CN':'UMC',
    'TH':'UMC','MY':'UMC','BG':'UMC','RO':'UMC','IN':'LMC','PH':'LMC',
    'VN':'LMC','ID':'LMC','NG':'LMC','KE':'LMC','EG':'LMC','MA':'LMC',
    'PK':'LMC','BD':'LMC','ET':'LIC','TZ':'LIC','UG':'LIC','GH':'LMC',
}

INCOME_LABELS = {'HIC':'Revenus élevés','UMC':'Revenus moyens supérieurs',
                 'LMC':'Revenus moyens inférieurs','LIC':'Revenus faibles'}

def load(name):
    df = pd.read_csv(f'{BASE}/{name}', encoding='utf-8', parse_dates=['date'])
    df['date'] = pd.to_datetime(df['date']).dt.tz_localize(None)
    return df

tls = load('http_tls_version_clean.csv')
ipv = load('http_ip_version_clean.csv')
http = load('http_http_version_clean.csv')

tls13 = tls.groupby('country_iso2')['TLS 1.3'].mean()
ipv6  = ipv.groupby('country_iso2')['IPv6'].mean()
http3 = http.groupby('country_iso2')['HTTP/3'].mean()

pays = pd.DataFrame({'tls13': tls13, 'ipv6': ipv6, 'http3': http3}).reset_index()
pays.columns = ['country', 'tls13', 'ipv6', 'http3']

# Tentative API World Bank
wb_ok = False
try:
    url = "https://api.worldbank.org/v2/country/all/indicator/NY.GDP.PCAP.CD?format=json&date=2023&per_page=300"
    r = requests.get(url, timeout=15)
    data = r.json()
    records = []
    for item in data[1]:
        if item.get('value') is not None:
            iso = item.get('countryiso3code', '')[:2]
            records.append({'country': item['country']['id'], 'gdp': item['value']})
    wb_df = pd.DataFrame(records)
    if len(wb_df) > 50:
        pays = pays.merge(wb_df, on='country', how='left')
        wb_ok = True
        print(f"API World Bank OK : {wb_df['country'].nunique()} pays")
except Exception as e:
    print(f"API WB échouée: {e}")

if not wb_ok:
    pays['gdp'] = pays['country'].map(GDP_FALLBACK)
    print(f"Fallback GDP utilisé : {pays['gdp'].notna().sum()} pays avec données")

# Niveau de revenu
pays['income'] = pays['country'].map(INCOME_FALLBACK)
pays = pays.dropna(subset=['tls13'])

# Analyse par income level
income_stats = pays.groupby('income').agg(
    n=('tls13','count'),
    tls13_mean=('tls13','mean'), tls13_std=('tls13','std'),
    ipv6_mean=('ipv6','mean'),
    http3_mean=('http3','mean'),
    gdp_mean=('gdp','mean')
).round(2)
income_order = ['HIC','UMC','LMC','LIC']
income_stats = income_stats.reindex([i for i in income_order if i in income_stats.index])
print("\n=== Métriques par niveau de revenu ===")
print(income_stats.to_string())

# Corrélations Spearman
pays_clean = pays.dropna(subset=['gdp','tls13'])
rho_tls, p_tls = spearmanr(pays_clean['gdp'], pays_clean['tls13'])
rho_ipv, p_ipv = spearmanr(pays_clean['gdp'], pays_clean['ipv6'].fillna(0))
rho_h3, p_h3   = spearmanr(pays_clean['gdp'], pays_clean['http3'].fillna(0))
print(f"\nSpearman PIB/hab vs TLS 1.3 : rho={rho_tls:.3f}  p={p_tls:.4f}  n={len(pays_clean)}")
print(f"Spearman PIB/hab vs IPv6    : rho={rho_ipv:.3f}  p={p_ipv:.4f}")
print(f"Spearman PIB/hab vs HTTP/3  : rho={rho_h3:.3f}  p={p_h3:.4f}")

# Kruskal-Wallis entre income levels
groups_kw = [pays[pays['income']==i]['tls13'].dropna().values for i in income_order if i in pays['income'].values]
groups_kw = [g for g in groups_kw if len(g) >= 3]
if len(groups_kw) >= 2:
    H_kw, p_kw = kruskal(*groups_kw)
    print(f"Kruskal-Wallis TLS 1.3 entre income levels: H={H_kw:.2f}  p={p_kw:.4f}")

# Figure 1 : Scatter PIB vs TLS 1.3
fig, ax = plt.subplots(figsize=(11, 7))
income_colors = {'HIC':'#1F77B4','UMC':'#2CA02C','LMC':'#FF7F0E','LIC':'#D62728','':'',' ':''}
for inc, grp in pays_clean.groupby('income'):
    ax.scatter(np.log10(grp['gdp']+1), grp['tls13'],
               c=income_colors.get(inc,'gray'), alpha=0.6, s=40,
               label=INCOME_LABELS.get(inc, inc))
# Droite de régression
x_r = np.log10(pays_clean['gdp']+1)
coeffs = np.polyfit(x_r, pays_clean['tls13'], 1)
x_line = np.linspace(x_r.min(), x_r.max(), 100)
ax.plot(x_line, np.polyval(coeffs, x_line), 'k--', linewidth=1.5, alpha=0.6)
ax.set_xlabel('PIB/habitant (log₁₀, US$)', fontsize=11)
ax.set_ylabel('Adoption TLS 1.3 (%)', fontsize=11)
ax.set_title(f'PIB/habitant vs adoption TLS 1.3 — Spearman ρ={rho_tls:.3f} (p={p_tls:.4f})', fontsize=12)
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('etude8_scatter_gdp_tls.png', dpi=150, bbox_inches='tight')
plt.close()

# Figure 2 : Boxplot TLS 1.3 par income level
fig, ax = plt.subplots(figsize=(10, 5))
data_box = [pays[pays['income']==i]['tls13'].dropna().values for i in income_order if i in pays['income'].values]
labels_box = [INCOME_LABELS.get(i, i) for i in income_order if i in pays['income'].values]
bp = ax.boxplot(data_box, labels=labels_box, patch_artist=True)
colors_box = ['#1F77B4','#2CA02C','#FF7F0E','#D62728']
for patch, c in zip(bp['boxes'], colors_box):
    patch.set_facecolor(c); patch.set_alpha(0.7)
ax.set_ylabel('Adoption TLS 1.3 (%)', fontsize=11)
ax.set_title('Adoption TLS 1.3 par niveau de revenu (Kruskal-Wallis)', fontsize=12)
ax.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig('etude8_boxplot_income.png', dpi=150, bbox_inches='tight')
plt.close()

pays.to_csv('etude8_pays_gdp.csv', index=False, encoding='utf-8')
print("\nFichiers : etude8_scatter_gdp_tls.png, etude8_boxplot_income.png, etude8_pays_gdp.csv")
print(f"\n=== RÉSUMÉ ===")
print(f"Source PIB : {'API World Bank' if wb_ok else 'Fallback codé'}")
print(f"rho(PIB, TLS1.3)={rho_tls:.3f} p={p_tls:.4f}")
print(f"KW income levels: H={H_kw:.2f} p={p_kw:.4f}" if len(groups_kw)>=2 else "")
