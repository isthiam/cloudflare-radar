# etude10_iqi_proxy.py — IQI comme proxy du développement
import pandas as pd
import numpy as np
import matplotlib
import os; os.chdir(os.path.dirname(os.path.abspath(__file__)))

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')
from scipy.stats import spearmanr, linregress

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cleaned')

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
    'DZ':5694,'LY':6573,'TN':4029,'SD':851,'CM':1612,'CI':2664,
}

INCOME = {
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

# Charge IQI bandwidth
iqi = pd.read_csv(f'{BASE}/iqi_bandwidth_clean.csv', encoding='utf-8', parse_dates=['date'])
iqi['date'] = pd.to_datetime(iqi['date']).dt.tz_localize(None)
iqi_bw = iqi[iqi['metric'] == 'BANDWIDTH'].copy()

# Agrégation par pays
iqi_mean = iqi_bw.groupby('country_iso2')['p50'].mean().reset_index()
iqi_mean.columns = ['country', 'iqi_p50']

# Tendance temporelle de l'IQI par pays (coefficient de régression = pente)
def trend_coeff(series):
    if series.dropna().shape[0] < 4:
        return np.nan
    x = np.arange(len(series))
    mask = ~series.isna()
    if mask.sum() < 4:
        return np.nan
    slope, _, _, _, _ = linregress(x[mask], series[mask])
    return slope

iqi_trend = iqi_bw.sort_values('date').groupby('country_iso2')['p50'].apply(trend_coeff).reset_index()
iqi_trend.columns = ['country', 'iqi_trend']

# Fusion
df = iqi_mean.merge(iqi_trend, on='country', how='left')
df['gdp'] = df['country'].map(GDP_FALLBACK)
df['income'] = df['country'].map(INCOME)

# Essai API World Bank
try:
    import requests
    r = requests.get('https://api.worldbank.org/v2/country/all/indicator/NY.GDP.PCAP.CD?format=json&date=2023&per_page=300', timeout=10)
    wbdata = r.json()
    for item in wbdata[1]:
        if item.get('value'):
            iso2 = item['country']['id']
            if iso2 in df['country'].values:
                df.loc[df['country']==iso2, 'gdp'] = item['value']
    print("API WB utilisée pour enrichir GDP")
except:
    print("Fallback GDP utilisé")

df_clean = df.dropna(subset=['iqi_p50', 'gdp'])
print(f"Pays avec données IQI + GDP : {len(df_clean)}")

# Corrélations
rho, p_rho = spearmanr(df_clean['gdp'], df_clean['iqi_p50'])
print(f"Spearman IQI vs PIB/hab : rho={rho:.3f}  p={p_rho:.4f}")

# Régression log-log
log_gdp = np.log10(df_clean['gdp'] + 1)
log_iqi = np.log10(df_clean['iqi_p50'].clip(lower=0.01) + 1)
slope, intercept, r_value, p_val, se = linregress(log_gdp, log_iqi)
r2 = r_value**2
print(f"Régression log-log : pente={slope:.3f}  R²={r2:.3f}  p={p_val:.4f}")

# Quadrants (IQI vs GDP, médianes comme seuils)
iqi_med = df_clean['iqi_p50'].median()
gdp_med = df_clean['gdp'].median()
print(f"\nSeuils médians : IQI={iqi_med:.1f}  GDP={gdp_med:.0f}")

def quadrant(row):
    if row['iqi_p50'] >= iqi_med and row['gdp'] >= gdp_med:
        return 'Leaders (haut IQI, haut PIB)'
    elif row['iqi_p50'] >= iqi_med and row['gdp'] < gdp_med:
        return 'Efficaces (haut IQI, bas PIB)'
    elif row['iqi_p50'] < iqi_med and row['gdp'] >= gdp_med:
        return 'Sous-performants (bas IQI, haut PIB)'
    else:
        return 'En retard (bas IQI, bas PIB)'

df_clean = df_clean.copy()
df_clean['quadrant'] = df_clean.apply(quadrant, axis=1)
print("\nDistribution par quadrant :")
print(df_clean['quadrant'].value_counts().to_string())
print("\nExemples par quadrant (5 pays) :")
for q in df_clean['quadrant'].unique():
    ex = df_clean[df_clean['quadrant']==q]['country'].head(5).tolist()
    print(f"  {q}: {ex}")

# Relation tendance IQI vs PIB
df_trend = df_clean.dropna(subset=['iqi_trend'])
if len(df_trend) > 10:
    rho_t, p_t = spearmanr(df_trend['gdp'], df_trend['iqi_trend'])
    print(f"\nSpearman tendance IQI vs PIB : rho={rho_t:.3f}  p={p_t:.4f}")
    interp_t = "Les pays riches voient leur IQI croître plus vite" if rho_t > 0 else "Les pays émergents ont une dynamique IQI plus forte"
    print(f"  → {interp_t}")

# Figure
income_colors = {'HIC':'#1F77B4','UMC':'#2CA02C','LMC':'#FF7F0E','LIC':'#D62728'}
INCOME_LABELS = {'HIC':'Revenus élevés','UMC':'Moy. sup.','LMC':'Moy. inf.','LIC':'Faibles'}
fig, ax = plt.subplots(figsize=(12, 7))
for inc, grp in df_clean.groupby('income'):
    ax.scatter(np.log10(grp['gdp']+1), grp['iqi_p50'],
               c=income_colors.get(inc,'gray'), alpha=0.65, s=40,
               label=INCOME_LABELS.get(inc, inc))
# Droite de régression
x_lin = np.linspace(log_gdp.min(), log_gdp.max(), 100)
y_lin = 10**(slope * x_lin + intercept) - 1
ax.plot(x_lin, y_lin, 'k--', linewidth=1.5, alpha=0.6, label=f'Régression (R²={r2:.2f})')
# Labels pour pays remarquables
highlights = ['US','CN','IN','DE','FR','NG','ET','SG','JP','BR','ZA','KE']
for _, row in df_clean.iterrows():
    if row['country'] in highlights and not np.isnan(row['iqi_p50']):
        ax.annotate(row['country'], (np.log10(row['gdp']+1), row['iqi_p50']),
                    fontsize=8, alpha=0.85, xytext=(3,3), textcoords='offset points')
ax.set_xlabel('PIB/habitant (log₁₀, US$)', fontsize=11)
ax.set_ylabel('IQI bande passante médiane (Mbps)', fontsize=11)
ax.set_title(f'IQI vs PIB/habitant — ρ={rho:.3f} (p={p_rho:.4f})  R²={r2:.3f}', fontsize=12)
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('etude10_scatter_iqi_gdp.png', dpi=150, bbox_inches='tight')
plt.close()

df_clean.to_csv('etude10_iqi_gdp.csv', index=False, encoding='utf-8')
print("\nFichiers : etude10_scatter_iqi_gdp.png, etude10_iqi_gdp.csv")
print(f"\n=== RÉSUMÉ ===")
print(f"rho(IQI, PIB) = {rho:.3f}  p = {p_rho:.4f}  R² = {r2:.3f}")
