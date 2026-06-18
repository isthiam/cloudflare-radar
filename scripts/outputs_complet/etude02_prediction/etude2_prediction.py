# etude2_prediction.py — Indices ISE/IMP/IVC + prévision ARIMA
import pandas as pd
import numpy as np
import matplotlib
import os; os.chdir(os.path.dirname(os.path.abspath(__file__)))

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cleaned')

def load(name):
    return pd.read_csv(f'{BASE}/{name}', encoding='utf-8', parse_dates=['date'])

# --- Chargement ---
dmarc  = load('email_dmarc_clean.csv')
dkim   = load('email_dkim_clean.csv')
spf    = load('email_spf_clean.csv')
mal    = load('email_malicious_clean.csv')
spam   = load('email_spam_clean.csv')
spoof  = load('email_spoof_clean.csv')
bgp    = load('bgp_timeseries_clean.csv')
tls    = load('http_tls_version_clean.csv')
ipv    = load('http_ip_version_clean.csv')
http   = load('http_http_version_clean.csv')
bot    = load('http_bot_class_clean.csv')
l3bit  = load('attacks_l3_bitrate_clean.csv')

# Normalise dates (enlever tz)
def strip_tz(df):
    df['date'] = pd.to_datetime(df['date']).dt.tz_localize(None)
    return df

for df in [dmarc, dkim, spf, mal, spam, spoof, bgp, tls, ipv, http, bot, l3bit]:
    strip_tz(df)

# Dates de référence (53 semaines depuis bgp)
dates = bgp['date'].sort_values().reset_index(drop=True)

# --- ISE : Indice Sécurité Email ---
def weekly_global(df, col):
    g = df.groupby('date')[col].mean() if 'country_iso2' in df.columns else df.set_index('date')[col]
    return g.reindex(dates).interpolate()

dmarc_pass = dmarc.groupby('date')['PASS'].mean().reindex(dates).interpolate()
dkim_pass  = dkim.groupby('date')['PASS'].mean().reindex(dates).interpolate()
spf_pass   = spf.groupby('date')['PASS'].mean().reindex(dates).interpolate()

mal_pct   = mal.groupby('date')['MALICIOUS'].mean().reindex(dates).fillna(0).interpolate()
spam_pct  = spam.groupby('date')['SPAM'].mean().reindex(dates).fillna(0).interpolate()
spoof_pct = spoof.groupby('date')['SPOOF'].mean().reindex(dates).fillna(0).interpolate()

ISE = (dmarc_pass * 0.35 + dkim_pass * 0.35 + spf_pass * 0.30) - \
      (mal_pct + spam_pct + spoof_pct).div(3) * 0.5
ISE = ISE.fillna(ISE.median())

# --- IMP : Indice Maturité Protocolaire ---
tls13  = tls.groupby('date')['TLS 1.3'].mean().reindex(dates).interpolate()
tlsq   = tls.groupby('date')['TLS QUIC'].mean().reindex(dates).interpolate()
ipv6   = ipv.groupby('date')['IPv6'].mean().reindex(dates).interpolate()
http3  = http.groupby('date')['HTTP/3'].mean().reindex(dates).interpolate()
human  = bot.groupby('date')['human'].mean().reindex(dates).fillna(50).interpolate()

raw_IMP = (ipv6 * 0.25 + http3 * 0.25 + tls13 * 0.25 + tlsq * 0.10 + human * 0.10 + pd.Series(50, index=dates) * 0.05)
mn, mx = raw_IMP.min(), raw_IMP.max()
IMP = (raw_IMP - mn) / (mx - mn) * 100
IMP = IMP.fillna(IMP.median())

# --- IVC : Indice Vulnérabilité Composite ---
bgp_vals = bgp.set_index('date')['values'].reindex(dates).interpolate()
bgp_risk = (bgp_vals - bgp_vals.min()) / (bgp_vals.max() - bgp_vals.min()) * 100

under500 = l3bit[l3bit['dimension'] == 'bitrate'].set_index('date')['UNDER_500_MBPS'].reindex(dates).interpolate()
net_attack = 100 - under500.fillna(75)

email_threat = 100 - ISE
proto_weak   = 100 - IMP

IVC = (bgp_risk * 0.30 + email_threat * 0.30 + proto_weak * 0.20 + net_attack * 0.20)
IVC = IVC.fillna(IVC.median())

# Sauvegarde
out = pd.DataFrame({'date': dates, 'ISE': ISE.values, 'IMP': IMP.values, 'IVC': IVC.values})
out.to_csv('etude2_indices.csv', index=False, encoding='utf-8')
print("Indices calculés :")
print(out.describe().round(2))

# --- ARIMA ---
try:
    from statsmodels.tsa.arima.model import ARIMA
    from statsmodels.tsa.holtwinters import ExponentialSmoothing
    arima_ok = True
except ImportError:
    arima_ok = False
    print("statsmodels non disponible")

results = {}
forecasts = {}
n_forecast = 4

def best_arima(series, name):
    best_aic, best_order, best_model = np.inf, (1,1,1), None
    for p in range(3):
        for d in range(2):
            for q in range(3):
                try:
                    m = ARIMA(series.values, order=(p,d,q)).fit()
                    if m.aic < best_aic:
                        best_aic, best_order, best_model = m.aic, (p,d,q), m
                except:
                    pass
    if best_model is None:
        best_model = ARIMA(series.values, order=(1,1,0)).fit()
        best_order = (1,1,0)
        best_aic = best_model.aic
    fc = best_model.get_forecast(steps=n_forecast)
    mean_fc = fc.predicted_mean
    ci = fc.conf_int(alpha=0.05)
    print(f"  {name}: ARIMA{best_order}  AIC={best_aic:.1f}  Prévision S+4={mean_fc[-1]:.2f}")
    return best_order, best_aic, mean_fc, ci

if arima_ok:
    print("\n--- Sélection ARIMA ---")
    for name, series in [('ISE', ISE), ('IMP', IMP), ('IVC', IVC)]:
        order, aic, fc_mean, fc_ci = best_arima(series, name)
        results[name] = {'order': order, 'aic': aic}
        forecasts[name] = {'mean': fc_mean, 'ci': fc_ci}
else:
    print("Fallback ExponentialSmoothing")
    for name, series in [('ISE', ISE), ('IMP', IMP), ('IVC', IVC)]:
        m = ExponentialSmoothing(series.values, trend='add').fit()
        fc_mean = m.forecast(n_forecast)
        results[name] = {'order': 'ETS', 'aic': 0}
        forecasts[name] = {'mean': fc_mean, 'ci': None}

# --- Figure ---
last_date = dates.iloc[-1]
future_dates = pd.date_range(last_date + pd.Timedelta(weeks=1), periods=n_forecast, freq='W')

fig, axes = plt.subplots(3, 1, figsize=(14, 12), sharex=False)
colors = {'ISE': '#1F77B4', 'IMP': '#2CA02C', 'IVC': '#D62728'}

for ax, (name, series) in zip(axes, [('ISE', ISE), ('IMP', IMP), ('IVC', IVC)]):
    ax.plot(dates, series.values, color=colors[name], linewidth=1.8, label=f'{name} observé')
    fc = forecasts[name]
    ax.plot(future_dates, fc['mean'], '--o', color=colors[name], linewidth=1.5, markersize=5, label='Prévision')
    if fc['ci'] is not None:
        ci_vals = fc['ci'] if hasattr(fc['ci'], 'iloc') else fc['ci']
        ci_lo = ci_vals[:, 0] if hasattr(ci_vals, '__getitem__') and not hasattr(ci_vals, 'iloc') else ci_vals.iloc[:, 0]
        ci_hi = ci_vals[:, 1] if hasattr(ci_vals, '__getitem__') and not hasattr(ci_vals, 'iloc') else ci_vals.iloc[:, 1]
        ax.fill_between(future_dates, ci_lo, ci_hi,
                        alpha=0.25, color=colors[name], label='IC 95%')
    ax.axvline(x=last_date, color='gray', linestyle=':', alpha=0.7)
    ax.set_ylabel(name, fontsize=11)
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)
    ax.set_title(f'{name} — Série observée et prévision ARIMA 4 semaines', fontsize=11)

plt.tight_layout()
plt.savefig('etude2_forecast.png', dpi=150, bbox_inches='tight')
plt.close()
print("\nGraphique sauvegardé : etude2_forecast.png")

# Tableau final
print("\n=== Résultats ARIMA ===")
print(f"{'Indice':<6} {'Modèle':<12} {'AIC':<8} {'Moy obs':<10} {'Prév S+1':<10} {'Prév S+4'}")
for name in ['ISE', 'IMP', 'IVC']:
    s = {'ISE': ISE, 'IMP': IMP, 'IVC': IVC}[name]
    fc = forecasts[name]['mean']
    print(f"{name:<6} {str(results[name]['order']):<12} {results[name]['aic']:<8.1f} {s.mean():<10.2f} {fc[0]:<10.2f} {fc[-1]:.2f}")
