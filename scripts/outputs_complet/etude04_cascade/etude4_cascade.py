# etude4_cascade.py — Effet cascade ISE → IVC (Granger, cross-correlation)
import pandas as pd
import numpy as np
import matplotlib
import os; os.chdir(os.path.dirname(os.path.abspath(__file__)))

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

# Charge les indices calculés par etude2
try:
    idx = pd.read_csv('etude2_indices.csv', encoding='utf-8', parse_dates=['date'])
    ISE = idx['ISE'].values
    IMP = idx['IMP'].values
    IVC = idx['IVC'].values
    dates = idx['date'].values
    print(f"Indices chargés depuis etude2_indices.csv ({len(ISE)} semaines)")
except FileNotFoundError:
    print("etude2_indices.csv non trouvé — recalcul minimal")
    import sys; sys.exit(1)

from scipy.stats import pearsonr, spearmanr

# --- Cross-corrélation ISE vs IVC ---
lags = range(-8, 9)
cc = []
for lag in lags:
    if lag >= 0:
        x, y = ISE[:len(ISE)-lag], IVC[lag:]
    else:
        x, y = ISE[-lag:], IVC[:len(IVC)+lag]
    r, p = pearsonr(x, y)
    cc.append({'lag': lag, 'corr': r, 'pvalue': p})

cc_df = pd.DataFrame(cc)
best = cc_df.loc[cc_df['corr'].abs().idxmax()]
print(f"\nCross-corrélation ISE↔IVC:")
print(cc_df.to_string(index=False))
print(f"\nLag optimal : {int(best['lag'])} semaines (r={best['corr']:.3f}, p={best['pvalue']:.4f})")

lag_opt = int(best['lag'])

# Corrélation de Pearson avec lag optimal
if lag_opt >= 0:
    x_lag, y_lag = ISE[:len(ISE)-lag_opt], IVC[lag_opt:]
else:
    x_lag, y_lag = ISE[-lag_opt:], IVC[:len(IVC)+lag_opt]
r_lag, p_lag = pearsonr(x_lag, y_lag)
rsp, psp = spearmanr(x_lag, y_lag)
print(f"\nCorrélation ISE(t) vs IVC(t+{lag_opt}): Pearson r={r_lag:.3f} p={p_lag:.4f} | Spearman rho={rsp:.3f} p={psp:.4f}")

# --- Test de Granger ---
try:
    from statsmodels.tsa.stattools import grangercausalitytests
    print("\n--- Test de Granger : ISE → IVC ---")
    data_iv = np.column_stack([IVC, ISE])
    gc_res = grangercausalitytests(data_iv, maxlag=4, verbose=False)
    granger_rows = []
    for lag, res in gc_res.items():
        fstat = res[0]['ssr_ftest'][0]
        pval  = res[0]['ssr_ftest'][1]
        granger_rows.append({'lag': lag, 'F_stat': fstat, 'p_value': pval, 'significatif': '*' if pval < 0.05 else ''})
        print(f"  Lag={lag}: F={fstat:.3f}  p={pval:.4f}  {'***' if pval<0.01 else ('*' if pval<0.05 else '')}")

    print("\n--- Test de Granger : IVC → ISE (causalité inverse) ---")
    data_vi = np.column_stack([ISE, IVC])
    gc_res2 = grangercausalitytests(data_vi, maxlag=4, verbose=False)
    for lag, res in gc_res2.items():
        fstat2 = res[0]['ssr_ftest'][0]
        pval2  = res[0]['ssr_ftest'][1]
        print(f"  Lag={lag}: F={fstat2:.3f}  p={pval2:.4f}  {'***' if pval2<0.01 else ('*' if pval2<0.05 else '')}")

    granger_df = pd.DataFrame(granger_rows)
    granger_ok = True
except Exception as e:
    print(f"Granger non disponible: {e}")
    granger_df = pd.DataFrame({'lag':[1,2,3,4],'F_stat':[np.nan]*4,'p_value':[np.nan]*4})
    granger_ok = False

# --- Figure ---
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13, 9))

# Subplot 1 : ISE vs IVC double axe
color_ise = '#1F77B4'
color_ivc = '#D62728'
ax1.plot(dates, ISE, color=color_ise, linewidth=1.8, label='ISE (sécurité email)')
ax1b = ax1.twinx()
ax1b.plot(dates, IVC, color=color_ivc, linewidth=1.8, linestyle='--', label='IVC (vulnérabilité)')
ax1.set_ylabel('ISE', color=color_ise, fontsize=11)
ax1b.set_ylabel('IVC', color=color_ivc, fontsize=11)
ax1.set_title(f'ISE vs IVC — lag optimal = {lag_opt} semaine(s) (r={r_lag:.3f})', fontsize=12)
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax1b.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize=9)
ax1.grid(True, alpha=0.3)

# Subplot 2 : Cross-corrélogramme
bar_colors = ['#D62728' if r > 0 else '#1F77B4' for r in cc_df['corr']]
ax2.bar(cc_df['lag'], cc_df['corr'], color=bar_colors, alpha=0.7, edgecolor='white')
ax2.axhline(0, color='black', linewidth=0.8)
ax2.axvline(best['lag'], color='orange', linestyle='--', linewidth=1.5, label=f'Lag optimal = {int(best["lag"])}')
ax2.set_xlabel('Lag (semaines)', fontsize=11)
ax2.set_ylabel('Corrélation de Pearson', fontsize=11)
ax2.set_title('Cross-corrélogramme ISE(t) — IVC(t+lag)', fontsize=12)
ax2.legend(fontsize=9)
ax2.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('etude4_cascade.png', dpi=150, bbox_inches='tight')
plt.close()
print("\nGraphique sauvegardé : etude4_cascade.png")

# Stocker pour le rapport
print(f"\n=== RÉSUMÉ ÉTUDE 4 ===")
print(f"Lag optimal ISE→IVC : {lag_opt} semaine(s)")
print(f"r Pearson : {r_lag:.3f}  (p={p_lag:.4f})")
print(f"rho Spearman : {rsp:.3f}  (p={psp:.4f})")
if granger_ok:
    sig = granger_df[granger_df['p_value'] < 0.05]
    print(f"Granger ISE→IVC significatif pour lags : {sig['lag'].tolist() if not sig.empty else 'aucun (p>0.05)'}")
