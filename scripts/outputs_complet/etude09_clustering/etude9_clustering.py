# etude9_clustering.py — Clustering k-means des pays
import pandas as pd
import numpy as np
import matplotlib
import os; os.chdir(os.path.dirname(os.path.abspath(__file__)))

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
from scipy.stats import spearmanr

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cleaned')

def load(name):
    df = pd.read_csv(f'{BASE}/{name}', encoding='utf-8', parse_dates=['date'])
    df['date'] = pd.to_datetime(df['date']).dt.tz_localize(None)
    return df

# Charger ou recalculer pays
try:
    pays = pd.read_csv('etude1_pays.csv', encoding='utf-8')
    print("Données pays chargées depuis etude1_pays.csv")
except FileNotFoundError:
    tls = load('http_tls_version_clean.csv')
    ipv = load('http_ip_version_clean.csv')
    http = load('http_http_version_clean.csv')
    iqi = load('iqi_bandwidth_clean.csv')
    iqi_bw = iqi[iqi['metric'] == 'BANDWIDTH']
    pays = pd.DataFrame({
        'country': tls.groupby('country_iso2')['TLS 1.3'].mean().index,
        'tls13': tls.groupby('country_iso2')['TLS 1.3'].mean().values,
        'ipv6': ipv.groupby('country_iso2')['IPv6'].mean().reindex(tls.groupby('country_iso2')['TLS 1.3'].mean().index).values,
        'http3': http.groupby('country_iso2')['HTTP/3'].mean().reindex(tls.groupby('country_iso2')['TLS 1.3'].mean().index).values,
        'iqi_p50': iqi_bw.groupby('country_iso2')['p50'].mean().reindex(tls.groupby('country_iso2')['TLS 1.3'].mean().index).values,
    })

features = ['tls13', 'ipv6', 'http3', 'iqi_p50']
X = pays[features].copy()

# Filtre pays avec trop de NaN
threshold = 0.5
mask = X.isnull().mean(axis=1) < threshold
X = X[mask].copy()
pays_filtered = pays[mask].copy()

# Imputation médiane
for col in features:
    X[col].fillna(X[col].median(), inplace=True)

print(f"Pays retenus après filtrage : {len(X)}")

# Normalisation
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Sélection k optimal
inertias, silhouettes = [], []
K_range = range(2, 7)
for k in K_range:
    km = KMeans(n_clusters=k, random_state=42, n_init=10)
    labels = km.fit_predict(X_scaled)
    inertias.append(km.inertia_)
    silhouettes.append(silhouette_score(X_scaled, labels))

best_k = K_range[np.argmax(silhouettes)]
print(f"\nSilhouette scores: {dict(zip(K_range, [round(s,3) for s in silhouettes]))}")
print(f"k optimal (silhouette max) : {best_k}")

# Figure elbow
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
ax1.plot(list(K_range), inertias, 'bo-', linewidth=2)
ax1.set_xlabel('Nombre de clusters k', fontsize=11)
ax1.set_ylabel('Inertie (WCSS)', fontsize=11)
ax1.set_title('Courbe Elbow', fontsize=12)
ax1.grid(True, alpha=0.3)
ax2.plot(list(K_range), silhouettes, 'ro-', linewidth=2)
ax2.axvline(best_k, color='gray', linestyle='--', alpha=0.7)
ax2.set_xlabel('Nombre de clusters k', fontsize=11)
ax2.set_ylabel('Silhouette score', fontsize=11)
ax2.set_title('Score de silhouette', fontsize=12)
ax2.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('etude9_elbow.png', dpi=150, bbox_inches='tight')
plt.close()

# Modèle final
km_final = KMeans(n_clusters=best_k, random_state=42, n_init=10)
pays_filtered = pays_filtered.copy()
pays_filtered['cluster'] = km_final.fit_predict(X_scaled)

# Profil des clusters
centros = pd.DataFrame(scaler.inverse_transform(km_final.cluster_centers_), columns=features)
print(f"\n=== Profil des {best_k} clusters ===")
for c in range(best_k):
    subset = pays_filtered[pays_filtered['cluster'] == c]
    print(f"\nCluster {c} ({len(subset)} pays):")
    print(f"  TLS 1.3: {centros.iloc[c]['tls13']:.1f}%  IPv6: {centros.iloc[c]['ipv6']:.1f}%  HTTP/3: {centros.iloc[c]['http3']:.1f}%  IQI: {centros.iloc[c]['iqi_p50']:.1f}")
    # 5 pays représentatifs (plus proches du centroïde)
    dists = np.linalg.norm(X_scaled[pays_filtered['cluster'] == c] - km_final.cluster_centers_[c], axis=1)
    rep_idx = np.argsort(dists)[:5]
    reps = subset.iloc[rep_idx]['country'].tolist()
    print(f"  Représentatifs : {reps}")

# Naming automatique
cluster_labels = {}
for c in range(best_k):
    t = centros.iloc[c]['tls13']
    i = centros.iloc[c]['ipv6']
    if t >= 75 and i >= 20:
        cluster_labels[c] = 'Leaders numériques'
    elif t >= 60 and i >= 10:
        cluster_labels[c] = 'En transition'
    elif t >= 45:
        cluster_labels[c] = 'Adoption modérée'
    else:
        cluster_labels[c] = 'Infrastructures fragiles'

pays_filtered['cluster_label'] = pays_filtered['cluster'].map(cluster_labels)
print("\nNaming des clusters :", cluster_labels)

# PCA 2D
pca = PCA(n_components=2, random_state=42)
X_pca = pca.fit_transform(X_scaled)
pays_filtered['pc1'] = X_pca[:, 0]
pays_filtered['pc2'] = X_pca[:, 1]
print(f"\nVariance expliquée par PCA: {pca.explained_variance_ratio_.sum()*100:.1f}%")

# Figure PCA
palette = ['#1F77B4','#FF7F0E','#2CA02C','#D62728','#9467BD']
fig, ax = plt.subplots(figsize=(12, 8))
for c in range(best_k):
    mask_c = pays_filtered['cluster'] == c
    ax.scatter(pays_filtered[mask_c]['pc1'], pays_filtered[mask_c]['pc2'],
               c=palette[c], label=f"C{c}: {cluster_labels[c]}", alpha=0.6, s=30)
    # Labels représentatifs
    subset = pays_filtered[mask_c]
    dists = np.linalg.norm(X_scaled[mask_c] - km_final.cluster_centers_[c], axis=1)
    for idx_rel in np.argsort(dists)[:3]:
        row = subset.iloc[idx_rel]
        ax.annotate(row['country'], (row['pc1'], row['pc2']),
                    fontsize=7, alpha=0.85, xytext=(3,3), textcoords='offset points')
ax.set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]*100:.1f}%)', fontsize=11)
ax.set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]*100:.1f}%)', fontsize=11)
ax.set_title(f'Clustering k-Means ({best_k} clusters) — Projection PCA', fontsize=13)
ax.legend(fontsize=9, loc='best')
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('etude9_pca.png', dpi=150, bbox_inches='tight')
plt.close()

# Test hypothèse résilience-exposition
rho, p_rho = spearmanr(pays_filtered['tls13'].fillna(0), pays_filtered['iqi_p50'].fillna(0))
print(f"\nCorrélation Spearman TLS1.3 vs IQI_p50: rho={rho:.3f}  p={p_rho:.4f}")
interp = "positive (les pays bien infrastructurés adoptent aussi mieux TLS)" if rho > 0 else "négative (les pays à faible infra adoptent paradoxalement mieux TLS)"
print(f"Interprétation : corrélation {interp}")

pays_filtered.to_csv('etude9_clusters.csv', index=False, encoding='utf-8')
print("\nFichiers sauvegardés : etude9_elbow.png, etude9_pca.png, etude9_clusters.csv")
print(f"\n=== RÉSUMÉ ===")
print(f"k optimal : {best_k}  |  Silhouette : {max(silhouettes):.3f}")
print(f"Variance PCA : {pca.explained_variance_ratio_.sum()*100:.1f}%")
print(f"Rho Spearman (résilience-exposition) : {rho:.3f} (p={p_rho:.4f})")
