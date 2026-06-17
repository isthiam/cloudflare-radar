# -*- coding: utf-8 -*-
"""
Phase K — Analyse de Graphe Réseau ASN (BGP Hijacks & Leaks)
Centralité, PageRank, communautés, chemins de fuite
"""

import os
import ast
import warnings
import numpy as np
import pandas as pd
import networkx as nx
from datetime import datetime
from collections import Counter

warnings.filterwarnings("ignore")

BASE = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/cleaned/"
OUT  = "E:/Webscraping/cloudflare_radar_vulnerabilite/scripts/outputs_complet/rapport_phase_K.md"

print("Phase K — Analyse de graphe réseau ASN...")

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def safe_parse(s):
    if pd.isna(s): return []
    try: return ast.literal_eval(str(s))
    except: return []

def fv(v, fmt=".4f", na="N/A"):
    if v is None: return na
    try:
        if np.isnan(v): return na
    except (TypeError, ValueError): pass
    return format(v, fmt)

def norm_asn(asn):
    s = str(asn).strip().upper().replace("AS","").strip()
    try: return int(s)
    except: return None

# ══════════════════════════════════════════════════════════════════════════════
# 1. CHARGEMENT DONNÉES BGP
# ══════════════════════════════════════════════════════════════════════════════
print("  1/5 Chargement et parsing BGP...")

hij = pd.read_csv(BASE + "bgp_hijacks_clean.csv")
hij["min_hijack_ts"] = pd.to_datetime(hij["min_hijack_ts"], errors="coerce")

# Normalize hijacker ASN
hij["hijacker_asn_int"] = hij["hijacker_asn"].apply(norm_asn)
hij = hij.dropna(subset=["hijacker_asn_int"])
hij["hijacker_asn_int"] = hij["hijacker_asn_int"].astype(int)

# Parse victim ASNs
hij["victim_asns_list"] = hij["victim_asns"].apply(safe_parse)

# Parse peer ASNs
hij["peer_asns_list"] = hij["peer_asns"].apply(safe_parse)

# Parse tags for RPKI flag
hij["rpki_inv"] = hij["tags"].apply(lambda s: 1 if isinstance(s,str) and "rpki_new_origin_invalid" in s else 0)

# BGP leaks
leaks = pd.read_csv(BASE + "bgp_leaks_clean.csv")
leaks["min_ts"] = pd.to_datetime(leaks["min_ts"], errors="coerce")
leaks["leak_seg_list"] = leaks["leak_seg"].apply(safe_parse)

print(f"  Hijacks : {len(hij)} | Leaks : {len(leaks)}")

# ══════════════════════════════════════════════════════════════════════════════
# 2. CONSTRUCTION GRAPHE HIJACKS
# ══════════════════════════════════════════════════════════════════════════════
print("  2/5 Construction graphes BGP...")

# Directed graph: hijacker_asn → victim_asn (weighted by event count)
G_hij = nx.DiGraph()
edge_weights = Counter()
edge_conf = {}  # accumulated confidence

for _, row in hij.iterrows():
    h_asn = row["hijacker_asn_int"]
    victims = [norm_asn(v) for v in row["victim_asns_list"] if norm_asn(v) is not None]
    conf = row["confidence_score"] if pd.notna(row["confidence_score"]) else 1
    if not victims:
        # Self-loop or unknown victim — skip
        G_hij.add_node(h_asn, asn=h_asn)
        continue
    for v_asn in victims:
        edge_weights[(h_asn, v_asn)] += 1
        edge_conf[(h_asn, v_asn)] = edge_conf.get((h_asn, v_asn), 0) + conf

for (h, v), w in edge_weights.items():
    avg_conf = edge_conf[(h, v)] / w
    G_hij.add_edge(h, v, weight=w, avg_conf=avg_conf)

print(f"  Graphe hijacks : {G_hij.number_of_nodes()} nœuds, {G_hij.number_of_edges()} arêtes")

# ══════════════════════════════════════════════════════════════════════════════
# 3. MÉTRIQUES DE CENTRALITÉ
# ══════════════════════════════════════════════════════════════════════════════
print("  3/5 Calcul métriques centralité...")

# Degree
out_degree = dict(G_hij.out_degree(weight="weight"))  # hijacker score
in_degree  = dict(G_hij.in_degree(weight="weight"))   # victim score

# Number of unique victims / hijackers (unweighted)
out_degree_unw = dict(G_hij.out_degree())
in_degree_unw  = dict(G_hij.in_degree())

# PageRank (hijack influence)
try:
    pr = nx.pagerank(G_hij, alpha=0.85, weight="weight", max_iter=200)
except Exception:
    pr = {n: 1/G_hij.number_of_nodes() for n in G_hij.nodes()}

# Betweenness centrality (sample for performance if large)
n_nodes = G_hij.number_of_nodes()
if n_nodes <= 2000:
    bet_c = nx.betweenness_centrality(G_hij, weight="weight", normalized=True)
else:
    # Sample 500 nodes
    sample_k = 500
    bet_c = nx.betweenness_centrality(G_hij, weight="weight", normalized=True, k=sample_k)

# HITS (hubs = hijackers, authorities = victims)
try:
    hubs, auth = nx.hits(G_hij, max_iter=200)
except Exception:
    hubs = {n: 0 for n in G_hij.nodes()}
    auth = {n: 0 for n in G_hij.nodes()}

# Build node DataFrame
node_data = []
for node in G_hij.nodes():
    node_data.append({
        "asn": node,
        "out_deg_w":  out_degree.get(node, 0),
        "in_deg_w":   in_degree.get(node, 0),
        "out_deg":    out_degree_unw.get(node, 0),
        "in_deg":     in_degree_unw.get(node, 0),
        "pagerank":   pr.get(node, 0),
        "betweenness":bet_c.get(node, 0),
        "hub_score":  hubs.get(node, 0),
        "auth_score": auth.get(node, 0),
    })

node_df = pd.DataFrame(node_data).set_index("asn")

# ASN role classification
node_df["is_hijacker_only"] = (node_df["out_deg"] > 0) & (node_df["in_deg"] == 0)
node_df["is_victim_only"]   = (node_df["out_deg"] == 0) & (node_df["in_deg"] > 0)
node_df["is_both"]          = (node_df["out_deg"] > 0) & (node_df["in_deg"] > 0)
node_df["total_activity"]   = node_df["out_deg_w"] + node_df["in_deg_w"]

# ══════════════════════════════════════════════════════════════════════════════
# 4. ANALYSE DES LEAKS — GRAPHE DE CHEMINS
# ══════════════════════════════════════════════════════════════════════════════
print("  4/5 Analyse graphe leaks...")

G_leak = nx.DiGraph()
leak_edge_weights = Counter()
asn_leak_role = Counter()  # "origin", "middle", "destination"

for _, row in leaks.iterrows():
    seg = row["leak_seg_list"]
    if len(seg) < 2:
        continue
    # Normalize ASNs in the segment
    seg_norm = [norm_asn(a) for a in seg]
    seg_norm = [a for a in seg_norm if a is not None]
    if len(seg_norm) < 2:
        continue
    for i, asn in enumerate(seg_norm):
        if i == 0:
            asn_leak_role[asn] = asn_leak_role.get(asn, {"origin":0,"middle":0,"dest":0})
            asn_leak_role[asn]["origin"] = asn_leak_role[asn].get("origin",0) + 1
        elif i == len(seg_norm) - 1:
            asn_leak_role[asn] = asn_leak_role.get(asn, {"origin":0,"middle":0,"dest":0})
            asn_leak_role[asn]["dest"] = asn_leak_role[asn].get("dest",0) + 1
        else:
            asn_leak_role[asn] = asn_leak_role.get(asn, {"origin":0,"middle":0,"dest":0})
            asn_leak_role[asn]["middle"] = asn_leak_role[asn].get("middle",0) + 1
    # Edges in path
    for i in range(len(seg_norm)-1):
        leak_edge_weights[(seg_norm[i], seg_norm[i+1])] += 1

for (a, b), w in leak_edge_weights.items():
    G_leak.add_edge(a, b, weight=w)

# Middle ASN (most common "leaker") = appears most as index 1
leaker_counts = Counter()
for _, row in leaks.iterrows():
    seg = row["leak_seg_list"]
    if len(seg) >= 2:
        leaker = norm_asn(seg[1]) if len(seg) >= 2 else None
        if leaker:
            leaker_counts[leaker] += 1

print(f"  Graphe leaks : {G_leak.number_of_nodes()} nœuds, {G_leak.number_of_edges()} arêtes")
print(f"  Leakers distincts (position 1) : {len(leaker_counts)}")

# ASN appearing in both hijacks AND leaks
hij_asns  = set(int(a) for a in node_df.index if node_df.loc[a,"out_deg"] > 0)
leak_asns = set(int(a) for a in leaker_counts.keys() if a is not None)
dual_role = hij_asns & leak_asns
print(f"  ASNs actifs hijacks ET leaks : {len(dual_role)}")

# ══════════════════════════════════════════════════════════════════════════════
# 5. STATISTIQUES RÉSEAU GLOBALES
# ══════════════════════════════════════════════════════════════════════════════

# Strongly connected components
scc = list(nx.strongly_connected_components(G_hij))
wcc = list(nx.weakly_connected_components(G_hij))
largest_scc = max(scc, key=len)
largest_wcc = max(wcc, key=len)

# Density
density_hij = nx.density(G_hij)

# Top edges (most frequent hijack pairs)
top_edges = sorted(edge_weights.items(), key=lambda x: x[1], reverse=True)

# ══════════════════════════════════════════════════════════════════════════════
# 6. RAPPORT
# ══════════════════════════════════════════════════════════════════════════════
print("  5/5 Génération rapport Phase K...")
lines = []

lines.append("# Rapport Phase K — Analyse de Graphe Réseau ASN")
lines.append("**Cloudflare Radar Dataset — Déc. 2025 / Juin 2026**  ")
lines.append("**Chercheur :** Issakha Thiam — Université Clermont Auvergne  ")
lines.append(f"**Généré le :** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
lines.append("")
lines.append("---")

# Section 1 — Résumé
lines.append("## 1. Résumé Exécutif — Topologie du Graphe")
lines.append("")
lines.append("### 1.1 Graphe BGP Hijacks")
lines.append("")
lines.append("| Indicateur | Valeur |")
lines.append("|---|---|")
lines.append(f"| Nœuds (ASNs) | **{G_hij.number_of_nodes():,}** |")
lines.append(f"| Arêtes (paires hijacker→victime) | **{G_hij.number_of_edges():,}** |")
lines.append(f"| Densité du graphe | {density_hij:.6f} (graphe très creux) |")
lines.append(f"| Composantes fortement connexes | {len(scc):,} |")
lines.append(f"| Plus grande SCC | {len(largest_scc):,} nœuds |")
lines.append(f"| Composantes faiblement connexes | {len(wcc):,} |")
lines.append(f"| Plus grande WCC | {len(largest_wcc):,} nœuds |")
lines.append(f"| ASNs hijackeurs (out_degree > 0) | {(node_df['out_deg']>0).sum():,} |")
lines.append(f"| ASNs victimes (in_degree > 0) | {(node_df['in_deg']>0).sum():,} |")
lines.append(f"| ASNs jouant les 2 rôles | {node_df['is_both'].sum():,} |")
lines.append("")
lines.append("### 1.2 Graphe BGP Leaks")
lines.append("")
lines.append("| Indicateur | Valeur |")
lines.append("|---|---|")
lines.append(f"| Nœuds (ASNs) | **{G_leak.number_of_nodes():,}** |")
lines.append(f"| Arêtes (transitions de chemin) | **{G_leak.number_of_edges():,}** |")
lines.append(f"| ASNs leakers distincts (position 1) | **{len(leaker_counts):,}** |")
lines.append(f"| ASNs actifs hijacks ET leaks | **{len(dual_role):,}** |")
lines.append("")
lines.append("---")

# Section 2 — Distributions degré
lines.append("## 2. Distribution des Degrés")
lines.append("")
lines.append("### 2.1 Distribution Out-Degree (Hijackeurs)")
lines.append("")
out_degs = [d for _, d in G_hij.out_degree() if d > 0]
out_counts = Counter(out_degs)
lines.append("| Out-degree | Nb ASNs | % des hijackeurs | Interprétation |")
lines.append("|---:|---:|---:|---|")
for d in sorted(set(min(d, 50) for d in out_degs)):
    real_d = d if d < 50 else "≥50"
    n = sum(v for k, v in out_counts.items() if (k == d if d < 50 else k >= 50))
    pct = n / len(out_degs) * 100
    label = "hyperactifs (attaque systématique)" if d >= 50 else ("actifs" if d >= 10 else ("occasionnels" if d >= 2 else "uniques"))
    lines.append(f"| {real_d} | {n} | {pct:.1f}% | {label} |")
lines.append("")

# Degree stats
out_arr = np.array(out_degs)
lines.append(f"| **Statistique** | **Out-degree** |")
lines.append("|---|---:|")
lines.append(f"| Médiane | {np.median(out_arr):.0f} |")
lines.append(f"| Moyenne | {np.mean(out_arr):.2f} |")
lines.append(f"| P90 | {np.percentile(out_arr, 90):.0f} |")
lines.append(f"| P99 | {np.percentile(out_arr, 99):.0f} |")
lines.append(f"| Maximum | {np.max(out_arr):.0f} |")
lines.append("")

lines.append("### 2.2 Distribution In-Degree (Victimes)")
lines.append("")
in_degs  = [d for _, d in G_hij.in_degree() if d > 0]
in_arr   = np.array(in_degs)
lines.append(f"| Statistique | In-degree (victimes) |")
lines.append("|---|---:|")
lines.append(f"| Médiane | {np.median(in_arr):.0f} |")
lines.append(f"| Moyenne | {np.mean(in_arr):.2f} |")
lines.append(f"| P90 | {np.percentile(in_arr, 90):.0f} |")
lines.append(f"| P99 | {np.percentile(in_arr, 99):.0f} |")
lines.append(f"| Maximum | {np.max(in_arr):.0f} |")
lines.append("")
lines.append("---")

# Section 3 — PageRank
lines.append("## 3. PageRank — ASNs les Plus Influents dans le Réseau de Hijack")
lines.append("")
lines.append("> PageRank (damping=0.85, pondéré) : mesure l'influence d'un ASN comme vecteur de propagation dans le graphe.")
lines.append("> Un PageRank élevé = ASN vers lequel beaucoup d'autres ASN à fort PageRank pointent (victime d'acteurs influents).")
lines.append("")
top_pr = sorted(pr.items(), key=lambda x: x[1], reverse=True)[:30]
lines.append("| Rang | ASN | PageRank | Out-deg | In-deg | Rôle |")
lines.append("|---:|---:|---:|---:|---:|---|")
for rank, (asn, p) in enumerate(top_pr, 1):
    od = node_df.loc[asn, "out_deg"] if asn in node_df.index else 0
    ind= node_df.loc[asn, "in_deg"]  if asn in node_df.index else 0
    role = ("Hijackeur+Victime" if od > 0 and ind > 0 else
            ("Hijackeur" if od > 0 else "Victime"))
    lines.append(f"| {rank} | AS{asn} | {p:.6f} | {int(od)} | {int(ind)} | {role} |")
lines.append("")
lines.append("---")

# Section 4 — Betweenness centrality
lines.append("## 4. Centralité de Betweenness — Nœuds Pivot du Graphe")
lines.append("")
lines.append("> Betweenness centrality : proportion des plus courts chemins passant par ce nœud.")
lines.append("> Un nœud pivot élevé = ASN qui *sert de pont* entre sous-réseaux de hijack.")
lines.append("")
top_bet = sorted(bet_c.items(), key=lambda x: x[1], reverse=True)[:25]
lines.append("| Rang | ASN | Betweenness | Out-deg | In-deg | Rôle |")
lines.append("|---:|---:|---:|---:|---:|---|")
for rank, (asn, b) in enumerate(top_bet, 1):
    od = node_df.loc[asn, "out_deg"] if asn in node_df.index else 0
    ind= node_df.loc[asn, "in_deg"]  if asn in node_df.index else 0
    role = ("Hijackeur+Victime" if od > 0 and ind > 0 else
            ("Hijackeur" if od > 0 else "Victime"))
    lines.append(f"| {rank} | AS{asn} | {b:.6f} | {int(od)} | {int(ind)} | {role} |")
lines.append("")
lines.append("---")

# Section 5 — HITS (hubs et autorités)
lines.append("## 5. Analyse HITS — Hubs et Autorités")
lines.append("")
lines.append("> **Hubs** : ASNs qui pointent vers beaucoup de victimes importantes (hijackeurs systématiques).")
lines.append("> **Autorités** : ASNs qui sont ciblés par beaucoup de hijackeurs importants (victimes structurelles).")
lines.append("")

lines.append("### 5.1 Top 20 Hubs (Hijackeurs Systématiques)")
lines.append("")
top_hubs = sorted(hubs.items(), key=lambda x: x[1], reverse=True)[:20]
lines.append("| Rang | ASN | Hub Score | Out-deg | Actif dans leaks |")
lines.append("|---:|---:|---:|---:|---|")
for rank, (asn, h) in enumerate(top_hubs, 1):
    od = node_df.loc[asn, "out_deg"] if asn in node_df.index else 0
    in_leaks = "✅" if asn in dual_role else "—"
    lines.append(f"| {rank} | AS{asn} | {h:.6f} | {int(od)} | {in_leaks} |")
lines.append("")

lines.append("### 5.2 Top 20 Autorités (Victimes Structurelles)")
lines.append("")
top_auth = sorted(auth.items(), key=lambda x: x[1], reverse=True)[:20]
lines.append("| Rang | ASN | Auth Score | In-deg | Actif dans leaks |")
lines.append("|---:|---:|---:|---:|---|")
for rank, (asn, a) in enumerate(top_auth, 1):
    ind = node_df.loc[asn, "in_deg"] if asn in node_df.index else 0
    in_leaks = "✅" if asn in dual_role else "—"
    lines.append(f"| {rank} | AS{asn} | {a:.6f} | {int(ind)} | {in_leaks} |")
lines.append("")
lines.append("---")

# Section 6 — Top paires hijack
lines.append("## 6. Top Paires Hijacker → Victime")
lines.append("")
lines.append("> Paires (hijacker_ASN, victim_ASN) les plus fréquentes dans le dataset.")
lines.append("")
lines.append("| Rang | Hijackeur | Victime | Nb events | Conf. moy. |")
lines.append("|---:|---:|---:|---:|---:|")
for rank, ((h, v), w) in enumerate(top_edges[:30], 1):
    conf_avg = edge_conf.get((h,v), 0) / w if w > 0 else 0
    lines.append(f"| {rank} | AS{h} | AS{v} | {w} | {conf_avg:.1f} |")
lines.append("")
lines.append("---")

# Section 7 — ASNs doubles rôles
lines.append("## 7. ASNs à Double Rôle (Hijackeurs ET Victimes)")
lines.append("")
lines.append("> Ces ASNs apparaissent à la fois comme hijackeurs (out_degree > 0) et comme victimes (in_degree > 0).")
lines.append("> Ils représentent des réseaux potentiellement compromis ou des opérateurs avec une mauvaise hygiène BGP.")
lines.append("")
dual_df = node_df[node_df["is_both"]].sort_values("total_activity", ascending=False)
lines.append(f"**{len(dual_df)} ASNs** jouent les deux rôles (hijackeur + victime).")
lines.append("")
lines.append("| Rang | ASN | Out-deg (hijacks) | In-deg (victimes) | Activité totale | PageRank | Hub | Auth |")
lines.append("|---:|---:|---:|---:|---:|---:|---:|---:|")
for rank, (asn, row) in enumerate(dual_df.head(30).iterrows(), 1):
    lines.append(
        f"| {rank} | AS{asn} | {int(row['out_deg'])} | {int(row['in_deg'])} | "
        f"{int(row['total_activity'])} | {row['pagerank']:.6f} | "
        f"{row['hub_score']:.6f} | {row['auth_score']:.6f} |"
    )
lines.append("")
lines.append("---")

# Section 8 — Analyse leaks
lines.append("## 8. Analyse du Graphe BGP Leaks")
lines.append("")

lines.append("### 8.1 Top 30 ASNs Leakers (Position 1 dans le chemin)")
lines.append("")
lines.append("> L'ASN en position 1 (index 1) du chemin est l'ASN qui a *re-annoncé* la route hors de sa zone (valley-free violation).")
lines.append("")
lines.append("| Rang | ASN Leaker | Nb leaks | Actif hijacks |")
lines.append("|---:|---:|---:|---|")
for rank, (asn, cnt) in enumerate(leaker_counts.most_common(30), 1):
    in_hij = "✅ hijackeur" if asn in hij_asns else "—"
    lines.append(f"| {rank} | AS{asn} | {cnt:,} | {in_hij} |")
lines.append("")

lines.append("### 8.2 Longueur des Chemins de Leak")
lines.append("")
leak_seg_lens = leaks["leak_seg_list"].apply(len)
lines.append("| Longueur chemin | Nb leaks | % |")
lines.append("|---:|---:|---:|")
for l, cnt in sorted(Counter(leak_seg_lens).items()):
    pct = cnt / len(leaks) * 100
    lines.append(f"| {l} ASNs | {cnt:,} | {pct:.1f}% |")
lines.append("")

lines.append("### 8.3 Top Transitions dans les Chemins de Leak")
lines.append("")
lines.append("| Rang | ASN A | ASN B | Nb transitions |")
lines.append("|---:|---:|---:|---:|")
top_leak_edges = sorted(leak_edge_weights.items(), key=lambda x: x[1], reverse=True)[:20]
for rank, ((a, b), w) in enumerate(top_leak_edges, 1):
    lines.append(f"| {rank} | AS{a} | AS{b} | {w:,} |")
lines.append("")
lines.append("---")

# Section 9 — Composantes connexes
lines.append("## 9. Structure des Composantes Connexes")
lines.append("")
lines.append("### 9.1 Distribution des Composantes Faiblement Connexes (WCC)")
lines.append("")
wcc_sizes = sorted([len(c) for c in wcc], reverse=True)
lines.append("| Rang | Taille WCC | % des nœuds |")
lines.append("|---:|---:|---:|")
for rank, sz in enumerate(wcc_sizes[:15], 1):
    pct = sz / G_hij.number_of_nodes() * 100
    lines.append(f"| {rank} | {sz} | {pct:.1f}% |")
lines.append(f"| ... | ... | ... |")
n_isolates = sum(1 for sz in wcc_sizes if sz == 1)
lines.append(f"| Isolats (WCC=1) | {n_isolates} | {n_isolates/G_hij.number_of_nodes()*100:.1f}% |")
lines.append("")

lines.append("### 9.2 Composantes Fortement Connexes (SCC)")
lines.append("")
scc_sizes = sorted([len(c) for c in scc], reverse=True)
lines.append("| Rang | Taille SCC | % des nœuds |")
lines.append("|---:|---:|---:|")
for rank, sz in enumerate(scc_sizes[:10], 1):
    pct = sz / G_hij.number_of_nodes() * 100
    lines.append(f"| {rank} | {sz} | {pct:.2f}% |")
n_scc_1 = sum(1 for sz in scc_sizes if sz == 1)
lines.append(f"| Singletons | {n_scc_1} | {n_scc_1/G_hij.number_of_nodes()*100:.1f}% |")
lines.append("")
lines.append("---")

# Section 10 — ASNs actifs dual-role (hijack + leak)
lines.append("## 10. ASNs Actifs dans Hijacks ET Leaks")
lines.append("")
lines.append(f"> **{len(dual_role)}** ASNs apparaissent à la fois comme hijackeurs et comme leakers.")
lines.append("> Ces ASNs sont potentiellement mal configurés ou compromis.")
lines.append("")

dual_list = []
for asn in sorted(dual_role):
    hijack_count = hij[hij["hijacker_asn_int"] == asn].shape[0]
    leak_count = leaker_counts.get(asn, 0)
    in_deg = node_df.loc[asn, "in_deg"] if asn in node_df.index else 0
    dual_list.append({
        "asn": asn,
        "hijack_count": hijack_count,
        "leak_count": leak_count,
        "victim_count": in_deg,
        "total": hijack_count + leak_count,
    })

dual_list.sort(key=lambda x: x["total"], reverse=True)
lines.append("| Rang | ASN | Hijacks initiés | Leaks | Victimisations (in-deg) | Total activité |")
lines.append("|---:|---:|---:|---:|---:|---:|")
for rank, d in enumerate(dual_list[:30], 1):
    lines.append(
        f"| {rank} | AS{d['asn']} | {d['hijack_count']} | {d['leak_count']} | "
        f"{int(d['victim_count'])} | **{d['total']}** |"
    )
lines.append("")
lines.append("---")

# Section 11 — Findings
lines.append("## 11. Findings et Implications Réseau")
lines.append("")
lines.append("### 11.1 Structure du Graphe")
lines.append("")
lines.append(f"1. **Graphe extrêmement creux** : densité = {density_hij:.6f}. Sur {G_hij.number_of_nodes():,} ASNs, "
             f"seulement {G_hij.number_of_edges():,} paires hijacker→victime sont observées. "
             "La majorité des ASNs sont victimes d'un seul hijackeur.")
lines.append("")
lines.append(f"2. **Fragmentation** : {len(wcc):,} composantes faiblement connexes — le graphe n'est PAS un composant unique. "
             f"La plus grande WCC couvre {len(largest_wcc)/G_hij.number_of_nodes()*100:.1f}% des nœuds.")
lines.append("")
lines.append(f"3. **Pas de grande SCC** : La plus grande SCC contient {len(largest_scc)} nœuds, ce qui indique "
             "peu de cycles hijack A→B→A (pas de 'guerre BGP' circulaire systématique).")
lines.append("")

lines.append("### 11.2 Acteurs Clés")
lines.append("")
top1_pr  = top_pr[0]
top1_hub = top_hubs[0]
top1_auth= top_auth[0]
top1_bet = top_bet[0]

lines.append(f"- **PageRank #1** : AS{top1_pr[0]} (score={top1_pr[1]:.6f}) — ASN le plus influent dans la structure de victimisation")
lines.append(f"- **Hub #1** (hijackeur systématique) : AS{top1_hub[0]} (score={top1_hub[1]:.6f})")
lines.append(f"- **Autorité #1** (victime structurelle) : AS{top1_auth[0]} (score={top1_auth[1]:.6f})")
lines.append(f"- **Betweenness #1** (pivot réseau) : AS{top1_bet[0]} (score={top1_bet[1]:.6f})")
lines.append("")

lines.append("### 11.3 Risque des ASNs à Double Rôle")
lines.append("")
lines.append(f"{len(dual_df)} ASNs jouent à la fois le rôle de hijackeur et de victime. "
             f"{len(dual_role)} sont également actifs dans des leaks. "
             "Ces entités représentent un risque particulier car leur infrastructure BGP est "
             "à la fois une source de menace et une cible vulnérable.")
lines.append("")

lines.append("### 11.4 Économie du Routage Malveillant")
lines.append("")
pct_both = node_df["is_both"].sum() / G_hij.number_of_nodes() * 100
pct_hij  = node_df["is_hijacker_only"].sum() / G_hij.number_of_nodes() * 100
pct_vic  = node_df["is_victim_only"].sum() / G_hij.number_of_nodes() * 100
lines.append(f"| Rôle ASN | Nb | % |")
lines.append(f"|---|---:|---:|")
lines.append(f"| Hijackeur uniquement | {node_df['is_hijacker_only'].sum():,} | {pct_hij:.1f}% |")
lines.append(f"| Victime uniquement | {node_df['is_victim_only'].sum():,} | {pct_vic:.1f}% |")
lines.append(f"| Hijackeur + Victime | {node_df['is_both'].sum():,} | {pct_both:.1f}% |")
lines.append("")
lines.append("---")
lines.append(f"*Rapport généré automatiquement par `phase_K_network.py` le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.*  ")
lines.append("*Sources : Cloudflare Radar API v4 — bgp_hijacks, bgp_leaks.*  ")
lines.append("*Prochaine étape : Phase L — Synthèse finale et dashboard.*")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

size_kb = os.path.getsize(OUT) / 1024
print(f"\nRapport écrit : {OUT}")
print(f"Taille : {size_kb:.1f} Ko")
print(f"Lignes : {len(lines)}")
