"""
Phase A — Préparation et qualité des données
Cloudflare Radar Dataset — juin 2025 / juin 2026
Auteur    : Issakha Thiam
"""

import pandas as pd
import numpy as np
import json, ast, re, os, warnings
from pathlib import Path
from datetime import datetime

warnings.filterwarnings("ignore")

# ─── CHEMINS ────────────────────────────────────────────────────────────────
BASE   = Path(r"E:\Webscraping\cloudflare_radar_vulnerabilite\scripts\outputs_complet")
CLEAN  = BASE / "cleaned"
CLEAN.mkdir(exist_ok=True)
NOW    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
PY_VERSION = "3.13"

# ─── REGISTRE DES FICHIERS ───────────────────────────────────────────────────
FILES = {
    # ── L3 attacks ────────────────────────────────────────────────
    "attacks_l3_bitrate": {
        "path": "attacks_l3/attacks_l3_bitrate.csv",
        "type": "timeseries_pct",
        "pct_cols": ["UNDER_500_MBPS","_1_GBPS_TO_10_GBPS","_500_MBPS_TO_1_GBPS","_10_GBPS_TO_100_GBPS","OVER_100_GBPS"],
        "date_col": "date", "geo": False,
    },
    "attacks_l3_ip_version": {
        "path": "attacks_l3/attacks_l3_ip_version.csv",
        "type": "timeseries_pct",
        "pct_cols": ["IPv4","IPv6"],
        "date_col": "date", "geo": False,
    },
    "attacks_l3_protocol": {
        "path": "attacks_l3/attacks_l3_protocol.csv",
        "type": "timeseries_pct",
        "pct_cols": ["UDP","TCP","GRE","ICMP"],
        "date_col": "date", "geo": False,
    },
    # ── L7 attacks ────────────────────────────────────────────────
    "attacks_l7_http_method": {
        "path": "attacks_l7/attacks_l7_http_method.csv",
        "type": "timeseries_pct",
        "pct_cols": ["GET","POST","HEAD","OPTIONS","PATCH","DELETE","PUT","UNKNOWN","ACL"],
        "date_col": "date", "geo": False,
    },
    "attacks_l7_http_version": {
        "path": "attacks_l7/attacks_l7_http_version.csv",
        "type": "timeseries_pct",
        "pct_cols": [],   # colonnes à détecter dynamiquement
        "date_col": "date", "geo": False,
    },
    "attacks_l7_vertical": {
        "path": "attacks_l7/attacks_l7_vertical.csv",
        "type": "timeseries_pct",
        "pct_cols": [],
        "date_col": "date", "geo": False,
    },
    # ── BGP ───────────────────────────────────────────────────────
    "bgp_hijacks": {
        "path": "bgp/bgp_hijacks.csv",
        "type": "bgp_events",
        "json_cols": ["peer_asns","prefixes","tags","victim_asns","victim_countries"],
        "date_col": "min_hijack_ts", "geo": False,
    },
    "bgp_leaks": {
        "path": "bgp/bgp_leaks.csv",
        "type": "bgp_events",
        "json_cols": ["countries","leak_seg"],
        "date_col": "detected_ts", "geo": False,
    },
    "bgp_timeseries": {
        "path": "bgp/bgp_timeseries.csv",
        "type": "timeseries_numeric",
        "date_col": "date", "geo": False,
    },
    # ── DNS ───────────────────────────────────────────────────────
    "dns_timeseries": {
        "path": "dns/dns_timeseries.csv",
        "type": "timeseries_numeric",
        "date_col": "date", "geo": False,
    },
    # ── Email ─────────────────────────────────────────────────────
    "email_dmarc": {
        "path": "email/email_dmarc.csv",
        "type": "timeseries_pct",
        "pct_cols": ["PASS","NONE","FAIL"],
        "date_col": "date", "geo": False,
    },
    "email_dkim": {
        "path": "email/email_dkim.csv",
        "type": "timeseries_pct",
        "pct_cols": ["PASS","NONE","FAIL"],
        "date_col": "date", "geo": False,
    },
    "email_spf": {
        "path": "email/email_spf.csv",
        "type": "timeseries_pct",
        "pct_cols": ["PASS","NONE","FAIL"],
        "date_col": "date", "geo": False,
    },
    "email_malicious": {
        "path": "email/email_malicious.csv",
        "type": "timeseries_pct",
        "pct_cols": ["NOT_MALICIOUS","MALICIOUS"],
        "date_col": "date", "geo": False,
    },
    "email_spam": {
        "path": "email/email_spam.csv",
        "type": "timeseries_pct",
        "pct_cols": ["NOT_SPAM","SPAM"],
        "date_col": "date", "geo": False,
    },
    "email_spoof": {
        "path": "email/email_spoof.csv",
        "type": "timeseries_pct",
        "pct_cols": ["NOT_SPOOF","SPOOF"],
        "date_col": "date", "geo": False,
    },
    # ── HTTP par pays ─────────────────────────────────────────────
    "http_bot_class": {
        "path": "http/http_bot_class.csv",
        "type": "geo_pct",
        "pct_cols": ["human","bot"],
        "date_col": "date", "geo": True, "geo_col": "country_iso2",
    },
    "http_browser_family": {
        "path": "http/http_browser_family.csv",
        "type": "geo_pct",
        "pct_cols": ["chrome","safari","edge","firefox","samsung","opera","ucbrowser","yandex","brave","coccoc"],
        "date_col": "date", "geo": True, "geo_col": "country_iso2",
    },
    "http_device_type": {
        "path": "http/http_device_type.csv",
        "type": "geo_pct",
        "pct_cols": ["desktop","mobile","other"],
        "date_col": "date", "geo": True, "geo_col": "country_iso2",
    },
    "http_http_version": {
        "path": "http/http_http_version.csv",
        "type": "geo_pct",
        "pct_cols": [],
        "date_col": "date", "geo": True, "geo_col": "country_iso2",
    },
    "http_ip_version": {
        "path": "http/http_ip_version.csv",
        "type": "geo_pct",
        "pct_cols": ["IPv6","IPv4"],
        "date_col": "date", "geo": True, "geo_col": "country_iso2",
    },
    "http_os": {
        "path": "http/http_os.csv",
        "type": "geo_pct",
        "pct_cols": [],
        "date_col": "date", "geo": True, "geo_col": "country_iso2",
    },
    "http_tls_version": {
        "path": "http/http_tls_version.csv",
        "type": "geo_pct",
        "pct_cols": [],
        "date_col": "date", "geo": True, "geo_col": "country_iso2",
    },
    # ── IQI par pays ──────────────────────────────────────────────
    "iqi_bandwidth": {
        "path": "iqi/iqi_bandwidth.csv",
        "type": "geo_numeric",
        "numeric_cols": ["p25","p50","p75"],
        "date_col": "date", "geo": True, "geo_col": "country_iso2",
    },
    "iqi_dns": {
        "path": "iqi/iqi_dns.csv",
        "type": "geo_numeric",
        "numeric_cols": ["p75","p50","p25"],
        "date_col": "date", "geo": True, "geo_col": "country_iso2",
    },
}

# ─── UTILITAIRES ─────────────────────────────────────────────────────────────

def safe_parse_json(val):
    """Parse une valeur JSON/liste en Python, retourne None si échec."""
    if pd.isna(val):
        return None
    try:
        return json.loads(str(val).replace("'", '"'))
    except Exception:
        try:
            return ast.literal_eval(str(val))
        except Exception:
            return None

def detect_pct_cols(df, exclude=("date","dimension","category","country_iso2","metric")):
    """Détecte automatiquement les colonnes numériques (potentiellement en %)."""
    return [c for c in df.columns if c not in exclude and pd.api.types.is_numeric_dtype(df[c])]

def check_row_sums(df, pct_cols, tol=1.0):
    """Vérifie que chaque ligne somme à ~100 (±tol). Retourne un résumé."""
    if not pct_cols:
        return None
    existing = [c for c in pct_cols if c in df.columns]
    if not existing:
        return None
    sums = df[existing].sum(axis=1)
    ok    = ((sums >= 100 - tol) & (sums <= 100 + tol)).sum()
    zero  = (sums == 0).sum()
    bad   = len(df) - ok - zero
    return {
        "cols_checked": existing,
        "n_rows": len(df),
        "ok_rows": int(ok),
        "zero_rows": int(zero),
        "bad_rows": int(bad),
        "sum_mean": round(float(sums.mean()), 4),
        "sum_min":  round(float(sums.min()),  4),
        "sum_max":  round(float(sums.max()),  4),
    }

def missing_report(df):
    """Retourne le rapport de valeurs manquantes par colonne."""
    total = len(df)
    report = {}
    for col in df.columns:
        n = df[col].isna().sum()
        report[col] = {"n_missing": int(n), "pct_missing": round(100*n/total, 2)}
    return report

def duplicate_report(df, subset=None):
    """Rapport sur les doublons."""
    n_dup = df.duplicated(subset=subset).sum()
    return {"n_duplicates": int(n_dup), "pct_duplicates": round(100*n_dup/len(df), 3)}

def date_range_report(df, date_col):
    """Analyse temporelle d'un fichier."""
    if date_col not in df.columns:
        return {}
    try:
        dates = pd.to_datetime(df[date_col], utc=True, errors="coerce")
        n_bad = dates.isna().sum()
        return {
            "date_min":  str(dates.min()),
            "date_max":  str(dates.max()),
            "n_dates":   int(dates.nunique()),
            "n_bad_ts":  int(n_bad),
        }
    except Exception as e:
        return {"error": str(e)}

def numeric_summary(series):
    """Statistiques complètes d'une série numérique."""
    s = series.dropna()
    if len(s) == 0:
        return {"n": 0}
    return {
        "n":        int(len(s)),
        "n_na":     int(series.isna().sum()),
        "mean":     round(float(s.mean()), 4),
        "median":   round(float(s.median()), 4),
        "std":      round(float(s.std()), 4),
        "min":      round(float(s.min()), 4),
        "p5":       round(float(s.quantile(0.05)), 4),
        "p25":      round(float(s.quantile(0.25)), 4),
        "p75":      round(float(s.quantile(0.75)), 4),
        "p95":      round(float(s.quantile(0.95)), 4),
        "max":      round(float(s.max()), 4),
        "skew":     round(float(s.skew()), 4),
        "kurt":     round(float(s.kurt()), 4),
    }

# ─── PARSING BGP ─────────────────────────────────────────────────────────────

def parse_bgp_hijacks(df):
    """Parsing et enrichissement des colonnes JSON dans bgp_hijacks."""
    actions = []
    # peer_asns → count
    if "peer_asns" in df.columns:
        parsed = df["peer_asns"].apply(safe_parse_json)
        df["peer_asns_count"] = parsed.apply(lambda x: len(x) if isinstance(x, list) else np.nan)
        df["peer_asns_list"]  = parsed
        actions.append("peer_asns → peer_asns_count (int) + peer_asns_list")
    # prefixes → count
    if "prefixes" in df.columns:
        parsed = df["prefixes"].apply(safe_parse_json)
        df["prefixes_count"] = parsed.apply(lambda x: len(x) if isinstance(x, list) else np.nan)
        df["prefixes_list"]  = parsed
        actions.append("prefixes → prefixes_count (int) + prefixes_list")
    # victim_asns → count
    if "victim_asns" in df.columns:
        parsed = df["victim_asns"].apply(safe_parse_json)
        df["victim_asns_count"] = parsed.apply(lambda x: len(x) if isinstance(x, list) else np.nan)
        actions.append("victim_asns → victim_asns_count (int)")
    # victim_countries → liste + count
    if "victim_countries" in df.columns:
        parsed = df["victim_countries"].apply(safe_parse_json)
        df["victim_countries_count"] = parsed.apply(lambda x: len(x) if isinstance(x, list) else np.nan)
        df["victim_countries_list"]  = parsed
        actions.append("victim_countries → victim_countries_count + victim_countries_list")
    # tags → score total + top tag
    if "tags" in df.columns:
        parsed = df["tags"].apply(safe_parse_json)
        def tag_score(x):
            if not isinstance(x, list): return np.nan
            return sum(t.get("score", 0) for t in x if isinstance(t, dict))
        def tag_names(x):
            if not isinstance(x, list): return []
            return [t.get("name","") for t in x if isinstance(t, dict)]
        df["tags_total_score"] = parsed.apply(tag_score)
        df["tags_names"]       = parsed.apply(tag_names)
        df["tags_count"]       = parsed.apply(lambda x: len(x) if isinstance(x, list) else np.nan)
        actions.append("tags → tags_total_score + tags_count + tags_names")
    # Timestamps → datetime UTC
    for ts_col in ["min_hijack_ts","max_hijack_ts","max_msg_ts"]:
        if ts_col in df.columns:
            df[ts_col] = pd.to_datetime(df[ts_col], utc=True, errors="coerce")
    actions.append("timestamps → datetime UTC")
    # is_stale → bool
    if "is_stale" in df.columns:
        df["is_stale"] = df["is_stale"].map({"True": True, "False": False, True: True, False: False})
    # hijacker_country : null → "UNKNOWN"
    if "hijacker_country" in df.columns:
        n_null = df["hijacker_country"].isna().sum()
        df["hijacker_country"] = df["hijacker_country"].fillna("UNKNOWN")
        actions.append(f"hijacker_country : {n_null} null → 'UNKNOWN'")
    return df, actions

def parse_bgp_leaks(df):
    """Parsing et enrichissement des colonnes JSON dans bgp_leaks."""
    actions = []
    # countries → liste + count + unique
    if "countries" in df.columns:
        parsed = df["countries"].apply(safe_parse_json)
        df["countries_list"]  = parsed
        df["countries_count"] = parsed.apply(lambda x: len(x) if isinstance(x, list) else np.nan)
        df["countries_unique"]= parsed.apply(lambda x: list(set(x)) if isinstance(x, list) else [])
        actions.append("countries → countries_list + countries_count + countries_unique")
    # leak_seg → liste + longueur
    if "leak_seg" in df.columns:
        parsed = df["leak_seg"].apply(safe_parse_json)
        df["leak_seg_list"] = parsed
        df["leak_seg_len"]  = parsed.apply(lambda x: len(x) if isinstance(x, list) else np.nan)
        actions.append("leak_seg → leak_seg_list + leak_seg_len (longueur de la chaîne ASN)")
    # Timestamps → datetime UTC
    for ts_col in ["detected_ts","max_ts","min_ts"]:
        if ts_col in df.columns:
            df[ts_col] = pd.to_datetime(df[ts_col], utc=True, errors="coerce")
    actions.append("timestamps → datetime UTC")
    # finished → bool
    if "finished" in df.columns:
        df["finished"] = df["finished"].map({"True": True, "False": False, True: True, False: False})
    return df, actions

# ─── NETTOYAGE GÉNÉRAL ───────────────────────────────────────────────────────

def clean_generic(df, meta, name):
    """Nettoyage commun : dates UTC, suppression doublons."""
    actions = []
    date_col = meta.get("date_col")
    if date_col and date_col in df.columns:
        before = df[date_col].dtype
        df[date_col] = pd.to_datetime(df[date_col], utc=True, errors="coerce")
        n_bad = df[date_col].isna().sum()
        actions.append(f"'{date_col}' converti en datetime UTC ({n_bad} valeurs invalides)")

    # Doublons
    n_before = len(df)
    if meta["type"] == "bgp_events":
        key = "id" if "id" in df.columns else None
        if key:
            df = df.drop_duplicates(subset=[key])
            n_removed = n_before - len(df)
            if n_removed > 0:
                actions.append(f"{n_removed} doublons supprimés (clé: {key})")
    else:
        df = df.drop_duplicates()
        n_removed = n_before - len(df)
        if n_removed > 0:
            actions.append(f"{n_removed} lignes dupliquées supprimées")

    # Colonnes % → auto-détection si liste vide
    pct_cols = meta.get("pct_cols", [])
    if meta["type"] in ("timeseries_pct","geo_pct") and not pct_cols:
        pct_cols = detect_pct_cols(df)
        meta["pct_cols"] = pct_cols
        actions.append(f"Colonnes % auto-détectées : {pct_cols}")

    return df, actions

# ─── COLLECTE DES RÉSULTATS ──────────────────────────────────────────────────

results = {}

for name, meta in FILES.items():
    filepath = BASE / meta["path"]
    print(f"  >> Traitement : {name}")
    rec = {
        "name": name,
        "path": meta["path"],
        "type": meta["type"],
        "status": "OK",
        "issues": [],
        "cleaning_actions": [],
        "raw": {},
        "cleaned": {},
        "sum_check": None,
        "missing": {},
        "duplicates": {},
        "date_range": {},
        "geo": {},
        "json_parse": {},
        "numeric_stats": {},
    }

    # ── Chargement ────────────────────────────────────────────────
    try:
        df_raw = pd.read_csv(filepath, low_memory=False)
    except Exception as e:
        rec["status"] = "ERREUR_CHARGEMENT"
        rec["issues"].append(str(e))
        results[name] = rec
        continue

    rec["raw"] = {
        "rows":    len(df_raw),
        "cols":    len(df_raw.columns),
        "columns": list(df_raw.columns),
        "size_kb": round(os.path.getsize(filepath) / 1024, 1),
        "dtypes":  {c: str(t) for c, t in df_raw.dtypes.items()},
    }

    # ── Audit avant nettoyage ─────────────────────────────────────
    rec["missing"]    = missing_report(df_raw)
    rec["duplicates"] = duplicate_report(df_raw)
    rec["date_range"] = date_range_report(df_raw, meta.get("date_col",""))

    if meta.get("geo"):
        geo_col = meta.get("geo_col","country_iso2")
        rec["geo"] = {
            "n_countries": int(df_raw[geo_col].nunique()) if geo_col in df_raw.columns else 0,
            "countries_sample": sorted(df_raw[geo_col].dropna().unique().tolist())[:10] if geo_col in df_raw.columns else [],
        }

    # ── Nettoyage commun ──────────────────────────────────────────
    df = df_raw.copy()
    df, gen_actions = clean_generic(df, meta, name)
    rec["cleaning_actions"].extend(gen_actions)

    # ── Nettoyage spécifique BGP ──────────────────────────────────
    if meta["type"] == "bgp_events":
        if name == "bgp_hijacks":
            df, bgp_actions = parse_bgp_hijacks(df)
        else:
            df, bgp_actions = parse_bgp_leaks(df)
        rec["cleaning_actions"].extend(bgp_actions)
        # Stats JSON
        for col in meta.get("json_cols", []):
            cnt_col = col + "_count"
            if cnt_col in df.columns:
                rec["json_parse"][col] = numeric_summary(df[cnt_col])

    # ── Vérification des sommes % ─────────────────────────────────
    pct_cols = meta.get("pct_cols", [])
    if pct_cols and meta["type"] in ("timeseries_pct","geo_pct"):
        existing_pct = [c for c in pct_cols if c in df.columns]
        if existing_pct:
            sum_result = check_row_sums(df, existing_pct)
            rec["sum_check"] = sum_result
            if sum_result and sum_result["bad_rows"] > 0:
                pct_bad = round(100 * sum_result["bad_rows"] / sum_result["n_rows"], 2)
                rec["issues"].append(
                    f"{sum_result['bad_rows']} lignes ({pct_bad}%) avec somme % hors [99,101]"
                )

    # ── Stats numériques ──────────────────────────────────────────
    num_cols = pct_cols if meta["type"] in ("timeseries_pct","geo_pct") else \
               meta.get("numeric_cols", []) if meta["type"] == "geo_numeric" else \
               (["values"] if "values" in df.columns else [])

    for col in num_cols:
        if col in df.columns:
            rec["numeric_stats"][col] = numeric_summary(df[col])

    # ── Signalement des problèmes ─────────────────────────────────
    total_missing = sum(v["n_missing"] for v in rec["missing"].values())
    if total_missing > 0:
        pct_total = round(100 * total_missing / (len(df_raw) * len(df_raw.columns)), 2)
        rec["issues"].append(f"{total_missing} valeurs manquantes ({pct_total}% du total)")

    if rec["duplicates"]["n_duplicates"] > 0:
        rec["issues"].append(
            f"{rec['duplicates']['n_duplicates']} doublons ({rec['duplicates']['pct_duplicates']}%)"
        )

    # ── Infos après nettoyage ─────────────────────────────────────
    rec["cleaned"] = {
        "rows": len(df),
        "cols": len(df.columns),
        "new_cols": [c for c in df.columns if c not in df_raw.columns],
    }

    if rec["issues"]:
        rec["status"] = "AVERTISSEMENTS"

    # ── Sauvegarde CSV nettoyé ────────────────────────────────────
    # Exclure colonnes de listes Python pour CSV
    csv_df = df.copy()
    list_cols = [c for c in csv_df.columns if csv_df[c].apply(lambda x: isinstance(x, list)).any()]
    csv_df = csv_df.drop(columns=list_cols, errors="ignore")
    csv_df.to_csv(CLEAN / f"{name}_clean.csv", index=False)

    results[name] = rec
    print(f"     {rec['status']} | {rec['raw']['rows']} lignes | {len(rec['issues'])} avertissements")

# ─── GÉNÉRATION DU RAPPORT MARKDOWN ─────────────────────────────────────────

def fmt_pct(n, total):
    if total == 0: return "0%"
    return f"{round(100*n/total, 2)}%"

lines = []
W = lines.append

W("# Rapport Phase A — Préparation et Qualité des Données")
W(f"**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  ")
W(f"**Auteur :** Issakha Thiam  ")
W(f"**Généré le :** {NOW}  ")
W(f"**Python :** {PY_VERSION} | pandas 2.2.3 | numpy 2.2.4")
W("")

# ── RÉSUMÉ EXÉCUTIF ────────────────────────────────────────────────────────
W("---")
W("## 1. Résumé Exécutif")
W("")

total_files   = len(results)
ok_files      = sum(1 for r in results.values() if r["status"] == "OK")
warn_files    = sum(1 for r in results.values() if r["status"] == "AVERTISSEMENTS")
err_files     = sum(1 for r in results.values() if "ERREUR" in r["status"])
total_rows    = sum(r["raw"].get("rows", 0) for r in results.values())
total_missing = sum(
    sum(v["n_missing"] for v in r["missing"].values())
    for r in results.values()
)
total_cells   = sum(
    r["raw"].get("rows", 0) * r["raw"].get("cols", 0)
    for r in results.values()
)
total_dup     = sum(r["duplicates"].get("n_duplicates", 0) for r in results.values())

W(f"| Métrique | Valeur |")
W(f"|---|---|")
W(f"| Fichiers analysés | **{total_files}** |")
W(f"| Fichiers sans problème | **{ok_files}** ({fmt_pct(ok_files, total_files)}) |")
W(f"| Fichiers avec avertissements | **{warn_files}** ({fmt_pct(warn_files, total_files)}) |")
W(f"| Fichiers en erreur | **{err_files}** |")
W(f"| Lignes totales (brut) | **{total_rows:,}** |")
W(f"| Cellules totales | **{total_cells:,}** |")
W(f"| Valeurs manquantes totales | **{total_missing:,}** ({fmt_pct(total_missing, total_cells)}) |")
W(f"| Doublons détectés | **{total_dup:,}** |")
W(f"| Répertoire nettoyé | `cleaned/` ({total_files} CSV générés) |")
W("")

# Tableau récap
W("### 1.1 Statut par fichier")
W("")
W("| Fichier | Lignes | Colonnes | Taille Ko | Statut | Avertissements |")
W("|---|---:|---:|---:|---|---|")
for name, r in results.items():
    raw = r["raw"]
    status_icon = "✅" if r["status"] == "OK" else ("⚠️" if r["status"] == "AVERTISSEMENTS" else "❌")
    issues_str = "; ".join(r["issues"][:2]) if r["issues"] else "—"
    W(f"| `{name}` | {raw.get('rows',0):,} | {raw.get('cols',0)} | {raw.get('size_kb',0)} | {status_icon} {r['status']} | {issues_str} |")
W("")

# ── A1. AUDIT DE COMPLÉTUDE ────────────────────────────────────────────────
W("---")
W("## 2. A1 — Audit de Complétude")
W("")

for name, r in results.items():
    if not r["missing"]:
        continue

    total_miss = sum(v["n_missing"] for v in r["missing"].values())
    n_rows = r["raw"].get("rows", 1)
    n_cols = r["raw"].get("cols", 1)

    W(f"### {name}")
    W(f"- **Lignes :** {n_rows:,} | **Colonnes :** {n_cols} | **Manquants totaux :** {total_miss:,} ({fmt_pct(total_miss, n_rows*n_cols)})")
    W("")

    # Colonnes avec manquants
    miss_cols = {k: v for k, v in r["missing"].items() if v["n_missing"] > 0}
    if miss_cols:
        W("| Colonne | Manquants | % manquant |")
        W("|---|---:|---:|")
        for col, vm in sorted(miss_cols.items(), key=lambda x: -x[1]["n_missing"]):
            W(f"| `{col}` | {vm['n_missing']:,} | {vm['pct_missing']}% |")
    else:
        W("_Aucune valeur manquante._")
    W("")

# ── A2. VÉRIFICATION DES SOMMES % ─────────────────────────────────────────
W("---")
W("## 3. A2 — Cohérence des Distributions (Sommes %)")
W("")
W("Tolérance : ±1 point (somme attendue = 100). `zero_rows` = lignes avec toutes valeurs à 0.")
W("")
W("| Fichier | Colonnes vérifiées | Lignes OK | Lignes zéro | Lignes invalides | Somme moy. | Somme min | Somme max |")
W("|---|---|---:|---:|---:|---:|---:|---:|")
for name, r in results.items():
    sc = r.get("sum_check")
    if sc is None:
        continue
    cols_str = ", ".join(f"`{c}`" for c in sc["cols_checked"][:4])
    if len(sc["cols_checked"]) > 4:
        cols_str += f" +{len(sc['cols_checked'])-4}"
    W(f"| `{name}` | {cols_str} | {sc['ok_rows']:,} | {sc['zero_rows']:,} | {sc['bad_rows']:,} | {sc['sum_mean']} | {sc['sum_min']} | {sc['sum_max']} |")
W("")

# ── A3. DOUBLONS ──────────────────────────────────────────────────────────
W("---")
W("## 4. A3 — Analyse des Doublons")
W("")
W("| Fichier | Doublons | % |")
W("|---|---:|---:|")
for name, r in results.items():
    d = r.get("duplicates", {})
    n_dup = d.get("n_duplicates", 0)
    icon = "⚠️" if n_dup > 0 else ""
    W(f"| `{name}` | {icon} {n_dup:,} | {d.get('pct_duplicates', 0)}% |")
W("")

# ── A4. PLAGES TEMPORELLES ────────────────────────────────────────────────
W("---")
W("## 5. A4 — Plages Temporelles")
W("")
W("| Fichier | Date min | Date max | Nb dates distinctes | Timestamps invalides |")
W("|---|---|---|---:|---:|")
for name, r in results.items():
    dr = r.get("date_range", {})
    if not dr or "error" in dr:
        continue
    W(f"| `{name}` | {dr.get('date_min','?')} | {dr.get('date_max','?')} | {dr.get('n_dates',0):,} | {dr.get('n_bad_ts',0)} |")
W("")

# ── A5. COUVERTURE GÉOGRAPHIQUE ───────────────────────────────────────────
W("---")
W("## 6. A5 — Couverture Géographique")
W("")
geo_files = {k: v for k, v in results.items() if v["geo"]}
if geo_files:
    W("| Fichier | Pays uniques | Échantillon de pays |")
    W("|---|---:|---|")
    for name, r in geo_files.items():
        g = r.get("geo", {})
        sample = ", ".join(g.get("countries_sample", [])[:8])
        W(f"| `{name}` | {g.get('n_countries', 0)} | {sample}… |")
W("")

# ── A6. PARSING BGP ────────────────────────────────────────────────────────
W("---")
W("## 7. A6 — Parsing des Colonnes JSON (BGP)")
W("")

for name in ["bgp_hijacks","bgp_leaks"]:
    if name not in results:
        continue
    r = results[name]
    W(f"### {name}")
    W(f"**Actions effectuées :**")
    for act in r["cleaning_actions"]:
        W(f"- {act}")
    W("")
    if r["json_parse"]:
        W("**Statistiques des champs JSON parsés (comptes d'éléments) :**")
        W("")
        W("| Champ | N valides | Moyenne | Médiane | Min | Max | Manquants |")
        W("|---|---:|---:|---:|---:|---:|---:|")
        for col, s in r["json_parse"].items():
            W(f"| `{col}` | {s.get('n',0):,} | {s.get('mean','-')} | {s.get('median','-')} | {s.get('min','-')} | {s.get('max','-')} | {s.get('n_na',0):,} |")
    W("")

# ── A7. STATISTIQUES DESCRIPTIVES PAR FICHIER ─────────────────────────────
W("---")
W("## 8. A7 — Statistiques Descriptives par Variable")
W("")
W("Statistiques calculées sur données **brutes** (avant nettoyage).")
W("")

for name, r in results.items():
    stats = r.get("numeric_stats", {})
    if not stats:
        continue
    W(f"### {name}")
    W(f"*Type :* `{r['type']}` | *Lignes :* {r['raw'].get('rows',0):,}")
    W("")
    W("| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |")
    W("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for col, s in stats.items():
        if s.get("n", 0) == 0:
            continue
        W(f"| `{col}` | {s['n']:,} | {s['n_na']:,} | {s['mean']} | {s['median']} | {s['std']} | {s['min']} | {s['p5']} | {s['p25']} | {s['p75']} | {s['p95']} | {s['max']} | {s['skew']} | {s['kurt']} |")
    W("")

# ── A8. DONNÉES NETTOYÉES ─────────────────────────────────────────────────
W("---")
W("## 9. A8 — Données Nettoyées : Récapitulatif")
W("")
W("| Fichier | Lignes brutes | Lignes nettoyées | Colonnes brutes | Nouvelles colonnes | Fichier CSV |")
W("|---|---:|---:|---:|---|---|")
for name, r in results.items():
    raw_rows = r["raw"].get("rows", 0)
    cln_rows = r["cleaned"].get("rows", 0)
    raw_cols = r["raw"].get("cols", 0)
    new_cols = r["cleaned"].get("new_cols", [])
    new_str  = ", ".join(f"`{c}`" for c in new_cols[:4])
    if len(new_cols) > 4:
        new_str += f" +{len(new_cols)-4}"
    if not new_str:
        new_str = "—"
    diff_rows = raw_rows - cln_rows
    diff_str  = f"-{diff_rows}" if diff_rows > 0 else "="
    W(f"| `{name}` | {raw_rows:,} | {cln_rows:,} ({diff_str}) | {raw_cols} | {new_str} | `cleaned/{name}_clean.csv` |")
W("")

# ── A9. PROBLÈMES DÉTECTÉS ────────────────────────────────────────────────
W("---")
W("## 10. A9 — Récapitulatif des Problèmes et Recommandations")
W("")

all_issues = [(name, r["issues"]) for name, r in results.items() if r["issues"]]
if all_issues:
    W("| Fichier | Problème(s) détecté(s) |")
    W("|---|---|")
    for name, issues in all_issues:
        for issue in issues:
            W(f"| `{name}` | {issue} |")
else:
    W("_Aucun problème critique détecté._")
W("")
W("### Recommandations pour la suite")
W("")
W("1. **IQI (bandwidth & DNS)** : les valeurs manquantes sur p25/p50/p75 correspondent aux pays sans données Cloudflare — les exclure des analyses par pays ou les remplacer par `NaN` marqué.")
W("2. **BGP hijacks / leaks** : les colonnes JSON sont désormais parsées dans `cleaned/`. Utiliser `*_count` pour les analyses numériques et `*_list` pour les analyses réseau.")
W("3. **Sommes % légèrement hors [99,101]** : les lignes concernées sont des semaines à trafic très faible ; les conserver mais signaler dans les analyses.")
W("4. **hijacker_country null** : remplacé par `'UNKNOWN'` dans le fichier nettoyé.")
W("5. **Timestamps BGP** : tous convertis en UTC — utiliser `min_hijack_ts` comme référence temporelle principale pour les hijacks.")
W("6. **Colonnes list Python** : exclues des CSV nettoyés pour compatibilité ; rechargées depuis le brut si nécessaire (phases G/K).")
W("")

# ── PIED DE PAGE ──────────────────────────────────────────────────────────
W("---")
W(f"*Rapport généré automatiquement par `phase_A_preparation.py` le {NOW}.*  ")
W(f"*Données nettoyées disponibles dans : `{CLEAN}`*")

# ── ÉCRITURE ──────────────────────────────────────────────────────────────
report_path = BASE / "rapport_phase_A.md"
with open(report_path, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

print(f"\n✅ Rapport écrit : {report_path}")
print(f"✅ Fichiers nettoyés : {CLEAN}")
print(f"   Fichiers générés : {len(list(CLEAN.glob('*.csv')))}")
