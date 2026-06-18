# pilier1.py
# -*- coding: utf-8 -*-
"""
Pilier HTTP – protocoles HTTP (HTTP/1.x, 2, 3)
Endpoint Cloudflare Radar :
    GET /radar/http/timeseries_groups/http_version

- Utilise dateRange (ex: "1d", "7d", "30d")
- Location facultative (ISO2, ex: "SN"). Ne pas utiliser "WORLD".
- Parse timeseries_groups (meta + serie_0) format observé :
    serie_0 = { "timestamps": [...], "HTTP/2": [...], "HTTP/1.x": [...], "HTTP/3": [...] }
  + fallback sur l'autre format possible (dimension -> {timestamps, values})
- Export Excel + sauvegarde JSON brut

⚠️ Remplace le token dans le code.
"""

import os
import json
import time
import logging
import requests
import pandas as pd
from typing import Dict, Any, List, Optional


# ====================================================
# 🔐 TOKEN CLOUDLFARE RADAR — À METTRE ICI
# ====================================================
CLOUDFLARE_API_TOKEN = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn"  # <<< REMPLACER


# ==============================
# CONFIG
# ==============================

BASE_URL = "https://api.cloudflare.com/client/v4"
ENDPOINT = "/radar/http/timeseries_groups/http_version"

DATE_RANGE = "7d"
AGG_INTERVAL = "1d"

# Pays ISO2 optionnel. Exemple: "SN"
LOCATION: Optional[str] = None

OUTPUT_DIR = "radar_http_version_simple"
OUTPUT_JSON = "http_version_raw.json"
OUTPUT_EXCEL = "http_version.xlsx"


# ==============================
# LOGGING
# ==============================

logger = logging.getLogger("radar_http_version")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s",
                              "%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)


# ==============================
# AUTH HEADERS (TOKEN DIRECT)
# ==============================

def get_auth_headers() -> Dict[str, str]:
    if not CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_TOKEN == "VOTRE_TOKEN_ICI":
        raise RuntimeError("⚠️ Aucun token Cloudflare Radar n’a été défini dans le code.")
    return {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }


# ==============================
# REQUÊTE ROBUSTE
# ==============================

def robust_get(url: str, headers: Dict[str, str], params: Dict[str, Any],
               max_retries: int = 6, backoff_factor: float = 1.6) -> Dict[str, Any]:

    attempt = 0
    while True:
        attempt += 1
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=60)
        except requests.RequestException as e:
            if attempt >= max_retries:
                raise RuntimeError(f"Échec requête après {max_retries} essais : {e}")
            sleep_t = backoff_factor ** attempt
            logger.warning(f"Erreur réseau: {e} | retry #{attempt} dans {sleep_t:.1f}s")
            time.sleep(sleep_t)
            continue

        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt >= max_retries:
                raise RuntimeError(f"Erreur {resp.status_code}: {resp.text[:800]}")
            sleep_t = backoff_factor ** attempt
            logger.warning(f"Erreur {resp.status_code} | retry #{attempt} dans {sleep_t:.1f}s")
            time.sleep(sleep_t)
            continue

        if resp.status_code >= 400:
            raise RuntimeError(
                f"Erreur client {resp.status_code} (params={params}) : {resp.text[:800]}"
            )

        try:
            data = resp.json()
        except ValueError:
            raise RuntimeError(f"Réponse non-JSON : {resp.text[:200]}")

        if isinstance(data, dict) and data.get("success") is False:
            raise RuntimeError(f"API Radar success=false : {data}")

        return data


# ==============================
# JSON (timeseries_groups) → DATAFRAME
# ==============================

def convert_http_version_response_to_df(data: Dict[str, Any]) -> pd.DataFrame:
    """
    Supporte 2 formats Radar timeseries_groups :

    Format A (observé):
      result.serie_0 = {
        "timestamps": [...],
        "HTTP/2":   [...],
        "HTTP/1.x": [...],
        "HTTP/3":   [...]
      }

    Format B:
      result.serie_0 = {
        "HTTP/1.x": {"timestamps": [...], "values": [...]},
        ...
      }

    Sortie: timestamp | http_version | value (+ meta)
    """
    result = data.get("result", data)
    if isinstance(result, dict):
        logger.info(f"Keys(result) = {list(result.keys())[:20]}")

    serie_0 = result.get("serie_0")
    if not isinstance(serie_0, dict) or not serie_0:
        return pd.DataFrame()

    # -------- Format A --------
    if "timestamps" in serie_0 and isinstance(serie_0.get("timestamps"), list):
        timestamps = serie_0.get("timestamps") or []
        rows: List[Dict[str, Any]] = []

        dim_keys = [k for k in serie_0.keys() if k != "timestamps"]
        for dim in dim_keys:
            values = serie_0.get(dim)
            if not isinstance(values, list):
                continue
            n = min(len(timestamps), len(values))
            for i in range(n):
                rows.append({
                    "timestamp": timestamps[i],
                    "http_version": dim,
                    "value": values[i],
                })

        df = pd.DataFrame(rows)
        if df.empty:
            return df

        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.sort_values(["timestamp", "http_version"])

        meta = result.get("meta", {})
        if isinstance(meta, dict):
            df["aggInterval"] = meta.get("aggInterval")
            df["normalization"] = meta.get("normalization")
            units = meta.get("units")
            if isinstance(units, list) and units:
                df["unit_name"] = units[0].get("name")
                df["unit_value"] = units[0].get("value")

        return df

    # -------- Format B --------
    rows2: List[Dict[str, Any]] = []
    for dim, obj in serie_0.items():
        if not isinstance(obj, dict):
            continue
        ts = obj.get("timestamps") or []
        vals = obj.get("values") or []
        n = min(len(ts), len(vals))
        for i in range(n):
            rows2.append({
                "timestamp": ts[i],
                "http_version": dim,
                "value": vals[i],
            })

    df2 = pd.DataFrame(rows2)
    if df2.empty:
        return df2

    df2["timestamp"] = pd.to_datetime(df2["timestamp"], errors="coerce", utc=True)
    df2 = df2.sort_values(["timestamp", "http_version"])

    meta = result.get("meta", {})
    if isinstance(meta, dict):
        df2["aggInterval"] = meta.get("aggInterval")
        df2["normalization"] = meta.get("normalization")
        units = meta.get("units")
        if isinstance(units, list) and units:
            df2["unit_name"] = units[0].get("name")
            df2["unit_value"] = units[0].get("value")

    return df2


def make_excel_safe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Excel/openpyxl ne supporte pas les datetime timezone-aware.
    On retire le timezone (UTC) avant export.
    """
    if "timestamp" in df.columns and pd.api.types.is_datetime64tz_dtype(df["timestamp"]):
        df = df.copy()
        df["timestamp"] = df["timestamp"].dt.tz_convert(None)
    return df


# ==============================
# MAIN
# ==============================

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    headers = get_auth_headers()

    url = BASE_URL + ENDPOINT
    params: Dict[str, Any] = {
        "dateRange": DATE_RANGE,
        "aggInterval": AGG_INTERVAL,
    }
    if LOCATION:
        params["location"] = LOCATION.upper()

    logger.info("=== DÉMARRAGE PILIER HTTP VERSION (simple) ===")
    logger.info(f"URL    : {url}")
    logger.info(f"Params : {params}")

    data = robust_get(url, headers=headers, params=params)

    # Sauvegarde JSON brut
    json_path = os.path.join(OUTPUT_DIR, OUTPUT_JSON)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info(f"JSON brut → {json_path}")

    df = convert_http_version_response_to_df(data)
    if df.empty:
        res = data.get("result", {})
        serie_0 = res.get("serie_0") if isinstance(res, dict) else None
        logger.error("❌ DataFrame vide.")
        logger.error(f"success={data.get('success')}, result_has_serie_0={isinstance(serie_0, dict)}")
        if isinstance(serie_0, dict):
            logger.error(f"keys(serie_0)={list(serie_0.keys())[:30]}")
        return

    # Déduplication
    if "timestamp" in df.columns and "http_version" in df.columns:
        df = df.drop_duplicates(subset=["timestamp", "http_version"])

    # Excel-safe
    df_excel = make_excel_safe(df)

    excel_path = os.path.join(OUTPUT_DIR, OUTPUT_EXCEL)
    with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
        df_excel.to_excel(writer, sheet_name="http_version", index=False)

        meta = (data.get("result", {}) or {}).get("meta", {})
        if isinstance(meta, dict) and meta:
            pd.DataFrame([meta]).to_excel(writer, sheet_name="meta", index=False)

    logger.info("=== TERMINÉ ===")
    logger.info(f"Excel → {excel_path}")
    logger.info(f"Lignes totales : {len(df_excel)}")
    logger.info(f"Colonnes : {list(df_excel.columns)}")


if __name__ == "__main__":
    main()
