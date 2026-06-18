# -*- coding: utf-8 -*-
"""
Version STABLE – IQI (latence) + Outages (événements)
Cloudflare Radar – API client/v4

- IQI : /radar/quality/iqi/timeseries_groups
- Outages : /radar/annotations/outages

Auteur : Issakha Thiam
Date : Décembre 2025
"""

import pandas as pd
import requests
import logging
import time
import io

# ==========================
# ⚙️ CONFIG GLOBALE
# ==========================
BASE = "https://api.cloudflare.com/client/v4/radar"

# 🔑 Ton jeton API Radar (lecture seule)
TOKEN = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn"  # <-- MET TON TOKEN ICI

HEADERS = {
    "Accept": "application/json",
    "Authorization": f"Bearer {TOKEN}",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# ==========================
# 📡 Helpers HTTP
# ==========================
def get_json(endpoint: str, params: dict):
    """Appel JSON générique sur /client/v4/radar/..."""
    url = f"{BASE}/{endpoint.lstrip('/')}"
    try:
        r = requests.get(url, params=params, headers=HEADERS, timeout=30)
        if r.status_code == 200:
            return r.json()
        logging.warning(f"{endpoint} {params} → {r.status_code}")
        return None
    except Exception as e:
        logging.warning(f"Erreur {endpoint}: {e}")
        return None


def get_text(endpoint: str, params: dict):
    """Appel texte/CSV brut (pour outages avec format=CSV)."""
    url = f"{BASE}/{endpoint.lstrip('/')}"
    try:
        r = requests.get(url, params=params, headers=HEADERS, timeout=30)
        if r.status_code == 200:
            return r.text
        logging.warning(f"{endpoint} {params} → {r.status_code}")
        return None
    except Exception as e:
        logging.warning(f"Erreur {endpoint}: {e}")
        return None


# ==========================
# 📊 IQI – Latence globale
# ==========================
def fetch_iqi_latency_global():
    """
    IQI latence globale sur 52 semaines, agrégation hebdo (1w).

    Endpoint :
      GET /radar/quality/iqi/timeseries_groups
    Params :
      metric = LATENCY
      aggInterval = 1w
      dateRange = 52w
      format = JSON
    """
    logging.info("→ Récupération IQI (latence globale, 52w)")

    params = {
        "metric": "LATENCY",
        "aggInterval": "1w",
        "dateRange": "52w",
        "format": "JSON",
    }

    js = get_json("quality/iqi/timeseries_groups", params)
    if not js or "result" not in js:
        logging.error("❌ Impossible de récupérer IQI (aucun result).")
        return pd.DataFrame()

    result = js["result"]
    if "serie_0" not in result:
        logging.error("❌ Structure inattendue pour IQI (pas de serie_0).")
        return pd.DataFrame()

    serie = result["serie_0"]
    timestamps = serie.get("timestamps", [])
    p25 = serie.get("p25", [])
    p50 = serie.get("p50", [])
    p75 = serie.get("p75", [])

    if not timestamps:
        logging.warning("IQI → aucun timestamp, pas de données.")
        return pd.DataFrame()

    df = pd.DataFrame({
        "date": pd.to_datetime(timestamps),
        "iqi_latency_p25": pd.to_numeric(p25, errors="coerce"),
        "iqi_latency_p50": pd.to_numeric(p50, errors="coerce"),
        "iqi_latency_p75": pd.to_numeric(p75, errors="coerce"),
    })

    # Ajout année / mois
    df["year"] = df["date"].dt.year
    df["month"] = df["date"].dt.month

    logging.info(f"✅ IQI récupéré : {len(df)} lignes")
    return df


# ==========================
# ⚡ Outages – événements
# ==========================
def fetch_outages_events_global():
    """
    Outages globaux sur 52 semaines (événements).

    Endpoint :
      GET /radar/annotations/outages
    On utilise format=CSV pour obtenir un tableau directement.
    """
    logging.info("→ Récupération des outages (événements, 52w)")

    params = {
        "dateRange": "52w",
        "format": "CSV",
    }

    txt = get_text("annotations/outages", params)
    if not txt:
        logging.error("❌ Impossible de récupérer les outages (texte vide).")
        return pd.DataFrame()

    try:
        df = pd.read_csv(io.StringIO(txt))
    except Exception as e:
        logging.error(f"❌ Erreur parsing CSV outages : {e}")
        return pd.DataFrame()

    if df.empty:
        logging.warning("Outages → CSV vide, aucune ligne.")
        return df

    # Si les colonnes startTime / endTime existent, on les parse en datetime
    for col in ["startTime", "endTime", "start_time", "end_time"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")

    logging.info(f"✅ Outages récupérés : {len(df)} événements")
    return df


# ==========================
# 💾 MAIN
# ==========================
if __name__ == "__main__":
    t0 = time.time()
    logging.info("🌍 Version STABLE – IQI (latence) + Outages (52w)")

    # 1) IQI
    df_iqi = fetch_iqi_latency_global()

    # 2) Outages
    df_out = fetch_outages_events_global()

    # 3) Exports
    if not df_iqi.empty:
        df_iqi.to_csv("radar_iqi_latency_global_52w.csv", index=False)
        logging.info("💾 Export IQI → radar_iqi_latency_global_52w.csv")

    if not df_out.empty:
        df_out.to_csv("radar_outages_events_global_52w.csv", index=False)
        logging.info("💾 Export Outages → radar_outages_events_global_52w.csv")

    logging.info(f"⏱ Temps total : {time.time():.1f}s")
