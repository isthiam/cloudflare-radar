# -*- coding: utf-8 -*-
"""
Cloudflare Radar – Attaques L3 (IPv4+IPv6)
Extraction DAILY – timeseries_groups/ip_version
Multi-pays (ISO3 -> ISO2)

Sorties:
- radar_attacks_l3_daily_ip_version_by_country.csv
- radar_attacks_l3_daily_ip_version_failures.csv
"""

import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, List, Optional

import requests
import pandas as pd

# ======================
# CONFIG
# ======================

BASE = "https://api.cloudflare.com/client/v4/radar"
TOKEN = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn"  # <-- Mets ton token Cloudflare (Radar scope)

HEADERS = {
    "Accept": "application/json",
    "Authorization": f"Bearer {TOKEN}",
}

COUNTRIES_ISO3 = ["FRA", "DEU", "GBR", "NLD", "ESP"]
ISO3_TO_ISO2 = {
    "FRA": "FR",
    "DEU": "DE",
    "GBR": "GB",
    "NLD": "NL",
    "ESP": "ES",
}

# Fenêtre: 1 an, découpée en chunks
DATE_END = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
DATE_START = DATE_END - timedelta(days=365)

CHUNK_DAYS = 30
SLEEP = 0.25
TIMEOUT = 30

# Endpoint ciblé
ENDPOINT = "/attacks/layer3/timeseries_groups/ip_version"
URL = f"{BASE}{ENDPOINT}"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# ======================
# UTILS
# ======================

def iso_z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_json_snippet(obj: Any, max_chars: int = 800) -> str:
    """Extrait JSON compact (pour logs/failures)"""
    try:
        s = json.dumps(obj, ensure_ascii=False)
    except Exception:
        s = str(obj)
    return s[:max_chars]


def get_json(params: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], int, str]:
    """
    GET Cloudflare Radar
    Retourne: (json, status_code, error_text)
    """
    try:
        r = requests.get(URL, headers=HEADERS, params=params, timeout=TIMEOUT)
    except Exception as e:
        return None, 0, str(e)

    if r.status_code == 200:
        try:
            return r.json(), 200, ""
        except Exception as e:
            return None, 200, f"JSON decode error: {e} / text={r.text[:200]}"
    else:
        return None, r.status_code, r.text[:800]


# ======================
# PARSE
# ======================

def parse_ip_version_timeseries_groups(js: Dict[str, Any]) -> pd.DataFrame:
    """
    Parse l'endpoint /attacks/layer3/timeseries_groups/ip_version

    Structure typique:
    {
      "success": true,
      "result": {
        "serie_0": {
          "timestamps": [...],
          "IPv4": [...],
          "IPv6": [...]
        }
      }
    }
    """
    result = js.get("result") or {}

    # Plusieurs implémentations utilisent serie_0 / series_0 / etc.
    serie = None
    for key in ("serie_0", "series_0", "main", "serie0", "series0"):
        if key in result and isinstance(result[key], dict):
            serie = result[key]
            break

    # fallback: prend le premier dict trouvé dans result
    if serie is None:
        for v in result.values():
            if isinstance(v, dict) and ("timestamps" in v):
                serie = v
                break

    if not serie:
        return pd.DataFrame()

    timestamps = serie.get("timestamps") or []
    ipv4 = serie.get("IPv4") or []
    ipv6 = serie.get("IPv6") or []

    if not timestamps:
        return pd.DataFrame()

    # harmonisation longueurs
    m = len(timestamps)
    if ipv4 and len(ipv4) < m:
        m = min(m, len(ipv4))
    if ipv6 and len(ipv6) < m:
        m = min(m, len(ipv6))

    timestamps = timestamps[:m]
    ipv4 = (ipv4[:m] if ipv4 else [None] * m)
    ipv6 = (ipv6[:m] if ipv6 else [None] * m)

    df = pd.DataFrame({
        "date": pd.to_datetime(timestamps, utc=True),
        "ipv4": pd.to_numeric(ipv4, errors="coerce"),
        "ipv6": pd.to_numeric(ipv6, errors="coerce"),
    })

    # total pratique
    df["total"] = df[["ipv4", "ipv6"]].sum(axis=1, min_count=1)
    return df


# ======================
# EXTRACTION PAR FENÊTRES
# ======================

def fetch_window(iso2: str, start: datetime, end: datetime) -> Tuple[pd.DataFrame, int, str, Optional[Dict[str, Any]]]:
    params = {
        "name": "main",
        "direction": "Target",
        "aggInterval": "1d",
        "dateStart": iso_z(start),
        "dateEnd": iso_z(end),
        "location": iso2,
    }

    js, status, err = get_json(params)
    if js is None:
        return pd.DataFrame(), status, err, None

    df = parse_ip_version_timeseries_groups(js)
    return df, status, err, js


def fetch_country_daily(iso3: str) -> Tuple[pd.DataFrame, List[dict]]:
    iso2 = ISO3_TO_ISO2.get(iso3)
    if not iso2:
        raise ValueError(f"ISO3 inconnu: {iso3}")

    logging.info(f"→ {iso3} ({iso2}): extraction…")

    chunks = []
    failures: List[dict] = []

    cur = DATE_START
    while cur < DATE_END:
        nxt = min(cur + timedelta(days=CHUNK_DAYS), DATE_END)

        df, status, err, js = fetch_window(iso2, cur, nxt)

        if not df.empty:
            chunks.append(df)
        else:
            # si 200 mais vide, garde un snippet du result pour debug
            snippet = ""
            if status == 200 and js is not None:
                snippet = safe_json_snippet(js.get("result", {}), 800)

            failures.append({
                "country_iso3": iso3,
                "country_iso2": iso2,
                "start": iso_z(cur),
                "end": iso_z(nxt),
                "status": status,
                "error": (err[:200] if err else ""),
                "result_snippet": snippet,
            })

        cur = nxt
        time.sleep(SLEEP)

    if not chunks:
        return pd.DataFrame(), failures

    out = pd.concat(chunks, ignore_index=True)
    out["country_iso3"] = iso3
    out["country_iso2"] = iso2
    out["year"] = out["date"].dt.year
    out["month"] = out["date"].dt.month
    return out, failures


# ======================
# MAIN
# ======================

def main():
    if not TOKEN.strip():
        logging.error("❌ TOKEN vide. Mets ton token Cloudflare dans TOKEN.")
        return

    t0 = time.time()
    logging.info("🌍 Extraction DAILY – Attaques L3 – ip_version (IPv4+IPv6)")

    all_rows = []
    all_failures: List[dict] = []

    for c in COUNTRIES_ISO3:
        df_c, fails = fetch_country_daily(c)

        if not df_c.empty:
            logging.info(f"✅ {c}: {len(df_c)} lignes")
            all_rows.append(df_c)
        else:
            logging.warning(f"⚠️ {c}: aucune donnée (toutes fenêtres vides)")

        all_failures.extend(fails)

    if not all_rows:
        logging.error("❌ Aucune donnée extraite pour tous les pays.")
        # même dans ce cas, export failures (utile)
        if all_failures:
            pd.DataFrame(all_failures).to_csv(
                "radar_attacks_l3_daily_ip_version_failures.csv",
                index=False,
                encoding="utf-8"
            )
            logging.info("💾 Export failures: radar_attacks_l3_daily_ip_version_failures.csv")
        return

    df_all = pd.concat(all_rows, ignore_index=True).sort_values(["country_iso3", "date"])

    out_file = "radar_attacks_l3_daily_ip_version_by_country.csv"
    df_all.to_csv(out_file, index=False, encoding="utf-8")
    logging.info(f"💾 Export OK: {out_file} ({len(df_all)} lignes)")

    if all_failures:
        fail_file = "radar_attacks_l3_daily_ip_version_failures.csv"
        pd.DataFrame(all_failures).to_csv(fail_file, index=False, encoding="utf-8")
        logging.info(f"💾 Export failures: {fail_file}")

    logging.info(f"⏱ Temps total : {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
