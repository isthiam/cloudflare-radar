# -*- coding: utf-8 -*-
"""
Cloudflare Radar – Attaques Layer3
Extraction DAILY – "valeurs brutes" disponibles : BYTES (metric=bytes)
Multi-pays (ISO2) avec chunking (fenêtres 30 jours)

Sorties:
- radar_attacks_l3_bytes_daily_by_country.csv
- radar_attacks_l3_bytes_daily_failures.csv
"""

import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, List, Optional

import requests
import pandas as pd

# ======================
# CONFIG
# ======================

BASE = "https://api.cloudflare.com/client/v4/radar"

TOKEN = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn"  # <-- mets ton token Radar ici
HEADERS = {"Accept": "application/json", "Authorization": f"Bearer {TOKEN}"}

# 5 pays Europe (ceux que tu as testés)
COUNTRIES_ISO3 = [
    "AFG","ALB","DZA","AND","AGO","ARG","ARM","AUS","AUT","AZE",
    "BHR","BGD","BEL","BEN","BOL","BIH","BWA","BRA","BGR","BFA",
    "BDI","KHM","CMR","CAN","CAF","TCD","CHL","CHN","COL","COG",
    "COD","CRI","CIV","HRV","CUB","CYP","CZE","DNK","DOM","ECU",
    "EGY","SLV","EST","ETH","FIN","FRA","GAB","GEO","DEU","GHA",
    "GRC","GTM","GIN","HTI","HND","HUN","ISL","IND","IDN","IRN",
    "IRQ","IRL","ISR","ITA","JPN","JOR","KAZ","KEN","KWT","LVA",
    "LBN","LBY","LTU","LUX","MDG","MWI","MYS","MLI","MLT","MEX",
    "MAR","NLD","NZL","NER","NGA","NOR","OMN","PAK","PAN","PER",
    "PHL","POL","PRT","QAT","ROU","RUS","SAU","SEN","SRB","SGP",
    "SVK","SVN","ZAF","KOR","ESP","LKA","SDN","SWE","CHE","SYR",
    "TWN","TZA","THA","TUN","TUR","UGA","UKR","ARE","GBR","USA",
    "URY","VEN","VNM","YEM","ZMB","ZWE"
]

ISO3_TO_ISO2 = {
    "AFG":"AF","ALB":"AL","DZA":"DZ","AND":"AD","AGO":"AO","ARG":"AR",
    "ARM":"AM","AUS":"AU","AUT":"AT","AZE":"AZ","BHR":"BH","BGD":"BD",
    "BEL":"BE","BEN":"BJ","BOL":"BO","BIH":"BA","BWA":"BW","BRA":"BR",
    "BGR":"BG","BFA":"BF","BDI":"BI","KHM":"KH","CMR":"CM","CAN":"CA",
    "CAF":"CF","TCD":"TD","CHL":"CL","CHN":"CN","COL":"CO","COG":"CG",
    "COD":"CD","CRI":"CR","CIV":"CI","HRV":"HR","CUB":"CU","CYP":"CY",
    "CZE":"CZ","DNK":"DK","DOM":"DO","ECU":"EC","EGY":"EG","SLV":"SV",
    "EST":"EE","ETH":"ET","FIN":"FI","FRA":"FR","GAB":"GA","GEO":"GE",
    "DEU":"DE","GHA":"GH","GRC":"GR","GTM":"GT","GIN":"GN","HTI":"HT",
    "HND":"HN","HUN":"HU","ISL":"IS","IND":"IN","IDN":"ID","IRN":"IR",
    "IRQ":"IQ","IRL":"IE","ISR":"IL","ITA":"IT","JPN":"JP","JOR":"JO",
    "KAZ":"KZ","KEN":"KE","KWT":"KW","LVA":"LV","LBN":"LB","LBY":"LY",
    "LTU":"LT","LUX":"LU","MDG":"MG","MWI":"MW","MYS":"MY","MLI":"ML",
    "MLT":"MT","MEX":"MX","MAR":"MA","NLD":"NL","NZL":"NZ","NER":"NE",
    "NGA":"NG","NOR":"NO","OMN":"OM","PAK":"PK","PAN":"PA","PER":"PE",
    "PHL":"PH","POL":"PL","PRT":"PT","QAT":"QA","ROU":"RO","RUS":"RU",
    "SAU":"SA","SEN":"SN","SRB":"RS","SGP":"SG","SVK":"SK","SVN":"SI",
    "ZAF":"ZA","KOR":"KR","ESP":"ES","LKA":"LK","SDN":"SD","SWE":"SE",
    "CHE":"CH","SYR":"SY","TWN":"TW","TZA":"TZ","THA":"TH","TUN":"TN",
    "TUR":"TR","UGA":"UG","UKR":"UA","ARE":"AE","GBR":"GB","USA":"US",
    "URY":"UY","VEN":"VE","VNM":"VN","YEM":"YE","ZMB":"ZM","ZWE":"ZW"
}


# Période: dernier 365 jours (jours complets UTC)
DATE_END = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
DATE_START = DATE_END - timedelta(days=365)

AGG_INTERVAL = "1d"     # Radar attend "1d"
CHUNK_DAYS = 30
SLEEP = 0.25

# direction : "Target" (attaques ciblant le pays) ou "Origin"
DIRECTION = "Target"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ======================
# UTILS
# ======================

def iso_z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_json(endpoint: str, params: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], int, str]:
    url = f"{BASE}/{endpoint.lstrip('/')}"
    try:
        r = requests.get(url, headers=HEADERS, params=params, timeout=30)
    except Exception as e:
        return None, 0, str(e)

    if r.status_code == 200:
        return r.json(), 200, ""
    return None, r.status_code, r.text


def parse_layer3_timeseries_bytes(js: Dict[str, Any]) -> pd.DataFrame:
    """
    Parse réponse de /radar/attacks/layer3/timeseries (metric=bytes)

    Typiquement: result -> { meta, serie_1, serie_2 ... }
    Dans la pratique, tu as souvent result.main.timestamps + result.main.values
    Mais on le rend robuste : on cherche un objet avec 'timestamps' et 'values'.
    """
    result = js.get("result", {})
    if not isinstance(result, dict):
        return pd.DataFrame()

    # cas fréquent: result["main"]
    candidates = []
    if "main" in result and isinstance(result["main"], dict):
        candidates.append(result["main"])
    # fallback: premier dict qui contient timestamps+values
    for v in result.values():
        if isinstance(v, dict) and "timestamps" in v and "values" in v:
            candidates.append(v)

    if not candidates:
        return pd.DataFrame()

    obj = candidates[0]
    ts = obj.get("timestamps", []) or []
    vals = obj.get("values", []) or []

    if not ts or not vals:
        return pd.DataFrame()

    # sécurité longueurs
    m = min(len(ts), len(vals))
    ts = ts[:m]
    vals = vals[:m]

    df = pd.DataFrame(
        {
            "date": pd.to_datetime(ts, utc=True),
            "attack_bytes": pd.to_numeric(vals, errors="coerce"),
        }
    ).dropna(subset=["attack_bytes"])

    return df


# ======================
# EXTRACTION PAR FENÊTRES
# ======================

def fetch_window_bytes(iso2: str, start: datetime, end: datetime) -> Tuple[pd.DataFrame, int, str]:
    params = {
        "aggInterval": AGG_INTERVAL,
        "dateStart": iso_z(start),
        "dateEnd": iso_z(end),
        "location": iso2,
        "direction": DIRECTION,
        # clé: bytes = "brut" disponible en Layer3
        "metric": "bytes",
    }

    js, status, err = get_json("attacks/layer3/timeseries", params)
    if js is None:
        return pd.DataFrame(), status, err

    df = parse_layer3_timeseries_bytes(js)
    return df, status, err


def fetch_country_daily_bytes(iso3: str) -> Tuple[pd.DataFrame, List[dict]]:
    iso2 = ISO3_TO_ISO2[iso3]
    logging.info(f"→ {iso3} ({iso2}): extraction bytes…")

    rows = []
    failures = []

    cur = DATE_START
    while cur < DATE_END:
        nxt = min(cur + timedelta(days=CHUNK_DAYS), DATE_END)

        df, status, err = fetch_window_bytes(iso2, cur, nxt)

        if not df.empty:
            rows.append(df)
        else:
            failures.append(
                {
                    "country": iso3,
                    "iso2": iso2,
                    "start": iso_z(cur),
                    "end": iso_z(nxt),
                    "status": status,
                    "error": (err or "")[:250],
                }
            )

        cur = nxt
        time.sleep(SLEEP)

    if not rows:
        return pd.DataFrame(), failures

    out = pd.concat(rows, ignore_index=True).drop_duplicates(subset=["date"])
    out["country"] = iso3
    out["year"] = out["date"].dt.year
    out["month"] = out["date"].dt.month

    return out.sort_values("date"), failures


# ======================
# MAIN
# ======================

def main():
    t0 = time.time()
    logging.info("🌍 Extraction DAILY – Layer3 bytes (metric=bytes)")

    all_rows = []
    all_failures = []

    for c in COUNTRIES_ISO3:
        df_c, fails = fetch_country_daily_bytes(c)
        if not df_c.empty:
            logging.info(f"✅ {c}: {len(df_c)} lignes")
            all_rows.append(df_c)
        else:
            logging.warning(f"⚠️ {c}: aucune donnée")
        all_failures.extend(fails)

    if not all_rows:
        logging.error("❌ Aucune donnée extraite.")
        if all_failures:
            pd.DataFrame(all_failures).to_csv("radar_attacks_l3_bytes_daily_failures.csv", index=False, encoding="utf-8")
            logging.info("💾 Export failures: radar_attacks_l3_bytes_daily_failures.csv")
        return

    df_all = pd.concat(all_rows, ignore_index=True).sort_values(["country", "date"])
    df_all.to_csv("radar_attacks_l3_bytes_daily_by_country.csv", index=False, encoding="utf-8")
    logging.info(f"💾 Export OK: radar_attacks_l3_bytes_daily_by_country.csv ({len(df_all)} lignes)")

    if all_failures:
        pd.DataFrame(all_failures).to_csv("radar_attacks_l3_bytes_daily_failures.csv", index=False, encoding="utf-8")
        logging.info("💾 Export failures: radar_attacks_l3_bytes_daily_failures.csv")

    logging.info(f"⏱ Temps total : {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
