# -*- coding: utf-8 -*-
"""
Cloudflare Radar (client/v4) - Attaques L3 par version IP (IPv4 vs IPv6)
Extraction DAILY par pays via location=ISO2.
Workaround "Internal Error": requêtes en tranches (chunking) + fallback.

Sorties:
- radar_attacks_l3_ip_version_daily_by_country.csv
- radar_attacks_l3_ip_version_daily_failures.csv
"""

import time
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta, timezone

import requests
import pandas as pd

# ======================
# ⚙️ PARAMÈTRES
# ======================

BASE = "https://api.cloudflare.com/client/v4/radar"
TOKEN = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn" # <-- mets ton token Radar Read ici

HEADERS = {
    "Accept": "application/json",
    "Authorization": f"Bearer {TOKEN}",
}

ENDPOINT = "attacks/layer3/timeseries_groups/ip_version"

# Période globale (on va chunker dedans)
DATE_START = datetime(2025, 1, 1, tzinfo=timezone.utc)
DATE_END   = datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

# DAILY demandé sous forme attendue par l'API
AGG_INTERVAL = "1d"  # ✅ attendu: '15m'|'1h'|'1d'|'1w'|''

COUNTRIES_ISO3 = ["FRA", "DEU", "GBR", "NLD", "ESP"]

ISO3_TO_ISO2 = {
    "FRA": "FR",
    "DEU": "DE",
    "GBR": "GB",
    "NLD": "NL",
    "ESP": "ES",
}

COMMON_PARAMS = {
    "name": "main",
    "direction": "Target",
    "protocol": "TCP",
    "aggInterval": AGG_INTERVAL,
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ======================
# Helpers
# ======================

def iso_z(dt: datetime) -> str:
    """YYYY-mm-ddTHH:MM:ssZ"""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_json(params: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], int, str]:
    url = f"{BASE}/{ENDPOINT}"
    for attempt in range(5):
        try:
            r = requests.get(url, headers=HEADERS, params=params, timeout=60)
        except Exception as e:
            return None, 0, str(e)

        if r.status_code == 200:
            return r.json(), 200, ""
        if r.status_code == 429:
            wait = 2 ** attempt
            logging.warning(f"429 rate limit → pause {wait}s")
            time.sleep(wait)
            continue

        txt = (r.text or "")[:800]
        return None, r.status_code, txt

    return None, 429, "rate limited"


def parse_ip_version_result(js: Dict[str, Any]) -> pd.DataFrame:
    """
    Parse robuste:
    - result.main.timestamps
    - result.main.IPv4
    - result.main.IPv6
    Cloudflare peut renvoyer des longueurs différentes -> on tronque à min_len.
    """
    result = js.get("result", {})
    main = result.get("main", {}) if isinstance(result, dict) else {}

    ts = main.get("timestamps", []) or []
    v4 = main.get("IPv4", []) or []
    v6 = main.get("IPv6", []) or []

    # On tronque à la même taille
    min_len = min(len(ts), len(v4), len(v6))
    if min_len == 0:
        return pd.DataFrame()

    if len(ts) != len(v4) or len(ts) != len(v6):
        logging.warning(
            f"⚠️ Longueurs différentes (timestamps={len(ts)}, IPv4={len(v4)}, IPv6={len(v6)}). "
            f"Troncature à {min_len}."
        )

    ts = ts[:min_len]
    v4 = v4[:min_len]
    v6 = v6[:min_len]

    df = pd.DataFrame({
        "date": pd.to_datetime(ts, utc=True, errors="coerce"),
        "attack_ipv4_pct": pd.to_numeric(v4, errors="coerce"),
        "attack_ipv6_pct": pd.to_numeric(v6, errors="coerce"),
    })

    df = df.dropna(subset=["date", "attack_ipv6_pct"])
    df["year"] = df["date"].dt.year
    df["month"] = df["date"].dt.month
    return df


def is_internal_error(status: int, err: str) -> bool:
    return status == 400 and ("Internal Error" in err or "internal error" in err)


# ======================
# Fetch par tranche
# ======================

def fetch_window(location_iso2: str, start: datetime, end: datetime) -> Tuple[pd.DataFrame, int, str]:
    params = dict(COMMON_PARAMS)
    params["location"] = location_iso2
    params["dateStart"] = iso_z(start)
    params["dateEnd"] = iso_z(end)

    js, status, err = get_json(params)
    if js is None:
        return pd.DataFrame(), status, err

    df = parse_ip_version_result(js)
    return df, status, ""


def fetch_country_daily_chunked(country_iso3: str) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    iso2 = ISO3_TO_ISO2[country_iso3]
    failures = []
    frames = []

    # 1) Test de stabilité sur une petite fenêtre
    test_start = DATE_END - timedelta(days=30)
    df_test, status, err = fetch_window(iso2, test_start, DATE_END)
    if df_test.empty:
        failures.append({"country_iso3": country_iso3, "iso2": iso2, "stage": "test_30d", "status": status, "error": err[:300]})
        # Si internal error, on retente test 7 jours
        if is_internal_error(status, err):
            test_start2 = DATE_END - timedelta(days=7)
            df_test2, status2, err2 = fetch_window(iso2, test_start2, DATE_END)
            if df_test2.empty:
                failures.append({"country_iso3": country_iso3, "iso2": iso2, "stage": "test_7d", "status": status2, "error": err2[:300]})
                return pd.DataFrame(), failures
        else:
            return pd.DataFrame(), failures

    # 2) Chunking sur toute la période
    #    D'abord 30 jours, si internal error -> 7 jours, si besoin -> 1 jour
    chunk_sizes = [30, 7, 1]
    chunk_days = 30

    cur = DATE_START
    while cur < DATE_END:
        ok = False
        for cd in chunk_sizes:
            chunk_days = cd
            nxt = min(cur + timedelta(days=chunk_days), DATE_END)
            df_chunk, st, er = fetch_window(iso2, cur, nxt)

            if not df_chunk.empty:
                frames.append(df_chunk)
                ok = True
                break

            if is_internal_error(st, er):
                # réduire la fenêtre et retenter
                failures.append({"country_iso3": country_iso3, "iso2": iso2, "stage": f"chunk_{cd}d", "status": st, "error": "Internal Error -> retry smaller"})
                continue

            # autre erreur: on log et on abandonne ce chunk
            failures.append({"country_iso3": country_iso3, "iso2": iso2, "stage": f"chunk_{cd}d", "status": st, "error": er[:300]})
            break

        if not ok:
            # si on ne peut pas récupérer ce segment, on avance quand même pour ne pas bloquer
            cur = cur + timedelta(days=chunk_days)
        else:
            cur = nxt

        time.sleep(0.2)

    if not frames:
        return pd.DataFrame(), failures

    df_all = pd.concat(frames, ignore_index=True)
    df_all = df_all.sort_values("date").drop_duplicates(subset=["date"], keep="last")
    df_all = df_all.sort_values("date")
    df_all["country_iso3"] = country_iso3
    df_all["country_iso2"] = iso2
    df_all["source"] = ENDPOINT
    return df_all, failures


# ======================
# MAIN
# ======================

def main():
    if not TOKEN.strip():
        raise SystemExit("❌ TOKEN vide. Renseigne TOKEN dans le script.")

    logging.info("🌍 Extraction DAILY par pays (chunking) – Attaques L3 IP version")
    t0 = time.time()

    all_frames = []
    all_failures = []

    for c in COUNTRIES_ISO3:
        logging.info(f"→ {c} ({ISO3_TO_ISO2[c]}): extraction…")
        df_c, fails = fetch_country_daily_chunked(c)

        all_failures.extend(fails)

        if df_c.empty:
            logging.warning(f"⚠️ {c}: aucune donnée extraite")
        else:
            logging.info(f"✅ {c}: {len(df_c)} lignes")
            all_frames.append(df_c)

    out_data = "radar_attacks_l3_ip_version_daily_by_country.csv"
    out_fail = "radar_attacks_l3_ip_version_daily_failures.csv"

    if all_frames:
        df_all = pd.concat(all_frames, ignore_index=True)
        cols = ["date","country_iso3","country_iso2","attack_ipv4_pct","attack_ipv6_pct","year","month","source"]
        df_all = df_all[cols].sort_values(["country_iso3","date"])
        df_all.to_csv(out_data, index=False, encoding="utf-8")
        logging.info(f"💾 Export OK: {out_data} ({len(df_all)} lignes)")
    else:
        logging.error("❌ Aucune donnée extraite pour aucun pays.")

    pd.DataFrame(all_failures).to_csv(out_fail, index=False, encoding="utf-8")
    logging.info(f"💾 Export failures: {out_fail}")

    logging.info(f"⏱ Temps total : {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
