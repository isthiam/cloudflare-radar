# -*- coding: utf-8 -*-
"""
Extraction mondiale Cloudflare Radar (client/v4)
→ Données brutes par pays : IPv6, TLS, IQI (latence), attaques L3, outages
Auteur : Issakha Thiam
Date : Octobre 2025
"""

import pandas as pd
import requests
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# ======================
# ⚙️ PARAMÈTRES GÉNÉRAUX
# ======================
THREADS = 3
BASE = "https://api.cloudflare.com/client/v4/radar"
TOKEN = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn"  # 👉 insère ici ton token Cloudflare Radar

HEADERS = {"Accept": "application/json", "Authorization": f"Bearer {TOKEN}"}

# 🌍 Quelques pays pour test (tu peux élargir ensuite)
COUNTRIES = ["SEN", "FRA", "MAR", "CIV", "GHA", "NGA", "EGY", "ZAF"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ======================
# 📦 Conversion ISO-3 → ISO-2
# ======================
ISO3_TO_2 = {
    "SEN": "SN", "FRA": "FR", "MAR": "MA", "CIV": "CI", "GHA": "GH",
    "NGA": "NG", "EGY": "EG", "ZAF": "ZA"
}
def a3_to_a2(code): return ISO3_TO_2.get(code, code[:2])

# ======================
# 📡 Fonction générique de requête
# ======================
def get_json(endpoint, params):
    url = f"{BASE}/{endpoint.lstrip('/')}"
    try:
        r = requests.get(url, headers=HEADERS, params=params, timeout=30)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 429:
            logging.warning(f"Rate limit → pause 10s ({endpoint})")
            time.sleep(10)
            return get_json(endpoint, params)
        else:
            logging.warning(f"{endpoint} {params} → {r.status_code}")
            return None
    except Exception as e:
        logging.warning(f"Erreur {endpoint}: {e}")
        return None

# ======================
# 🧱 Extraction unitaire
# ======================
def extract_http_ip_version(country_a3):
    loc = a3_to_a2(country_a3)
    js = get_json("http/timeseries/ip_version",
        {"name": "main", "dateRange": "52w", "location": loc, "aggInterval": "1w", "format": "json"})
    if not js or "result" not in js: return pd.DataFrame()
    d = js["result"]["main"]
    return pd.DataFrame({
        "date": pd.to_datetime(d["timestamps"]),
        "country": country_a3,
        "ipv4_pct": pd.to_numeric(d.get("IPv4", []), errors="coerce"),
        "ipv6_pct": pd.to_numeric(d.get("IPv6", []), errors="coerce")
    })

def extract_http_tls_version(country_a3):
    loc = a3_to_a2(country_a3)
    js = get_json("http/timeseries/tls_version",
        {"name": "main", "dateRange": "52w", "location": loc, "aggInterval": "1w", "format": "json"})
    if not js or "result" not in js: return pd.DataFrame()
    d = js["result"]["main"]
    return pd.DataFrame({
        "date": pd.to_datetime(d["timestamps"]),
        "country": country_a3,
        "tls12_pct": pd.to_numeric(d.get("TLSv1_2", []), errors="coerce"),
        "tls13_pct": pd.to_numeric(d.get("TLSv1_3", []), errors="coerce")
    })

def extract_iqi_latency(country_a3):
    loc = a3_to_a2(country_a3)
    js = get_json("quality/iqi/timeseries_groups",
        {"name": "main", "dateRange": "12w", "location": loc,
         "metric": "latency", "aggInterval": "1w", "format": "json"})
    if not js or "result" not in js: return pd.DataFrame()
    d = js["result"]["main"]
    return pd.DataFrame({
        "date": pd.to_datetime(d["timestamps"]),
        "country": country_a3,
        "latency_p25": pd.to_numeric(d.get("p25", []), errors="coerce"),
        "latency_p50": pd.to_numeric(d.get("p50", []), errors="coerce"),
        "latency_p75": pd.to_numeric(d.get("p75", []), errors="coerce")
    })

def extract_l3_attacks(country_a3):
    loc = a3_to_a2(country_a3)
    js = get_json("attacks/layer3/timeseries_groups",
        {"name": "main", "dateRange": "52w", "location": loc,
         "aggInterval": "1w", "format": "json"})
    if not js or "result" not in js: return pd.DataFrame()
    d = js["result"]["main"]
    return pd.DataFrame({
        "date": pd.to_datetime(d["timestamps"]),
        "country": country_a3,
        "tcp_pct": pd.to_numeric(d.get("tcp", []), errors="coerce"),
        "udp_pct": pd.to_numeric(d.get("udp", []), errors="coerce"),
        "icmp_pct": pd.to_numeric(d.get("icmp", []), errors="coerce"),
        "gre_pct": pd.to_numeric(d.get("gre", []), errors="coerce")
    })

def extract_outages(country_a3):
    loc = a3_to_a2(country_a3)
    rows = []
    offset = 0
    while True:
        js = get_json("annotations/outages",
            {"dateRange": "52w", "locations": loc, "limit": 200, "offset": offset, "format": "json"})
        if not js or "result" not in js or not js["result"].get("annotations"):
            break
        for a in js["result"]["annotations"]:
            rows.append({
                "country": country_a3,
                "start": a.get("startDate"), "end": a.get("endDate"),
                "scope": a.get("scope"),
                "cause": a.get("outage", {}).get("outageCause"),
                "type": a.get("outage", {}).get("outageType")
            })
        if len(js["result"]["annotations"]) < 200:
            break
        offset += 200
    return pd.DataFrame(rows)

# ======================
# 🌍 Extraction par pays
# ======================
def extract_country_data(country):
    logging.info(f"→ Extraction {country} en cours...")
    dfs = [
        extract_http_ip_version(country),
        extract_http_tls_version(country),
        extract_iqi_latency(country),
        extract_l3_attacks(country)
    ]
    # Outages à part (liste d'événements)
    outages_df = extract_outages(country)
    dfs = [d for d in dfs if not d.empty]
    if not dfs: 
        logging.warning(f"{country} → aucune donnée.")
        return pd.DataFrame()
    df = dfs[0]
    for d in dfs[1:]:
        df = df.merge(d, on=["country", "date"], how="outer")
    df["year"] = df["date"].dt.year
    df["month"] = df["date"].dt.month
    return df, outages_df

# ======================
# 🚀 Pipeline global
# ======================
def run_all():
    full_data, full_outages = [], []
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = [ex.submit(extract_country_data, c) for c in COUNTRIES]
        for fut in as_completed(futures):
            try:
                data, outages = fut.result()
                if not data.empty: full_data.append(data)
                if not outages.empty: full_outages.append(outages)
            except Exception as e:
                logging.error(f"Erreur thread: {e}")

    if not full_data:
        logging.error("❌ Aucune donnée extraite.")
        return None, None
    df_main = pd.concat(full_data, ignore_index=True)
    df_out = pd.concat(full_outages, ignore_index=True) if full_outages else pd.DataFrame()
    return df_main, df_out

# ======================
# 💾 MAIN
# ======================
if __name__ == "__main__":
    t0 = time.time()
    df, outages = run_all()

    if df is not None and not df.empty:
        df.to_csv("radar_api_v4_donnees_brutes.csv", index=False)
        logging.info(f"✅ Données principales exportées ({len(df)} lignes)")
    if outages is not None and not outages.empty:
        outages.to_csv("radar_api_v4_outages.csv", index=False)
        logging.info(f"✅ Pannes exportées ({len(outages)} événements)")
    logging.info(f"⏱ Temps total : {time.time()-t0:.1f}s")
