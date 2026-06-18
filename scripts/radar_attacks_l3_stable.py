# -*- coding: utf-8 -*-
"""
Version STABLE – Cloudflare Radar (client/v4)
Pilier : Attaques réseau L3 par version IP (IPv4 vs IPv6)

Ce script :
1) interroge l'endpoint officiel qui fonctionne :
   /client/v4/radar/attacks/layer3/timeseries_groups/ip_version
2) récupère la série globale (52 semaines)
3) duplique cette série pour chaque pays ISO3 de ta liste,
   afin d'obtenir un jeu de données date × pays × (attack_ipv4_pct, attack_ipv6_pct)

Auteur : Issakha Thiam
Date : Décembre 2025
"""

import time
import logging
from typing import Dict, Any, Optional, List

import requests
import pandas as pd

# ======================
# ⚙️ PARAMÈTRES GÉNÉRAUX
# ======================

BASE = "https://api.cloudflare.com/client/v4/radar"

# 👉 RENSEIGNE ICI TON TOKEN RADAR (il DOIT déjà marcher avec le curl que tu as testé)
TOKEN = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn"

HEADERS = {
    "Accept": "application/json",
    "Authorization": f"Bearer {TOKEN}",
}

# On part sur 52 semaines (format Radar v4)
DATE_RANGE = "208w"

# Ta liste de pays ISO3 (tu peux la réduire / étendre)
COUNTRIES_ISO3 = [
    "AFG","ALB","DZA","AND","AGO","ATG","ARG","ARM","AUS","AUT",
    "AZE","BHS","BHR","BGD","BRB","BLR","BEL","BLZ","BEN","BTN",
    "BOL","BIH","BWA","BRA","BRN","BGR","BFA","BDI","CPV","KHM",
    "CMR","CAN","CAF","TCD","CHL","CHN","COL","COM","COG","COD",
    "CRI","CIV","HRV","CUB","CYP","CZE","DNK","DJI","DMA","DOM",
    "ECU","EGY","SLV","GNQ","ERI","EST","SWZ","ETH","FJI","FIN",
    "FRA","GAB","GMB","GEO","DEU","GHA","GRC","GRD","GTM","GIN",
    "GNB","GUY","HTI","HND","HUN","ISL","IND","IDN","IRN","IRQ",
    "IRL","ISR","ITA","JAM","JPN","JOR","KAZ","KEN","KIR","PRK",
    "KOR","KWT","KGZ","LAO","LVA","LBN","LSO","LBR","LBY","LIE",
    "LTU","LUX","MDG","MWI","MYS","MDV","MLI","MLT","MHL","MRT",
    "MUS","MEX","FSM","MDA","MCO","MNG","MNE","MAR","MOZ","MMR",
    "NAM","NRU","NPL","NLD","NZL","NIC","NER","NGA","MKD","NOR",
    "OMN","PAK","PLW","PAN","PNG","PRY","PER","PHL","POL","PRT",
    "QAT","ROU","RUS","RWA","KNA","LCA","VCT","WSM","SMR","STP",
    "SAU","SEN","SRB","SYC","SLE","SGP","SVK","SVN","SLB","SOM",
    "ZAF","SSD","ESP","LKA","SDN","SUR","SWE","CHE","SYR","TWN",
    "TJK","TZA","THA","TLS","TGO","TON","TTO","TUN","TUR","TKM",
    "TUV","UGA","UKR","ARE","GBR","USA","URY","UZB","VUT","VAT",
    "VEN","VNM","YEM","ZMB","ZWE"
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# ======================
# 🔁 FONCTION GÉNÉRIQUE
# ======================

def get_json(endpoint: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Appel générique de l'API Radar v4 (client/v4/radar/...).
    Gestion simple des erreurs et tentative de retry sur 429 (rate limit).
    """
    url = f"{BASE}/{endpoint.lstrip('/')}"
    for attempt in range(3):
        try:
            r = requests.get(url, headers=HEADERS, params=params, timeout=30)
        except Exception as e:
            logging.warning(f"Exception réseau sur {endpoint}: {e}")
            return None

        if r.status_code == 200:
            return r.json()
        elif r.status_code == 429:
            wait = 2 ** attempt
            logging.warning(f"{endpoint} {params} → 429 (rate limit), pause {wait}s")
            time.sleep(wait)
            continue
        else:
            logging.warning(f"{endpoint} {params} → {r.status_code}")
            return None

    return None


# ======================
# 🛡 ATTAQUES L3 – VERSION IP
# ======================

def fetch_attacks_l3_ip_version_global() -> pd.DataFrame:
    """
    Récupère la série temporelle GLOBALE des attaques L3 par version IP (IPv4 / IPv6).

    Endpoint qui a déjà été testé et fonctionne :
    GET /client/v4/radar/attacks/layer3/timeseries_groups/ip_version
      ?name=main&dateRange=52w&direction=Target&protocol=TCP

    Retour attendu (dans result.main) :
      - timestamps : liste de dates
      - IPv4       : liste de valeurs
      - IPv6       : liste de valeurs
    """
    logging.info("→ Récupération globale des attaques L3 par IP version")

    params = {
        "name": "main",
        "dateRange": DATE_RANGE,
        "direction": "Target",
        "protocol": "TCP",
    }

    js = get_json("attacks/layer3/timeseries_groups/ip_version", params)
    if not js or "result" not in js:
        logging.error("❌ Impossible de récupérer les données globales (aucun result).")
        return pd.DataFrame()

    result = js["result"]
    main = result.get("main", {})
    timestamps = main.get("timestamps", [])
    if not timestamps:
        logging.error("❌ Aucun timestamp dans result.main.")
        return pd.DataFrame()

    df = pd.DataFrame({
        "date": pd.to_datetime(timestamps),
        "attack_ipv4_pct": main.get("IPv4", []),
        "attack_ipv6_pct": main.get("IPv6", []),
    })

    df["year"] = df["date"].dt.year
    df["month"] = df["date"].dt.month
    df["source"] = "attacks/layer3/timeseries_groups/ip_version"

    logging.info(f"✅ Série globale récupérée : {len(df)} lignes")
    return df


def expand_global_to_countries(df_global: pd.DataFrame, countries_iso3: List[str]) -> pd.DataFrame:
    """
    Duplique la série globale pour chaque pays ISO3 fourni.

    Cela permet d'avoir un tableau date × pays × (attack_ipv4_pct, attack_ipv6_pct),
    en supposant que la structure des attaques observée globalement s'applique
    à chacun des pays (approximation pour l'indicateur X d'exposition).
    """
    if df_global.empty:
        return pd.DataFrame()

    all_rows = []
    for c in countries_iso3:
        tmp = df_global.copy()
        tmp["country"] = c
        all_rows.append(tmp)

    df_all = pd.concat(all_rows, ignore_index=True)
    # Réorganiser les colonnes pour plus de lisibilité
    cols_order = [
        "date", "country", "attack_ipv4_pct", "attack_ipv6_pct",
        "year", "month", "source"
    ]
    df_all = df_all[cols_order]
    logging.info(f"✅ Série pays × date construite : {len(df_all)} lignes pour {len(countries_iso3)} pays")
    return df_all


# ======================
# 🚀 MAIN
# ======================

def main():
    t0 = time.time()
    logging.info("🌍 Version STABLE – Attaques L3 par IP (Global + Pays)")

    # 1) Récupération globale
    df_global = fetch_attacks_l3_ip_version_global()
    if df_global.empty:
        logging.error("❌ Pas de données globales → arrêt.")
        return

    # 2) Expansion à la liste des pays
    df_countries = expand_global_to_countries(df_global, COUNTRIES_ISO3)

    # 3) Export CSV
    df_global.to_csv("radar_attacks_l3_ip_version_global.csv", index=False)
    logging.info("💾 Export : radar_attacks_l3_ip_version_global.csv")

    df_countries.to_csv("radar_attacks_l3_ip_version_by_country.csv", index=False)
    logging.info("💾 Export : radar_attacks_l3_ip_version_by_country.csv")

    logging.info(f"⏱ Temps total : {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
