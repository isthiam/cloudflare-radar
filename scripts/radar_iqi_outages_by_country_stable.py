# -*- coding: utf-8 -*-
"""
Version STABLE – IQI (latence) + Outages par pays (52 semaines)
Cloudflare Radar – API client/v4

Piliers :
- IQI LATENCY (p25 / p50 / p75) par pays (agg = 1 semaine)
- OUTAGES : événements, filtrés sur la liste de pays d'intérêt

Auteur : Issakha Thiam
Date : Décembre 2025
"""

import pandas as pd
import requests
import logging
import time

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

# Pays d'intérêt : alpha-2 -> alpha-3
COUNTRIES_ALPHA2_TO_ALPHA3 = {
    "AF": "AFG", "AX": "ALA", "AL": "ALB", "DZ": "DZA", "AS": "ASM",
    "AD": "AND", "AO": "AGO", "AI": "AIA", "AQ": "ATA", "AG": "ATG",
    "AR": "ARG", "AM": "ARM", "AW": "ABW", "AU": "AUS", "AT": "AUT",
    "AZ": "AZE", "BS": "BHS", "BH": "BHR", "BD": "BGD", "BB": "BRB",
    "BY": "BLR", "BE": "BEL", "BZ": "BLZ", "BJ": "BEN", "BM": "BMU",
    "BT": "BTN", "BO": "BOL", "BQ": "BES", "BA": "BIH", "BW": "BWA",
    "BV": "BVT", "BR": "BRA", "IO": "IOT", "BN": "BRN", "BG": "BGR",
    "BF": "BFA", "BI": "BDI", "KH": "KHM", "CM": "CMR", "CA": "CAN",
    "CV": "CPV", "KY": "CYM", "CF": "CAF", "TD": "TCD", "CL": "CHL",
    "CN": "CHN", "CX": "CXR", "CC": "CCK", "CO": "COL", "KM": "COM",
    "CG": "COG", "CD": "COD", "CK": "COK", "CR": "CRI", "CI": "CIV",
    "HR": "HRV", "CU": "CUB", "CW": "CUW", "CY": "CYP", "CZ": "CZE",
    "DK": "DNK", "DJ": "DJI", "DM": "DMA", "DO": "DOM", "EC": "ECU",
    "EG": "EGY", "SV": "SLV", "GQ": "GNQ", "ER": "ERI", "EE": "EST",
    "SZ": "SWZ", "ET": "ETH", "FK": "FLK", "FO": "FRO", "FJ": "FJI",
    "FI": "FIN", "FR": "FRA", "GF": "GUF", "PF": "PYF", "TF": "ATF",
    "GA": "GAB", "GM": "GMB", "GE": "GEO", "DE": "DEU", "GH": "GHA",
    "GI": "GIB", "GR": "GRC", "GL": "GRL", "GD": "GRD", "GP": "GLP",
    "GU": "GUM", "GT": "GTM", "GG": "GGY", "GN": "GIN", "GW": "GNB",
    "GY": "GUY", "HT": "HTI", "HM": "HMD", "VA": "VAT", "HN": "HND",
    "HK": "HKG", "HU": "HUN", "IS": "ISL", "IN": "IND", "ID": "IDN",
    "IR": "IRN", "IQ": "IRQ", "IE": "IRL", "IM": "IMN", "IL": "ISR",
    "IT": "ITA", "JM": "JAM", "JP": "JPN", "JE": "JEY", "JO": "JOR",
    "KZ": "KAZ", "KE": "KEN", "KI": "KIR", "KP": "PRK", "KR": "KOR",
    "KW": "KWT", "KG": "KGZ", "LA": "LAO", "LV": "LVA", "LB": "LBN",
    "LS": "LSO", "LR": "LBR", "LY": "LBY", "LI": "LIE", "LT": "LTU",
    "LU": "LUX", "MO": "MAC", "MG": "MDG", "MW": "MWI", "MY": "MYS",
    "MV": "MDV", "ML": "MLI", "MT": "MLT", "MH": "MHL", "MQ": "MTQ",
    "MR": "MRT", "MU": "MUS", "YT": "MYT", "MX": "MEX", "FM": "FSM",
    "MD": "MDA", "MC": "MCO", "MN": "MNG", "ME": "MNE", "MS": "MSR",
    "MA": "MAR", "MZ": "MOZ", "MM": "MMR", "NA": "NAM", "NR": "NRU",
    "NP": "NPL", "NL": "NLD", "NC": "NCL", "NZ": "NZL", "NI": "NIC",
    "NE": "NER", "NG": "NGA", "NU": "NIU", "NF": "NFK", "MK": "MKD",
    "MP": "MNP", "NO": "NOR", "OM": "OMN", "PK": "PAK", "PW": "PLW",
    "PS": "PSE", "PA": "PAN", "PG": "PNG", "PY": "PRY", "PE": "PER",
    "PH": "PHL", "PN": "PCN", "PL": "POL", "PT": "PRT", "PR": "PRI",
    "QA": "QAT", "RE": "REU", "RO": "ROU", "RU": "RUS", "RW": "RWA",
    "BL": "BLM", "SH": "SHN", "KN": "KNA", "LC": "LCA", "MF": "MAF",
    "PM": "SPM", "VC": "VCT", "WS": "WSM", "SM": "SMR", "ST": "STP",
    "SA": "SAU", "SN": "SEN", "RS": "SRB", "SC": "SYC", "SL": "SLE",
    "SG": "SGP", "SX": "SXM", "SK": "SVK", "SI": "SVN", "SB": "SLB",
    "SO": "SOM", "ZA": "ZAF", "GS": "SGS", "SS": "SSD", "ES": "ESP",
    "LK": "LKA", "SD": "SDN", "SR": "SUR", "SJ": "SJM", "SE": "SWE",
    "CH": "CHE", "SY": "SYR", "TW": "TWN", "TJ": "TJK", "TZ": "TZA",
    "TH": "THA", "TL": "TLS", "TG": "TGO", "TK": "TKL", "TO": "TON",
    "TT": "TTO", "TN": "TUN", "TR": "TUR", "TM": "TKM", "TC": "TCA",
    "TV": "TUV", "UG": "UGA", "UA": "UKR", "AE": "ARE", "GB": "GBR",
    "US": "USA", "UM": "UMI", "UY": "URY", "UZ": "UZB", "VU": "VUT",
    "VE": "VEN", "VN": "VNM", "VG": "VGB", "VI": "VIR", "WF": "WLF",
    "EH": "ESH", "YE": "YEM", "ZM": "ZMB", "ZW": "ZWE"
}


COUNTRIES_ALPHA2 = list(COUNTRIES_ALPHA2_TO_ALPHA3.keys())


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


# ==========================
# 📊 IQI – Latence par pays
# ==========================
def fetch_iqi_latency_country(country_alpha2: str) -> pd.DataFrame:
    """
    Récupère la série IQI LATENCY pour un pays (code alpha-2)
    sur 52 semaines, agrégation hebdo (1w).

    Endpoint :
      GET /radar/quality/iqi/timeseries_groups

    Params principaux :
      metric = LATENCY
      aggInterval = 1w
      dateRange = 52w
      location = <code pays alpha-2 (ex: SN, FR)>
    """
    logging.info(f"→ IQI LATENCY pour {country_alpha2}")

    params = {
        "metric": "LATENCY",
        "aggInterval": "1w",
        "dateRange": "52w",
        "format": "JSON",
        "location": country_alpha2,
    }

    js = get_json("quality/iqi/timeseries_groups", params)
    if not js or "result" not in js:
        logging.warning(f"{country_alpha2} → IQI : aucun result")
        return pd.DataFrame()

    result = js["result"]
    serie = result.get("serie_0", {})
    timestamps = serie.get("timestamps", [])
    p25 = serie.get("p25", [])
    p50 = serie.get("p50", [])
    p75 = serie.get("p75", [])

    if not timestamps:
        logging.warning(f"{country_alpha2} → IQI : aucune donnée (timestamps vide)")
        return pd.DataFrame()

    df = pd.DataFrame(
        {
            "date": pd.to_datetime(timestamps),
            "iqi_latency_p25": pd.to_numeric(p25, errors="coerce"),
            "iqi_latency_p50": pd.to_numeric(p50, errors="coerce"),
            "iqi_latency_p75": pd.to_numeric(p75, errors="coerce"),
        }
    )

    df["country_alpha2"] = country_alpha2
    df["country"] = COUNTRIES_ALPHA2_TO_ALPHA3.get(country_alpha2, country_alpha2)
    df["year"] = df["date"].dt.year
    df["month"] = df["date"].dt.month

    return df


def fetch_iqi_latency_all_countries() -> pd.DataFrame:
    """Boucle sur la liste COUNTRIES_ALPHA2 et concatène toutes les séries IQI."""
    all_dfs = []
    for c2 in COUNTRIES_ALPHA2:
        df_c = fetch_iqi_latency_country(c2)
        if not df_c.empty:
            all_dfs.append(df_c)

    if not all_dfs:
        logging.error("❌ IQI : aucune donnée pour aucun pays.")
        return pd.DataFrame()

    df_all = pd.concat(all_dfs, ignore_index=True)
    logging.info(f"✅ IQI LATENCY – total {len(df_all)} lignes pour {df_all['country'].nunique()} pays")
    return df_all


# ==========================
# ⚡ Outages – événements
# ==========================
def fetch_outages_events_global() -> pd.DataFrame:
    """
    Récupère tous les outages sur 52 semaines (global),
    puis renvoie un DataFrame brut (JSON → tabulaire).

    Endpoint :
      GET /radar/annotations/outages?dateRange=52w&format=json
    """
    logging.info("→ Récupération des outages globaux (52w)")

    params = {
        "dateRange": "52w",
        "format": "json",
    }

    js = get_json("annotations/outages", params)
    if not js or "result" not in js:
        logging.error("❌ Outages : aucun result")
        return pd.DataFrame()

    result = js["result"]
    annotations = result.get("annotations", [])
    if not annotations:
        logging.warning("Outages : liste annotations vide")
        return pd.DataFrame()

    # Chaque élément est un dict ; on convertit en DataFrame "large"
    df = pd.json_normalize(annotations)

    # Nettoyage de quelques colonnes de temps si présentes
    for col in ["startDate", "endDate", "start_time", "end_time"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")

    logging.info(f"✅ Outages globaux : {len(df)} événements bruts")
    return df


def filter_outages_by_countries(df_out_global: pd.DataFrame) -> pd.DataFrame:
    """
    À partir du DataFrame global, sélectionne uniquement
    les outages qui touchent au moins un des pays d'intérêt.

    Colonnes typiques utiles :
      - locations (liste de codes alpha-2, ex: ['US', 'FR'])
      - outage.outageCause
      - outage.outageType
      - scope, eventType, linkedUrl, etc.
    """
    if df_out_global.empty:
        logging.warning("Outages globaux vides → rien à filtrer.")
        return df_out_global

    # On s'assure que la colonne 'locations' existe et est une liste
    if "locations" not in df_out_global.columns:
        logging.warning("Outages : pas de colonne 'locations' → filtrage impossible.")
        return pd.DataFrame()

    # On va "exploser" les locations pour avoir une ligne par (outage, location)
    df = df_out_global.copy()

    # Si locations est du JSON string, on pourrait faire un ast.literal_eval,
    # mais normalement json_normalize le convertit déjà en liste Python.
    df = df.explode("locations")
    df.rename(columns={"locations": "country_alpha2"}, inplace=True)

    # Filtrer uniquement nos pays d'intérêt (SN, MA, etc.)
    df = df[df["country_alpha2"].isin(COUNTRIES_ALPHA2)].copy()
    if df.empty:
        logging.warning("Outages : aucun événement concernant les pays d'intérêt.")
        return df

    # Ajouter le code ISO3
    df["country"] = df["country_alpha2"].map(COUNTRIES_ALPHA2_TO_ALPHA3)

    # Colonnes utiles (on garde large, tu pourras réduire ensuite)
    colonnes_interessantes = [
        "country_alpha2",
        "country",
        "startDate" if "startDate" in df.columns else None,
        "endDate" if "endDate" in df.columns else None,
        "scope" if "scope" in df.columns else None,
        "eventType" if "eventType" in df.columns else None,
        "outage.outageCause" if "outage.outageCause" in df.columns else None,
        "outage.outageType" if "outage.outageType" in df.columns else None,
        "linkedUrl" if "linkedUrl" in df.columns else None,
    ]
    # On enlève les None
    colonnes_interessantes = [c for c in colonnes_interessantes if c is not None]

    df = df[colonnes_interessantes]

    logging.info(f"✅ Outages filtrés : {len(df)} lignes pour {df['country'].nunique()} pays")
    return df


# ==========================
# 💾 MAIN
# ==========================
if __name__ == "__main__":
    t0 = time.time()
    logging.info("🌍 Version STABLE – IQI LATENCY + OUTAGES, par pays (52w)")

    # 1) IQI LATENCY par pays
    df_iqi = fetch_iqi_latency_all_countries()

    # 2) Outages globaux puis filtrés
    df_out_global = fetch_outages_events_global()
    df_out_countries = filter_outages_by_countries(df_out_global)

    # 3) Exports
    if not df_iqi.empty:
        df_iqi.to_csv("radar_iqi_latency_by_country_52w.csv", index=False)
        logging.info("💾 Export IQI → radar_iqi_latency_by_country_52w.csv")

    if not df_out_countries.empty:
        df_out_countries.to_csv("radar_outages_events_by_country_52w.csv", index=False)
        logging.info("💾 Export Outages → radar_outages_events_by_country_52w.csv")

    logging.info(f"⏱ Temps total : {time.time() - t0:.1f}s")
