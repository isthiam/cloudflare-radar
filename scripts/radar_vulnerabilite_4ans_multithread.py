# -*- coding: utf-8 -*-
"""
Extraction mondiale (≈200 pays) des indicateurs Cloudflare Radar 2021–2025,
version robuste avec authentification par token et gestion d'erreurs améliorée.
Auteur : Issakha Thiam
Date : Octobre 2025
"""

import pandas as pd
import requests
import time
import logging
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import json
from typing import Optional, Dict, List
import backoff

# ======================
# 1️⃣ CONFIGURATION
# ======================
# Token Cloudflare Radar API (à configurer)
CF_API_TOKEN = "votre_token_ici"  # Remplacez par votre token réel

START_DATE = "2021-01-01"
END_DATE = "2025-10-01"

# Liste complète des pays
COUNTRIES = [
    "AFG", "AGO", "ALB", "DZA", "AND", "ARE", "ARG", "ARM", "AUS", "AUT", "AZE",
    "BDI", "BEL", "BEN", "BFA", "BGD", "BGR", "BHR", "BHS", "BIH", "BLR", "BLZ",
    "BOL", "BRA", "BRN", "BTN", "BWA", "CAF", "CAN", "CHE", "CHL", "CHN", "CIV",
    "CMR", "COD", "COG", "COL", "COM", "CPV", "CRI", "CUB", "CYP", "CZE", "DEU",
    "DJI", "DNK", "DOM", "DZA", "ECU", "EGY", "ERI", "ESP", "EST", "ETH", "FIN",
    "FJI", "FRA", "GAB", "GBR", "GEO", "GHA", "GIN", "GMB", "GNB", "GNQ", "GRC",
    "GRD", "GTM", "GUY", "HND", "HRV", "HTI", "HUN", "IDN", "IND", "IRL", "IRN",
    "IRQ", "ISL", "ISR", "ITA", "JAM", "JOR", "JPN", "KAZ", "KEN", "KGZ", "KHM",
    "KOR", "KWT", "LAO", "LBN", "LBR", "LBY", "LIE", "LKA", "LSO", "LTU", "LUX",
    "LVA", "MAR", "MDA", "MDG", "MDV", "MEX", "MKD", "MLI", "MLT", "MMR", "MNE",
    "MNG", "MOZ", "MRT", "MUS", "MWI", "MYS", "NAM", "NER", "NGA", "NIC", "NLD",
    "NOR", "NPL", "NZL", "OMN", "PAK", "PAN", "PER", "PHL", "PNG", "POL", "PRT",
    "PRY", "QAT", "ROU", "RUS", "RWA", "SAU", "SDN", "SEN", "SGP", "SLB", "SLE",
    "SLV", "SMR", "SOM", "SRB", "STP", "SUR", "SVK", "SVN", "SWE", "SWZ", "SYC",
    "SYR", "TCD", "TGO", "THA", "TJK", "TKM", "TLS", "TON", "TTO", "TUN", "TUR",
    "TWN", "TZA", "UGA", "UKR", "URY", "USA", "UZB", "VAT", "VEN", "VNM", "YEM",
    "ZAF", "ZMB", "ZWE"
]

# Configuration des threads
THREADS = 4
BASE_URL = "https://api.cloudflare.com/client/v4/radar"
REQUEST_TIMEOUT = 45
MAX_RETRIES = 3

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"radar_extraction_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)

# ======================
# 2️⃣ CLASSES UTILITAIRES
# ======================
class RateLimiter:
    """Simple rate limiter pour éviter les requêtes trop fréquentes"""
    def __init__(self, calls_per_second=2):
        self.calls_per_second = calls_per_second
        self.last_call = 0
        
    def wait_if_needed(self):
        elapsed = time.time() - self.last_call
        if elapsed < 1.0 / self.calls_per_second:
            time.sleep(1.0 / self.calls_per_second - elapsed)
        self.last_call = time.time()

class APIClient:
    """Client API avec gestion du token et des erreurs"""
    
    def __init__(self, token: str):
        self.token = token
        self.rate_limiter = RateLimiter(calls_per_second=2)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        })
    
    @backoff.on_exception(
        backoff.expo,
        (requests.exceptions.RequestException, requests.exceptions.Timeout),
        max_tries=MAX_RETRIES
    )
    def get(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Effectue une requête GET avec gestion des erreurs et retry"""
        self.rate_limiter.wait_if_needed()
        
        url = f"{BASE_URL}/{endpoint.lstrip('/')}"
        
        try:
            response = self.session.get(
                url,
                params=params,
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success", True):
                    return data
                else:
                    logging.warning(f"API error: {data.get('errors', 'Unknown error')}")
                    return None
            elif response.status_code == 429:
                logging.warning("Rate limit atteint, pause de 60 secondes...")
                time.sleep(60)
                return None
            elif response.status_code == 401:
                logging.error("Token d'authentification invalide ou expiré")
                return None
            else:
                logging.warning(f"HTTP {response.status_code} pour {endpoint}")
                return None
                
        except requests.exceptions.Timeout:
            logging.warning(f"Timeout pour {endpoint}")
            return None
        except requests.exceptions.RequestException as e:
            logging.warning(f"Erreur réseau pour {endpoint}: {e}")
            return None
        except json.JSONDecodeError:
            logging.warning(f"Réponse JSON invalide pour {endpoint}")
            return None

# Initialisation du client API
api_client = APIClient(CF_API_TOKEN)

# ======================
# 3️⃣ FONCTIONS D'EXTRACTION
# ======================
def extract_timeseries(endpoint: str, country: str, value_fields: List[str]) -> pd.DataFrame:
    """
    Extrait les séries temporelles pour un pays et un endpoint donnés
    """
    params = {
        "country": country,
        "dateStart": START_DATE,
        "dateEnd": END_DATE,
        "format": "json"
    }
    
    data = api_client.get(endpoint, params)
    
    if not data or "result" not in data:
        return pd.DataFrame()
    
    result = data["result"]
    
    # Structure des données peut varier selon l'endpoint
    if "timeseries" in result:
        timeseries = result["timeseries"]
    elif "data" in result:
        timeseries = result["data"]
    else:
        return pd.DataFrame()
    
    if not timeseries:
        return pd.DataFrame()
    
    # Convertir en DataFrame
    records = []
    for point in timeseries:
        record = {"date": point.get("date"), "country": country}
        for field in value_fields:
            if field in point:
                record[field] = point[field]
        records.append(record)
    
    df = pd.DataFrame(records)
    if not df.empty:
        df["date"] = pd.to_datetime(df["date"])
    
    return df

def extract_country_data(country: str) -> pd.DataFrame:
    """
    Extrait toutes les données pour un pays spécifique
    """
    logging.info(f"Extraction pour {country}")
    
    dataframes = []
    
    try:
        # 1. Latence (quality index)
        df_latency = extract_timeseries(
            "http/summary/ip_version",
            country,
            ["p25", "p50", "p75"]
        )
        if not df_latency.empty:
            df_latency = df_latency.rename(columns={
                "p25": "latency_p25",
                "p50": "latency_p50", 
                "p75": "latency_p75"
            })
            dataframes.append(df_latency)
        
        # 2. Adoption IPv6
        df_ipv6 = extract_timeseries(
            "http/summary/ip_version",
            country, 
            ["ipv6_percentage"]
        )
        if not df_ipv6.empty:
            df_ipv6 = df_ipv6.rename(columns={"ipv6_percentage": "ipv6_share"})
            dataframes.append(df_ipv6)
        
        # 3. TLS 1.3
        df_tls = extract_timeseries(
            "http/summary/tls_version",
            country,
            ["tls_13_percentage"]
        )
        if not df_tls.empty:
            df_tls = df_tls.rename(columns={"tls_13_percentage": "tls13_share"})
            dataframes.append(df_tls)
        
        # 4. Attaques DDoS
        df_attacks = extract_timeseries(
            "attacks/layer3/summary",
            country,
            ["total", "avg_bps"]
        )
        if not df_attacks.empty:
            df_attacks = df_attacks.rename(columns={
                "total": "attack_count",
                "avg_bps": "attack_avg_bps"
            })
            dataframes.append(df_attacks)
        
        if not dataframes:
            logging.warning(f"Aucune donnée pour {country}")
            return pd.DataFrame()
        
        # Fusionner tous les DataFrames
        df_merged = dataframes[0]
        for df in dataframes[1:]:
            if not df.empty:
                df_merged = pd.merge(
                    df_merged, 
                    df, 
                    on=["date", "country"], 
                    how="outer",
                    suffixes=('', '_drop')
                )
                # Supprimer les colonnes dupliquées
                df_merged = df_merged.loc[:, ~df_merged.columns.str.endswith('_drop')]
        
        # Calcul des indices
        df_merged = calculate_indices(df_merged)
        
        return df_merged
        
    except Exception as e:
        logging.error(f"Erreur lors de l'extraction pour {country}: {str(e)}")
        return pd.DataFrame()

def calculate_indices(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calcule les indices de vulnérabilité
    """
    if df.empty:
        return df
    
    # S'assurer que les colonnes existent
    for col in ["latency_p75", "ipv6_share", "tls13_share", "attack_count"]:
        if col not in df.columns:
            df[col] = np.nan
    
    # Extraire les composantes temporelles
    df["year"] = df["date"].dt.year
    df["month"] = df["date"].dt.month
    df["day"] = df["date"].dt.day
    
    # Calculer les z-scores par date (globalement)
    shock_components = ["latency_p75", "attack_count"]
    exposure_components = ["ipv6_share", "tls13_share"]
    
    for col in shock_components + exposure_components:
        if col in df.columns:
            # Normalisation Min-Max au lieu de z-score pour éviter les problèmes avec std=0
            df[f"{col}_norm"] = (df[col] - df[col].min()) / (df[col].max() - df[col].min() + 1e-10)
    
    # Calcul des indices (inverser pour ipv6 et tls - plus c'est haut, mieux c'est)
    if "latency_p75_norm" in df.columns and "attack_count_norm" in df.columns:
        df["shock_index"] = (df["latency_p75_norm"] + df["attack_count_norm"]) / 2
    
    if "ipv6_share_norm" in df.columns and "tls13_share_norm" in df.columns:
        df["exposure_index"] = ((1 - df["ipv6_share_norm"]) + (1 - df["tls13_share_norm"])) / 2
    
    if "shock_index" in df.columns and "exposure_index" in df.columns:
        df["vulnerability_score"] = 0.6 * df["shock_index"] + 0.4 * df["exposure_index"]
    
    # Classement par vulnérabilité
    if "vulnerability_score" in df.columns:
        df["vulnerability_rank"] = df["vulnerability_score"].rank(ascending=False)
    
    return df

# ======================
# 4️⃣ PIPELINE PRINCIPALE
# ======================
def run_extraction() -> tuple:
    """
    Exécute l'extraction complète pour tous les pays
    """
    all_data = []
    failed_countries = []
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_country = {
            executor.submit(extract_country_data, country): country 
            for country in COUNTRIES
        }
        
        for future in as_completed(future_to_country):
            country = future_to_country[future]
            try:
                df = future.result(timeout=60)
                if not df.empty:
                    all_data.append(df)
                    logging.info(f"✓ {country}: {len(df)} enregistrements extraits")
                else:
                    failed_countries.append(country)
                    logging.warning(f"✗ {country}: Aucune donnée")
            except Exception as e:
                failed_countries.append(country)
                logging.error(f"✗ {country}: Erreur - {str(e)}")
    
    if not all_data:
        logging.error("Aucune donnée n'a pu être extraite")
        return None, None, None, failed_countries
    
    # Concaténer toutes les données
    df_all = pd.concat(all_data, ignore_index=True)
    
    # Créer les agrégations temporelles
    df_daily = df_all.copy()
    
    df_monthly = df_all.copy()
    df_monthly["month_period"] = df_monthly["date"].dt.to_period("M")
    df_monthly = df_monthly.groupby(["country", "month_period"]).mean(numeric_only=True).reset_index()
    
    df_yearly = df_all.copy()
    df_yearly["year_period"] = df_yearly["date"].dt.year
    df_yearly = df_yearly.groupby(["country", "year_period"]).mean(numeric_only=True).reset_index()
    
    logging.info(f"Extraction terminée: {len(all_data)} pays réussis, {len(failed_countries)} échecs")
    
    return df_daily, df_monthly, df_yearly, failed_countries

# ======================
# 5️⃣ SAUVEGARDE DES DONNÉES
# ======================
def save_results(df_daily: pd.DataFrame, df_monthly: pd.DataFrame, 
                 df_yearly: pd.DataFrame, failed_countries: list):
    """
    Sauvegarde les résultats dans des fichiers CSV
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Sauvegarder les données
    if df_daily is not None and not df_daily.empty:
        df_daily.to_csv(f"radar_global_daily_{timestamp}.csv", index=False)
        logging.info(f"Données quotidiennes sauvegardées: radar_global_daily_{timestamp}.csv")
    
    if df_monthly is not None and not df_monthly.empty:
        df_monthly.to_csv(f"radar_global_monthly_{timestamp}.csv", index=False)
        logging.info(f"Données mensuelles sauvegardées: radar_global_monthly_{timestamp}.csv")
    
    if df_yearly is not None and not df_yearly.empty:
        df_yearly.to_csv(f"radar_global_yearly_{timestamp}.csv", index=False)
        logging.info(f"Données annuelles sauvegardées: radar_global_yearly_{timestamp}.csv")
    
    # Sauvegarder la liste des échecs
    if failed_countries:
        with open(f"failed_countries_{timestamp}.txt", "w") as f:
            f.write("\n".join(failed_countries))
        logging.info(f"Liste des échecs sauvegardée: failed_countries_{timestamp}.txt")
    
    # Générer un rapport sommaire
    report = {
        "timestamp": timestamp,
        "total_countries": len(COUNTRIES),
        "successful": len(COUNTRIES) - len(failed_countries),
        "failed": len(failed_countries),
        "failed_list": failed_countries,
        "date_range": f"{START_DATE} to {END_DATE}"
    }
    
    with open(f"extraction_report_{timestamp}.json", "w") as f:
        json.dump(report, f, indent=2)
    
    return report

# ======================
# 6️⃣ FONCTION PRINCIPALE
# ======================
def main():
    """
    Fonction principale d'exécution
    """
    start_time = time.time()
    
    logging.info("=" * 60)
    logging.info("DÉMARRAGE DE L'EXTRACTION CLOUDFLARE RADAR")
    logging.info(f"Période: {START_DATE} - {END_DATE}")
    logging.info(f"Nombre de pays: {len(COUNTRIES)}")
    logging.info("=" * 60)
    
    # Vérifier le token
    if CF_API_TOKEN == "votre_token_ici":
        logging.error("ERREUR: Vous devez configurer votre token API Cloudflare")
        logging.error("Remplacez 'votre_token_ici' par votre token réel")
        return
    
    # Tester la connexion API
    logging.info("Test de connexion à l'API Cloudflare...")
    test_data = api_client.get("http/summary/ip_version", {"country": "FRA", "dateStart": "2024-01-01", "dateEnd": "2024-01-02"})
    
    if test_data is None:
        logging.error("Échec de la connexion à l'API. Vérifiez votre token.")
        return
    
    logging.info("Connexion API réussie ✓")
    
    # Exécuter l'extraction
    df_daily, df_monthly, df_yearly, failed = run_extraction()
    
    # Sauvegarder les résultats
    if df_daily is not None:
        report = save_results(df_daily, df_monthly, df_yearly, failed)
        
        # Afficher le rapport
        logging.info("\n" + "=" * 60)
        logging.info("RAPPORT D'EXTRACTION")
        logging.info("=" * 60)
        logging.info(f"Pays traités avec succès: {report['successful']}")
        logging.info(f"Pays en échec: {report['failed']}")
        logging.info(f"Temps d'exécution: {time.time() - start_time:.2f} secondes")
        
        if report['failed'] > 0:
            logging.info(f"Pays en échec: {', '.join(report['failed_list'])}")
    
    logging.info("Extraction terminée!")

# ======================
# 7️⃣ POINT D'ENTRÉE
# ======================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Extraction interrompue par l'utilisateur")
    except Exception as e:
        logging.error(f"Erreur inattendue: {str(e)}")
        import traceback
        traceback.print_exc()