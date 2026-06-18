# radar_piliers_download_excel.py
# -*- coding: utf-8 -*-
"""
Téléchargement automatique des 7 piliers Cloudflare Radar + export Excel.

Piliers :
1) HTTP – IP version (IPv4/IPv6)
2) HTTP – TLS version (TLS 1.2 / 1.3)
3) HTTP – protocoles HTTP (HTTP/1.x, 2, 3)
4) Attaques L3 – par version IP
5) DNS – volume de requêtes 1.1.1.1
6) BGP – mises à jour de routage
7) Outages – pannes Internet globales

Fonctionnalités :
- Appels à l’API Radar v4
- Téléchargement en parallèle (ThreadPoolExecutor)
- Requêtes robustes (retries exponentiels)
- Sauvegarde des réponses brutes en JSON
- Conversion en DataFrame
- Fichier Excel unique avec 1 onglet par pilier

Usage simple :
    python radar_piliers_download_excel.py --output-dir data_radar --date-range 30d

Auteur : ChatGPT (adapté pour Issakha)
"""

import os
import json
import time
import logging
import argparse
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import pandas as pd

# ==============================
# CONFIG GLOBALE
# ==============================

BASE_URL = "https://api.cloudflare.com/client/v4"

# Mapping des 7 piliers -> endpoints Radar
PILIERS_CONFIG: Dict[str, Dict[str, Any]] = {
    "http_ip_version": {
        "label": "HTTP – IP version (IPv4/IPv6)",
        "endpoint": "/radar/http/timeseries/ip_version",
        "default_params": {
            "dateRange": "30d",     # ou utiliser dateStart/dateEnd
            "aggInterval": "1d",    # 15m, 1h, 1d...
            "location": "WORLD",    # WORLD ou code pays (FR, US, SN...)
        },
    },
    "http_tls_version": {
        "label": "HTTP – TLS version (TLS 1.2 / 1.3)",
        "endpoint": "/radar/http/timeseries/tls_version",
        "default_params": {
            "dateRange": "30d",
            "aggInterval": "1d",
            "location": "WORLD",
        },
    },
    "http_protocol": {
        "label": "HTTP – protocoles HTTP (HTTP/1.x, 2, 3)",
        # Variante possible : /radar/http/timeseries/http_version
        "endpoint": "/radar/http/timeseries/http_protocol",
        "default_params": {
            "dateRange": "30d",
            "aggInterval": "1d",
            "location": "WORLD",
        },
    },
    "attacks_l3_ip_version": {
        "label": "Attaques L3 – par version IP",
        # Endpoint "timeseries_groups" groupé par dimension ip_version
        "endpoint": "/radar/attacks/layer3/timeseries_groups/ip_version",
        "default_params": {
            "dateRange": "30d",
            "aggInterval": "1d",
            "location": "WORLD",
        },
    },
    "dns_1_1_1_1": {
        "label": "DNS – volume de requêtes 1.1.1.1",
        "endpoint": "/radar/dns/timeseries",
        "default_params": {
            "dateRange": "30d",
            "aggInterval": "1d",
            "location": "WORLD",
        },
    },
    "bgp_updates": {
        "label": "BGP – mises à jour de routage",
        "endpoint": "/radar/bgp/timeseries",
        "default_params": {
            "dateRange": "30d",
            "aggInterval": "1d",
        },
    },
    "outages": {
        "label": "Outages – pannes Internet globales",
        "endpoint": "/radar/annotations/outages",
        "default_params": {
            "dateRange": "30d",
            "location": "WORLD",
        },
    },
}


# ==============================
# LOGGING
# ==============================

logger = logging.getLogger("radar_piliers")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)


# ==============================
# FONCTIONS UTILITAIRES
# ==============================

def get_auth_headers() -> Dict[str, str]:
    """Construit les headers d’authentification à partir de CLOUDFLARE_API_TOKEN."""
    token = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn"
    if not token:
        raise RuntimeError(
            "La variable d’environnement CLOUDFLARE_API_TOKEN n’est pas définie.\n"
            "Crée un token Radar dans ton compte Cloudflare puis fais :\n"
            "  export CLOUDFLARE_API_TOKEN=\"...\"  (Linux/macOS)\n"
            "  $env:CLOUDFLARE_API_TOKEN=\"...\"    (PowerShell)\n"
        )
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def robust_get(
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, Any]] = None,
    max_retries: int = 5,
    backoff_factor: float = 1.5,
) -> Dict[str, Any]:
    """
    Requête GET robuste avec retries exponentiels.
    Retourne le JSON décodé (client v4 -> champs success, result, errors...).
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=60)
        except requests.RequestException as e:
            if attempt >= max_retries:
                raise RuntimeError(f"Échec de la requête après {max_retries} essais: {e}")
            sleep_time = backoff_factor ** attempt
            logger.warning(f"Erreur réseau ({e}), retry #{attempt} dans {sleep_time:.1f}s...")
            time.sleep(sleep_time)
            continue

        if resp.status_code >= 500:
            if attempt >= max_retries:
                raise RuntimeError(
                    f"Status {resp.status_code} après {max_retries} essais pour {url}: {resp.text[:500]}"
                )
            sleep_time = backoff_factor ** attempt
            logger.warning(
                f"Erreur serveur {resp.status_code} pour {url}, retry #{attempt} dans {sleep_time:.1f}s..."
            )
            time.sleep(sleep_time)
            continue

        if resp.status_code >= 400:
            raise RuntimeError(
                f"Erreur {resp.status_code} pour {url} (params={params}): {resp.text[:500]}"
            )

        try:
            data = resp.json()
        except ValueError:
            raise RuntimeError(f"Réponse non-JSON de l’API pour {url}: {resp.text[:200]}")

        if isinstance(data, dict) and data.get("success") is False:
            raise RuntimeError(f"API Radar a renvoyé success=false pour {url}: {data}")

        return data


def save_json(data: Any, filepath: str) -> None:
    """Sauvegarde un objet Python en JSON, encodage UTF-8."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def build_params(
    defaults: Dict[str, Any],
    date_range: Optional[str],
    date_start: Optional[str],
    date_end: Optional[str],
    agg_interval: Optional[str],
    location: Optional[str],
) -> Dict[str, Any]:
    """
    Construit les paramètres finaux pour un pilier en prenant :
    - defaults du pilier
    - puis overrides globaux (dateRange ou dateStart/dateEnd, aggInterval, location)
    """
    params = dict(defaults)

    if date_range:
        params["dateRange"] = date_range
        params.pop("dateStart", None)
        params.pop("dateEnd", None)
    else:
        if date_start:
            params["dateStart"] = date_start
        if date_end:
            params["dateEnd"] = date_end

    if agg_interval:
        params["aggInterval"] = agg_interval

    if location:
        params["location"] = location

    return params


# ==============================
# CONVERSION JSON -> DATAFRAME
# ==============================

def convert_radar_response_to_df(pilier_key: str, data: Dict[str, Any]) -> pd.DataFrame:
    """
    Essaie de convertir la réponse Radar en DataFrame.
    On gère explicitement le cas fréquent :
        result -> series[] -> {dimensions{}, data[]}
    Puis fallback sur un json_normalize générique.
    """
    # La structure Radar est souvent : { success: true, result: {...} }
    result = data.get("result", data)

    # Cas "series" (time series multiples par dimension)
    if isinstance(result, dict) and isinstance(result.get("series"), list):
        rows: List[Dict[str, Any]] = []
        for series in result["series"]:
            dims = series.get("dimensions", {}) or {}
            for point in series.get("data", []):
                row = {}
                row.update(dims)
                row.update(point)
                rows.append(row)
        if rows:
            return pd.DataFrame(rows)

    # Cas "timeseries" direct
    if isinstance(result, dict) and isinstance(result.get("timeseries"), list):
        return pd.json_normalize(result["timeseries"], sep=".")

    # Si result est déjà une liste d’objets simples (ex: outages)
    if isinstance(result, list):
        return pd.json_normalize(result, sep=".")

    # Sinon : fallback sur le dict complet
    return pd.json_normalize(result, sep=".")


def download_pilier(
    pilier_key: str,
    pilier_cfg: Dict[str, Any],
    headers: Dict[str, str],
    base_output_dir: str,
    date_range: Optional[str],
    date_start: Optional[str],
    date_end: Optional[str],
    agg_interval: Optional[str],
    location: Optional[str],
) -> Dict[str, Any]:
    """
    Télécharge un pilier, sauvegarde le JSON, retourne un dict avec :
        {
            "key": pilier_key,
            "label": "...",
            "json_path": "...",
            "data": <dict JSON>,
            "error": None ou str
        }
    """
    label = pilier_cfg["label"]
    endpoint = pilier_cfg["endpoint"]
    defaults = pilier_cfg.get("default_params", {})

    params = build_params(
        defaults,
        date_range=date_range,
        date_start=date_start,
        date_end=date_end,
        agg_interval=agg_interval,
        location=location,
    )

    url = BASE_URL + endpoint
    logger.info(f"[{pilier_key}] Appel API → {url} avec params={params}")

    out: Dict[str, Any] = {
        "key": pilier_key,
        "label": label,
        "json_path": None,
        "data": None,
        "error": None,
    }

    try:
        data = robust_get(url, headers=headers, params=params)

        # Sauvegarde JSON brut
        json_path = os.path.join(base_output_dir, f"{pilier_key}.json")
        save_json(data, json_path)

        out["json_path"] = json_path
        out["data"] = data
        logger.info(f"[{pilier_key}] Sauvegardé (JSON) → {json_path}")
    except Exception as e:
        err = f"Échec du téléchargement : {e}"
        logger.error(f"[{pilier_key}] {err}")
        out["error"] = err

    return out


# ==============================
# MAIN
# ==============================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Télécharge les 7 piliers Cloudflare Radar et les exporte en Excel."
    )

    parser.add_argument(
        "--output-dir",
        "-o",
        default="radar_piliers_data",
        help="Répertoire de sortie pour les fichiers JSON/Excel (défaut : radar_piliers_data)",
    )

    parser.add_argument(
        "--date-range",
        help='Fenêtre relative, ex: "7d", "30d". Si fourni, écrase dateStart/dateEnd.',
    )
    parser.add_argument(
        "--date-start",
        help='Date de début (YYYY-MM-DD). Utilisée si dateRange n’est pas fourni.',
    )
    parser.add_argument(
        "--date-end",
        help='Date de fin (YYYY-MM-DD). Utilisée si dateRange n’est pas fourni.',
    )
    parser.add_argument(
        "--agg-interval",
        default=None,
        help='Intervalle d’agrégation, ex: "15m", "1h", "1d". Écrase les valeurs par défaut des piliers.',
    )
    parser.add_argument(
        "--location",
        default=None,
        help='Code de localisation Radar, ex: "WORLD", "FR", "US", "SN"...',
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=7,
        help="Nombre maximum de threads pour le téléchargement parallèle (défaut : 7).",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    headers = get_auth_headers()

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    logger.info("=== DÉMARRAGE TÉLÉCHARGEMENT DES 7 PILIERS RADAR ===")
    logger.info(f"Répertoire de sortie : {output_dir}")

    results: Dict[str, Dict[str, Any]] = {}

    # Téléchargement en parallèle
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = {
            executor.submit(
                download_pilier,
                pilier_key=key,
                pilier_cfg=cfg,
                headers=headers,
                base_output_dir=output_dir,
                date_range=args.date_range,
                date_start=args.date_start,
                date_end=args.date_end,
                agg_interval=args.agg_interval,
                location=args.location,
            ): key
            for key, cfg in PILIERS_CONFIG.items()
        }

        for fut in as_completed(futures):
            key = futures[fut]
            try:
                res = fut.result()
                results[key] = res
            except Exception as e:
                logger.error(f"[{key}] Exception inattendue : {e}")
                results[key] = {"key": key, "label": PILIERS_CONFIG[key]["label"], "data": None, "error": str(e)}

    # Construction de l’Excel global
    excel_path = os.path.join(output_dir, "radar_piliers.xlsx")
    logger.info(f"=== CONSTRUCTION DU FICHIER EXCEL : {excel_path} ===")

    with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
        for key, res in results.items():
            label = res.get("label", key)
            data = res.get("data")
            error = res.get("error")

            sheet_name = key[:31]  # Limite Excel pour les noms d’onglets

            if error or data is None:
                # On crée au moins un onglet avec le message d’erreur
                df_err = pd.DataFrame(
                    [{"pilier": key, "label": label, "error": error or "Aucune donnée"}]
                )
                df_err.to_excel(writer, sheet_name=sheet_name, index=False)
                continue

            try:
                df = convert_radar_response_to_df(key, data)
                if df.empty:
                    df = pd.DataFrame(
                        [{"info": "Réponse vide ou non interprétable", "pilier": key, "label": label}]
                    )
            except Exception as e:
                logger.error(f"[{key}] Erreur lors de la conversion en DataFrame : {e}")
                df = pd.DataFrame(
                    [{"pilier": key, "label": label, "error": f"Conversion en DataFrame impossible: {e}"}]
                )

            df.to_excel(writer, sheet_name=sheet_name, index=False)
            logger.info(f"[{key}] Onglet Excel écrit ({sheet_name}), lignes={len(df)}")

    logger.info("=== TÉLÉCHARGEMENT + EXPORT EXCEL TERMINÉS ===")
    logger.info(f"Fichier Excel principal : {excel_path}")

    # Petit récap console
    for key, res in results.items():
        logger.info(f"{key}: error={res.get('error')}, json={res.get('json_path')}")


if __name__ == "__main__":
    main()
