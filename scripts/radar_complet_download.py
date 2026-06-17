# -*- coding: utf-8 -*-
"""
radar_complet_download.py
Téléchargement COMPLET de toutes les données Cloudflare Radar disponibles.

Catégories couvertes :
  A. HTTP par pays (timeseries_groups, 52w, aggInterval=1d)
       ip_version, tls_version, http_version, device_type, bot_class, os, browser_family
  B. Attaques L7 globales (12w, aggInterval=1d)  — max validé : >12w → 400
       par vertical, méthode HTTP, version HTTP
  C. Attaques L3 par pays (52w) - dimensions manquantes
       par protocole (TCP/UDP/ICMP/GRE)
  D. IQI par pays (52w, 1w) - métriques manquantes
       bande passante (BANDWIDTH), temps réponse DNS (DNS)
  E. BGP global (208w)
       timeseries, événements hijacks, événements leaks
  F. Email Security global (208w)
       DMARC, DKIM, SPF, malicious, spam
  G. DNS global (208w)
       timeseries 1.1.1.1

Sortie : dossier outputs_complet/ avec un CSV par catégorie

Auteur  : Issakha Thiam
Créé    : Juin 2026
"""

import asyncio
import json
import logging
import sys
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

API_TOKEN = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn"
BASE_URL = "https://api.cloudflare.com/client/v4"

DATE_RANGE_GLOBAL = "52w"     # 1 an – validé pour L3/BGP/Email/DNS avec aggInterval=1w
DATE_RANGE_L7 = "12w"         # Max validé pour L7 attacks avec aggInterval=1d (>12w → 400)
DATE_RANGE_HTTP_COUNTRY = "52w"  # Max validé pour HTTP timeseries_groups + location (aggInterval=1w)
DATE_RANGE_COUNTRY = "52w"   # 1 an  – IQI, outages par pays
AGG_DAY = "1d"
AGG_WEEK = "1w"

OUTPUT_DIR = Path("outputs_complet")

MAX_CALLS_PER_MIN = 100       # limite prudente (API Radar : ~120/min)
REQUEST_CONCURRENCY = 12
COUNTRY_CONCURRENCY = 10
MAX_RETRIES = 4

TIMEOUT = httpx.Timeout(connect=20.0, read=60.0, write=20.0, pool=60.0)
LIMITS  = httpx.Limits(max_connections=25, max_keepalive_connections=12)

# ─────────────────────────────────────────────────────────────────────────────
# Rate Limiter
# ─────────────────────────────────────────────────────────────────────────────

class AsyncRateLimiter:
    def __init__(self, max_calls: int, period: float = 60.0):
        self.max_calls = max_calls
        self.period = period
        self.calls: deque = deque()
        self._lock = asyncio.Lock()

    async def acquire(self):
        while True:
            async with self._lock:
                now = asyncio.get_running_loop().time()
                while self.calls and now - self.calls[0] > self.period:
                    self.calls.popleft()
                if len(self.calls) < self.max_calls:
                    self.calls.append(now)
                    return
                wait = self.period - (now - self.calls[0])
            await asyncio.sleep(max(wait, 0.05))

# ─────────────────────────────────────────────────────────────────────────────
# Generic API call
# ─────────────────────────────────────────────────────────────────────────────

async def api_get(
    client: httpx.AsyncClient,
    path: str,
    params: Dict[str, Any],
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
) -> Optional[Dict[str, Any]]:
    url = f"{BASE_URL}{path}"
    for attempt in range(1, MAX_RETRIES + 1):
        await rl.acquire()
        async with sem:
            try:
                resp = await client.get(url, params=params)
                if resp.status_code == 404:
                    logging.debug(f"404: {path}")
                    return None
                if resp.status_code in (429, 500, 502, 503, 504):
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(min(2 ** attempt, 16))
                        continue
                resp.raise_for_status()
                data = resp.json()
                if not data.get("success", True):
                    logging.debug(f"success=false: {path} {params}")
                    return None
                return data
            except Exception as e:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(min(2 ** attempt, 16))
                    continue
                logging.warning(f"Échec {path} [{params}]: {e}")
                return None
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Response parsers
# ─────────────────────────────────────────────────────────────────────────────

def parse_timeseries_groups(
    data: Optional[Dict[str, Any]],
    country: Optional[str] = None,
    extra: Optional[Dict] = None,
) -> List[Dict[str, Any]]:
    """
    Parse a timeseries_groups / timeseries response.
    Handles: result.main, result.serie_0, result.serie_1
    Returns list of flat row dicts.
    """
    if not data:
        return []

    result = data.get("result", {})

    # Find the data block
    block = None
    for key in ("main", "serie_0", "serie_1"):
        if key in result and isinstance(result[key], dict):
            block = result[key]
            break
    # Fallback: first dict value that has 'timestamps'
    if block is None:
        for v in result.values():
            if isinstance(v, dict) and "timestamps" in v:
                block = v
                break

    if block is None:
        return []

    timestamps = block.get("timestamps", [])
    if not timestamps:
        return []

    # All value series (exclude 'timestamps')
    series = {
        k: v for k, v in block.items()
        if k != "timestamps" and isinstance(v, list)
    }

    rows = []
    for i, ts in enumerate(timestamps):
        row: Dict[str, Any] = {"date": ts}
        if country:
            row["country_iso2"] = country
        if extra:
            row.update(extra)
        for k, vals in series.items():
            if i < len(vals):
                v = vals[i]
                try:
                    row[k] = float(v) if v is not None else None
                except (ValueError, TypeError):
                    row[k] = v
        rows.append(row)

    return rows

# ─────────────────────────────────────────────────────────────────────────────
# Country list from API
# ─────────────────────────────────────────────────────────────────────────────

async def list_countries_iso2(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
) -> List[str]:
    rows = []
    offset = 0
    limit = 500
    while True:
        data = await api_get(
            client, "/radar/entities/locations",
            {"format": "JSON", "limit": limit, "offset": offset},
            rl, sem,
        )
        if not data:
            break
        locs = data.get("result", {}).get("locations", [])
        if not locs:
            break
        rows.extend(locs)
        if len(locs) < limit:
            break
        offset += limit

    iso2s = sorted({
        r["alpha2"] for r in rows
        if isinstance(r.get("alpha2"), str) and len(r["alpha2"]) == 2
    })
    logging.info(f"Pays/territoires disponibles : {len(iso2s)}")
    return iso2s

# ─────────────────────────────────────────────────────────────────────────────
# A. HTTP metrics per country
# ─────────────────────────────────────────────────────────────────────────────

HTTP_ENDPOINTS: Dict[str, str] = {
    "ip_version":     "/radar/http/timeseries_groups/ip_version",
    "tls_version":    "/radar/http/timeseries_groups/tls_version",
    "http_version":   "/radar/http/timeseries_groups/http_version",
    "device_type":    "/radar/http/timeseries_groups/device_type",
    "bot_class":      "/radar/http/timeseries_groups/bot_class",
    "os":             "/radar/http/timeseries_groups/os",
    "browser_family": "/radar/http/timeseries_groups/browser_family",
}


async def _fetch_http_one(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
    country: str,
    metric: str,
) -> List[Dict[str, Any]]:
    # NOTE: pas de 'name=main' — HTTP timeseries_groups l'interdit (→400)
    # Max dateRange validé avec aggInterval=1w : 52w (1 an, 53 pts hebdo)
    data = await api_get(
        client, HTTP_ENDPOINTS[metric],
        {"location": country,
         "dateRange": DATE_RANGE_HTTP_COUNTRY,
         "aggInterval": AGG_WEEK, "format": "JSON"},
        rl, sem,
    )
    return parse_timeseries_groups(data, country=country)


async def fetch_all_http(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
    countries: List[str],
) -> Dict[str, pd.DataFrame]:
    accum: Dict[str, List] = {m: [] for m in HTTP_ENDPOINTS}
    c_sem = asyncio.Semaphore(COUNTRY_CONCURRENCY)
    total = len(countries) * len(HTTP_ENDPOINTS)
    done = [0]

    async def one(country: str, metric: str):
        async with c_sem:
            rows = await _fetch_http_one(client, rl, sem, country, metric)
        if rows:
            accum[metric].extend(rows)
        done[0] += 1
        if done[0] % 100 == 0:
            logging.info(f"  HTTP: {done[0]}/{total}")

    await asyncio.gather(
        *[one(c, m) for m in HTTP_ENDPOINTS for c in countries],
        return_exceptions=True,
    )
    logging.info(f"  HTTP: {done[0]}/{total} terminé")
    return {m: pd.DataFrame(rows) for m, rows in accum.items()}

# ─────────────────────────────────────────────────────────────────────────────
# B. L7 Attacks global
# ─────────────────────────────────────────────────────────────────────────────

L7_ENDPOINTS: Dict[str, str] = {
    "vertical":     "/radar/attacks/layer7/timeseries_groups/vertical",
    "http_method":  "/radar/attacks/layer7/timeseries_groups/http_method",
    "http_version": "/radar/attacks/layer7/timeseries_groups/http_version",
}


async def fetch_l7_global(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
) -> Dict[str, pd.DataFrame]:
    results: Dict[str, pd.DataFrame] = {}
    for name, path in L7_ENDPOINTS.items():
        data = await api_get(
            client, path,
            {"dateRange": DATE_RANGE_L7,
             "aggInterval": AGG_DAY, "format": "JSON"},
            rl, sem,
        )
        rows = parse_timeseries_groups(data, extra={"dimension": name})
        results[name] = pd.DataFrame(rows)
        logging.info(f"  L7 {name}: {len(rows)} lignes")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# C. L3 Attacks per country – protocole
# ─────────────────────────────────────────────────────────────────────────────

L3_GLOBAL_ENDPOINTS: Dict[str, str] = {
    "protocol": "/radar/attacks/layer3/timeseries_groups/protocol",
    "bitrate":  "/radar/attacks/layer3/timeseries_groups/bitrate",
    "ip_version": "/radar/attacks/layer3/timeseries_groups/ip_version",
}


async def fetch_l3_global(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
) -> Dict[str, pd.DataFrame]:
    results: Dict[str, pd.DataFrame] = {}
    for name, path in L3_GLOBAL_ENDPOINTS.items():
        data = await api_get(
            client, path,
            {"dateRange": DATE_RANGE_GLOBAL,
             "aggInterval": AGG_WEEK, "format": "JSON"},
            rl, sem,
        )
        rows = parse_timeseries_groups(data, extra={"dimension": name})
        results[name] = pd.DataFrame(rows)
        logging.info(f"  L3 {name}: {len(rows)} lignes")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# D. IQI per country – métriques manquantes
# ─────────────────────────────────────────────────────────────────────────────

IQI_METRICS = ["BANDWIDTH", "DNS"]


async def _fetch_iqi_one(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
    country: str,
    metric: str,
) -> List[Dict[str, Any]]:
    data = await api_get(
        client, "/radar/quality/iqi/timeseries_groups",
        {"metric": metric, "location": country,
         "dateRange": DATE_RANGE_COUNTRY,
         "aggInterval": AGG_WEEK, "format": "JSON"},
        rl, sem,
    )
    return parse_timeseries_groups(data, country=country, extra={"metric": metric})


async def fetch_all_iqi(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
    countries: List[str],
) -> Dict[str, pd.DataFrame]:
    accum: Dict[str, List] = {m: [] for m in IQI_METRICS}
    c_sem = asyncio.Semaphore(COUNTRY_CONCURRENCY)
    total = len(countries) * len(IQI_METRICS)
    done = [0]

    async def one(country: str, metric: str):
        async with c_sem:
            rows = await _fetch_iqi_one(client, rl, sem, country, metric)
        if rows:
            accum[metric].extend(rows)
        done[0] += 1
        if done[0] % 50 == 0:
            logging.info(f"  IQI: {done[0]}/{total}")

    await asyncio.gather(
        *[one(c, m) for m in IQI_METRICS for c in countries],
        return_exceptions=True,
    )
    logging.info(f"  IQI: {done[0]}/{total} terminé")
    return {m: pd.DataFrame(rows) for m, rows in accum.items()}

# ─────────────────────────────────────────────────────────────────────────────
# E. BGP global
# ─────────────────────────────────────────────────────────────────────────────

async def fetch_bgp_timeseries(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
) -> pd.DataFrame:
    data = await api_get(
        client, "/radar/bgp/timeseries",
        {"dateRange": DATE_RANGE_GLOBAL, "aggInterval": AGG_WEEK, "format": "JSON"},
        rl, sem,
    )
    if not data:
        return pd.DataFrame()
    result = data.get("result", {})
    # BGP timeseries peut avoir result.data (list de {date, value})
    if isinstance(result.get("data"), list):
        return pd.DataFrame(result["data"])
    rows = parse_timeseries_groups(data)
    return pd.DataFrame(rows)


async def fetch_bgp_events(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
    event_type: str,   # "hijacks" ou "leaks"
) -> pd.DataFrame:
    path = f"/radar/bgp/{event_type}/events"
    all_events: List[Dict] = []
    page = 1
    per_page = 100

    while True:
        data = await api_get(
            client, path,
            {"dateRange": DATE_RANGE_GLOBAL,
             "page": page, "per_page": per_page, "format": "JSON"},
            rl, sem,
        )
        if not data:
            break
        result = data.get("result", {})
        # Hijacks: result.events.data ou result.hijacks
        events: List = []
        for key in ("events", event_type, "data", "items"):
            v = result.get(key)
            if v is None and isinstance(result.get("events"), dict):
                v = result["events"].get(key)
            if isinstance(v, list):
                events = v
                break

        if not events:
            break

        all_events.extend(events)
        logging.info(f"  BGP {event_type}: {len(all_events)} événements (page {page})")

        # Pagination check
        result_info = data.get("result_info", {})
        total_count = result_info.get("total_count", result_info.get("total", 0))
        if total_count and len(all_events) >= total_count:
            break
        if len(events) < per_page:
            break
        page += 1
        if page > 200:
            break

    if not all_events:
        return pd.DataFrame()

    # Flatten nested dicts (1 niveau)
    rows = []
    for e in all_events:
        if not isinstance(e, dict):
            continue
        row: Dict[str, Any] = {}
        for k, v in e.items():
            if isinstance(v, dict):
                for kk, vv in v.items():
                    row[f"{k}_{kk}"] = vv
            elif isinstance(v, list):
                row[k] = json.dumps(v)
            else:
                row[k] = v
        rows.append(row)
    return pd.DataFrame(rows)

# ─────────────────────────────────────────────────────────────────────────────
# F. Email Security global
# ─────────────────────────────────────────────────────────────────────────────

EMAIL_ENDPOINTS: Dict[str, str] = {
    "dmarc":     "/radar/email/security/timeseries_groups/dmarc",
    "dkim":      "/radar/email/security/timeseries_groups/dkim",
    "spf":       "/radar/email/security/timeseries_groups/spf",
    "malicious": "/radar/email/security/timeseries_groups/malicious",
    "spam":      "/radar/email/security/timeseries_groups/spam",
    "spoof":     "/radar/email/security/timeseries_groups/spoof",
}


async def fetch_email_global(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
) -> Dict[str, pd.DataFrame]:
    results: Dict[str, pd.DataFrame] = {}
    for name, path in EMAIL_ENDPOINTS.items():
        data = await api_get(
            client, path,
            {"dateRange": DATE_RANGE_GLOBAL,
             "aggInterval": AGG_WEEK, "format": "JSON"},
            rl, sem,
        )
        rows = parse_timeseries_groups(data, extra={"category": name})
        results[name] = pd.DataFrame(rows)
        logging.info(f"  Email {name}: {len(rows)} lignes")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# G. DNS global
# ─────────────────────────────────────────────────────────────────────────────

async def fetch_dns_timeseries(
    client: httpx.AsyncClient,
    rl: AsyncRateLimiter,
    sem: asyncio.Semaphore,
) -> pd.DataFrame:
    data = await api_get(
        client, "/radar/dns/timeseries",
        {"dateRange": DATE_RANGE_GLOBAL, "aggInterval": AGG_WEEK, "format": "JSON"},
        rl, sem,
    )
    if not data:
        return pd.DataFrame()
    result = data.get("result", {})
    # DNS timeseries: result.serie_0.timestamps + result.serie_0.values
    rows = parse_timeseries_groups(data)
    if not rows:
        # Fallback: direct list in result
        if isinstance(result.get("data"), list):
            return pd.DataFrame(result["data"])
    return pd.DataFrame(rows)

# ─────────────────────────────────────────────────────────────────────────────
# Save helper
# ─────────────────────────────────────────────────────────────────────────────

def save_csv(df: pd.DataFrame, path: Path, label: str) -> None:
    if df is None or df.empty:
        logging.warning(f"[{label}] DataFrame vide, pas sauvegardé")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False, encoding="utf-8-sig")
    logging.info(f"[{label}] → {path}  ({len(df):,} lignes)")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    log_file = OUTPUT_DIR / f"download_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    # Uniquement fichier (pas stdout/stderr) — évite PermissionError en mode background
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )
    # Supprimer le logging verbose httpx (évite 50k lignes parasites)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    # Petite confirmation à l'écran (une seule ligne)
    print(f"[INFO] Log -> {log_file}", flush=True)

    logging.info("=" * 65)
    logging.info("DÉMARRAGE TÉLÉCHARGEMENT COMPLET — CLOUDFLARE RADAR")
    logging.info(f"Période globale : {DATE_RANGE_GLOBAL} | par pays : {DATE_RANGE_COUNTRY}")
    logging.info("=" * 65)

    rl  = AsyncRateLimiter(MAX_CALLS_PER_MIN)
    sem = asyncio.Semaphore(REQUEST_CONCURRENCY)

    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {API_TOKEN}", "Accept": "application/json"},
        timeout=TIMEOUT,
        limits=LIMITS,
        follow_redirects=True,
    ) as client:

        # Liste des pays depuis l'API
        countries = await list_countries_iso2(client, rl, sem)

        # ── A. HTTP par pays ─────────────────────────────────────────
        logging.info("\n=== A. HTTP métriques par pays (%s, aggInterval=1w, 7 métriques × %d pays) ===",
                     DATE_RANGE_HTTP_COUNTRY, len(countries))
        http_dfs = await fetch_all_http(client, rl, sem, countries)
        for metric, df in http_dfs.items():
            save_csv(df, OUTPUT_DIR / "http" / f"http_{metric}.csv", f"http_{metric}")

        # ── B. L7 Attacks global ─────────────────────────────────────
        logging.info("\n=== B. Attaques L7 globales (%s) ===", DATE_RANGE_GLOBAL)
        l7_dfs = await fetch_l7_global(client, rl, sem)
        for name, df in l7_dfs.items():
            save_csv(df, OUTPUT_DIR / "attacks_l7" / f"attacks_l7_{name}.csv",
                     f"l7_{name}")

        # ── C. L3 Attacks global – dimensions manquantes ────────────
        logging.info("\n=== C. Attaques L3 globales – protocole/bitrate/ip_version (%s) ===",
                     DATE_RANGE_GLOBAL)
        l3_dfs = await fetch_l3_global(client, rl, sem)
        for metric, df in l3_dfs.items():
            save_csv(df, OUTPUT_DIR / "attacks_l3" / f"attacks_l3_{metric}.csv",
                     f"l3_{metric}")

        # ── D. IQI par pays ───────────────────────────────────────────
        logging.info("\n=== D. IQI par pays – bandwidth + DNS (%s) ===",
                     DATE_RANGE_COUNTRY)
        iqi_dfs = await fetch_all_iqi(client, rl, sem, countries)
        for metric, df in iqi_dfs.items():
            save_csv(df, OUTPUT_DIR / "iqi" / f"iqi_{metric.lower()}.csv",
                     f"iqi_{metric}")

        # ── E. BGP global ─────────────────────────────────────────────
        logging.info("\n=== E. BGP global (%s) ===", DATE_RANGE_GLOBAL)
        df_bgp_ts = await fetch_bgp_timeseries(client, rl, sem)
        save_csv(df_bgp_ts,
                 OUTPUT_DIR / "bgp" / "bgp_timeseries.csv", "bgp_timeseries")
        for evt in ("hijacks", "leaks"):
            df_evt = await fetch_bgp_events(client, rl, sem, evt)
            save_csv(df_evt, OUTPUT_DIR / "bgp" / f"bgp_{evt}.csv", f"bgp_{evt}")

        # ── F. Email Security global ──────────────────────────────────
        logging.info("\n=== F. Email Security global (%s) ===", DATE_RANGE_GLOBAL)
        email_dfs = await fetch_email_global(client, rl, sem)
        for name, df in email_dfs.items():
            save_csv(df, OUTPUT_DIR / "email" / f"email_{name}.csv", f"email_{name}")

        # ── G. DNS global ─────────────────────────────────────────────
        logging.info("\n=== G. DNS timeseries global (%s) ===", DATE_RANGE_GLOBAL)
        df_dns = await fetch_dns_timeseries(client, rl, sem)
        save_csv(df_dns, OUTPUT_DIR / "dns" / "dns_timeseries.csv", "dns_timeseries")

    logging.info("\n" + "=" * 65)
    logging.info("TÉLÉCHARGEMENT TERMINÉ  ✓")
    logging.info("Fichiers dans : %s", OUTPUT_DIR.resolve())
    logging.info("=" * 65)


if __name__ == "__main__":
    asyncio.run(main())
