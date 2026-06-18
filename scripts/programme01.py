import asyncio
import json
from collections import deque
from typing import Any

import httpx
import pandas as pd


API_TOKEN = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn"
BASE_URL = "https://api.cloudflare.com/client/v4"

DATE_RANGE = "52w"
LIMIT_PER_GROUP = 100

# Réglages stables
COUNTRY_CONCURRENCY = 8
REQUEST_CONCURRENCY = 16
GEO_CONCURRENCY = 8
MAX_RETRIES = 5
MAX_CALLS_PER_MINUTE = 120

TIMEOUT = httpx.Timeout(connect=20.0, read=60.0, write=30.0, pool=60.0)
LIMITS = httpx.Limits(max_connections=30, max_keepalive_connections=15)


class AsyncRateLimiter:
    def __init__(self, max_calls: int, period_seconds: float = 60.0):
        self.max_calls = max_calls
        self.period = period_seconds
        self.calls = deque()
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

                wait_for = self.period - (now - self.calls[0])

            await asyncio.sleep(max(wait_for, 0.05))


def build_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Accept": "application/json",
    }


async def api_get(
    client: httpx.AsyncClient,
    path: str,
    params: dict[str, Any] | None,
    rate_limiter: AsyncRateLimiter,
    req_semaphore: asyncio.Semaphore,
    accept_404: bool = False,
) -> dict[str, Any] | None:
    url = f"{BASE_URL}{path}"

    for attempt in range(1, MAX_RETRIES + 1):
        await rate_limiter.acquire()

        async with req_semaphore:
            try:
                resp = await client.get(url, params=params)

                if resp.status_code == 404 and accept_404:
                    return None

                if resp.status_code in (429, 500, 502, 503, 504):
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(min(2 ** (attempt - 1), 12) + 0.2 * attempt)
                        continue

                resp.raise_for_status()

                payload = resp.json()

                if not payload.get("success", True):
                    raise RuntimeError(
                        f"API success=false | url={resp.request.url} | payload={json.dumps(payload, ensure_ascii=False)[:1500]}"
                    )

                return payload

            except (httpx.HTTPError, json.JSONDecodeError) as e:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(min(2 ** (attempt - 1), 12) + 0.2 * attempt)
                    continue

                raise RuntimeError(
                    f"GET failed | url={url} | params={params} | error={e}"
                ) from e

    raise RuntimeError(f"GET failed after retries | url={url} | params={params}")


async def list_countries(
    client: httpx.AsyncClient,
    rate_limiter: AsyncRateLimiter,
    req_semaphore: asyncio.Semaphore,
) -> pd.DataFrame:
    rows = []
    offset = 0
    limit = 500

    while True:
        payload = await api_get(
            client=client,
            path="/radar/entities/locations",
            params={"format": "JSON", "limit": limit, "offset": offset},
            rate_limiter=rate_limiter,
            req_semaphore=req_semaphore,
        )

        locs = payload.get("result", {}).get("locations", [])
        if not locs:
            break

        rows.extend(locs)

        if len(locs) < limit:
            break

        offset += limit

    df = pd.DataFrame(rows)

    for col in ["alpha2", "name", "continent", "region", "subregion"]:
        if col not in df.columns:
            df[col] = None

    df = df[df["alpha2"].astype(str).str.len() == 2].copy()
    df = df.sort_values(["name", "alpha2"]).drop_duplicates(subset=["alpha2"]).reset_index(drop=True)
    return df


def extract_series_block(result: dict[str, Any], series_name: str = "main") -> tuple[dict[str, Any], list[str], list[str]]:
    block = result.get(series_name, {})
    if not isinstance(block, dict):
        return {}, [], []

    timestamps = block.get("timestamps", [])
    geo_ids = [k for k in block.keys() if k not in ("timestamps", "other")]
    return block, timestamps, geo_ids


async def fetch_country_metric(
    client: httpx.AsyncClient,
    rate_limiter: AsyncRateLimiter,
    req_semaphore: asyncio.Semaphore,
    country_code: str,
    metric_name: str,
) -> dict[str, Any]:
    if metric_name == "total_bytes":
        path = "/radar/netflows/timeseries_groups/ADM1"
        params = {
            "name": "main",
            "location": country_code,
            "product": "ALL",
            "dateRange": DATE_RANGE,
            "limitPerGroup": LIMIT_PER_GROUP,
            "format": "JSON",
        }
    elif metric_name == "http_bytes":
        path = "/radar/netflows/timeseries_groups/ADM1"
        params = {
            "name": "main",
            "location": country_code,
            "product": "HTTP",
            "dateRange": DATE_RANGE,
            "limitPerGroup": LIMIT_PER_GROUP,
            "format": "JSON",
        }
    elif metric_name == "http_requests":
        path = "/radar/http/timeseries_groups/ADM1"
        params = {
            "name": "main",
            "location": country_code,
            "dateRange": DATE_RANGE,
            "limitPerGroup": LIMIT_PER_GROUP,
            "format": "JSON",
        }
    else:
        raise ValueError(f"Métrique inconnue : {metric_name}")

    payload = await api_get(
        client=client,
        path=path,
        params=params,
        rate_limiter=rate_limiter,
        req_semaphore=req_semaphore,
    )

    result = payload.get("result", {})
    block, timestamps, geo_ids = extract_series_block(result, "main")

    return {
        "metric_name": metric_name,
        "path": path,
        "params": params,
        "block": block,
        "timestamps": timestamps,
        "geo_ids": geo_ids,
        "meta": result.get("meta", payload.get("meta", {})),
    }


async def fetch_country_all_metrics(
    client: httpx.AsyncClient,
    rate_limiter: AsyncRateLimiter,
    req_semaphore: asyncio.Semaphore,
    country_row: dict[str, Any],
) -> dict[str, Any]:
    country_code = country_row["alpha2"]
    country_name = country_row["name"]

    metric_tasks = [
        fetch_country_metric(client, rate_limiter, req_semaphore, country_code, "total_bytes"),
        fetch_country_metric(client, rate_limiter, req_semaphore, country_code, "http_bytes"),
        fetch_country_metric(client, rate_limiter, req_semaphore, country_code, "http_requests"),
    ]

    results = await asyncio.gather(*metric_tasks, return_exceptions=True)

    metrics = []
    errors = []

    for res in results:
        if isinstance(res, Exception):
            errors.append({
                "country_code": country_code,
                "country_name": country_name,
                "error": str(res),
            })
        else:
            metrics.append(res)

    return {
        "country": country_row,
        "metrics": metrics,
        "errors": errors,
    }


async def resolve_geo(
    client: httpx.AsyncClient,
    rate_limiter: AsyncRateLimiter,
    req_semaphore: asyncio.Semaphore,
    geo_id: str,
) -> dict[str, Any]:
    """
    Ne casse jamais le pipeline global.
    """
    try:
        payload = await api_get(
            client=client,
            path=f"/radar/geolocations/{geo_id}",
            params={"format": "JSON"},
            rate_limiter=rate_limiter,
            req_semaphore=req_semaphore,
            accept_404=True,
        )

        if payload is None:
            return {
                "geo_id": str(geo_id),
                "geo_name": None,
                "geo_code": None,
                "geo_type": None,
                "geo_latitude": None,
                "geo_longitude": None,
                "parent_geo_id": None,
                "parent_geo_name": None,
                "parent_geo_type": None,
                "geo_found": False,
                "geo_error": "404 Not Found",
            }

        result = payload.get("result", {})
        geo = result.get("geolocation", result)
        parent = geo.get("parent") if isinstance(geo.get("parent"), dict) else {}

        return {
            "geo_id": str(geo_id),
            "geo_name": geo.get("name"),
            "geo_code": geo.get("code"),
            "geo_type": geo.get("type"),
            "geo_latitude": geo.get("latitude"),
            "geo_longitude": geo.get("longitude"),
            "parent_geo_id": parent.get("geoId"),
            "parent_geo_name": parent.get("name"),
            "parent_geo_type": parent.get("type"),
            "geo_found": True,
            "geo_error": None,
        }

    except Exception as e:
        return {
            "geo_id": str(geo_id),
            "geo_name": None,
            "geo_code": None,
            "geo_type": None,
            "geo_latitude": None,
            "geo_longitude": None,
            "parent_geo_id": None,
            "parent_geo_name": None,
            "parent_geo_type": None,
            "geo_found": False,
            "geo_error": str(e),
        }


async def resolve_all_geos(
    client: httpx.AsyncClient,
    rate_limiter: AsyncRateLimiter,
    req_semaphore: asyncio.Semaphore,
    geo_ids: list[str],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    cache: dict[str, dict[str, Any]] = {}
    missing: list[dict[str, Any]] = []

    geo_ids = sorted(set(map(str, geo_ids)))
    geo_semaphore = asyncio.Semaphore(GEO_CONCURRENCY)

    async def worker(gid: str):
        async with geo_semaphore:
            info = await resolve_geo(client, rate_limiter, req_semaphore, gid)
            cache[gid] = info

            if not info.get("geo_found", False):
                missing.append({
                    "geo_id": gid,
                    "error": info.get("geo_error"),
                })

    await asyncio.gather(*(worker(gid) for gid in geo_ids), return_exceptions=False)
    return cache, missing


def metric_label(metric_name: str) -> str:
    return {
        "total_bytes": "Nombre total d'octets",
        "http_bytes": "Octets HTTP",
        "http_requests": "Requêtes HTTP",
    }[metric_name]


def flatten_country_metric_rows(
    country_row: dict[str, Any],
    metric_result: dict[str, Any],
    geo_cache: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    block = metric_result["block"]
    timestamps = metric_result["timestamps"]
    mname = metric_result["metric_name"]

    rows = []

    for geo_id, values in block.items():
        if geo_id in ("timestamps", "other"):
            continue

        geo_info = geo_cache.get(str(geo_id), {
            "geo_id": str(geo_id),
            "geo_name": None,
            "geo_code": None,
            "geo_type": None,
            "geo_latitude": None,
            "geo_longitude": None,
            "parent_geo_id": None,
            "parent_geo_name": None,
            "parent_geo_type": None,
            "geo_found": False,
            "geo_error": "missing from cache",
        })

        for ts, val in zip(timestamps, values):
            try:
                value_num = float(val) if val is not None else None
            except Exception:
                value_num = None

            rows.append({
                "country_code": country_row["alpha2"],
                "country_name": country_row["name"],
                "continent": country_row.get("continent"),
                "region": country_row.get("region"),
                "subregion": country_row.get("subregion"),
                "metric": metric_label(mname),
                "metric_key": mname,
                "geo_id": str(geo_id),
                "geo_name": geo_info.get("geo_name"),
                "geo_code": geo_info.get("geo_code"),
                "geo_type": geo_info.get("geo_type"),
                "parent_geo_id": geo_info.get("parent_geo_id"),
                "parent_geo_name": geo_info.get("parent_geo_name"),
                "parent_geo_type": geo_info.get("parent_geo_type"),
                "geo_found": geo_info.get("geo_found"),
                "geo_error": geo_info.get("geo_error"),
                "timestamp": ts,
                "value": value_num,
                "raw_value": val,
            })

    return rows


async def main():
    rate_limiter = AsyncRateLimiter(MAX_CALLS_PER_MINUTE, 60.0)
    req_semaphore = asyncio.Semaphore(REQUEST_CONCURRENCY)

    async with httpx.AsyncClient(
        headers=build_headers(),
        timeout=TIMEOUT,
        limits=LIMITS,
        http2=False,
        follow_redirects=True,
    ) as client:

        countries_df = await list_countries(client, rate_limiter, req_semaphore)
        countries = countries_df.to_dict(orient="records")
        print(f"{len(countries)} pays/territoires trouvés")

        country_sem = asyncio.Semaphore(COUNTRY_CONCURRENCY)

        async def process_country(country_row: dict[str, Any]) -> dict[str, Any]:
            async with country_sem:
                return await fetch_country_all_metrics(client, rate_limiter, req_semaphore, country_row)

        country_results = await asyncio.gather(*(process_country(c) for c in countries))

        all_geo_ids = []
        all_errors = []
        meta_rows = []

        for item in country_results:
            all_errors.extend(item["errors"])
            for m in item["metrics"]:
                all_geo_ids.extend(m["geo_ids"])
                meta_rows.append({
                    "country_code": item["country"]["alpha2"],
                    "country_name": item["country"]["name"],
                    "metric": metric_label(m["metric_name"]),
                    "meta_json": json.dumps(m["meta"], ensure_ascii=False),
                })

        print(f"Geo IDs uniques à résoudre : {len(set(all_geo_ids))}")

        geo_cache, missing_geo = await resolve_all_geos(
            client, rate_limiter, req_semaphore, all_geo_ids
        )

        all_rows = []
        for item in country_results:
            for m in item["metrics"]:
                all_rows.extend(flatten_country_metric_rows(item["country"], m, geo_cache))

    df = pd.DataFrame(all_rows)
    df_errors = pd.DataFrame(all_errors)
    df_meta = pd.DataFrame(meta_rows)
    df_geo = pd.DataFrame(list(geo_cache.values()))
    df_missing = pd.DataFrame(missing_geo).drop_duplicates()

    df.to_csv("radar_adm1_timeseries_all_countries_async.csv", index=False, encoding="utf-8-sig")
    df_errors.to_csv("radar_adm1_timeseries_errors_async.csv", index=False, encoding="utf-8-sig")
    df_meta.to_csv("radar_adm1_timeseries_meta_async.csv", index=False, encoding="utf-8-sig")
    df_geo.to_csv("radar_adm1_geolocations_cache_async.csv", index=False, encoding="utf-8-sig")
    df_missing.to_csv("radar_adm1_missing_geolocations_async.csv", index=False, encoding="utf-8-sig")

    print("\nTerminé")
    print(f"Lignes exportées : {len(df):,}")
    print(f"Erreurs API : {len(df_errors):,}")
    print(f"Geo IDs résolus/cache : {len(df_geo):,}")
    print(f"Geo IDs non résolus : {len(df_missing):,}")


if __name__ == "__main__":
    asyncio.run(main())