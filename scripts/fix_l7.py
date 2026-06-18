# -*- coding: utf-8 -*-
"""
fix_l7.py
Récupère les données L7 attacks globales avec aggInterval=1d.
Teste d'abord dateRange=12w, sinon repli sur 4w.
"""
import asyncio
import logging
from datetime import datetime
from pathlib import Path

import httpx
import pandas as pd

API_TOKEN = "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn"
BASE_URL = "https://api.cloudflare.com/client/v4"
OUTPUT_DIR = Path("outputs_complet")

L7_ENDPOINTS = {
    "vertical":     "/radar/attacks/layer7/timeseries_groups/vertical",
    "http_method":  "/radar/attacks/layer7/timeseries_groups/http_method",
    "http_version": "/radar/attacks/layer7/timeseries_groups/http_version",
}

TIMEOUT = httpx.Timeout(connect=20.0, read=60.0, write=20.0, pool=60.0)


async def try_l7(client: httpx.AsyncClient, path: str, date_range: str) -> dict | None:
    url = f"{BASE_URL}{path}"
    params = {"dateRange": date_range, "aggInterval": "1d", "format": "JSON"}
    try:
        resp = await client.get(url, params=params)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success", True):
                return data
        print(f"  [{resp.status_code}] {path} dateRange={date_range}")
        return None
    except Exception as e:
        print(f"  [ERR] {path} dateRange={date_range}: {e}")
        return None


def parse_rows(data: dict, name: str) -> list:
    if not data:
        return []
    result = data.get("result", {})
    block = None
    for key in ("serie_0", "main", "serie_1"):
        if key in result and isinstance(result[key], dict):
            block = result[key]
            break
    if block is None:
        for v in result.values():
            if isinstance(v, dict) and "timestamps" in v:
                block = v
                break
    if not block:
        return []
    timestamps = block.get("timestamps", [])
    series = {k: v for k, v in block.items() if k != "timestamps" and isinstance(v, list)}
    rows = []
    for i, ts in enumerate(timestamps):
        row = {"date": ts, "dimension": name}
        for k, vals in series.items():
            if i < len(vals):
                v = vals[i]
                try:
                    row[k] = float(v) if v is not None else None
                except (ValueError, TypeError):
                    row[k] = v
        rows.append(row)
    return rows


async def main():
    log_file = OUTPUT_DIR / f"fix_l7_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(log_file, encoding="utf-8")],
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    print(f"[INFO] Log -> {log_file}", flush=True)

    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {API_TOKEN}", "Accept": "application/json"},
        timeout=TIMEOUT,
        follow_redirects=True,
    ) as client:
        # Find the best dateRange for L7 attacks (daily only)
        # Try 52w first, then 26w, 12w, 4w
        for test_range in ("52w", "26w", "12w", "4w"):
            data = await try_l7(client, "/radar/attacks/layer7/timeseries_groups/vertical", test_range)
            if data:
                rows = parse_rows(data, "test")
                print(f"[OK] dateRange={test_range} -> {len(rows)} points", flush=True)
                logging.info(f"Best dateRange for L7: {test_range} ({len(rows)} pts)")
                best_range = test_range
                break
        else:
            print("[FAIL] No dateRange worked for L7", flush=True)
            return

        # Fetch all L7 endpoints with the best range
        all_rows = []
        for name, path in L7_ENDPOINTS.items():
            data = await try_l7(client, path, best_range)
            rows = parse_rows(data, name)
            all_rows.extend(rows)
            print(f"  L7 {name}: {len(rows)} lignes (dateRange={best_range})", flush=True)
            logging.info(f"L7 {name}: {len(rows)} lignes")

        if all_rows:
            df = pd.DataFrame(all_rows)
            out_dir = OUTPUT_DIR / "attacks_l7"
            out_dir.mkdir(parents=True, exist_ok=True)
            for name in L7_ENDPOINTS:
                sub = df[df["dimension"] == name]
                if not sub.empty:
                    path_out = out_dir / f"attacks_l7_{name}.csv"
                    sub.to_csv(path_out, index=False, encoding="utf-8-sig")
                    print(f"  Saved: {path_out} ({len(sub)} lignes)", flush=True)
                    logging.info(f"[l7_{name}] -> {path_out} ({len(sub)} lignes)")
        print("[DONE]", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
