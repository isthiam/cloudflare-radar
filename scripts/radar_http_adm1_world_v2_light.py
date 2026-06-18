# -*- coding: utf-8 -*-
"""
Cloudflare Radar - ADM1 regional traffic downloader (version légère)

Objectif
--------
1. Détecter automatiquement les pays avec données ADM1
2. Télécharger le détail uniquement pour ces pays
3. Exporter :
   - coverage/adm1_coverage_by_country.csv
   - coverage/countries_with_data.csv
   - coverage/countries_without_data.csv
   - coverage/summary.txt
   - data/ISO3.csv
   - failures/ISO3_failures.csv
   - manifest.csv

Important
---------
La granularité ADM1 n'est disponible dans l'API Radar qu'à partir du 2025-09-29.

Usage
-----
Windows:
  setx CLOUDFLARE_API_TOKEN "TON_TOKEN"
  (ré-ouvre le terminal)
  python radar_http_adm1_world_light.py --countries MEX,FRA,USA --years 1

Monde entier:
  python radar_http_adm1_world_light.py --years 1 --chunk-days 30 --sleep 0.5

Dépendances
-----------
pip install pycountry requests pandas
"""

from __future__ import annotations

import os
import time
import argparse
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

import requests
import pandas as pd

try:
    import pycountry
except Exception:
    pycountry = None


BASE = "https://api.cloudflare.com/client/v4/radar"
ENDPOINT = "http/summary/adm1"
ADM1_AVAILABLE_FROM = datetime(2025, 9, 29, tzinfo=timezone.utc)


# =========================================================
# Logging
# =========================================================
def setup_logging(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "run_log.txt"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )


# =========================================================
# ISO mapping
# =========================================================
def build_iso3_to_iso2() -> Dict[str, str]:
    if pycountry is None:
        raise RuntimeError("pycountry n'est pas installé. Fais: pip install pycountry")
    mapping: Dict[str, str] = {}
    for c in pycountry.countries:
        a3 = getattr(c, "alpha_3", None)
        a2 = getattr(c, "alpha_2", None)
        if a3 and a2:
            mapping[str(a3).upper()] = str(a2).upper()
    return mapping


def iso8601_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today_utc_midnight() -> datetime:
    return datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


# =========================================================
# API
# =========================================================
def get_json_with_retries(
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    max_attempts: int = 6,
    base_sleep: float = 1.0,
    timeout: int = 60,
) -> Tuple[int, Optional[Dict[str, Any]], str]:
    last_err = ""

    for attempt in range(1, max_attempts + 1):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=timeout)
        except Exception as e:
            last_err = f"network_error: {e}"
            if attempt == max_attempts:
                return 0, None, last_err
            time.sleep(base_sleep * (2 ** (attempt - 1)))
            continue

        if r.status_code == 200:
            try:
                return 200, r.json(), ""
            except Exception as e:
                return 200, None, f"json_parse_error: {e}"

        txt = (r.text or "")[:4000]
        last_err = txt

        retry = False
        if r.status_code == 429:
            retry = True
        elif 500 <= r.status_code <= 599:
            retry = True
        elif r.status_code == 400 and "Internal Error" in txt:
            retry = True

        if not retry or attempt == max_attempts:
            return r.status_code, None, txt

        time.sleep(base_sleep * (2 ** (attempt - 1)))

    return 0, None, last_err or "unknown_error"


# =========================================================
# Parsing robuste
# =========================================================
def _rows_from_list(value: Any, country_iso2: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "country_iso2": country_iso2,
                    "adm1": item.get("adm1") or item.get("name") or item.get("label"),
                    "geoId": item.get("geoId") or item.get("geo_id"),
                    "value": item.get("value"),
                    "rank": item.get("rank"),
                }
            )
    return rows


def parse_adm1_result(js: Dict[str, Any], country_iso2: str) -> pd.DataFrame:
    result = js.get("result", {})
    rows: List[Dict[str, Any]] = []

    if isinstance(result, list):
        rows.extend(_rows_from_list(result, country_iso2))

    elif isinstance(result, dict):
        preferred_keys = ["main", "summary_0", "top_0", "summary", "data"]
        for k in preferred_keys:
            if k in result:
                rows.extend(_rows_from_list(result.get(k), country_iso2))

        if not rows:
            for _, v in result.items():
                rows.extend(_rows_from_list(v, country_iso2))

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows).drop_duplicates().reset_index(drop=True)
    return df


# =========================================================
# Fetch one window
# =========================================================
def fetch_window(
    iso2: str,
    start_dt: datetime,
    end_dt: datetime,
    headers: Dict[str, str],
) -> Tuple[pd.DataFrame, int, str]:
    url = f"{BASE}/{ENDPOINT}"
    params = {
        "dateStart": iso8601_z(start_dt),
        "dateEnd": iso8601_z(end_dt),
        "location": iso2,
        "format": "JSON",
    }

    status, js, err = get_json_with_retries(url, headers=headers, params=params)
    if status != 200 or js is None:
        return pd.DataFrame(), status, err

    df = parse_adm1_result(js, iso2)
    return df, 200, ""


# =========================================================
# Coverage probe
# =========================================================
@dataclass
class ProbeRun:
    iso3: str
    iso2: str
    has_data: bool
    rows: int
    status_code: int
    probe_start: str
    probe_end: str
    note: str


def probe_country_any_data(
    iso3: str,
    iso2: str,
    headers: Dict[str, str],
    start_dt: datetime,
    end_dt: datetime,
) -> ProbeRun:
    df, status, err = fetch_window(iso2, start_dt, end_dt, headers)

    if status != 200:
        return ProbeRun(
            iso3=iso3,
            iso2=iso2,
            has_data=False,
            rows=0,
            status_code=status,
            probe_start=iso8601_z(start_dt),
            probe_end=iso8601_z(end_dt),
            note=(err or "api_error")[:300],
        )

    if df.empty:
        return ProbeRun(
            iso3=iso3,
            iso2=iso2,
            has_data=False,
            rows=0,
            status_code=200,
            probe_start=iso8601_z(start_dt),
            probe_end=iso8601_z(end_dt),
            note="no_adm1_data",
        )

    return ProbeRun(
        iso3=iso3,
        iso2=iso2,
        has_data=True,
        rows=len(df),
        status_code=200,
        probe_start=iso8601_z(start_dt),
        probe_end=iso8601_z(end_dt),
        note="adm1_available",
    )


# =========================================================
# Detailed download
# =========================================================
@dataclass
class CountryRun:
    iso3: str
    iso2: str
    status: str
    rows: int
    start: str
    end: str
    failures: int
    file: str
    note: str


def load_existing_if_good(out_file: Path, min_rows: int = 5) -> Optional[int]:
    if not out_file.exists():
        return None
    try:
        df = pd.read_csv(out_file)
        if len(df) >= min_rows:
            return len(df)
    except Exception:
        return None
    return None


def save_failures(fail_file: Path, failures: List[Dict[str, Any]]) -> None:
    if not failures:
        return
    fail_file.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(failures).to_csv(fail_file, index=False, encoding="utf-8")


def run_chunked_download(
    iso3: str,
    iso2: str,
    start_dt: datetime,
    end_dt: datetime,
    headers: Dict[str, str],
    chunk_days: int,
    sleep_between_calls: float,
) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    frames: List[pd.DataFrame] = []
    failures: List[Dict[str, Any]] = []

    cur = start_dt
    while cur < end_dt:
        nxt = min(cur + timedelta(days=chunk_days), end_dt)

        dfw, status, err = fetch_window(iso2, cur, nxt, headers)

        if dfw.empty:
            failures.append(
                {
                    "iso3": iso3,
                    "iso2": iso2,
                    "dateStart": iso8601_z(cur),
                    "dateEnd": iso8601_z(nxt),
                    "status": status,
                    "error": (err or "empty")[:500],
                }
            )
        else:
            dfw["window_start"] = iso8601_z(cur)
            dfw["window_end"] = iso8601_z(nxt)
            frames.append(dfw)

        cur = nxt
        time.sleep(sleep_between_calls)

    if not frames:
        return pd.DataFrame(), failures

    df = pd.concat(frames, ignore_index=True)
    df = df.drop_duplicates().reset_index(drop=True)
    return df, failures


def fetch_country_detail(
    iso3: str,
    iso2: str,
    years_back: int,
    chunk_days: int,
    headers: Dict[str, str],
    sleep_between_calls: float,
    out_data_dir: Path,
    out_fail_dir: Path,
    force: bool,
) -> CountryRun:
    out_file = out_data_dir / f"{iso3}.csv"
    fail_file = out_fail_dir / f"{iso3}_failures.csv"

    end_dt = today_utc_midnight()
    requested_start = end_dt - timedelta(days=365 * years_back)
    start_dt = max(requested_start, ADM1_AVAILABLE_FROM)

    if start_dt >= end_dt:
        return CountryRun(
            iso3=iso3,
            iso2=iso2,
            status="FAIL",
            rows=0,
            start=iso8601_z(start_dt),
            end=iso8601_z(end_dt),
            failures=0,
            file=str(out_file),
            note="invalid_requested_period",
        )

    if not force:
        existing_rows = load_existing_if_good(out_file, min_rows=5)
        if existing_rows is not None:
            return CountryRun(
                iso3=iso3,
                iso2=iso2,
                status="SKIPPED",
                rows=existing_rows,
                start=iso8601_z(start_dt),
                end=iso8601_z(end_dt),
                failures=0,
                file=str(out_file),
                note="existing_file",
            )

    df, failures = run_chunked_download(
        iso3=iso3,
        iso2=iso2,
        start_dt=start_dt,
        end_dt=end_dt,
        headers=headers,
        chunk_days=chunk_days,
        sleep_between_calls=sleep_between_calls,
    )
    save_failures(fail_file, failures)

    if df.empty:
        return CountryRun(
            iso3=iso3,
            iso2=iso2,
            status="FAIL",
            rows=0,
            start=iso8601_z(start_dt),
            end=iso8601_z(end_dt),
            failures=len(failures),
            file=str(out_file),
            note="all_windows_failed_or_empty",
        )

    df["country"] = iso3
    df["iso2"] = iso2

    if "value" in df.columns:
        df["value_num"] = pd.to_numeric(df["value"], errors="coerce")
        if df["value_num"].dropna().between(0, 1).all():
            df["percentage"] = (df["value_num"] * 100).round(4)
        else:
            df["percentage"] = df["value_num"]

    out_data_dir.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_file, index=False, encoding="utf-8")

    status = "OK" if len(failures) == 0 else "PARTIAL"
    note = "ok_full_horizon" if status == "OK" else f"partial failures={len(failures)}"

    return CountryRun(
        iso3=iso3,
        iso2=iso2,
        status=status,
        rows=len(df),
        start=iso8601_z(start_dt),
        end=iso8601_z(end_dt),
        failures=len(failures),
        file=str(out_file),
        note=note,
    )


# =========================================================
# Main
# =========================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", default="", help="Token Radar (sinon env CLOUDFLARE_API_TOKEN)")
    parser.add_argument("--years", type=int, default=1, help="Horizon en années (default 1)")
    parser.add_argument("--chunk-days", type=int, default=30, help="Taille fenêtre en jours (default 30)")
    parser.add_argument("--sleep", type=float, default=0.5, help="Pause entre appels (default 0.5)")
    parser.add_argument("--force", action="store_true", help="Re-télécharger même si fichier existe")
    parser.add_argument("--countries", default="", help="ISO3 list séparée par virgules (subset)")
    parser.add_argument("--out", default="outputs_regions_world_v2_light", help="Dossier sortie")
    args = parser.parse_args()

    token = (args.token or "").strip() or os.getenv("CLOUDFLARE_API_TOKEN", "0kOM4DWQjoajiw6AGMfPyZynTDdfMK5uexi3CJwn").strip()
    if not token:
        raise SystemExit("❌ Token manquant. Mets CLOUDFLARE_API_TOKEN ou passe --token.")

    out_dir = Path(args.out).resolve()
    coverage_dir = out_dir / "coverage"
    out_data = out_dir / "data"
    out_fail = out_dir / "failures"

    coverage_dir.mkdir(parents=True, exist_ok=True)
    out_data.mkdir(parents=True, exist_ok=True)
    out_fail.mkdir(parents=True, exist_ok=True)

    setup_logging(out_dir)

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }

    iso3_to_iso2 = build_iso3_to_iso2()
    all_iso3 = sorted(iso3_to_iso2.keys())

    if args.countries.strip():
        subset = [c.strip().upper() for c in args.countries.split(",") if c.strip()]
        countries = [c for c in subset if c in iso3_to_iso2]
        missing = [c for c in subset if c not in iso3_to_iso2]
        if missing:
            logging.warning(f"⚠️ ISO3 inconnus (ignorés): {missing}")
    else:
        countries = all_iso3

    probe_start = ADM1_AVAILABLE_FROM
    probe_end = today_utc_midnight()

    logging.info(f"🌍 Étape 1/2 - Probe ADM1 coverage | countries={len(countries)}")
    logging.info(f"📅 Période probe: {iso8601_z(probe_start)} -> {iso8601_z(probe_end)}")

    probes: List[ProbeRun] = []
    for i, iso3 in enumerate(countries, start=1):
        iso2 = iso3_to_iso2[iso3]
        logging.info(f"[PROBE {i}/{len(countries)}] → {iso3} ({iso2})")
        pr = probe_country_any_data(
            iso3=iso3,
            iso2=iso2,
            headers=headers,
            start_dt=probe_start,
            end_dt=probe_end,
        )
        probes.append(pr)
        logging.info(f"   has_data={pr.has_data} | rows={pr.rows} | status={pr.status_code} | {pr.note}")
        time.sleep(max(0.1, args.sleep))

    df_probe = pd.DataFrame([p.__dict__ for p in probes])
    df_probe.to_csv(coverage_dir / "adm1_coverage_by_country.csv", index=False, encoding="utf-8")

    df_yes = df_probe[df_probe["has_data"] == True].copy().sort_values(["iso3"])
    df_no = df_probe[df_probe["has_data"] == False].copy().sort_values(["iso3"])

    df_yes.to_csv(coverage_dir / "countries_with_data.csv", index=False, encoding="utf-8")
    df_no.to_csv(coverage_dir / "countries_without_data.csv", index=False, encoding="utf-8")

    total = len(df_probe)
    covered = int(df_probe["has_data"].sum())
    uncovered = total - covered
    coverage_pct = round(100 * covered / total, 2) if total else 0.0

    summary = f"""
Cloudflare Radar ADM1 coverage audit
====================================

Période testée:
  {iso8601_z(probe_start)} -> {iso8601_z(probe_end)}

Pays testés:
  {total}

Pays avec données ADM1:
  {covered}

Pays sans données ADM1:
  {uncovered}

Couverture (%):
  {coverage_pct}%
"""
    (coverage_dir / "summary.txt").write_text(summary.strip() + "\n", encoding="utf-8")

    logging.info(f"✅ Couverture ADM1: {coverage_pct}% ({covered}/{total})")

    # Étape 2
    covered_iso3 = df_yes["iso3"].tolist()
    logging.info(f"🌍 Étape 2/2 - Download détail ADM1 | countries_with_data={len(covered_iso3)}")

    runs: List[CountryRun] = []
    t0 = time.time()

    for i, iso3 in enumerate(covered_iso3, start=1):
        iso2 = iso3_to_iso2[iso3]
        logging.info(f"[DL {i}/{len(covered_iso3)}] → {iso3} ({iso2})")

        run = fetch_country_detail(
            iso3=iso3,
            iso2=iso2,
            years_back=args.years,
            chunk_days=args.chunk_days,
            headers=headers,
            sleep_between_calls=args.sleep,
            out_data_dir=out_data,
            out_fail_dir=out_fail,
            force=args.force,
        )

        runs.append(run)
        logging.info(f"   {run.status} | rows={run.rows} | failures={run.failures} | {run.note}")
        time.sleep(max(0.2, args.sleep))

        if i % 10 == 0:
            pd.DataFrame([r.__dict__ for r in runs]).to_csv(
                out_dir / "manifest.csv", index=False, encoding="utf-8"
            )

    manifest = pd.DataFrame([r.__dict__ for r in runs])
    manifest.to_csv(out_dir / "manifest.csv", index=False, encoding="utf-8")

    elapsed = time.time() - t0
    ok = (manifest["status"] == "OK").sum() if not manifest.empty else 0
    partial = (manifest["status"] == "PARTIAL").sum() if not manifest.empty else 0
    fail = (manifest["status"] == "FAIL").sum() if not manifest.empty else 0
    skipped = (manifest["status"] == "SKIPPED").sum() if not manifest.empty else 0

    logging.info("✅ Terminé.")
    logging.info(f"Résumé download: OK={ok} PARTIAL={partial} FAIL={fail} SKIPPED={skipped}")
    logging.info(f"Manifest: {out_dir / 'manifest.csv'}")
    logging.info(f"⏱ Temps total download: {elapsed/60:.1f} min")


if __name__ == "__main__":
    main()