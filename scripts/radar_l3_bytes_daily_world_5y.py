# -*- coding: utf-8 -*-
"""
Cloudflare Radar - Attaques L3 - ip_version - DAILY - metric=bytes
FULL WORLD, N years (default 4), chunking + retries + resume + probe + fallback 1y.

Outputs (default: outputs_world):
  outputs_world/
    data/        -> 1 CSV par pays (ISO3.csv)
    failures/    -> 1 CSV par pays (ISO3_failures.csv) si fenêtres vides/erreurs
    manifest.csv -> suivi global (OK/PARTIAL/NO_COVERAGE/FAIL/SKIPPED)

Usage Windows (recommandé):
  setx CLOUDFLARE_API_TOKEN "TON_TOKEN"
  (ré-ouvre le terminal)
  python radar_l3_bytes_daily_world_robust.py --years 4 --chunk-days 90 --sleep 0.5

Tester sur un sous-ensemble:
  python radar_l3_bytes_daily_world_robust.py --countries FRA,DEU,GBR,NLD,ESP --years 4

Dépendances:
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
ENDPOINT = "attacks/layer3/timeseries_groups/ip_version"


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
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def today_utc_midnight() -> datetime:
    return datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


# =========================================================
# API (retries)
# =========================================================
def get_json_with_retries(
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    max_attempts: int = 6,
    base_sleep: float = 1.0,
    timeout: int = 60,
) -> Tuple[int, Optional[Dict[str, Any]], str]:
    """
    Returns (status_code, json, error_text)
    Retries on:
      - 429 rate limit
      - 5xx
      - 400 with "Internal Error"
    """
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


def parse_ip_version_result(js: Dict[str, Any]) -> pd.DataFrame:
    """
    Parse result.main: timestamps, IPv4, IPv6
    Troncature à la longueur minimale si mismatch.
    """
    result = js.get("result", {})
    main = result.get("main", {}) if isinstance(result, dict) else {}
    ts = main.get("timestamps", []) or []
    v4 = main.get("IPv4", []) or []
    v6 = main.get("IPv6", []) or []

    m = min(len(ts), len(v4), len(v6))
    if m == 0:
        return pd.DataFrame()

    return pd.DataFrame(
        {
            "date": pd.to_datetime(ts[:m], utc=True),
            "attack_ipv4_bytes": v4[:m],
            "attack_ipv6_bytes": v6[:m],
        }
    )


def fetch_window(
    iso2: str,
    start_dt: datetime,
    end_dt: datetime,
    headers: Dict[str, str],
    chunk_days: int,
) -> Tuple[pd.DataFrame, int, str]:
    """
    Fetch daily bytes for one country iso2 in [start_dt, end_dt)
    """
    url = f"{BASE}/{ENDPOINT}"
    params = {
        "name": "main",
        "direction": "Target",
        "protocol": "TCP",
        "metric": "bytes",
        "aggInterval": "1d",
        "location": iso2,
        "dateStart": iso8601_z(start_dt),
        "dateEnd": iso8601_z(end_dt),
    }
    status, js, err = get_json_with_retries(url, headers=headers, params=params)
    if status != 200 or js is None:
        return pd.DataFrame(), status, err

    df = parse_ip_version_result(js)
    return df, 200, ""


# =========================================================
# Probe (availability)
# =========================================================
def probe_country_recent(
    iso2: str,
    headers: Dict[str, str],
    days: int = 30,
    chunk_days: int = 90,
) -> bool:
    """
    Quick test: if no data in last 'days', we mark NO_COVERAGE.
    """
    end_dt = today_utc_midnight()
    start_dt = end_dt - timedelta(days=days)

    df, status, err = fetch_window(iso2, start_dt, end_dt, headers=headers, chunk_days=chunk_days)
    return (not df.empty) and (len(df) >= 5)


# =========================================================
# Download orchestration
# =========================================================
@dataclass
class CountryRun:
    iso3: str
    iso2: str
    status: str           # OK / PARTIAL / NO_COVERAGE / FAIL / SKIPPED
    rows: int
    start: str
    end: str
    failures: int
    file: str
    note: str


def expected_days(start_dt: datetime, end_dt: datetime) -> int:
    return int((end_dt - start_dt).days)


def load_existing_if_good(out_file: Path, min_rows: int = 50) -> Optional[int]:
    if not out_file.exists():
        return None
    try:
        df = pd.read_csv(out_file, parse_dates=["date"])
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
    """
    Download in windows, return (df, failures_list)
    """
    frames: List[pd.DataFrame] = []
    failures: List[Dict[str, Any]] = []

    cur = start_dt
    while cur < end_dt:
        nxt = min(cur + timedelta(days=chunk_days), end_dt)

        dfw, status, err = fetch_window(iso2, cur, nxt, headers=headers, chunk_days=chunk_days)
        if dfw.empty:
            failures.append({
                "iso3": iso3,
                "iso2": iso2,
                "dateStart": iso8601_z(cur),
                "dateEnd": iso8601_z(nxt),
                "status": status,
                "error": (err or "empty")[:500],
            })
        else:
            frames.append(dfw)

        cur = nxt
        time.sleep(sleep_between_calls)

    if not frames:
        return pd.DataFrame(), failures

    df = pd.concat(frames, ignore_index=True)
    df = df.drop_duplicates(subset=["date"]).sort_values("date").reset_index(drop=True)
    return df, failures


def fetch_country(
    iso3: str,
    iso2: str,
    years_back: int,
    chunk_days: int,
    headers: Dict[str, str],
    sleep_between_calls: float,
    out_data_dir: Path,
    out_fail_dir: Path,
    force: bool,
    probe_days: int = 30,
    fallback_years: int = 1,
) -> CountryRun:
    out_file = out_data_dir / f"{iso3}.csv"
    fail_file = out_fail_dir / f"{iso3}_failures.csv"

    end_dt = today_utc_midnight()
    start_dt = end_dt - timedelta(days=365 * years_back)

    # Resume
    if not force:
        existing_rows = load_existing_if_good(out_file, min_rows=100)
        if existing_rows is not None:
            return CountryRun(
                iso3=iso3, iso2=iso2, status="SKIPPED", rows=existing_rows,
                start=iso8601_z(start_dt), end=iso8601_z(end_dt),
                failures=0, file=str(out_file), note="existing_file"
            )

    # Probe recent coverage
    if not probe_country_recent(iso2, headers=headers, days=probe_days, chunk_days=chunk_days):
        return CountryRun(
            iso3=iso3, iso2=iso2, status="NO_COVERAGE", rows=0,
            start=iso8601_z(start_dt), end=iso8601_z(end_dt),
            failures=0, file=str(out_file), note=f"no_recent_data_{probe_days}d"
        )

    # Main download (years_back)
    df, failures = run_chunked_download(
        iso3=iso3, iso2=iso2, start_dt=start_dt, end_dt=end_dt,
        headers=headers, chunk_days=chunk_days, sleep_between_calls=sleep_between_calls
    )
    save_failures(fail_file, failures)

    if df.empty:
        # Fallback 1 year if main horizon fails
        fallback_start = end_dt - timedelta(days=365 * fallback_years)
        df2, failures2 = run_chunked_download(
            iso3=iso3, iso2=iso2, start_dt=fallback_start, end_dt=end_dt,
            headers=headers, chunk_days=chunk_days, sleep_between_calls=sleep_between_calls
        )
        # merge failures (store separate note)
        if failures2:
            save_failures(fail_file, failures + [{"note": "fallback"}] + failures2)

        if df2.empty:
            return CountryRun(
                iso3=iso3, iso2=iso2, status="FAIL", rows=0,
                start=iso8601_z(start_dt), end=iso8601_z(end_dt),
                failures=len(failures), file=str(out_file),
                note="probe_ok_but_all_windows_failed"
            )

        df = df2
        status = "PARTIAL"
        note = f"fallback_{fallback_years}y_ok (main_{years_back}y_empty)"
        start_used = fallback_start
    else:
        # Decide OK vs PARTIAL
        exp = expected_days(start_dt, end_dt)
        if len(df) >= 0.9 * exp and len(failures) == 0:
            status = "OK"
            note = "ok_full_horizon"
        else:
            status = "PARTIAL"
            note = f"partial rows={len(df)} exp~{exp} failures={len(failures)}"
        start_used = start_dt

    # Add meta + export
    df["country"] = iso3
    df["iso2"] = iso2
    df["year"] = df["date"].dt.year
    df["month"] = df["date"].dt.month
    df = df[["date", "country", "iso2", "attack_ipv4_bytes", "attack_ipv6_bytes", "year", "month"]]

    out_data_dir.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_file, index=False, encoding="utf-8")

    return CountryRun(
        iso3=iso3, iso2=iso2, status=status, rows=len(df),
        start=iso8601_z(start_used), end=iso8601_z(end_dt),
        failures=len(failures), file=str(out_file), note=note
    )


# =========================================================
# CLI main
# =========================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", default="", help="Token Radar (sinon env CLOUDFLARE_API_TOKEN)")
    parser.add_argument("--years", type=int, default=4, help="Horizon en années (default 4)")
    parser.add_argument("--chunk-days", type=int, default=90, help="Taille fenêtre en jours (default 90)")
    parser.add_argument("--sleep", type=float, default=0.5, help="Pause entre appels (default 0.5)")
    parser.add_argument("--force", action="store_true", help="Re-télécharger même si fichier existe")
    parser.add_argument("--countries", default="", help="ISO3 list séparée par virgules (subset)")
    parser.add_argument("--out", default="outputs_world", help="Dossier sortie")
    parser.add_argument("--probe-days", type=int, default=30, help="Probe: fenêtre récente (jours)")
    parser.add_argument("--fallback-years", type=int, default=1, help="Fallback si horizon échoue (années)")
    args = parser.parse_args()

    token = (args.token or "").strip() or os.getenv("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        raise SystemExit("❌ Token manquant. Mets CLOUDFLARE_API_TOKEN ou passe --token.")

    out_dir = Path(args.out).resolve()
    out_data = out_dir / "data"
    out_fail = out_dir / "failures"
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
        countries = all_iso3  # FULL WORLD

    logging.info(
        f"🌍 L3 bytes DAILY - years={args.years}, chunk={args.chunk_days}j, countries={len(countries)}"
    )

    runs: List[CountryRun] = []
    t0 = time.time()

    for i, iso3 in enumerate(countries, start=1):
        iso2 = iso3_to_iso2[iso3]
        logging.info(f"[{i}/{len(countries)}] → {iso3} ({iso2})")

        run = fetch_country(
            iso3=iso3,
            iso2=iso2,
            years_back=args.years,
            chunk_days=args.chunk_days,
            headers=headers,
            sleep_between_calls=args.sleep,
            out_data_dir=out_data,
            out_fail_dir=out_fail,
            force=args.force,
            probe_days=args.probe_days,
            fallback_years=args.fallback_years,
        )

        runs.append(run)
        logging.info(f"   {run.status} | rows={run.rows} | failures={run.failures} | {run.note}")

        # mini pause entre pays
        time.sleep(max(0.2, args.sleep))

        # Sauvegarde manifest progressive (safe si arrêt)
        if i % 10 == 0:
            pd.DataFrame([r.__dict__ for r in runs]).to_csv(
                out_dir / "manifest.csv", index=False, encoding="utf-8"
            )

    manifest = pd.DataFrame([r.__dict__ for r in runs])
    manifest.to_csv(out_dir / "manifest.csv", index=False, encoding="utf-8")

    elapsed = time.time() - t0
    ok = (manifest["status"] == "OK").sum()
    partial = (manifest["status"] == "PARTIAL").sum()
    nocov = (manifest["status"] == "NO_COVERAGE").sum()
    fail = (manifest["status"] == "FAIL").sum()
    skipped = (manifest["status"] == "SKIPPED").sum()

    logging.info("✅ Terminé.")
    logging.info(f"Résumé: OK={ok} PARTIAL={partial} NO_COVERAGE={nocov} FAIL={fail} SKIPPED={skipped}")
    logging.info(f"Manifest: {out_dir / 'manifest.csv'}")
    logging.info(f"⏱ Temps total: {elapsed/60:.1f} min")


if __name__ == "__main__":
    main()
