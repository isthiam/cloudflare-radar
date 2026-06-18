import os
import pandas as pd
from pandas.errors import EmptyDataError
from pandas import DatetimeTZDtype


INPUT_LONG = "radar_adm1_timeseries_all_countries_async.csv"
INPUT_ERRORS = "radar_adm1_timeseries_errors_async.csv"
INPUT_GEO = "radar_adm1_geolocations_cache_async.csv"
INPUT_MISSING = "radar_adm1_missing_geolocations_async.csv"
OUTPUT_XLSX = "radar_adm1_analysis.xlsx"


def safe_read_csv(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        return pd.DataFrame()

    if os.path.getsize(path) == 0:
        return pd.DataFrame()

    try:
        return pd.read_csv(path, encoding="utf-8-sig", low_memory=False)
    except EmptyDataError:
        return pd.DataFrame()


def auto_adjust_columns(writer, df: pd.DataFrame, sheet_name: str, max_width: int = 40):
    worksheet = writer.sheets[sheet_name]
    for i, col in enumerate(df.columns):
        col_values = df[col].astype(str).fillna("")
        max_len = max([len(str(col))] + col_values.map(len).tolist())
        width = min(max_len + 2, max_width)
        worksheet.set_column(i, i, width)


def add_table(writer, df: pd.DataFrame, sheet_name: str):
    worksheet = writer.sheets[sheet_name]
    nrows, ncols = df.shape
    if nrows == 0 or ncols == 0:
        return

    worksheet.add_table(
        0, 0, nrows, ncols - 1,
        {
            "columns": [{"header": c} for c in df.columns],
            "style": "Table Style Medium 9",
        }
    )


def prepare_long_data(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    out = df.copy()

    if "timestamp" in out.columns:
        out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
        out["timestamp"] = out["timestamp"].dt.tz_localize(None)

    if "value" in out.columns:
        out["value"] = pd.to_numeric(out["value"], errors="coerce")

    if "geo_found" in out.columns:
        out["geo_found"] = out["geo_found"].astype("boolean")

    preferred_cols = [
        "country_code", "country_name", "continent", "region", "subregion",
        "metric", "metric_key",
        "geo_id", "geo_name", "geo_code", "geo_type",
        "parent_geo_id", "parent_geo_name", "parent_geo_type",
        "geo_found", "geo_error",
        "timestamp", "value", "raw_value"
    ]
    existing = [c for c in preferred_cols if c in out.columns]
    others = [c for c in out.columns if c not in existing]
    out = out[existing + others]

    return out


def build_aggreg_country_adm1(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    group_cols = ["country_code", "country_name", "metric", "geo_id", "geo_name", "geo_found"]

    agg = (
        df.groupby(group_cols, dropna=False)
        .agg(
            n_obs=("value", "count"),
            mean_value=("value", "mean"),
            median_value=("value", "median"),
            std_value=("value", "std"),
            min_value=("value", "min"),
            max_value=("value", "max"),
            first_timestamp=("timestamp", "min"),
            last_timestamp=("timestamp", "max"),
        )
        .reset_index()
    )

    agg["cv"] = agg["std_value"] / agg["mean_value"]
    agg = agg.sort_values(
        ["country_name", "metric", "mean_value"],
        ascending=[True, True, False]
    ).reset_index(drop=True)

    return agg


def build_top_adm1_by_country(agg: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    if agg.empty:
        return pd.DataFrame()

    out = agg.copy()
    out["rank_in_country_metric"] = (
        out.groupby(["country_code", "metric"])["mean_value"]
        .rank(method="dense", ascending=False)
    )

    out = out[out["rank_in_country_metric"] <= top_n].copy()
    out = out.sort_values(
        ["country_name", "metric", "rank_in_country_metric", "mean_value"],
        ascending=[True, True, True, False]
    ).reset_index(drop=True)

    return out


def build_country_metric_summary(df: pd.DataFrame, agg: pd.DataFrame) -> pd.DataFrame:
    if df.empty or agg.empty:
        return pd.DataFrame()

    if "geo_found" not in df.columns:
        df = df.copy()
        df["geo_found"] = False

    obs_summary = (
        df.groupby(["country_code", "country_name", "metric"], dropna=False)
        .agg(
            total_obs=("value", "count"),
            n_geo_ids=("geo_id", "nunique"),
            n_geo_names=("geo_name", "nunique"),
            n_missing_geo_rows=("geo_found", lambda s: (~s.fillna(False)).sum()),
        )
        .reset_index()
    )

    top1 = (
        agg.sort_values(["country_code", "metric", "mean_value"], ascending=[True, True, False])
        .groupby(["country_code", "metric"], dropna=False)
        .head(1)
        .loc[:, ["country_code", "metric", "geo_id", "geo_name", "mean_value"]]
        .rename(columns={
            "geo_id": "top_geo_id",
            "geo_name": "top_geo_name",
            "mean_value": "top_geo_mean_value"
        })
    )

    top5 = (
        agg.sort_values(["country_code", "metric", "mean_value"], ascending=[True, True, False])
        .groupby(["country_code", "metric"], dropna=False)
        .head(5)
        .groupby(["country_code", "metric"], dropna=False)
        .agg(
            top5_mean_sum=("mean_value", "sum"),
            top5_geo_count=("geo_id", "count"),
        )
        .reset_index()
    )

    out = obs_summary.merge(
        top1, on=["country_code", "metric"], how="left"
    ).merge(
        top5, on=["country_code", "metric"], how="left"
    )

    out = out.sort_values(["country_name", "metric"]).reset_index(drop=True)
    return out


def make_excel_safe(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    out = df.copy()

    for col in out.columns:
        if isinstance(out[col].dtype, DatetimeTZDtype):
            out[col] = out[col].dt.tz_localize(None)

    return out


def write_excel(
    df_long: pd.DataFrame,
    df_agg: pd.DataFrame,
    df_top: pd.DataFrame,
    df_summary: pd.DataFrame,
    df_missing: pd.DataFrame,
    df_errors: pd.DataFrame,
    df_geo: pd.DataFrame,
    output_path: str,
):
    with pd.ExcelWriter(output_path, engine="xlsxwriter", datetime_format="yyyy-mm-dd hh:mm:ss") as writer:
        workbook = writer.book

        header_format = workbook.add_format({
            "bold": True,
            "text_wrap": False,
            "valign": "top",
            "border": 1
        })

        sheets = [
            ("data_long", make_excel_safe(df_long)),
            ("aggreg_country_adm1", make_excel_safe(df_agg)),
            ("top_adm1_by_country", make_excel_safe(df_top)),
            ("country_metric_summary", make_excel_safe(df_summary)),
            ("missing_geos", make_excel_safe(df_missing)),
            ("api_errors", make_excel_safe(df_errors)),
            ("geo_cache", make_excel_safe(df_geo)),
        ]

        for sheet_name, df in sheets:
            if df.empty:
                empty_df = pd.DataFrame({"info": ["Aucune donnée"]})
                empty_df.to_excel(writer, sheet_name=sheet_name, index=False)
                auto_adjust_columns(writer, empty_df, sheet_name)
                continue

            # Limite Excel
            if len(df) > 1_048_575:
                df = df.iloc[:1_048_575].copy()

            df.to_excel(writer, sheet_name=sheet_name, index=False)

            worksheet = writer.sheets[sheet_name]
            for col_num, value in enumerate(df.columns):
                worksheet.write(0, col_num, value, header_format)

            add_table(writer, df, sheet_name)
            auto_adjust_columns(writer, df, sheet_name)
            worksheet.freeze_panes(1, 0)
            worksheet.set_column("A:Z", 18)

        print(f"Fichier Excel créé : {output_path}")


def main():
    print("Lecture des fichiers...")

    df_long = safe_read_csv(INPUT_LONG)
    df_errors = safe_read_csv(INPUT_ERRORS)
    df_geo = safe_read_csv(INPUT_GEO)
    df_missing = safe_read_csv(INPUT_MISSING)

    print(f"Données longues : {len(df_long):,} lignes")
    print(f"Erreurs API : {len(df_errors):,} lignes")
    print(f"Cache géo : {len(df_geo):,} lignes")
    print(f"Géo manquants : {len(df_missing):,} lignes")

    print("Préparation des données...")
    df_long = prepare_long_data(df_long)

    print("Agrégation pays / ADM1 / métrique...")
    df_agg = build_aggreg_country_adm1(df_long)

    print("Construction du top ADM1 par pays...")
    df_top = build_top_adm1_by_country(df_agg, top_n=10)

    print("Construction du résumé pays / métrique...")
    df_summary = build_country_metric_summary(df_long, df_agg)

    print("Export Excel...")
    write_excel(
        df_long=df_long,
        df_agg=df_agg,
        df_top=df_top,
        df_summary=df_summary,
        df_missing=df_missing,
        df_errors=df_errors,
        df_geo=df_geo,
        output_path=OUTPUT_XLSX,
    )

    print("\nTerminé.")
    print(f"- {OUTPUT_XLSX}")
    print(f"- data_long : {len(df_long):,}")
    print(f"- aggreg_country_adm1 : {len(df_agg):,}")
    print(f"- top_adm1_by_country : {len(df_top):,}")
    print(f"- country_metric_summary : {len(df_summary):,}")


if __name__ == "__main__":
    main()