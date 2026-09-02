"""
Trích các mẫu CÓ CVE hoặc CÓ CWE ra một file, rồi map CVE -> CWE
để sinh cột cwe_label_final.

Quy tắc cwe_label_final:
    1. Đã có cwe_id  -> copy lại y nguyên
    2. Chưa có       -> map từ cve_id qua NVD / CVE.org / OSV
    3. Không map được -> để trống

Bảng CVE -> CWE lấy từ cache của full_process.py, không tải lại DB.
"""

import gzip
import json

from collections import Counter
from pathlib import Path

import pandas as pd

from full_process import (
    normalize_cwe_value,
)


# ============================================================
# CONFIG
# ============================================================

INPUT_PARQUET = (
    "TitanVul_recovery_ALL_FINAL.parquet"
)

OUT_PARQUET = (
    "TitanVul_cwe_label_final.parquet"
)

OUT_CSV = (
    "TitanVul_cwe_label_final.csv"
)

OUT_AUDIT = (
    "TitanVul_cwe_label_final_audit.csv"
)

OUT_TRAINABLE = (
    "TitanVul_cwe_label_final_trainable.parquet"
)


NVD_SCAN_CACHE = Path(
    "nvd_scan_cache.json.gz"
)

CVEORG_SCAN_CACHE = Path(
    "cveorg_scan_cache.json.gz"
)

OSV_SCAN_CACHE = Path(
    "osv_scan_cache.json.gz"
)


# ============================================================
# CACHE
# ============================================================

def load_cache(path):

    path = Path(
        path
    )

    if not path.exists():

        print(
            f"WARNING thiếu cache: "
            f"{path}"
        )

        return {}

    with gzip.open(
        path,
        "rt",
        encoding="utf-8",
    ) as f:

        return json.load(
            f
        )


def clean_table(table):
    """Chuẩn hoá giá trị CWE, bỏ CVE không có CWE thật."""

    result = {}

    for cve, values in (
        table.items()
    ):

        cwes = []

        for value in values:

            for cwe in (
                normalize_cwe_value(
                    value
                )
            ):

                if cwe not in cwes:

                    cwes.append(
                        cwe
                    )

        if cwes:

            result[
                cve.strip().upper()
            ] = cwes

    return result


def build_tables():

    nvd = load_cache(
        NVD_SCAN_CACHE
    )

    org = load_cache(
        CVEORG_SCAN_CACHE
    )

    osv = load_cache(
        OSV_SCAN_CACHE
    )

    # Thứ tự = thứ tự ưu tiên khi map
    tables = [
        (
            "nvd_primary",
            clean_table(
                nvd.get(
                    "cve_to_primary",
                    {}
                )
            ),
        ),
        (
            "cveorg_primary",
            clean_table(
                org.get(
                    "cve_to_primary",
                    {}
                )
            ),
        ),
        (
            "osv_cwe_ids",
            clean_table(
                osv.get(
                    "cve_to_cwes",
                    {}
                )
            ),
        ),
        (
            "nvd_all",
            clean_table(
                nvd.get(
                    "cve_to_cwes",
                    {}
                )
            ),
        ),
        (
            "cveorg_all",
            clean_table(
                org.get(
                    "cve_to_cwes",
                    {}
                )
            ),
        ),
    ]

    print(
        "\n"
        + "=" * 78
    )

    print(
        "BẢNG CVE -> CWE"
    )

    print(
        "=" * 78
    )

    for name, table in tables:

        print(
            f"  {name:<16s} "
            f"{len(table):>8,} CVE"
        )

    return tables


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 78
    )

    print(
        "TRÍCH MẪU CÓ NHÃN + MAP CVE -> CWE"
    )

    print(
        "=" * 78
    )

    df = pd.read_parquet(
        INPUT_PARQUET
    )

    print(
        f"Input: {INPUT_PARQUET} "
        f"({len(df):,} dòng)"
    )

    tables = build_tables()

    # ========================================================
    # LỌC: có CVE hoặc có CWE
    # ========================================================

    has_cve = (
        df["cve_id"].notna()
    )

    has_cwe = (
        df["cwe_id"].notna()
    )

    labeled = (
        df[
            has_cve
            |
            has_cwe
        ]
        .copy()
        .reset_index(
            drop=True
        )
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "LỌC MẪU CÓ NHÃN"
    )

    print(
        "=" * 78
    )

    print(
        f"Tổng:              "
        f"{len(df):,}"
    )

    print(
        f"Có CVE hoặc CWE:   "
        f"{len(labeled):,}"
        f"  ({len(labeled)/len(df)*100:.2f}%)"
    )

    print(
        f"  có CVE:          "
        f"{int(has_cve.sum()):,}"
    )

    print(
        f"  có CWE:          "
        f"{int(has_cwe.sum()):,}"
    )

    print(
        f"  có cả hai:       "
        f"{int((has_cve & has_cwe).sum()):,}"
    )

    print(
        f"  chỉ CVE:         "
        f"{int((has_cve & ~has_cwe).sum()):,}"
    )

    print(
        f"  chỉ CWE:         "
        f"{int((has_cwe & ~has_cve).sum()):,}"
    )

    # ========================================================
    # cwe_label_final
    # ========================================================

    final_label = []
    final_source = []
    final_all = []

    stats = Counter()

    for idx in labeled.index:

        raw_cwe = labeled.at[
            idx,
            "cwe_id"
        ]

        # ----------------------------------------------------
        # 1. đã có CWE -> copy lại
        # ----------------------------------------------------

        if (
            isinstance(raw_cwe, str)
            and
            raw_cwe.strip()
        ):

            values = (
                normalize_cwe_value(
                    raw_cwe
                )
            )

            if values:

                # cwe_id_all giữ trọn danh sách gốc
                every = (
                    normalize_cwe_value(
                        str(
                            labeled.at[
                                idx,
                                "cwe_id_all"
                            ]
                            or ""
                        )
                    )
                    or values
                )

                final_label.append(
                    values[0]
                )

                final_source.append(
                    "existing_cwe_id"
                )

                final_all.append(
                    ";".join(
                        every
                    )
                )

                stats[
                    "existing_cwe_id"
                ] += 1

                continue

        # ----------------------------------------------------
        # 2. map từ CVE
        # ----------------------------------------------------

        raw_cve = labeled.at[
            idx,
            "cve_id"
        ]

        cve = (
            str(raw_cve)
            .strip()
            .upper()
            if isinstance(raw_cve, str)
            else ""
        )

        chosen = None
        source = None
        every = []

        if cve:

            for name, table in tables:

                values = table.get(
                    cve
                )

                if not values:
                    continue

                for cwe in values:

                    if cwe not in every:

                        every.append(
                            cwe
                        )

                if chosen is None:

                    chosen = values[0]
                    source = name

        if chosen is None:

            final_label.append(
                None
            )

            final_source.append(
                None
            )

            final_all.append(
                ""
            )

            stats[
                "khong_map_duoc"
            ] += 1

            continue

        final_label.append(
            chosen
        )

        final_source.append(
            source
        )

        final_all.append(
            ";".join(
                every
            )
        )

        stats[source] += 1

    labeled[
        "cwe_label_final"
    ] = final_label

    labeled[
        "cwe_label_final_source"
    ] = final_source

    labeled[
        "cwe_label_final_all"
    ] = final_all

    labeled[
        "has_cwe_label_final"
    ] = (
        labeled[
            "cwe_label_final"
        ].notna()
    )

    # ========================================================
    # BÁO CÁO
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "NGUỒN CỦA cwe_label_final"
    )

    print(
        "=" * 78
    )

    for key, value in (
        stats.most_common()
    ):

        print(
            f"  {key:<20s} "
            f"{value:>7,}"
        )

    filled = int(
        labeled[
            "has_cwe_label_final"
        ].sum()
    )

    print(
        f"\ncwe_label_final có giá trị: "
        f"{filled:,}/{len(labeled):,} "
        f"({filled/len(labeled)*100:.2f}%)"
    )

    multi = int(
        (
            labeled[
                "cwe_label_final_all"
            ]
            .str.count(";")
            > 0
        ).sum()
    )

    print(
        f"dòng có >1 CWE ứng viên:   "
        f"{multi:,}"
        f"  (xem cwe_label_final_all)"
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "PHÂN BỐ cwe_label_final (top 25)"
    )

    print(
        "=" * 78
    )

    counts = (
        labeled[
            "cwe_label_final"
        ]
        .value_counts()
    )

    print(
        f"Số lớp CWE: "
        f"{len(counts):,}"
    )

    print(
        counts
        .head(25)
        .to_string()
    )

    tail = int(
        (counts < 10).sum()
    )

    print(
        f"\nLớp có <10 mẫu: "
        f"{tail:,}"
        f"/{len(counts):,}"
    )

    # ========================================================
    # GHI FILE
    # ========================================================

    labeled.to_parquet(
        OUT_PARQUET,
        index=False,
    )

    labeled.to_csv(
        OUT_CSV,
        index=False,
    )

    audit_cols = [
        col
        for col in [
            "file_name",
            "extension",
            "language",

            "commit_link",
            "commit_sha",

            "cve_id",
            "cve_source",
            "cve_confidence",

            "cwe_id",
            "cwe_id_all",
            "cwe_source",
            "cwe_confidence",

            "cwe_label_final",
            "cwe_label_final_source",
            "cwe_label_final_all",
            "has_cwe_label_final",
        ]
        if col in labeled.columns
    ]

    labeled[
        audit_cols
    ].to_csv(
        OUT_AUDIT,
        index=True,
    )

    trainable = labeled[
        labeled[
            "has_cwe_label_final"
        ]
    ]

    trainable.to_parquet(
        OUT_TRAINABLE,
        index=False,
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "OUTPUT"
    )

    print(
        "=" * 78
    )

    print(
        f"{OUT_PARQUET}  "
        f"({len(labeled):,} dòng, "
        f"toàn bộ mẫu có nhãn)"
    )

    print(
        f"{OUT_CSV}"
    )

    print(
        f"{OUT_AUDIT}  "
        f"(bản gọn để soi tay)"
    )

    print(
        f"{OUT_TRAINABLE}  "
        f"({len(trainable):,} dòng, "
        f"chỉ dòng có cwe_label_final)"
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "DONE"
    )

    print(
        "=" * 78
    )


if __name__ == "__main__":
    main()
