"""
Lấy nhãn dòng lỗi từ BigVul cho các dòng TitanVul khớp được.

BigVul bản đầy đủ (36 cột) có lines_before / lines_after — chính là
"flaw lines" mà tác giả BigVul tạo ra bằng cách diff hai mini-version.
Trích dẫn README của họ:

  "We used the code changes information (mined from committed version
   patches) to localize which lines of code in the files were modified.
   Taking modified lines between the two mini-versions as flaw lines..."

Mirror bstee615/bigvul trên HuggingFace ĐÃ BỎ hai cột này - chỉ còn
11 cột. Bản dùng ở đây là DynaOuchebara/BigVul.

Khớp bằng func_before đã chuẩn hoá whitespace (chặt), có kiểm tra
thêm bằng commit_sha để báo mức tin cậy.

Ra:  TitanVul_line_labels_bigvul.parquet
     TitanVul_line_labels_bigvul_audit.csv
"""

import glob
import hashlib
import re
import sys

from collections import Counter

from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq


# Bản HF tự convert sang parquet: 1.1 GB thay vì 10.3 GB CSV,
# và đọc được CHỌN CỘT nên chỉ nạp 9/36 cột cần dùng.
ROOT = Path(
    __file__
).resolve().parent

DATA_OUT = ROOT / "data" / "output"

DATA_AUDIT = ROOT / "data" / "audit"

CACHE = ROOT / "cache"


# BigVul bản HF tự convert sang parquet: 1.2 GB thay vì 10.3 GB
# CSV, và đọc được CHỌN CỘT nên chỉ nạp 9/36 cột cần dùng.
BIGVUL_GLOB = str(
    CACHE / "bigvul" / "*.parquet"
)

INPUT_PARQUET = (
    DATA_OUT
    / "TitanVul_cwe_labels_trainable.parquet"
)

OUT_PARQUET = (
    DATA_OUT
    / "TitanVul_line_labels_bigvul.parquet"
)

OUT_AUDIT = (
    DATA_AUDIT
    / "TitanVul_line_labels_bigvul_audit.csv"
)


NEEDED = [
    "func_before",
    "func_after",
    "lines_before",
    "lines_after",
    "vul",
    "vul_func_with_fix",
    "commit_id",
    "CVE ID",
    "CWE ID",
    "codeLink",
    "project",
]


def norm_hash(text):
    """Hash hàm sau khi gộp mọi whitespace - khớp bền với format."""

    if not isinstance(
        text,
        str,
    ):
        return None

    squashed = (
        re.sub(
            r"\s+",
            " ",
            text,
        )
        .strip()
    )

    if not squashed:
        return None

    return hashlib.md5(
        squashed.encode()
    ).hexdigest()


def load_bigvul():

    files = sorted(
        glob.glob(
            BIGVUL_GLOB
        )
    )

    if not files:

        sys.exit(
            "Chưa có file BigVul parquet. "
            "Tải DynaOuchebara/BigVul trước."
        )

    frames = []
    skipped = []

    for path in files:

        print(
            f"  đọc {path.rsplit('/', 1)[-1]}",
            flush=True,
        )

        # bỏ qua file đang tải dở / hỏng thay vì chết cả script
        try:

            available = [
                c
                for c in pq.read_schema(
                    path
                ).names
                if c in NEEDED
            ]

            frame = pd.read_parquet(
                path,
                columns=available,
            )

        except Exception as e:

            print(
                f"    BỎ QUA (không đọc được): "
                f"{type(e).__name__}"
            )

            skipped.append(
                path
            )

            continue

        frames.append(
            frame
        )

    bigvul = pd.concat(
        frames,
        ignore_index=True,
    )

    print(
        f"  BigVul: {len(bigvul):,} dòng"
        f"  ({len(frames)}/{len(files)} file đọc được)"
    )

    if skipped:

        print(
            f"  CẢNH BÁO bỏ qua {len(skipped)} file "
            f"-> overlap báo dưới đây là CHƯA ĐỦ"
        )

    return bigvul


def main():

    print(
        "=" * 78
    )

    print(
        "LẤY NHÃN DÒNG TỪ BIGVUL"
    )

    print(
        "=" * 78
    )

    bigvul = load_bigvul()

    print(
        f"\ncột có: "
        f"{[c for c in NEEDED if c in bigvul.columns]}"
    )

    # ========================================================
    # chỉ giữ dòng BigVul thực sự có nhãn dòng
    # ========================================================

    has_lines = (
        bigvul["lines_before"]
        .astype("string")
        .fillna("")
        .str.strip()
        != ""
    )

    print(
        f"\nBigVul có lines_before: "
        f"{int(has_lines.sum()):,}"
        f"/{len(bigvul):,}"
    )

    print(
        f"  vul=1 và có lines_before: "
        f"{int((has_lines & (bigvul['vul'] == 1)).sum()):,}"
    )

    bigvul["h"] = (
        bigvul["func_before"]
        .map(
            norm_hash
        )
    )

    bigvul["sha"] = (
        bigvul["commit_id"]
        .astype("string")
        .str.strip()
        .str.lower()
    )

    # ưu tiên dòng có nhãn dòng khi một hash trùng nhiều bản ghi
    bigvul = (
        bigvul
        .assign(
            _rank=(
                (~has_lines).astype(int)
                +
                (bigvul["vul"] != 1).astype(int)
            )
        )
        .sort_values(
            "_rank"
        )
        .drop_duplicates(
            subset=["h"],
            keep="first",
        )
    )

    print(
        f"  sau khi gộp theo hash: "
        f"{len(bigvul):,} bản ghi duy nhất"
    )

    lookup = (
        bigvul
        .set_index("h")
        [
            [
                "lines_before",
                "lines_after",
                "vul",
                "vul_func_with_fix",
                "sha",
                "CVE ID",
                "CWE ID",
                "project",
            ]
        ]
    )

    # ========================================================
    # TITANVUL
    # ========================================================

    df = pd.read_parquet(
        INPUT_PARQUET
    )

    print(
        f"\nTitanVul: {len(df):,} dòng"
    )

    df["_h"] = (
        df["func_before"]
        .map(
            norm_hash
        )
    )

    joined = df.join(
        lookup.rename(
            columns={
                "lines_before":
                    "bigvul_lines_before",
                "lines_after":
                    "bigvul_lines_after",
                "vul":
                    "bigvul_vul",
                "vul_func_with_fix":
                    "bigvul_func_with_fix",
                "sha":
                    "bigvul_commit_id",
                "CVE ID":
                    "bigvul_cve_id",
                "CWE ID":
                    "bigvul_cwe_id",
                "project":
                    "bigvul_project",
            }
        ),
        on="_h",
    )

    matched = (
        joined["bigvul_lines_before"]
        .astype("string")
        .fillna("")
        .str.strip()
        != ""
    )

    joined["has_bigvul_lines"] = matched

    # ========================================================
    # mức tin cậy của phép khớp
    # ========================================================

    same_sha = (
        joined["commit_sha"]
        .astype("string")
        .str.lower()
        ==
        joined["bigvul_commit_id"]
        .astype("string")
        .str.lower()
    )

    same_cve = (
        joined["cve_id"]
        .astype("string")
        .str.upper()
        ==
        joined["bigvul_cve_id"]
        .astype("string")
        .str.upper()
    )

    joined["bigvul_match_level"] = None

    joined.loc[
        matched,
        "bigvul_match_level"
    ] = "func_only"

    joined.loc[
        matched & same_cve,
        "bigvul_match_level"
    ] = "func_and_cve"

    joined.loc[
        matched & same_sha,
        "bigvul_match_level"
    ] = "func_and_commit"

    joined.loc[
        matched & same_sha & same_cve,
        "bigvul_match_level"
    ] = "func_commit_cve"

    # số dòng lỗi BigVul ghi nhận
    joined["bigvul_line_count"] = (
        joined["bigvul_lines_before"]
        .astype("string")
        .fillna("")
        .apply(
            lambda s: (
                len(
                    [
                        x
                        for x in s.splitlines()
                        if x.strip()
                    ]
                )
                if s.strip()
                else 0
            )
        )
    )

    # ========================================================
    # BÁO CÁO
    # ========================================================

    n = len(joined)

    print(
        "\n"
        + "=" * 78
    )

    print(
        "KẾT QUẢ"
    )

    print(
        "=" * 78
    )

    print(
        f"Có nhãn dòng từ BigVul: "
        f"{int(matched.sum()):,}/{n:,} "
        f"({matched.mean() * 100:.2f}%)"
    )

    print(
        f"Chưa có:                "
        f"{int((~matched).sum()):,}"
    )

    print(
        "\nmức tin cậy phép khớp:"
    )

    print(
        joined
        .loc[
            matched,
            "bigvul_match_level"
        ]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    print(
        "\nBigVul vul flag của phần khớp:"
    )

    print(
        joined
        .loc[matched, "bigvul_vul"]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    print(
        "\nsố dòng lỗi mỗi hàm (BigVul):"
    )

    counts = (
        joined
        .loc[matched, "bigvul_line_count"]
    )

    print(
        f"  trung bình {counts.mean():.1f}"
        f"  |  trung vị {counts.median():.0f}"
        f"  |  max {counts.max()}"
    )

    dist = Counter(
        counts.clip(
            upper=11
        )
    )

    for k in sorted(
        dist
    ):

        label = (
            ">10"
            if k == 11
            else str(k)
        )

        print(
            f"    {label:>4s} dòng: "
            f"{dist[k]:>6,}"
        )

    print(
        "\ntheo ngôn ngữ:"
    )

    per_lang = (
        joined
        .groupby("language")
        .agg(
            tong=("_h", "size"),
            co_nhan_dong=(
                "has_bigvul_lines",
                "sum",
            ),
        )
    )

    per_lang["%"] = (
        per_lang["co_nhan_dong"]
        /
        per_lang["tong"]
        *
        100
    ).round(1)

    print(
        per_lang
        .sort_values(
            "tong",
            ascending=False,
        )
        .head(10)
        .to_string()
    )

    # ========================================================
    # GHI
    # ========================================================

    joined = joined.drop(
        columns=["_h"]
    )

    joined.to_parquet(
        OUT_PARQUET,
        index=False,
    )

    audit_cols = [
        c
        for c in [
            "file_name",
            "language",
            "cve_id",
            "cwe_label_final",
            "commit_sha",
            "bigvul_project",
            "bigvul_cve_id",
            "bigvul_cwe_id",
            "bigvul_vul",
            "bigvul_match_level",
            "bigvul_line_count",
            "bigvul_lines_before",
            "bigvul_lines_after",
            "has_bigvul_lines",
        ]
        if c in joined.columns
    ]

    joined[
        audit_cols
    ].to_csv(
        OUT_AUDIT,
        index=True,
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
        f"  {str(OUT_PARQUET.name):<45s} "
        f"{len(joined):>7,} dòng"
    )

    print(
        f"  {str(OUT_AUDIT.name):<45s} "
        f"{len(joined):>7,} dòng"
    )

    print(
        "\nDONE"
    )


if __name__ == "__main__":
    main()
