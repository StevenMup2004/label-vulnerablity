"""
Khôi phục CVE / CWE cho các dòng đang thiếu.

Tiêu chí: mỗi dòng chỉ cần CÓ ÍT NHẤT MỘT trong hai
(CVE hoặc CWE), không cần đủ cả hai.

Ba nguồn khôi phục, đã kiểm chứng bằng leave-one-out
trên chính các dòng đã có nhãn:

    lan truyền theo commit_link (CVE)  99.18%
    lan truyền theo commit_link (CWE)  94.21%
    regex CVE trong commit_message     89.94%

Vì độ chính xác khác nhau, nguồn của từng nhãn được ghi
lại ở cve_source / cwe_source. Nhãn gốc không bao giờ
bị ghi đè.

LƯU Ý QUAN TRỌNG:
Phần lớn các dòng thiếu cả hai KHÔNG phải mất dữ liệu mà
là vốn không có CVE (cve_description null 100% ở nhóm này).
CVE do MITRE/NVD cấp nên không thể suy ra từ code. Script
này chỉ khôi phục những gì thực sự tìm lại được từ
metadata, không sinh ra định danh mới.
"""

import re

import pandas as pd


INPUT_PARQUET = "TitanVul_language_FINAL.parquet"

OUTPUT_PARQUET = "TitanVul_language_FINAL_recovered.parquet"
OUTPUT_CSV = "TitanVul_language_FINAL_recovered.csv"


CVE_PATTERN = re.compile(
    r"CVE[-_ ]?(\d{4})[-_ ]?(\d{4,7})", re.I
)


def extract_cve(text):

    if not isinstance(text, str):
        return None

    match = CVE_PATTERN.search(text)

    if not match:
        return None

    return f"CVE-{match.group(1)}-{match.group(2)}"


def main():

    df = pd.read_parquet(INPUT_PARQUET)

    n = len(df)

    print("=" * 66)
    print("RECOVER CVE / CWE")
    print("=" * 66)

    before_any = (
        df["cve_id"].notna() | df["cwe_id"].notna()
    ).sum()

    print(f"Tổng dòng:            {n:,}")
    print(f"Có sẵn >=1 nhãn:      {before_any:,}")
    print(f"Thiếu cả hai:         {n - before_any:,}")

    df["cve_source"] = None
    df.loc[df["cve_id"].notna(), "cve_source"] = "original"

    df["cwe_source"] = None
    df.loc[df["cwe_id"].notna(), "cwe_source"] = "original"

    # --------------------------------------------------------
    # Bảng tra, xây từ CHÍNH các dòng đã có nhãn
    # --------------------------------------------------------

    def majority(series):
        mode = series.mode()
        return mode.iat[0] if len(mode) else None

    labelled_cve = df[
        df["cve_id"].notna() & df["commit_link"].notna()
    ]

    commit_to_cve = (
        labelled_cve.groupby("commit_link")["cve_id"]
        .agg(majority)
    )

    labelled_cwe = df[
        df["cwe_id"].notna() & df["commit_link"].notna()
    ]

    commit_to_cwe = (
        labelled_cwe.groupby("commit_link")["cwe_id"]
        .agg(majority)
    )

    cve_to_cwe = (
        df[df["cve_id"].notna() & df["cwe_id"].notna()]
        .groupby("cve_id")["cwe_id"]
        .agg(majority)
    )

    print(f"\nBảng commit->CVE:     {len(commit_to_cve):,}")
    print(f"Bảng commit->CWE:     {len(commit_to_cwe):,}")
    print(f"Bảng CVE->CWE:        {len(cve_to_cwe):,}")

    counters = {
        "cve_propagated": 0,
        "cve_regex": 0,
        "cwe_propagated": 0,
        "cwe_from_cve": 0,
    }

    # --------------------------------------------------------
    # 1. Lan truyền CVE theo commit  (99.18%)
    # --------------------------------------------------------

    need = df["cve_id"].isna() & df["commit_link"].notna()

    filled = df.loc[need, "commit_link"].map(commit_to_cve)

    idx = filled[filled.notna()].index

    df.loc[idx, "cve_id"] = filled.loc[idx]
    df.loc[idx, "cve_source"] = "propagated_commit"

    counters["cve_propagated"] = len(idx)

    # --------------------------------------------------------
    # 2. Regex CVE trong commit_message  (89.94%)
    # --------------------------------------------------------

    need = df["cve_id"].isna()

    filled = df.loc[need, "commit_message"].apply(
        extract_cve
    )

    idx = filled[filled.notna()].index

    df.loc[idx, "cve_id"] = filled.loc[idx]
    df.loc[idx, "cve_source"] = "regex_message"

    counters["cve_regex"] = len(idx)

    # --------------------------------------------------------
    # 3. Lan truyền CWE theo commit  (94.21%)
    # --------------------------------------------------------

    need = df["cwe_id"].isna() & df["commit_link"].notna()

    filled = df.loc[need, "commit_link"].map(commit_to_cwe)

    idx = filled[filled.notna()].index

    df.loc[idx, "cwe_id"] = filled.loc[idx]
    df.loc[idx, "cwe_source"] = "propagated_commit"

    counters["cwe_propagated"] = len(idx)

    # --------------------------------------------------------
    # 4. CVE -> CWE, dùng cả CVE vừa khôi phục
    # --------------------------------------------------------

    need = df["cwe_id"].isna() & df["cve_id"].notna()

    filled = df.loc[need, "cve_id"].map(cve_to_cwe)

    idx = filled[filled.notna()].index

    df.loc[idx, "cwe_id"] = filled.loc[idx]
    df.loc[idx, "cwe_source"] = "mapped_from_cve"

    counters["cwe_from_cve"] = len(idx)

    # --------------------------------------------------------
    # Báo cáo
    # --------------------------------------------------------

    print("\n" + "=" * 66)
    print("KHÔI PHỤC ĐƯỢC")
    print("=" * 66)

    for name, value in counters.items():
        print(f"  {name:20s} {value:6,}")

    has_any = df["cve_id"].notna() | df["cwe_id"].notna()

    df["has_vuln_label"] = has_any

    print("\n" + "=" * 66)
    print("KẾT QUẢ (tiêu chí: có ít nhất 1 trong 2)")
    print("=" * 66)

    print(
        f"  Trước:  {before_any:,}/{n:,} "
        f"({before_any / n * 100:.2f}%)"
    )
    print(
        f"  Sau:    {has_any.sum():,}/{n:,} "
        f"({has_any.sum() / n * 100:.2f}%)"
    )
    print(
        f"  Tăng:   +{has_any.sum() - before_any:,}"
    )
    print(
        f"  Vẫn thiếu cả hai: "
        f"{n - has_any.sum():,} "
        f"({(n - has_any.sum()) / n * 100:.2f}%)"
    )

    print("\nNguồn nhãn CVE:")
    print(df["cve_source"].value_counts(dropna=False).to_string())

    print("\nNguồn nhãn CWE:")
    print(df["cwe_source"].value_counts(dropna=False).to_string())

    df.to_parquet(OUTPUT_PARQUET, index=False)
    print(f"\nSaved: {OUTPUT_PARQUET}")

    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
