"""
Thêm cột phân loại lỗ hổng (CWE-699 / 7 loại / 4 nhóm) vào file nhãn dòng.

Chạy:
    python add_vuln_type.py data/output/ext80.parquet
    python add_vuln_type.py data/output/joern70.parquet

Cột thêm vào:
    vuln_type_7      1 trong 7 loại CWE-699 (loại chính)
    vuln_type_4      1 trong 4 nhóm  <- dùng chia expert
    vuln_type_7_all  đa nhãn, ngăn ';'
    vuln_type_4_all  đa nhãn, ngăn ';'
    vuln_type_how    quy tắc nào quyết định (để lọc/audit)
"""

import sys

from collections import Counter
from pathlib import Path

import pandas as pd

from vuln_type import Catalog, group_of, TYPE_TO_GROUP


def main():

    path = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else "data/output/ext80.parquet"
    )

    cat = Catalog()

    df = pd.read_parquet(path)

    # đa nhãn: dùng CWE đã lọc tổ tiên nếu có, không thì nhãn chính
    src = (
        df["cwe_pruned"]
        if "cwe_pruned" in df.columns
        else df["cwe_label_final"]
    )

    cache = {}

    def classify(value):

        cwes = [
            x.strip()
            for x in str(value).replace(",", ";").split(";")
            if x.strip().upper().startswith("CWE-")
        ]

        if not cwes:
            cwes = []

        types = set()
        hows = []

        for c in cwes:

            if c not in cache:
                cache[c] = cat.classify(c)

            t, how = cache[c]

            types |= t
            hows.append(how)

        # loại chính = của CWE đầu tiên phân được
        primary = None

        for c in cwes:

            t, _ = cache[c]

            if t:
                primary = sorted(t)[0]
                break

        how = (
            min(hows)
            if hows
            else "6_không_phân_được"
        )

        return primary, sorted(types), how

    out = src.map(classify)

    df["vuln_type_7"] = out.map(lambda x: x[0])

    df["vuln_type_7_all"] = out.map(
        lambda x: ";".join(x[1])
    )

    df["vuln_type_how"] = out.map(lambda x: x[2])

    df["vuln_type_4"] = df["vuln_type_7"].map(group_of)

    df["vuln_type_4_all"] = df["vuln_type_7_all"].map(
        lambda s: ";".join(
            sorted(
                {
                    TYPE_TO_GROUP[x]
                    for x in s.split(";")
                    if x in TYPE_TO_GROUP
                }
            )
        )
    )

    lab = (
        df[df["has_line_label"]]
        if "has_line_label" in df.columns
        else df
    )

    n = len(lab)

    miss = int(lab["vuln_type_7"].isna().sum())

    print(f"{path.name}: {len(df):,} dòng")

    print(
        f"mẫu có nhãn dòng: {n:,}  | "
        f"phủ {n - miss:,} = {(n - miss) / n * 100:.2f}%  | "
        f"sót {miss}"
    )

    print("\nquy tắc quyết định:")

    for k, v in (
        lab["vuln_type_how"]
        .value_counts()
        .sort_index()
        .items()
    ):
        print(f"  {k:<24}{v:>8,}{v / n * 100:>7.1f}%")

    print("\n7 LOẠI (chính | đa nhãn):")

    p7 = lab["vuln_type_7"].value_counts()

    m7 = Counter(
        x
        for s in lab["vuln_type_7_all"]
        for x in s.split(";")
        if x
    )

    for k, v in p7.items():
        print(
            f"  {k:<28}{v:>8,}{v / n * 100:>7.1f}%"
            f"{m7[k]:>9,}"
        )

    print("\n4 NHÓM (chính | đa nhãn):")

    p4 = lab["vuln_type_4"].value_counts()

    m4 = Counter(
        x
        for s in lab["vuln_type_4_all"]
        for x in s.split(";")
        if x
    )

    for k, v in p4.items():
        print(
            f"  {k:<28}{v:>8,}{v / n * 100:>7.1f}%"
            f"{m4[k]:>9,}"
        )

    print(
        f"  lệch max/min: {p4.max() / p4.min():.1f}x"
    )

    print(
        f"\nmẫu đa nhãn (>1 nhóm): "
        f"{int((lab['vuln_type_4_all'].str.count(';') > 0).sum()):,}"
    )

    df.to_parquet(path, index=False)

    print(f"\nĐÃ GHI: {path}")

    # audit theo CWE
    if "cwe_label_final" in lab.columns:

        rows = []

        for c in sorted(
            lab["cwe_label_final"].dropna().unique()
        ):
            t, how = cat.classify(c)

            rows.append(
                {
                    "cwe": c,
                    "name": cat.name.get(
                        str(c).replace("CWE-", ""),
                        "?",
                    ),
                    "n": int(
                        (lab["cwe_label_final"] == c).sum()
                    ),
                    "vuln_type_7": ";".join(sorted(t)),
                    "vuln_type_4": ";".join(
                        sorted(
                            {
                                TYPE_TO_GROUP[x]
                                for x in t
                                if x in TYPE_TO_GROUP
                            }
                        )
                    ),
                    "rule": how,
                }
            )

        a = (
            Path("data/audit")
            / f"vuln_type_{path.stem}.csv"
        )

        a.parent.mkdir(parents=True, exist_ok=True)

        (
            pd.DataFrame(rows)
            .sort_values("n", ascending=False)
            .to_csv(a, index=False)
        )

        print(f"audit theo CWE: {a}")


if __name__ == "__main__":
    main()
