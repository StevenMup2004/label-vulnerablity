"""
Thêm cột nhóm cơ chế lỗi (đa nhãn) vào file nhãn dòng.

Chạy:
    python add_cwe_groups.py data/output/ext80.parquet
    python add_cwe_groups.py data/output/joern70.parquet

Cột thêm vào:
    cwe_group        nhóm CHÍNH (một giá trị, để phân tầng/báo cáo)
    cwe_group_all    TẤT CẢ nhóm, ngăn bằng ';'  <- dùng cái này khi train
    n_cwe_groups     số nhóm
    cwe_group_src    tầng bằng chứng nào quyết định nhóm chính
    cwe_pruned       CWE sau khi bỏ tổ tiên
    cwe_multi_label  True nếu thuộc nhiều hơn một nhóm
"""

import sys

from collections import Counter
from pathlib import Path

import pandas as pd

from cwe_mech_groups import assign, split_memory


def main():

    path = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else "data/output/ext80.parquet"
    )

    df = pd.read_parquet(path)

    print(
        f"{path.name}: {len(df):,} dòng"
    )

    prim = []
    alls = []
    srcs = []
    prun = []

    for r in df.itertuples(index=False):

        p, gs, tier, pr = assign(
            getattr(r, "cwe_label_final_all", ""),
            getattr(r, "commit_message", "") or "",
            getattr(r, "cve_description", "") or "",
            getattr(r, "vul_lines_text", "") or "",
            getattr(r, "func_before", "") or "",
        )

        prim.append(p)
        alls.append(gs)
        srcs.append(tier)
        prun.append(";".join(pr))

    df["cwe_group"] = prim
    df["cwe_group_src"] = srcs
    df["cwe_pruned"] = prun

    # tầng 7: nhóm đa số của cùng project
    todo = df["cwe_group"].isna()

    if todo.any() and "project_key" in df.columns:

        maj = (
            df[~todo]
            .groupby("project_key")["cwe_group"]
            .agg(
                lambda s: s.value_counts().index[0]
            )
        )

        df.loc[todo, "cwe_group"] = (
            df.loc[todo, "project_key"].map(maj)
        )

        df.loc[
            todo & df["cwe_group"].notna(),
            "cwe_group_src"
        ] = "7_project"

    still = df["cwe_group"].isna()

    df.loc[still, "cwe_group"] = "mem_spatial"
    df.loc[still, "cwe_group_src"] = "8_mặc_định"

    # chẻ nhóm bộ nhớ theo mẫu hình code
    df["cwe_group"] = [
        split_memory(g, fb)
        for g, fb in zip(
            df["cwe_group"],
            df["func_before"],
        )
    ]

    df["cwe_group_all"] = [
        ";".join(
            sorted(
                {
                    split_memory(x, fb)
                    for x in (gs or [])
                }
                | {p}
            )
        )
        for gs, p, fb in zip(
            alls,
            df["cwe_group"],
            df["func_before"],
        )
    ]

    df["n_cwe_groups"] = (
        df["cwe_group_all"]
        .map(lambda s: len(s.split(";")))
    )

    df["cwe_multi_label"] = (
        df["n_cwe_groups"] > 1
    )

    lab = (
        df[df["has_line_label"]]
        if "has_line_label" in df.columns
        else df
    )

    n = len(lab)

    print(
        f"\nmẫu có nhãn dòng: {n:,}"
    )

    print("\nTẦNG QUYẾT ĐỊNH:")

    for k, v in (
        lab["cwe_group_src"]
        .value_counts()
        .sort_index()
        .items()
    ):
        print(
            f"  {k:<17}{v:>7,}{v / n * 100:>6.1f}%"
        )

    print("\nNHÓM (chính | kể cả phụ):")

    pc = lab["cwe_group"].value_counts()

    mc = Counter(
        x
        for s in lab["cwe_group_all"]
        for x in s.split(";")
    )

    for k in sorted(
        mc,
        key=lambda x: -mc[x],
    ):
        print(
            f"  {k:<15}{pc.get(k, 0):>8,}"
            f"{pc.get(k, 0) / n * 100:>6.1f}%"
            f"{mc[k]:>9,}{mc[k] - pc.get(k, 0):>+7,}"
        )

    print(
        f"\nđa nhãn : "
        f"{int(lab['cwe_multi_label'].sum()):,}"
        f" ({lab['cwe_multi_label'].mean() * 100:.1f}%)"
    )

    print(
        f"lệch max/min: {pc.max() / pc.min():.1f}x"
    )

    df.to_parquet(
        path,
        index=False,
    )

    print(
        f"\nĐÃ GHI: {path}"
    )


if __name__ == "__main__":
    main()
