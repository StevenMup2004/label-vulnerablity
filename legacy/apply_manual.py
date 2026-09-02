"""
Áp nhãn gán tay cho 43 mẫu cuối và chốt dataset.
"""

import pandas as pd

from manual_labels import MANUAL_LABELS


INPUT_PARQUET = "TitanVul_language_grouped.parquet"

OUTPUT_PARQUET = "TitanVul_language_FINAL.parquet"
OUTPUT_CSV = "TitanVul_language_FINAL.csv"


def main():

    df = pd.read_parquet(INPUT_PARQUET)

    print("=" * 70)
    print("APPLY MANUAL LABELS")
    print("=" * 70)

    remaining = df.index[df["group_n_sources"] <= 1]

    print(f"Samples needing manual label: {len(remaining):,}")
    print(f"Manual labels provided:       {len(MANUAL_LABELS):,}")

    # --------------------------------------------------------
    # Kiểm tra khớp: không thừa, không thiếu
    # --------------------------------------------------------

    provided = set(MANUAL_LABELS)
    target = set(remaining)

    missing = target - provided
    extra = provided - target

    if missing:
        print(f"THIẾU nhãn cho {len(missing)} mẫu: {sorted(missing)[:10]}")
    if extra:
        print(f"THỪA nhãn cho {len(extra)} mẫu: {sorted(extra)[:10]}")

    if not missing and not extra:
        print("Khớp chính xác 1-1.")

    df["manual_reason"] = None

    changed = 0

    for idx, (group, reason) in MANUAL_LABELS.items():

        if idx not in df.index:
            continue

        if df.at[idx, "language_group"] != group:
            changed += 1

        df.at[idx, "language_group"] = group
        df.at[idx, "group_source"] = "manual"
        df.at[idx, "group_confidence"] = "high"
        df.at[idx, "group_n_sources"] = 4
        df.at[idx, "manual_reason"] = reason
        df.at[idx, "needs_group_review"] = False

    print(f"\nNhãn bị sửa lại: {changed}")
    print(f"Nhãn xác nhận đúng: {len(MANUAL_LABELS) - changed}")

    # --------------------------------------------------------
    # Chốt
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("FINAL")
    print("=" * 70)

    print("\ngroup_confidence:")
    print(df["group_confidence"].value_counts().to_string())

    print("\nsố nhân chứng:")
    tier = df["group_n_sources"].value_counts().sort_index()
    for k, v in tier.items():
        print(f"  {k}: {v:6,}  ({v / len(df) * 100:5.2f}%)")

    print(
        f"\nneeds_group_review: "
        f"{int(df['needs_group_review'].sum()):,}"
    )

    print("\nLANGUAGE GROUP:")
    stats = (
        df["language_group"]
        .value_counts(dropna=False)
        .rename_axis("group")
        .reset_index(name="count")
    )
    stats["percent"] = (
        stats["count"] / len(df) * 100
    ).round(2)
    print(stats.to_string(index=False))

    df.to_parquet(OUTPUT_PARQUET, index=False)
    print(f"\nSaved: {OUTPUT_PARQUET}")

    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
