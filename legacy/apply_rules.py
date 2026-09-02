"""
Quét các mẫu còn lại trong needs_language_review
bằng rule-based detector.

Rule ở đây đóng vai TRỌNG TÀI THỨ BA, độc lập với
Linguist (thống kê ký tự) và với repo prior (ngữ cảnh repo):
nó chỉ đọc cú pháp của chính đoạn code.

Chính sách:

  1. Rule đồng ý family với nhãn hiện tại
     -> xác nhận, gỡ cờ review, nâng confidence

  2. Rule mâu thuẫn family VÀ rule rất chắc chắn
     -> sửa nhãn theo rule, VẪN giữ cờ review

  3. Rule không đủ chắc
     -> giữ nguyên mọi thứ, vẫn cần người xem

Không bao giờ đụng tới các mẫu đã có nhãn từ
extension / file_name / commit_link_path.
"""

import pandas as pd

import rule_based as R


INPUT_PARQUET = "TitanVul_language_final.parquet"

OUTPUT_PARQUET = "TitanVul_language_final_ruled.parquet"
OUTPUT_CSV = "TitanVul_language_final_ruled.csv"
OUTPUT_REVIEW = "TitanVul_language_review_ruled.csv"

TRUSTED_SOURCES = {
    "extension",
    "file_name",
    "commit_link_path",
}


def main():

    print("=" * 70)
    print("RULE-BASED SCAN")
    print("=" * 70)

    df = pd.read_parquet(INPUT_PARQUET)

    print(f"Loaded {len(df):,} samples")

    # --------------------------------------------------------
    # Cột kết quả rule
    # --------------------------------------------------------

    df["rule_language"] = None
    df["rule_family"] = None
    df["rule_margin"] = float("nan")
    df["rule_agreement"] = None

    target = df.index[
        df["needs_language_review"]
        & ~df["language_source"].isin(TRUSTED_SOURCES)
    ]

    print(f"Samples to scan: {len(target):,}")

    counters = {
        "confirmed": 0,
        "overridden": 0,
        "rule_unsure": 0,
        "no_rule_output": 0,
    }

    for idx in target:

        result = R.detect_with_agreement(
            df.at[idx, "func_before"],
            df.at[idx, "func_after"],
        )

        if result is None:
            counters["no_rule_output"] += 1
            continue

        df.at[idx, "rule_language"] = result["language"]
        df.at[idx, "rule_family"] = result["family"]
        df.at[idx, "rule_margin"] = result["margin"]
        df.at[idx, "rule_agreement"] = result["agreement"]

        current_family = R.family_of(
            df.at[idx, "language"]
        )

        # ----------------------------------------------------
        # CASE 1 - rule xác nhận nhãn hiện tại
        # ----------------------------------------------------

        if result["family"] == current_family:

            if not R.is_confident(
                result, R.CONFIRM_MIN_MARGIN
            ):
                counters["rule_unsure"] += 1
                continue

            counters["confirmed"] += 1

            df.at[idx, "needs_language_review"] = False

            if df.at[idx, "language_confidence"] == "low":
                df.at[idx, "language_confidence"] = "medium"

            df.at[idx, "language_decision"] = (
                str(df.at[idx, "language_decision"])
                + "+rule_confirms"
            )

            df.at[idx, "language_source"] = (
                str(df.at[idx, "language_source"])
                + "+rule"
            )

            continue

        # ----------------------------------------------------
        # CASE 2 - rule mâu thuẫn family
        #
        # Chỉ sửa khi rule đạt ngưỡng OVERRIDE và
        # before/after đồng thuận. Vẫn giữ cờ review
        # vì đây là trường hợp ba nguồn không thống nhất.
        # ----------------------------------------------------

        if (
            R.is_confident(result, R.OVERRIDE_MIN_MARGIN)
            and result["agreement"]
        ):

            counters["overridden"] += 1

            df.at[idx, "language"] = result["language"]
            df.at[idx, "language_family"] = result["family"]
            df.at[idx, "language_source"] = "rule_based"
            df.at[idx, "language_confidence"] = "medium"
            df.at[idx, "language_decision"] = (
                "rule_overrides_"
                + str(df.at[idx, "language_decision"])
            )

            continue

        counters["rule_unsure"] += 1

    # --------------------------------------------------------
    # Báo cáo
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)

    for name, value in counters.items():
        print(f"  {name:20s} {value:,}")

    print("\nconfidence:")
    print(
        df["language_confidence"]
        .value_counts()
        .to_string()
    )

    print(
        f"\nneeds_review: "
        f"{int(df['needs_language_review'].sum()):,}"
        f"/{len(df):,}"
    )

    print("\nlanguage distribution:")
    print(
        df["language"]
        .value_counts()
        .head(12)
        .to_string()
    )

    # --------------------------------------------------------
    # Lưu
    # --------------------------------------------------------

    df.to_parquet(OUTPUT_PARQUET, index=False)
    print(f"\nSaved: {OUTPUT_PARQUET}")

    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved: {OUTPUT_CSV}")

    review = df[df["needs_language_review"]].copy()
    review.to_csv(OUTPUT_REVIEW, index=False)
    print(f"Saved: {OUTPUT_REVIEW}  ({len(review):,} rows)")


if __name__ == "__main__":
    main()
