"""
Chốt nhãn ở mức NHÓM NGÔN NGỮ (language_group).

Yêu cầu: không cần phân biệt C với C++.
Cả hai (và C/C++, Objective-C) gộp thành một nhóm "C/C++".

Việc gộp này làm phần lớn cờ review tự tan, vì rất nhiều
mẫu trước đây bị gắn cờ chỉ do Linguist / repo prior / rule
không thống nhất được C hay C++ - một bất đồng giờ
không còn ý nghĩa.

Phần còn lại là bất đồng NHÓM thật sự
(chủ yếu C/C++ vs JavaScript), được phân xử bằng
bỏ phiếu giữa ba nguồn độc lập:

    linguist  - thống kê ký tự
    repo prior- ngữ cảnh repo
    rule      - cú pháp của chính đoạn code

Nhãn language cũ vẫn được giữ nguyên trong cột cũ,
không xoá gì cả.
"""

import pandas as pd

import rule_based as R
import token_prior as T


INPUT_PARQUET = "TitanVul_language_final_ruled.parquet"

OUTPUT_PARQUET = "TitanVul_language_grouped.parquet"
OUTPUT_CSV = "TitanVul_language_grouped.csv"
OUTPUT_REVIEW = "TitanVul_language_group_review.csv"

TRUSTED_SOURCES = {
    "extension",
    "file_name",
    "commit_link_path",
}


def as_group(value):
    if not isinstance(value, str):
        return None
    return R.family_of(value)


def best_of(before, after):
    """Lấy phía có margin lớn hơn; không đòi hai bên đồng thuận."""
    found = [x for x in (before, after) if x]
    if not found:
        return None
    return max(found, key=lambda r: r["margin"])


def main():

    print("=" * 70)
    print("FINALIZE LANGUAGE GROUP")
    print("=" * 70)

    df = pd.read_parquet(INPUT_PARQUET)

    print(f"Loaded {len(df):,} samples")

    # --------------------------------------------------------
    # Nhóm cho toàn bộ dataset
    # --------------------------------------------------------

    df["language_group"] = df["language"].apply(as_group)

    df["group_source"] = df["language_source"]

    df["group_confidence"] = df["language_confidence"]

    df["needs_group_review"] = False

    # --------------------------------------------------------
    # Xét TẤT CẢ mẫu có nhãn suy luận, không chỉ mẫu bị gắn cờ.
    #
    # Lý do: một mẫu không bị gắn cờ vẫn có thể chỉ dựa vào
    # đúng MỘT nguồn (điển hình là các mẫu github_linguist
    # mà rule chưa từng được hỏi ý kiến). Cho rule phát biểu
    # trên toàn bộ nhóm này thì mới biết mẫu nào thực sự
    # có nhiều nhân chứng độc lập.
    # --------------------------------------------------------

    target = df.index[
        ~df["language_source"].isin(TRUSTED_SOURCES)
    ]

    print(f"Inferred samples to check: {len(target):,}")

    # --------------------------------------------------------
    # Nguồn thứ tư: token prior
    #
    # Xây từ ĐÚNG các mẫu có nhãn chắc chắn, không bao giờ
    # từ nhãn suy luận - nếu không nó sẽ học lại chính
    # sai lầm của pipeline.
    # --------------------------------------------------------

    trusted = df[
        df["language_source"].isin(TRUSTED_SOURCES)
    ]

    token_prior = T.build_token_prior(
        trusted["func_before"],
        trusted["language"].apply(as_group),
    )

    print(f"Token prior entries: {len(token_prior):,}")

    # Số nhân chứng độc lập đồng thuận với nhãn cuối
    df["group_n_sources"] = 0

    # Nhãn trực tiếp từ đường dẫn file: coi như mức cao nhất
    df.loc[
        df["language_source"].isin(TRUSTED_SOURCES),
        "group_n_sources",
    ] = 4

    counters = {
        "resolved_all_agree": 0,
        "resolved_by_rule": 0,
        "resolved_by_vote": 0,
        "still_unresolved": 0,
    }

    for idx in target:

        current = as_group(df.at[idx, "language"])

        prior = as_group(
            df.at[idx, "repo_prior_language"]
        )

        linguist = as_group(
            df.at[idx, "linguist_before_language"]
        ) or as_group(
            df.at[idx, "linguist_after_language"]
        )

        # Rule chạy lại, không đòi before/after đồng thuận
        rule = best_of(
            R.detect_language(df.at[idx, "func_before"]),
            R.detect_language(df.at[idx, "func_after"]),
        )

        rule_group = rule["family"] if rule else None
        rule_margin = rule["margin"] if rule else 0

        # Nguồn thứ tư: từ vựng API, độc lập với cú pháp
        token_result = T.classify(
            df.at[idx, "func_before"], token_prior
        )

        token_group = (
            token_result["group"]
            if T.is_confident(token_result)
            else None
        )

        votes = [
            v
            for v in (
                linguist,
                prior,
                rule_group,
                token_group,
            )
            if isinstance(v, str)
        ]

        # ----------------------------------------------------
        # CASE 1
        # Mọi nguồn đọc được đều cùng một nhóm.
        #
        # Bất đồng trước đây chỉ là C vs C++,
        # nay không còn là bất đồng.
        # ----------------------------------------------------

        if votes and len(set(votes)) == 1:

            counters["resolved_all_agree"] += 1

            df.at[idx, "language_group"] = votes[0]
            df.at[idx, "group_n_sources"] = len(votes)

            if len(votes) >= 2:
                df.at[idx, "group_source"] = "all_sources_agree"
                df.at[idx, "group_confidence"] = "high"
            else:
                # Chỉ đúng một nguồn đọc được -> không có
                # nhân chứng nào để đối chiếu
                df.at[idx, "group_source"] = "single_source"
                df.at[idx, "group_confidence"] = "low"

            continue

        # ----------------------------------------------------
        # CASE 2
        # Bất đồng nhóm thật sự.
        #
        # Rule được ưu tiên khi nó đủ chắc: nó là nguồn
        # duy nhất đọc trực tiếp cú pháp của đoạn code,
        # trong khi prior chỉ nhìn repo và linguist
        # ở nhóm này gần như luôn low confidence.
        # ----------------------------------------------------

        if rule_group is not None and R.is_confident(
            {"family": rule_group, "margin": rule_margin},
            R.GROUP_MIN_MARGIN,
        ):

            counters["resolved_by_rule"] += 1

            support = sum(
                1 for v in votes if v == rule_group
            )

            df.at[idx, "language_group"] = rule_group
            df.at[idx, "group_source"] = (
                "rule+other" if support >= 2 else "rule_based"
            )
            df.at[idx, "group_n_sources"] = support
            df.at[idx, "group_confidence"] = (
                "high" if support >= 2 else "medium"
            )

            continue

        # ----------------------------------------------------
        # CASE 3
        # Rule không đủ chắc -> bỏ phiếu đa số.
        # Hoà phiếu thì ưu tiên prior (98.9% LOO)
        # rồi mới tới linguist.
        # ----------------------------------------------------

        if votes:

            tally = {}
            for v in votes:
                tally[v] = tally.get(v, 0) + 1

            top = max(tally.values())
            winners = [k for k, c in tally.items() if c == top]

            if len(winners) == 1:

                chosen = winners[0]
                source = "majority_vote"
                confidence = "medium"

            else:

                # Hoà phiếu -> xếp theo độ tin cậy ĐÃ ĐO
                # của từng nguồn, không theo cảm tính:
                #
                #   repo prior : 98.9% (leave-one-out)
                #   rule       : 97-98% nhưng chỉ khi đạt
                #                ngưỡng, mà ở đây thì không
                #   linguist   : nhóm mẫu này gần như luôn
                #                low confidence, và hay gán
                #                nhầm JavaScript cho code C
                #
                # Nên prior đi trước, linguist đi cuối.
                if isinstance(prior, str):
                    chosen = prior
                    source = "tie_break_repo_prior"
                    confidence = "medium"

                elif isinstance(rule_group, str):
                    chosen = rule_group
                    source = "tie_break_rule"
                    confidence = "low"

                elif isinstance(token_group, str):
                    # 97.3% (đo với repo lạ) - vẫn hơn hẳn
                    # linguist ở nhóm mẫu này
                    chosen = token_group
                    source = "tie_break_token"
                    confidence = "low"

                else:
                    chosen = linguist
                    source = "tie_break_linguist"
                    confidence = "low"

            counters["resolved_by_vote"] += 1

            df.at[idx, "language_group"] = chosen
            df.at[idx, "group_source"] = source
            df.at[idx, "group_confidence"] = confidence
            df.at[idx, "group_n_sources"] = sum(
                1 for v in votes if v == chosen
            )

            continue

        # ----------------------------------------------------
        # CASE 4
        # Không nguồn nào đọc được
        # ----------------------------------------------------

        counters["still_unresolved"] += 1

        df.at[idx, "needs_group_review"] = True
        df.at[idx, "group_confidence"] = "low"

    # --------------------------------------------------------
    # Báo cáo
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)

    for name, value in counters.items():
        print(f"  {name:22s} {value:,}")

    print("\ngroup_confidence:")
    print(df["group_confidence"].value_counts().to_string())

    print(
        f"\nneeds_group_review: "
        f"{int(df['needs_group_review'].sum()):,}"
        f"/{len(df):,}"
    )

    print("\nSỐ NHÂN CHỨNG ĐỘC LẬP ĐỒNG THUẬN:")
    tier = df["group_n_sources"].value_counts().sort_index()
    for k, v in tier.items():
        print(
            f"  {k} nguồn: {v:6,}  ({v / len(df) * 100:5.2f}%)"
        )

    print("\nLANGUAGE GROUP DISTRIBUTION:")
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

    # --------------------------------------------------------
    # Lưu
    # --------------------------------------------------------

    df.to_parquet(OUTPUT_PARQUET, index=False)
    print(f"\nSaved: {OUTPUT_PARQUET}")

    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved: {OUTPUT_CSV}")

    review = df[df["needs_group_review"]].copy()
    review.to_csv(OUTPUT_REVIEW, index=False)
    print(
        f"Saved: {OUTPUT_REVIEW}  ({len(review):,} rows)"
    )


if __name__ == "__main__":
    main()
