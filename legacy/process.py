import re
from collections import Counter

import pandas as pd


# ============================================================
# CONFIG
# ============================================================

INPUT_PARQUET = "TitanVul_language_FINAL.parquet"

OUTPUT_PARQUET = "TitanVul_recovery_2methods.parquet"
OUTPUT_CSV = "TitanVul_recovery_2methods.csv"
OUTPUT_AUDIT = "TitanVul_recovery_audit.csv"


# ------------------------------------------------------------
# majority:
# giống logic recover_labels.py hiện tại của bạn.
#
# unambiguous:
# chỉ propagate nếu 1 commit chỉ có đúng 1 CVE/CWE duy nhất.
#
# Muốn so trực tiếp với kết quả cũ thì để majority.
# ------------------------------------------------------------

COMMIT_MODE = "majority"


# ============================================================
# REGEX
# ============================================================

CVE_PATTERN = re.compile(
    r"\bCVE[-_ ]?(\d{4})[-_ ]?(\d{4,7})\b",
    re.IGNORECASE,
)

CWE_PATTERN = re.compile(
    r"\bCWE[-_ ]?(\d{1,5})\b",
    re.IGNORECASE,
)


# ============================================================
# HELPER: missing
# ============================================================

def is_missing(value):

    if value is None:
        return True

    try:
        if pd.isna(value):
            return True
    except Exception:
        pass

    if isinstance(value, str):

        value = value.strip()

        if value.lower() in {
            "",
            "nan",
            "none",
            "null",
            "unknown",
        }:
            return True

    return False


def clean_existing_labels(df):

    for col in ["cve_id", "cwe_id"]:

        df.loc[
            df[col].apply(is_missing),
            col
        ] = None

    return df


# ============================================================
# EXTRACT ALL EXPLICIT CVEs FROM COMMIT MESSAGE
# ============================================================

def extract_cves(text):

    if not isinstance(text, str):
        return []

    results = []

    for year, number in CVE_PATTERN.findall(text):

        cve = f"CVE-{year}-{number}"

        if cve not in results:
            results.append(cve)

    return results


# ============================================================
# EXTRACT ALL EXPLICIT CWEs FROM COMMIT MESSAGE
# ============================================================

def extract_cwes(text):

    if not isinstance(text, str):
        return []

    results = []

    for number in CWE_PATTERN.findall(text):

        cwe = f"CWE-{int(number)}"

        if cwe not in results:
            results.append(cwe)

    return results


# ============================================================
# MAJORITY
# ============================================================

def majority(series):

    values = [
        x
        for x in series
        if not is_missing(x)
    ]

    if not values:
        return None

    counts = Counter(values)

    return counts.most_common(1)[0][0]


# ============================================================
# BUILD COMMIT -> LABEL MAP
# ============================================================

def build_commit_map(
    df,
    label_column,
    mode="majority",
):

    subset = df[
        df["commit_link"].notna()
        &
        df[label_column].notna()
    ].copy()

    mapping = {}

    ambiguous = {}

    for commit, group in subset.groupby(
        "commit_link"
    ):

        labels = (
            group[label_column]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        if not labels:
            continue

        # ----------------------------------------------------
        # Không mâu thuẫn
        # ----------------------------------------------------

        if len(labels) == 1:

            mapping[commit] = labels[0]

            continue

        # ----------------------------------------------------
        # Commit có nhiều label
        # ----------------------------------------------------

        ambiguous[commit] = labels

        if mode == "majority":

            mapping[commit] = majority(
                group[label_column]
            )

        elif mode == "unambiguous":

            # Không propagate
            pass

        else:

            raise ValueError(
                f"Unknown COMMIT_MODE: {mode}"
            )

    return mapping, ambiguous


# ============================================================
# INITIALIZE SOURCES
# ============================================================

def init_sources(df):

    df["cve_source"] = None

    df.loc[
        df["cve_id"].notna(),
        "cve_source"
    ] = "original"

    df["cwe_source"] = None

    df.loc[
        df["cwe_id"].notna(),
        "cwe_source"
    ] = "original"

    return df


# ============================================================
# METHOD 1:
# PROPAGATE SAME COMMIT
# ============================================================

def apply_same_commit(
    original_df,
    commit_to_cve,
    commit_to_cwe,
):

    df = original_df.copy()

    # --------------------------------------------------------
    # CVE
    # --------------------------------------------------------

    need_cve = (
        df["cve_id"].isna()
        &
        df["commit_link"].notna()
    )

    candidates = (
        df.loc[
            need_cve,
            "commit_link"
        ]
        .map(commit_to_cve)
    )

    idx = candidates[
        candidates.notna()
    ].index

    df.loc[
        idx,
        "cve_id"
    ] = candidates.loc[idx]

    df.loc[
        idx,
        "cve_source"
    ] = "same_commit"

    # --------------------------------------------------------
    # CWE
    # --------------------------------------------------------

    need_cwe = (
        df["cwe_id"].isna()
        &
        df["commit_link"].notna()
    )

    candidates = (
        df.loc[
            need_cwe,
            "commit_link"
        ]
        .map(commit_to_cwe)
    )

    idx_cwe = candidates[
        candidates.notna()
    ].index

    df.loc[
        idx_cwe,
        "cwe_id"
    ] = candidates.loc[
        idx_cwe
    ]

    df.loc[
        idx_cwe,
        "cwe_source"
    ] = "same_commit"

    return df


# ============================================================
# METHOD 2:
# EXPLICIT LABEL FROM COMMIT MESSAGE
#
# Chỉ lấy nếu message chứa ĐÚNG 1 unique CVE/CWE.
#
# Ví dụ:
# "Fix CVE-2020-1234"
#
# → CVE-2020-1234
#
# Nếu message có 2 CVE khác nhau:
# không tự chọn.
# ============================================================

def apply_commit_message(
    original_df,
):

    df = original_df.copy()

    # ========================================================
    # Extract candidates
    # ========================================================

    df[
        "_message_cve_list"
    ] = (
        df["commit_message"]
        .apply(extract_cves)
    )

    df[
        "_message_cwe_list"
    ] = (
        df["commit_message"]
        .apply(extract_cwes)
    )

    # ========================================================
    # CVE
    # ========================================================

    need_cve = (
        df["cve_id"].isna()
    )

    single_cve = (
        df["_message_cve_list"]
        .apply(
            lambda x: (
                x[0]
                if len(x) == 1
                else None
            )
        )
    )

    idx = df.index[
        need_cve
        &
        single_cve.notna()
    ]

    df.loc[
        idx,
        "cve_id"
    ] = single_cve.loc[idx]

    df.loc[
        idx,
        "cve_source"
    ] = "commit_message_explicit"

    # ========================================================
    # CWE
    # ========================================================

    need_cwe = (
        df["cwe_id"].isna()
    )

    single_cwe = (
        df["_message_cwe_list"]
        .apply(
            lambda x: (
                x[0]
                if len(x) == 1
                else None
            )
        )
    )

    idx_cwe = df.index[
        need_cwe
        &
        single_cwe.notna()
    ]

    df.loc[
        idx_cwe,
        "cwe_id"
    ] = single_cwe.loc[
        idx_cwe
    ]

    df.loc[
        idx_cwe,
        "cwe_source"
    ] = "commit_message_explicit"

    return df


# ============================================================
# STATISTICS
# ============================================================

def calculate_stats(
    before,
    after,
):

    before_has_cve = (
        before["cve_id"].notna()
    )

    before_has_cwe = (
        before["cwe_id"].notna()
    )

    before_any = (
        before_has_cve
        |
        before_has_cwe
    )

    after_has_cve = (
        after["cve_id"].notna()
    )

    after_has_cwe = (
        after["cwe_id"].notna()
    )

    after_any = (
        after_has_cve
        |
        after_has_cwe
    )

    # --------------------------------------------------------
    # Số ô mới
    # --------------------------------------------------------

    new_cve = (
        ~before_has_cve
        &
        after_has_cve
    )

    new_cwe = (
        ~before_has_cwe
        &
        after_has_cwe
    )

    # --------------------------------------------------------
    # Dòng trước thiếu cả hai,
    # giờ có ít nhất một
    # --------------------------------------------------------

    rescued = (
        ~before_any
        &
        after_any
    )

    # --------------------------------------------------------
    # Dòng được bổ sung ít nhất một ô
    # kể cả trước đã có một label
    # --------------------------------------------------------

    touched = (
        new_cve
        |
        new_cwe
    )

    return {
        "new_cve": int(
            new_cve.sum()
        ),

        "new_cwe": int(
            new_cwe.sum()
        ),

        "rows_touched": int(
            touched.sum()
        ),

        "rows_rescued": int(
            rescued.sum()
        ),

        "after_has_any": int(
            after_any.sum()
        ),

        "rescued_mask": rescued,

        "touched_mask": touched,
    }


# ============================================================
# PRINT METHOD
# ============================================================

def print_method_stats(
    name,
    stats,
    total,
):

    print(
        "\n"
        + "=" * 76
    )

    print(name)

    print(
        "=" * 76
    )

    print(
        f"CVE mới:                     "
        f"{stats['new_cve']:,}"
    )

    print(
        f"CWE mới:                     "
        f"{stats['new_cwe']:,}"
    )

    print(
        f"Dòng được bổ sung >=1 ô:     "
        f"{stats['rows_touched']:,}"
    )

    print(
        f"Dòng thiếu cả 2 được cứu:    "
        f"{stats['rows_rescued']:,}"
    )

    print(
        f"Sau method có >=1 nhãn:      "
        f"{stats['after_has_any']:,}"
        f"/{total:,} "
        f"("
        f"{stats['after_has_any'] / total * 100:.2f}"
        f"%)"
    )


# ============================================================
# COMBINED:
#
# Original
#   ↓
# same commit
#   ↓
# explicit commit message
# ============================================================

def apply_combined(
    original,
    commit_to_cve,
    commit_to_cwe,
):

    df = apply_same_commit(
        original,
        commit_to_cve,
        commit_to_cwe,
    )

    # ========================================================
    # MESSAGE CANDIDATES
    # ========================================================

    message_cves = (
        df["commit_message"]
        .apply(extract_cves)
    )

    message_cwes = (
        df["commit_message"]
        .apply(extract_cwes)
    )

    single_cve = (
        message_cves.apply(
            lambda x: (
                x[0]
                if len(x) == 1
                else None
            )
        )
    )

    single_cwe = (
        message_cwes.apply(
            lambda x: (
                x[0]
                if len(x) == 1
                else None
            )
        )
    )

    # ========================================================
    # Fill remaining CVE
    # ========================================================

    idx = df.index[
        df["cve_id"].isna()
        &
        single_cve.notna()
    ]

    df.loc[
        idx,
        "cve_id"
    ] = single_cve.loc[idx]

    df.loc[
        idx,
        "cve_source"
    ] = "commit_message_explicit"

    # ========================================================
    # Fill remaining CWE
    # ========================================================

    idx = df.index[
        df["cwe_id"].isna()
        &
        single_cwe.notna()
    ]

    df.loc[
        idx,
        "cwe_id"
    ] = single_cwe.loc[idx]

    df.loc[
        idx,
        "cwe_source"
    ] = "commit_message_explicit"

    # Save candidates for audit
    df[
        "message_cve_candidates"
    ] = message_cves.apply(
        lambda x: ";".join(x)
    )

    df[
        "message_cwe_candidates"
    ] = message_cwes.apply(
        lambda x: ";".join(x)
    )

    return df


# ============================================================
# EXAMPLE:
# SAME COMMIT
# ============================================================

def print_same_commit_example(
    original,
    recovered,
):

    mask = (
        (
            recovered[
                "cve_source"
            ]
            ==
            "same_commit"
        )
        |
        (
            recovered[
                "cwe_source"
            ]
            ==
            "same_commit"
        )
    )

    samples = recovered[
        mask
    ]

    if len(samples) == 0:

        print(
            "\nKhông có sample SAME COMMIT."
        )

        return

    row = samples.iloc[0]

    idx = row.name

    print(
        "\n"
        + "=" * 76
    )

    print(
        "EXAMPLE 1 - SAME COMMIT"
    )

    print(
        "=" * 76
    )

    print(
        f"Index          : {idx}"
    )

    print(
        f"Commit         : "
        f"{row['commit_link']}"
    )

    print(
        f"File           : "
        f"{row['file_name']}"
    )

    print(
        f"\nOriginal CVE   : "
        f"{original.at[idx, 'cve_id']}"
    )

    print(
        f"Recovered CVE  : "
        f"{row['cve_id']}"
    )

    print(
        f"CVE source     : "
        f"{row['cve_source']}"
    )

    print(
        f"\nOriginal CWE   : "
        f"{original.at[idx, 'cwe_id']}"
    )

    print(
        f"Recovered CWE  : "
        f"{row['cwe_id']}"
    )

    print(
        f"CWE source     : "
        f"{row['cwe_source']}"
    )

    # --------------------------------------------------------
    # Donor rows
    # --------------------------------------------------------

    same_commit = original[
        original["commit_link"]
        ==
        row["commit_link"]
    ][
        [
            "file_name",
            "cve_id",
            "cwe_id",
        ]
    ]

    print(
        "\nCác dòng ORIGINAL "
        "cùng commit:"
    )

    print(
        same_commit.to_string()
    )


# ============================================================
# EXAMPLE:
# COMMIT MESSAGE
# ============================================================

def print_message_example(
    original,
    recovered,
):

    mask = (
        (
            recovered[
                "cve_source"
            ]
            ==
            "commit_message_explicit"
        )
        |
        (
            recovered[
                "cwe_source"
            ]
            ==
            "commit_message_explicit"
        )
    )

    samples = recovered[
        mask
    ]

    if len(samples) == 0:

        print(
            "\nKhông có sample "
            "COMMIT MESSAGE."
        )

        return

    row = samples.iloc[0]

    idx = row.name

    print(
        "\n"
        + "=" * 76
    )

    print(
        "EXAMPLE 2 - COMMIT MESSAGE"
    )

    print(
        "=" * 76
    )

    print(
        f"Index          : {idx}"
    )

    print(
        f"Commit         : "
        f"{row['commit_link']}"
    )

    print(
        f"File           : "
        f"{row['file_name']}"
    )

    print(
        "\nCOMMIT MESSAGE:"
    )

    print(
        "-" * 76
    )

    print(
        row["commit_message"]
    )

    print(
        "-" * 76
    )

    print(
        f"\nOriginal CVE   : "
        f"{original.at[idx, 'cve_id']}"
    )

    print(
        f"Recovered CVE  : "
        f"{row['cve_id']}"
    )

    print(
        f"CVE source     : "
        f"{row['cve_source']}"
    )

    print(
        f"\nOriginal CWE   : "
        f"{original.at[idx, 'cwe_id']}"
    )

    print(
        f"Recovered CWE  : "
        f"{row['cwe_id']}"
    )

    print(
        f"CWE source     : "
        f"{row['cwe_source']}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # LOAD
    # ========================================================

    df = pd.read_parquet(
        INPUT_PARQUET
    )

    df = clean_existing_labels(
        df
    )

    df = init_sources(
        df
    )

    original = df.copy()

    total = len(
        original
    )

    original_has_cve = (
        original[
            "cve_id"
        ].notna()
    )

    original_has_cwe = (
        original[
            "cwe_id"
        ].notna()
    )

    original_any = (
        original_has_cve
        |
        original_has_cwe
    )

    print(
        "=" * 76
    )

    print(
        "COMPARE LABEL RECOVERY METHODS"
    )

    print(
        "=" * 76
    )

    print(
        f"Total samples:              "
        f"{total:,}"
    )

    print(
        f"Original có CVE:            "
        f"{original_has_cve.sum():,}"
    )

    print(
        f"Original có CWE:            "
        f"{original_has_cwe.sum():,}"
    )

    print(
        f"Original có CVE hoặc CWE:   "
        f"{original_any.sum():,}"
    )

    print(
        f"Original thiếu cả hai:      "
        f"{(~original_any).sum():,}"
    )

    # ========================================================
    # BUILD SAME-COMMIT MAPS
    # ========================================================

    commit_to_cve, ambiguous_cve = (
        build_commit_map(
            original,
            "cve_id",
            COMMIT_MODE,
        )
    )

    commit_to_cwe, ambiguous_cwe = (
        build_commit_map(
            original,
            "cwe_id",
            COMMIT_MODE,
        )
    )

    print(
        "\nCommit mapping mode: "
        f"{COMMIT_MODE}"
    )

    print(
        f"commit -> CVE mapping:       "
        f"{len(commit_to_cve):,}"
    )

    print(
        f"commit -> CWE mapping:       "
        f"{len(commit_to_cwe):,}"
    )

    print(
        f"Commit có >1 CVE:            "
        f"{len(ambiguous_cve):,}"
    )

    print(
        f"Commit có >1 CWE:            "
        f"{len(ambiguous_cwe):,}"
    )

    # ========================================================
    # METHOD 1 INDEPENDENT
    # ========================================================

    same_commit_df = (
        apply_same_commit(
            original,
            commit_to_cve,
            commit_to_cwe,
        )
    )

    same_stats = (
        calculate_stats(
            original,
            same_commit_df,
        )
    )

    print_method_stats(
        "METHOD 1 - SAME COMMIT",
        same_stats,
        total,
    )

    # ========================================================
    # METHOD 2 INDEPENDENT
    # ========================================================

    message_df = (
        apply_commit_message(
            original
        )
    )

    message_stats = (
        calculate_stats(
            original,
            message_df,
        )
    )

    print_method_stats(
        "METHOD 2 - EXPLICIT LABEL IN COMMIT MESSAGE",
        message_stats,
        total,
    )

    # ========================================================
    # MESSAGE INFO
    # ========================================================

    cve_message_lists = (
        original[
            "commit_message"
        ]
        .apply(extract_cves)
    )

    cwe_message_lists = (
        original[
            "commit_message"
        ]
        .apply(extract_cwes)
    )

    print(
        "\n"
        + "=" * 76
    )

    print(
        "COMMIT MESSAGE CONTENT"
    )

    print(
        "=" * 76
    )

    print(
        "Message có >=1 CVE explicit: "
        f"{cve_message_lists.apply(bool).sum():,}"
    )

    print(
        "Message có đúng 1 CVE:        "
        f"{cve_message_lists.apply(lambda x: len(x) == 1).sum():,}"
    )

    print(
        "Message có >1 CVE:            "
        f"{cve_message_lists.apply(lambda x: len(x) > 1).sum():,}"
    )

    print(
        "\nMessage có >=1 CWE explicit: "
        f"{cwe_message_lists.apply(bool).sum():,}"
    )

    print(
        "Message có đúng 1 CWE:        "
        f"{cwe_message_lists.apply(lambda x: len(x) == 1).sum():,}"
    )

    print(
        "Message có >1 CWE:            "
        f"{cwe_message_lists.apply(lambda x: len(x) > 1).sum():,}"
    )

    # ========================================================
    # OVERLAP
    #
    # Xét trên những dòng ban đầu thiếu cả 2.
    # ========================================================

    same_rescued = (
        same_stats[
            "rescued_mask"
        ]
    )

    message_rescued = (
        message_stats[
            "rescued_mask"
        ]
    )

    both_can_rescue = (
        same_rescued
        &
        message_rescued
    )

    only_same = (
        same_rescued
        &
        ~message_rescued
    )

    only_message = (
        message_rescued
        &
        ~same_rescued
    )

    print(
        "\n"
        + "=" * 76
    )

    print(
        "OVERLAP - DÒNG BAN ĐẦU THIẾU CẢ CVE VÀ CWE"
    )

    print(
        "=" * 76
    )

    print(
        f"Chỉ SAME COMMIT cứu được:    "
        f"{only_same.sum():,}"
    )

    print(
        f"Chỉ COMMIT MESSAGE cứu được: "
        f"{only_message.sum():,}"
    )

    print(
        f"Cả hai đều cứu được:         "
        f"{both_can_rescue.sum():,}"
    )

    union_rescue = (
        same_rescued
        |
        message_rescued
    )

    print(
        f"Union 2 method cứu được:      "
        f"{union_rescue.sum():,}"
    )

    # ========================================================
    # COMBINED
    # ========================================================

    combined = (
        apply_combined(
            original,
            commit_to_cve,
            commit_to_cwe,
        )
    )

    combined_stats = (
        calculate_stats(
            original,
            combined,
        )
    )

    print_method_stats(
        "COMBINED - SAME COMMIT -> COMMIT MESSAGE",
        combined_stats,
        total,
    )

    # ========================================================
    # FINAL BREAKDOWN
    # ========================================================

    final_cve = (
        combined[
            "cve_id"
        ].notna()
    )

    final_cwe = (
        combined[
            "cwe_id"
        ].notna()
    )

    final_any = (
        final_cve
        |
        final_cwe
    )

    final_both = (
        final_cve
        &
        final_cwe
    )

    print(
        "\n"
        + "=" * 76
    )

    print(
        "FINAL RESULT"
    )

    print(
        "=" * 76
    )

    print(
        f"Có CVE:                       "
        f"{final_cve.sum():,}"
        f"/{total:,}"
    )

    print(
        f"Có CWE:                       "
        f"{final_cwe.sum():,}"
        f"/{total:,}"
    )

    print(
        f"Có cả CVE + CWE:              "
        f"{final_both.sum():,}"
        f"/{total:,}"
    )

    print(
        f"Có ít nhất 1 trong 2:         "
        f"{final_any.sum():,}"
        f"/{total:,} "
        f"("
        f"{final_any.sum() / total * 100:.2f}"
        f"%)"
    )

    print(
        f"Vẫn thiếu cả hai:             "
        f"{(~final_any).sum():,}"
        f"/{total:,} "
        f"("
        f"{(~final_any).sum() / total * 100:.2f}"
        f"%)"
    )

    print(
        "\nNguồn CVE:"
    )

    print(
        combined[
            "cve_source"
        ]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    print(
        "\nNguồn CWE:"
    )

    print(
        combined[
            "cwe_source"
        ]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    # ========================================================
    # EXAMPLES
    # ========================================================

    print_same_commit_example(
        original,
        same_commit_df,
    )

    print_message_example(
        original,
        message_df,
    )

    # ========================================================
    # AUDIT COLUMNS
    # ========================================================

    combined[
        "had_original_cve"
    ] = original[
        "cve_id"
    ].notna()

    combined[
        "had_original_cwe"
    ] = original[
        "cwe_id"
    ].notna()

    combined[
        "had_original_any"
    ] = original_any

    combined[
        "has_final_cve"
    ] = final_cve

    combined[
        "has_final_cwe"
    ] = final_cwe

    combined[
        "has_final_any"
    ] = final_any

    combined[
        "newly_rescued"
    ] = (
        ~original_any
        &
        final_any
    )

    # ========================================================
    # SAVE
    # ========================================================

    combined.to_parquet(
        OUTPUT_PARQUET,
        index=False,
    )

    combined.to_csv(
        OUTPUT_CSV,
        index=False,
    )

    audit_cols = [
        "cve_id",
        "cve_source",
        "cwe_id",
        "cwe_source",
        "commit_link",
        "commit_message",
        "file_name",
        "message_cve_candidates",
        "message_cwe_candidates",
        "had_original_cve",
        "had_original_cwe",
        "had_original_any",
        "has_final_cve",
        "has_final_cwe",
        "has_final_any",
        "newly_rescued",
    ]

    combined[
        audit_cols
    ].to_csv(
        OUTPUT_AUDIT,
        index=True,
    )

    print(
        "\n"
        + "=" * 76
    )

    print(
        "SAVED"
    )

    print(
        "=" * 76
    )

    print(
        OUTPUT_PARQUET
    )

    print(
        OUTPUT_CSV
    )

    print(
        OUTPUT_AUDIT
    )


if __name__ == "__main__":
    main()