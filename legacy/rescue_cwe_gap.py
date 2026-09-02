"""
Cứu các dòng có CVE nhưng NVD/CVE.org/OSV đều không có CWE
(NVD ghi NVD-CWE-noinfo hoặc NVD-CWE-Other).

Ba nguồn, theo thứ tự ưu tiên giảm dần:

  1. MITRE CWE catalog - Observed_Examples
     Chính MITRE chọn CVE làm ví dụ cho một CWE. Thẩm quyền
     cao nhất nhưng phủ rất ít.

  2. Red Hat Security Data API
     Red Hat tự gán CWE cho CVE ảnh hưởng sản phẩm của họ.
     Phủ tốt CVE C / kernel / OpenSSL - đúng nhóm đang thiếu.

  3. Rule trên cve_description
     Mô tả của NVD thường nói thẳng loại lỗi ("NULL pointer
     dereference", "out-of-bounds read"). Precision của TỪNG
     rule đã đo trên 6,985 CVE có nhãn vàng, ghi ở RULE_ACC.
     Chỉ giữ rule đạt >=60% exact match.

Không ghi đè cwe_label_final đã có. Mỗi nhãn mới đều có
source + confidence + độ chính xác đo được của rule.
"""

import json
import re

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
    "TitanVul_cwe_label_final.parquet"
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

MITRE_HITS = Path(
    "cwe_observed_examples_hits.json"
)

REDHAT_HITS = Path(
    "redhat_cwe_hits.json"
)


# ============================================================
# RULE: cve_description -> CWE
#
# exact% = đo trên 6,985 CVE có nhãn vàng.
# Thứ tự trong list = thứ tự ưu tiên (cụ thể trước).
# ============================================================

RULES = [
    # (tên, regex, CWE, exact%)
    (
        "null_deref",
        r"null\s*(?:pointer\s*)?(?:dereference|deref)",
        "CWE-476",
        76.8,
    ),
    (
        "use_after_free",
        r"use[\s-]?after[\s-]?free",
        "CWE-416",
        71.0,
    ),
    (
        "double_free",
        r"double[\s-]free",
        "CWE-415",
        73.6,
    ),
    (
        "oob_write",
        r"out[\s-]of[\s-]bounds?\s+write",
        "CWE-787",
        68.9,
    ),
    (
        "oob_read",
        r"out[\s-]of[\s-]bounds?\s+read"
        r"|buffer\s+over[\s-]?read"
        r"|over[\s-]?read",
        "CWE-125",
        78.2,
    ),
    (
        "xss",
        r"cross[\s-]site\s+scripting|\bxss\b",
        "CWE-79",
        95.3,
    ),
    (
        "sqli",
        r"sql\s+injection",
        "CWE-89",
        98.4,
    ),
    (
        "csrf",
        r"cross[\s-]site\s+request\s+forgery|\bcsrf\b",
        "CWE-352",
        92.3,
    ),
    (
        "path_traversal",
        r"(?:directory|path)\s+traversal",
        "CWE-22",
        91.8,
    ),
    (
        "integer_overflow",
        r"integer\s+overflow",
        "CWE-190",
        62.5,
    ),
    (
        "div_by_zero",
        r"divide[\s-]by[\s-]zero|division\s+by\s+zero",
        "CWE-369",
        84.4,
    ),
    (
        "race",
        r"race\s+condition",
        "CWE-362",
        86.0,
    ),
    (
        "format_string",
        r"format\s+string",
        "CWE-134",
        77.8,
    ),
    (
        "ssrf",
        r"server[\s-]side\s+request\s+forgery|\bssrf\b",
        "CWE-918",
        94.1,
    ),
    (
        "open_redirect",
        r"open\s+redirect",
        "CWE-601",
        89.5,
    ),
]


# ============================================================
# RULE THÔ
#
# "buffer overflow" chung, sau khi các rule cụ thể đã lọc.
#
# Nhãn vàng thực tế của nhóm này: CWE-119 45%, CWE-787 30%,
# CWE-120 10%, CWE-122 4%. Không có lựa chọn nào chắc chắn,
# nhưng 91% nằm trong họ CWE-119 nên CWE-119 là mức trừu
# tượng đúng cho một mô tả mơ hồ.
#
# confidence = low. Lọc ra nếu cần tập nhãn sạch.
# ============================================================

COARSE_RULES = [
    (
        "buffer_overflow_coarse",
        r"buffer\s+overflow"
        r"|heap[\s-]based\s+buffer"
        r"|stack[\s-]based\s+buffer",
        "CWE-119",
        45.0,
    ),
]


# ============================================================
# RULE BỊ LOẠI (giữ lại để không ai vô tình thêm lại)
#
#   code_exec        6.9%  "execute arbitrary code" là HẬU QUẢ
#   uninitialized   18.9%
#   off_by_one      25.8%  không nhãn nào chiếm ưu thế
#   type_confusion  40.0%
#   stack_exhaust   41.3%
#   infinite_loop   56.4%
#   memory_leak     59.9%
#   cmd_injection   65.1%
#   integer_underflow 68.0%
#   assert_fail     69.5%
#   xxe             70.6%
#
# ============================================================


COMPILED = [
    (
        name,
        re.compile(
            pattern,
            re.IGNORECASE,
        ),
        cwe,
        acc,
    )
    for name, pattern, cwe, acc in RULES
]


COMPILED_COARSE = [
    (
        name,
        re.compile(
            pattern,
            re.IGNORECASE,
        ),
        cwe,
        acc,
    )
    for name, pattern, cwe, acc in COARSE_RULES
]


def predict_from_description(text):
    """-> (cwe, rule, acc, is_coarse) hoặc (None, None, None, None)"""

    if not isinstance(
        text,
        str,
    ):
        return (
            None,
            None,
            None,
            None,
        )

    for name, rx, cwe, acc in COMPILED:

        if rx.search(text):

            return (
                cwe,
                name,
                acc,
                False,
            )

    for name, rx, cwe, acc in COMPILED_COARSE:

        if rx.search(text):

            return (
                cwe,
                name,
                acc,
                True,
            )

    return (
        None,
        None,
        None,
        None,
    )


def load_hits(path):

    path = Path(
        path
    )

    if not path.exists():

        print(
            f"WARNING thiếu {path}"
        )

        return {}

    raw = json.load(
        open(
            path,
            encoding="utf-8",
        )
    )

    result = {}

    for cve, values in raw.items():

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


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 78
    )

    print(
        "CỨU CÁC DÒNG CÓ CVE MÀ KHÔNG DB NÀO CÓ CWE"
    )

    print(
        "=" * 78
    )

    df = pd.read_parquet(
        INPUT_PARQUET
    )

    mitre = load_hits(
        MITRE_HITS
    )

    redhat = load_hits(
        REDHAT_HITS
    )

    print(
        f"MITRE Observed_Examples: "
        f"{len(mitre):,} CVE"
    )

    print(
        f"Red Hat API:             "
        f"{len(redhat):,} CVE"
    )

    print(
        f"Rule description:        "
        f"{len(RULES)} rule "
        f"+ {len(COARSE_RULES)} rule thô"
    )

    gap = df.index[
        df["cwe_label_final"].isna()
        &
        df["cve_id"].notna()
    ]

    print(
        f"\nDòng cần cứu: "
        f"{len(gap):,}"
        f"  ({df.loc[gap, 'cve_id'].nunique():,} CVE duy nhất)"
    )

    # ========================================================
    # cột mới
    # ========================================================

    for col, default in [
        (
            "cwe_label_final_rule",
            "",
        ),
        (
            "cwe_label_final_acc",
            None,
        ),
    ]:

        if col not in df.columns:
            df[col] = default

    # confidence cho phần đã có: kế thừa cwe_confidence
    if "cwe_label_final_conf" not in df.columns:

        df["cwe_label_final_conf"] = (
            df["cwe_confidence"]
            .where(
                df["cwe_label_final"].notna()
            )
        )

    stats = Counter()
    rule_stats = Counter()

    for idx in gap:

        cve = (
            str(
                df.at[
                    idx,
                    "cve_id"
                ]
            )
            .strip()
            .upper()
        )

        # ----------------------------------------------------
        # 1. MITRE
        # ----------------------------------------------------

        values = mitre.get(
            cve
        )

        if values:

            df.at[
                idx,
                "cwe_label_final"
            ] = values[0]

            df.at[
                idx,
                "cwe_label_final_all"
            ] = ";".join(
                values
            )

            df.at[
                idx,
                "cwe_label_final_source"
            ] = "mitre_observed_example"

            df.at[
                idx,
                "cwe_label_final_conf"
            ] = "high"

            stats[
                "mitre_observed_example"
            ] += 1

            continue

        # ----------------------------------------------------
        # 2. Red Hat
        # ----------------------------------------------------

        values = redhat.get(
            cve
        )

        if values:

            df.at[
                idx,
                "cwe_label_final"
            ] = values[0]

            df.at[
                idx,
                "cwe_label_final_all"
            ] = ";".join(
                values
            )

            df.at[
                idx,
                "cwe_label_final_source"
            ] = "redhat_cwe"

            df.at[
                idx,
                "cwe_label_final_conf"
            ] = "high"

            stats[
                "redhat_cwe"
            ] += 1

            continue

        # ----------------------------------------------------
        # 3. rule trên description
        # ----------------------------------------------------

        (
            cwe,
            rule,
            acc,
            coarse,
        ) = predict_from_description(
            df.at[
                idx,
                "cve_description"
            ]
        )

        if not cwe:

            stats[
                "van_khong_cuu_duoc"
            ] += 1

            continue

        df.at[
            idx,
            "cwe_label_final"
        ] = cwe

        df.at[
            idx,
            "cwe_label_final_all"
        ] = cwe

        df.at[
            idx,
            "cwe_label_final_source"
        ] = (
            "description_rule_coarse"
            if coarse
            else
            "description_rule"
        )

        df.at[
            idx,
            "cwe_label_final_rule"
        ] = rule

        df.at[
            idx,
            "cwe_label_final_acc"
        ] = acc

        df.at[
            idx,
            "cwe_label_final_conf"
        ] = (
            "low"
            if coarse
            else
            "medium"
        )

        stats[
            "description_rule_coarse"
            if coarse
            else
            "description_rule"
        ] += 1

        rule_stats[rule] += 1

    df["has_cwe_label_final"] = (
        df["cwe_label_final"].notna()
    )

    # ========================================================
    # BÁO CÁO
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "KẾT QUẢ CỨU"
    )

    print(
        "=" * 78
    )

    for key, value in [
        (
            "mitre_observed_example",
            stats["mitre_observed_example"],
        ),
        (
            "redhat_cwe",
            stats["redhat_cwe"],
        ),
        (
            "description_rule",
            stats["description_rule"],
        ),
        (
            "description_rule_coarse",
            stats["description_rule_coarse"],
        ),
        (
            "vẫn không cứu được",
            stats["van_khong_cuu_duoc"],
        ),
    ]:

        print(
            f"  {key:<26s} "
            f"{value:>6,}"
        )

    rescued = (
        len(gap)
        -
        stats["van_khong_cuu_duoc"]
    )

    print(
        f"\nCứu được: "
        f"{rescued:,}/{len(gap):,} "
        f"({rescued/len(gap)*100:.1f}%)"
    )

    if rule_stats:

        print(
            "\n"
            + "-" * 78
        )

        print(
            "RULE NÀO CHẠY (kèm exact% đã đo)"
        )

        print(
            "-" * 78
        )

        acc_by_rule = {
            name: acc
            for name, _, _, acc
            in RULES + COARSE_RULES
        }

        for rule, count in (
            rule_stats.most_common()
        ):

            print(
                f"  {rule:<24s} "
                f"{count:>5,}"
                f"   exact "
                f"{acc_by_rule[rule]:>5.1f}%"
            )

    filled = int(
        df["has_cwe_label_final"].sum()
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "TỔNG"
    )

    print(
        "=" * 78
    )

    print(
        f"cwe_label_final có giá trị: "
        f"{filled:,}/{len(df):,} "
        f"({filled/len(df)*100:.2f}%)"
    )

    print(
        "\nTheo confidence:"
    )

    print(
        df["cwe_label_final_conf"]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    print(
        "\nTheo source:"
    )

    print(
        df["cwe_label_final_source"]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    # ========================================================
    # GHI FILE
    # ========================================================

    df.to_parquet(
        OUT_PARQUET,
        index=False,
    )

    df.to_csv(
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
            "cwe_label_final_all",
            "cwe_label_final_source",
            "cwe_label_final_conf",
            "cwe_label_final_rule",
            "cwe_label_final_acc",
            "has_cwe_label_final",
        ]
        if col in df.columns
    ]

    df[
        audit_cols
    ].to_csv(
        OUT_AUDIT,
        index=True,
    )

    trainable = df[
        df["has_cwe_label_final"]
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
        f"({len(df):,} dòng)"
    )

    print(
        f"{OUT_CSV}"
    )

    print(
        f"{OUT_AUDIT}"
    )

    print(
        f"{OUT_TRAINABLE}  "
        f"({len(trainable):,} dòng)"
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
