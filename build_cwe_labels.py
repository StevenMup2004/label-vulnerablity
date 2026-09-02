"""
MỘT FILE: dò CWE qua TẤT CẢ nguồn rồi xuất một file nhãn duy nhất.

Thay cho cặp extract_cwe_label.py + rescue_cwe_gap.py.

Vào:  TitanVul_recovery_ALL_FINAL.parquet  (output của full_process.py)
Ra:   TitanVul_cwe_labels.parquet / .csv   (mọi dòng có CVE hoặc CWE)
      TitanVul_cwe_labels_audit.csv        (bản gọn)
      TitanVul_cwe_labels_trainable.parquet(chỉ dòng có cwe_label_final)
      TitanVul_cve_without_cwe.csv         (dòng có CVE mà không ra CWE)


THANG NGUỒN, ưu tiên giảm dần
=============================

 0. cwe_id có sẵn từ pipeline
      nhãn gốc dataset, hoặc do full_process.py điền từ
      commit vá / commit message / propagate cùng commit.

 1. NVD weaknesses type=Primary                       (feed cục bộ)
 2. CVE.org problemTypes của container CNA             (cvelistV5)
 3. NVD evaluatorComment / Impact / Solution           (ghi chú analyst NIST;
      trang NVD hiện ở mục "Evaluator Description")
 4. OSV database_specific  (cwe_ids dạng list + CWE dạng dict)
 5. MITRE CWE catalog - Observed_Examples              (map ngược CVE->CWE)
 6. NVD weaknesses (mọi type) / CVE.org mọi container  (khi chỉ ra 1 CWE)
 7. Red Hat Security Data API                          (gọi mạng, có cache)
 8. Feedly CVE enrichment                              (cache cục bộ)
      KHÔNG phải nguồn thẩm quyền - là AI enrichment của
      Feedly. Đo trên 44 CVE có nhãn vàng: 91% khớp chính
      xác, 0% lệch. Gắn confidence riêng "feedly" để lọc.
 9. Rule trên cve_description                          (precision đã đo)

Không nguồn nào ra CWE -> để trống. KHÔNG đoán.
"""

import gzip
import json
import os
import re
import time
import urllib.error
import urllib.request

from collections import Counter
from pathlib import Path

import pandas as pd

from full_process import (
    normalize_cwe_value,
)


# ============================================================
# CONFIG
# ============================================================

ROOT = Path(
    __file__
).resolve().parent

DATA_OUT = ROOT / "data" / "output"

DATA_AUDIT = ROOT / "data" / "audit"

CACHE = ROOT / "cache"


INPUT_PARQUET = (
    DATA_OUT
    / "TitanVul_recovery_ALL_FINAL.parquet"
)

OUT_PARQUET = (
    DATA_OUT / "TitanVul_cwe_labels.parquet"
)

OUT_CSV = (
    DATA_OUT / "TitanVul_cwe_labels.csv"
)

OUT_AUDIT = (
    DATA_AUDIT
    / "TitanVul_cwe_labels_audit.csv"
)

OUT_TRAINABLE = (
    DATA_OUT
    / "TitanVul_cwe_labels_trainable.parquet"
)

OUT_GAP = (
    DATA_AUDIT
    / "TitanVul_cve_without_cwe.csv"
)


NVD_SCAN_CACHE = (
    CACHE / "nvd_scan_cache.json.gz"
)

CVEORG_SCAN_CACHE = (
    CACHE / "cveorg_scan_cache.json.gz"
)

OSV_SCAN_CACHE = (
    CACHE / "osv_scan_cache.json.gz"
)

MITRE_OBSERVED = (
    CACHE / "cwe_observed_examples.json"
)

REDHAT_CACHE = (
    CACHE / "redhat_api_cache.json"
)

FEEDLY_CACHE = (
    CACHE / "feedly_cwe_cache.json"
)


# Red Hat: chỉ gọi mạng cho dòng mà mọi nguồn cục bộ đã tắc.
REDHAT_ENABLED = True

REDHAT_DELAY = 0.35

REDHAT_TIMEOUT = 30


# ============================================================
# RULE TRÊN cve_description
#
# exact% đo trên 6,985 CVE có nhãn vàng. Chỉ giữ rule >=60%.
# Các rule bị loại và lý do: xem rescue_cwe_gap.py
# ============================================================

RULES = [
    ("null_deref",
     r"null\s*(?:pointer\s*)?(?:dereference|deref)",
     "CWE-476", 76.8),

    ("use_after_free",
     r"use[\s-]?after[\s-]?free",
     "CWE-416", 71.0),

    ("double_free",
     r"double[\s-]free",
     "CWE-415", 73.6),

    ("oob_write",
     r"out[\s-]of[\s-]bounds?\s+write",
     "CWE-787", 68.9),

    ("oob_read",
     r"out[\s-]of[\s-]bounds?\s+read"
     r"|buffer\s+over[\s-]?read|over[\s-]?read",
     "CWE-125", 78.2),

    ("xss",
     r"cross[\s-]site\s+scripting|\bxss\b",
     "CWE-79", 95.3),

    ("sqli",
     r"sql\s+injection",
     "CWE-89", 98.4),

    ("csrf",
     r"cross[\s-]site\s+request\s+forgery|\bcsrf\b",
     "CWE-352", 92.3),

    ("path_traversal",
     r"(?:directory|path)\s+traversal",
     "CWE-22", 91.8),

    ("integer_overflow",
     r"integer\s+overflow",
     "CWE-190", 62.5),

    ("div_by_zero",
     r"divide[\s-]by[\s-]zero|division\s+by\s+zero",
     "CWE-369", 84.4),

    ("race",
     r"race\s+condition",
     "CWE-362", 86.0),

    ("format_string",
     r"format\s+string",
     "CWE-134", 77.8),

    ("ssrf",
     r"server[\s-]side\s+request\s+forgery|\bssrf\b",
     "CWE-918", 94.1),

    ("open_redirect",
     r"open\s+redirect",
     "CWE-601", 89.5),
]


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


def predict_from_description(text):

    if not isinstance(
        text,
        str,
    ):
        return (
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
            )

    return (
        None,
        None,
        None,
    )


# ============================================================
# LOAD SOURCE TABLES
# ============================================================

def load_gz(path):

    path = Path(
        path
    )

    if not path.exists():

        print(
            f"  WARNING thiếu {path}"
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
    """Chuẩn hoá CWE, bỏ CVE không còn CWE thật nào."""

    result = {}

    for cve, values in (
        table.items()
    ):

        cwes = []

        for value in values:

            for cwe in (
                normalize_cwe_value(
                    str(value)
                )
            ):

                if cwe not in cwes:

                    cwes.append(
                        cwe
                    )

        if cwes:

            result[
                str(cve)
                .strip()
                .upper()
            ] = cwes

    return result


def load_sources():

    print(
        "\n"
        + "=" * 78
    )

    print(
        "NGUỒN CWE"
    )

    print(
        "=" * 78
    )

    nvd = load_gz(
        NVD_SCAN_CACHE
    )

    org = load_gz(
        CVEORG_SCAN_CACHE
    )

    osv = load_gz(
        OSV_SCAN_CACHE
    )

    mitre = (
        json.load(
            open(
                MITRE_OBSERVED,
                encoding="utf-8",
            )
        )
        if MITRE_OBSERVED.exists()
        else {}
    )

    # thứ tự = thang ưu tiên
    ladder = [
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
            "cveorg_cna_primary",
            clean_table(
                org.get(
                    "cve_to_primary",
                    {}
                )
            ),
        ),
        (
            "nvd_evaluator_note",
            clean_table(
                nvd.get(
                    "cve_to_evaluator",
                    {}
                )
            ),
        ),
        (
            "osv_database_specific",
            clean_table(
                osv.get(
                    "cve_to_cwes",
                    {}
                )
            ),
        ),
        (
            "mitre_observed_example",
            clean_table(
                mitre
            ),
        ),
        (
            "nvd_all_weaknesses",
            clean_table(
                nvd.get(
                    "cve_to_cwes",
                    {}
                )
            ),
        ),
        (
            "cveorg_all_containers",
            clean_table(
                org.get(
                    "cve_to_cwes",
                    {}
                )
            ),
        ),
    ]

    for name, table in ladder:

        print(
            f"  {name:<24s} "
            f"{len(table):>8,} CVE"
        )

    return ladder


# ============================================================
# RED HAT
# ============================================================

def load_redhat_cache():

    if REDHAT_CACHE.exists():

        return json.load(
            open(
                REDHAT_CACHE,
                encoding="utf-8",
            )
        )

    return {}


def redhat_cwes(
    cve,
    cache,
):
    """
    -> list CWE, hoặc [] nếu Red Hat không có.

    Chỉ gọi mạng khi CVE chưa có trong cache.
    """

    if cve not in cache:

        if not REDHAT_ENABLED:
            return []

        url = (
            "https://access.redhat.com/"
            "hydra/rest/securitydata/cve/"
            f"{cve}.json"
        )

        try:

            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent":
                        "TitanVul-Research/1.0"
                },
            )

            cache[cve] = json.load(
                urllib.request.urlopen(
                    request,
                    timeout=REDHAT_TIMEOUT,
                )
            )

        except urllib.error.HTTPError as e:

            cache[cve] = {
                "_http": e.code
            }

        except Exception as e:

            cache[cve] = {
                "_err":
                    type(e).__name__
            }

        time.sleep(
            REDHAT_DELAY
        )

    record = cache[cve]

    if not isinstance(
        record,
        dict,
    ):
        return []

    return normalize_cwe_value(
        str(
            record.get(
                "cwe"
            )
            or ""
        )
    )


# ============================================================
# FEEDLY
#
# Chỉ đọc cache cục bộ, KHÔNG gọi mạng trong script này.
# Cache do feedly_crawl chuẩn bị riêng.
# ============================================================

def load_feedly():

    if not FEEDLY_CACHE.exists():

        print(
            f"  {'feedly (cache)':<24s} "
            f"{'(không có)':>8s}"
        )

        return {}

    raw = json.load(
        open(
            FEEDLY_CACHE,
            encoding="utf-8",
        )
    )

    result = {}

    for cve, values in raw.items():

        if not isinstance(
            values,
            list,
        ):
            continue

        cwes = []

        for item in values:

            if not isinstance(
                item,
                dict,
            ):
                continue

            for cwe in (
                normalize_cwe_value(
                    str(
                        item.get(
                            "cweID",
                            ""
                        )
                    )
                )
            ):

                if cwe not in cwes:

                    cwes.append(
                        cwe
                    )

        if cwes:

            result[
                str(cve)
                .strip()
                .upper()
            ] = cwes

    print(
        f"  {'feedly_enrichment':<24s} "
        f"{len(result):>8,} CVE"
    )

    return result


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 78
    )

    print(
        "DÒ CWE QUA TẤT CẢ NGUỒN"
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

    ladder = load_sources()

    feedly = load_feedly()

    redhat = load_redhat_cache()

    print(
        f"  {'redhat_api (cache)':<24s} "
        f"{len(redhat):>8,} CVE"
    )

    # ========================================================
    # LỌC: có CVE hoặc có CWE
    # ========================================================

    labeled = (
        df[
            df["cve_id"].notna()
            |
            df["cwe_id"].notna()
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
        "MẪU CÓ NHÃN"
    )

    print(
        "=" * 78
    )

    has_cve = (
        labeled["cve_id"].notna()
    )

    has_cwe = (
        labeled["cwe_id"].notna()
    )

    print(
        f"Tổng dataset:      "
        f"{len(df):,}"
    )

    print(
        f"Có CVE hoặc CWE:   "
        f"{len(labeled):,}"
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
        f"   <- cần dò thêm"
    )

    print(
        f"  chỉ CWE:         "
        f"{int((has_cwe & ~has_cve).sum()):,}"
    )

    # ========================================================
    # DÒ
    # ========================================================

    label = []
    source = []
    every_all = []
    rule_used = []
    rule_acc = []
    conf = []

    stats = Counter()
    rule_stats = Counter()
    redhat_calls = 0

    print(
        "\nĐang dò..."
    )

    for i, idx in enumerate(
        labeled.index
    ):

        if i and i % 5000 == 0:

            print(
                f"  {i:,}/{len(labeled):,}",
                flush=True,
            )

        raw_cwe = labeled.at[
            idx,
            "cwe_id"
        ]

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

        # ----------------------------------------------------
        # gom candidate từ MỌI nguồn cục bộ
        # ----------------------------------------------------

        candidates = []

        for name, table in ladder:

            for cwe in table.get(
                cve,
                []
            ):

                if cwe not in candidates:

                    candidates.append(
                        cwe
                    )

        # ----------------------------------------------------
        # tầng 0: đã có cwe_id
        # ----------------------------------------------------

        existing = (
            normalize_cwe_value(
                str(raw_cwe)
            )
            if isinstance(raw_cwe, str)
            else []
        )

        if existing:

            for cwe in existing:

                if cwe not in candidates:

                    candidates.append(
                        cwe
                    )

            label.append(
                existing[0]
            )

            source.append(
                "pipeline_cwe_id"
            )

            every_all.append(
                ";".join(
                    candidates
                )
            )

            rule_used.append(
                ""
            )

            rule_acc.append(
                None
            )

            conf.append(
                labeled.at[
                    idx,
                    "cwe_confidence"
                ]
                if "cwe_confidence"
                in labeled.columns
                else "high"
            )

            stats["pipeline_cwe_id"] += 1

            continue

        # ----------------------------------------------------
        # tầng 1..6: thang nguồn cục bộ, lấy khi CHỈ 1 CWE
        # ----------------------------------------------------

        chosen = None
        chosen_src = None

        for name, table in ladder:

            values = table.get(
                cve,
                []
            )

            if len(values) == 1:

                chosen = values[0]
                chosen_src = name

                break

        # toàn bộ nguồn chỉ ra đúng 1 CWE
        if (
            chosen is None
            and
            len(candidates) == 1
        ):

            chosen = candidates[0]
            chosen_src = "all_sources_single"

        # ----------------------------------------------------
        # tầng 7: Red Hat
        # ----------------------------------------------------

        if chosen is None and cve:

            before = len(redhat)

            rh = redhat_cwes(
                cve,
                redhat,
            )

            if len(redhat) > before:
                redhat_calls += 1

            for cwe in rh:

                if cwe not in candidates:

                    candidates.append(
                        cwe
                    )

            if rh:

                chosen = rh[0]
                chosen_src = "redhat_api"

        # ----------------------------------------------------
        # tầng 8: Feedly enrichment
        # ----------------------------------------------------

        if cve:

            for cwe in feedly.get(
                cve,
                []
            ):

                if cwe not in candidates:

                    candidates.append(
                        cwe
                    )

        if chosen is None and cve:

            values = feedly.get(
                cve,
                []
            )

            if values:

                chosen = values[0]
                chosen_src = "feedly_enrichment"

        # ----------------------------------------------------
        # tầng 9: rule trên description
        # ----------------------------------------------------

        rname = ""
        racc = None

        if chosen is None:

            (
                cwe,
                rname_,
                racc_,
            ) = predict_from_description(
                labeled.at[
                    idx,
                    "cve_description"
                ]
                if "cve_description"
                in labeled.columns
                else None
            )

            if cwe:

                chosen = cwe
                chosen_src = "description_rule"
                rname = rname_
                racc = racc_

                if cwe not in candidates:

                    candidates.append(
                        cwe
                    )

        # ----------------------------------------------------
        # nhiều CWE nhưng không tầng nào chốt được
        # ----------------------------------------------------

        if (
            chosen is None
            and
            len(candidates) > 1
        ):

            chosen = candidates[0]
            chosen_src = "multi_source_ambiguous"

        # ----------------------------------------------------

        if chosen is None:

            label.append(
                None
            )

            source.append(
                None
            )

            every_all.append(
                ";".join(
                    candidates
                )
            )

            rule_used.append(
                ""
            )

            rule_acc.append(
                None
            )

            conf.append(
                None
            )

            stats["KHONG_TRACE_DUOC"] += 1

            continue

        label.append(
            chosen
        )

        source.append(
            chosen_src
        )

        every_all.append(
            ";".join(
                candidates
            )
        )

        rule_used.append(
            rname
        )

        rule_acc.append(
            racc
        )

        conf.append(
            "feedly"
            if chosen_src == "feedly_enrichment"
            else
            "medium"
            if chosen_src in (
                "description_rule",
                "multi_source_ambiguous",
            )
            else
            "high"
        )

        stats[chosen_src] += 1

        if rname:
            rule_stats[rname] += 1

    labeled["cwe_label_final"] = label
    labeled["cwe_label_final_source"] = source
    labeled["cwe_label_final_all"] = every_all
    labeled["cwe_label_final_rule"] = rule_used
    labeled["cwe_label_final_acc"] = rule_acc
    labeled["cwe_label_final_conf"] = conf

    labeled["has_cwe_label_final"] = (
        labeled["cwe_label_final"].notna()
    )

    if redhat_calls:

        json.dump(
            redhat,
            open(
                REDHAT_CACHE,
                "w",
                encoding="utf-8",
            ),
        )

        print(
            f"  Red Hat: gọi mới "
            f"{redhat_calls:,} CVE"
        )

    # ========================================================
    # BÁO CÁO
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "NGUỒN QUYẾT ĐỊNH cwe_label_final"
    )

    print(
        "=" * 78
    )

    for key, value in (
        stats.most_common()
    ):

        print(
            f"  {key:<26s} "
            f"{value:>7,}"
        )

    if rule_stats:

        print(
            "\n  chi tiết description_rule:"
        )

        acc_by_rule = {
            name: acc
            for name, _, _, acc in RULES
        }

        for rule, count in (
            rule_stats.most_common()
        ):

            print(
                f"    {rule:<22s} "
                f"{count:>5,}"
                f"   exact "
                f"{acc_by_rule[rule]:>5.1f}%"
            )

    filled = int(
        labeled[
            "has_cwe_label_final"
        ].sum()
    )

    gap = labeled[
        labeled["cve_id"].notna()
        &
        ~labeled[
            "has_cwe_label_final"
        ]
    ]

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
        f"cwe_label_final có giá trị:  "
        f"{filled:,}/{len(labeled):,} "
        f"({filled/len(labeled)*100:.2f}%)"
    )

    print(
        f"\n>>> CÓ CVE MÀ KHÔNG CÓ CWE: "
        f"{len(gap):,} dòng"
        f"  /  {gap['cve_id'].nunique():,} CVE duy nhất"
    )

    print(
        f"    = {len(gap)/len(labeled)*100:.2f}% "
        f"số mẫu có nhãn"
    )

    print(
        f"    = {len(gap)/len(df)*100:.2f}% "
        f"toàn dataset"
    )

    if len(gap):

        print(
            "\n  theo ngôn ngữ:"
        )

        for k, v in (
            gap["language"]
            .value_counts()
            .head(10)
            .items()
        ):

            print(
                f"    {str(k):<14s} {v:>5,}"
            )

        desc = (
            gap["cve_description"]
            .astype("string")
        )

        usable = (
            desc.notna()
            &
            ~desc.str.strip()
            .str.lower()
            .isin(
                [
                    "",
                    "nan",
                    "none",
                    "null",
                ]
            )
        )

        print(
            f"\n  có cve_description: "
            f"{int(usable.sum()):,}"
            f"  |  trống: "
            f"{int((~usable).sum()):,}"
        )

    print(
        "\n  theo confidence:"
    )

    print(
        labeled["cwe_label_final_conf"]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    counts = (
        labeled["cwe_label_final"]
        .value_counts()
    )

    print(
        f"\n  số lớp CWE: {len(counts):,}"
        f"  |  lớp có <10 mẫu: "
        f"{int((counts < 10).sum()):,}"
    )

    print(
        "\n  top 15 lớp:"
    )

    print(
        counts
        .head(15)
        .to_string()
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
            "cve_description",

            "cwe_id",
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
        if col in labeled.columns
    ]

    labeled[
        audit_cols
    ].to_csv(
        OUT_AUDIT,
        index=True,
    )

    labeled[
        labeled["has_cwe_label_final"]
    ].to_parquet(
        OUT_TRAINABLE,
        index=False,
    )

    gap[
        audit_cols
    ].to_csv(
        OUT_GAP,
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

    for name, count in [
        (
            OUT_PARQUET.name,
            len(labeled),
        ),
        (
            OUT_CSV.name,
            len(labeled),
        ),
        (
            OUT_AUDIT.name,
            len(labeled),
        ),
        (
            OUT_TRAINABLE.name,
            filled,
        ),
        (
            OUT_GAP.name,
            len(gap),
        ),
    ]:

        print(
            f"  {str(name):<45s} "
            f"{count:>7,} dòng"
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
