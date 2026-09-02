import gzip
import json
import re
from datetime import datetime
from pathlib import Path

import pandas as pd
import requests


# ============================================================
# CONFIG
# ============================================================

INPUT_PARQUET = "TitanVul_recovery_3methods_FIXED.parquet"

OUTPUT_PARQUET = "TitanVul_recovery_4methods_NVD.parquet"
OUTPUT_CSV = "TitanVul_recovery_4methods_NVD.csv"
OUTPUT_AUDIT = "TitanVul_nvd_audit.csv"


# ============================================================
# NVD FEEDS
# ============================================================

NVD_FEED_BASE = (
    "https://nvd.nist.gov/"
    "feeds/json/cve/2.0"
)

NVD_CACHE_DIR = Path(
    "nvd_feeds"
)

# TitanVul của bạn có CVE khá cũ.
START_YEAR = 2002

END_YEAR = datetime.now().year

REQUEST_TIMEOUT = 180

DOWNLOAD_CHUNK_SIZE = (
    1024 * 1024
)


# ============================================================
# CONSERVATIVE MODE
#
# True:
#   chỉ auto-fill khi NVD reference có tag "Patch".
#
# False:
#   chỉ cần reference URL chứa exact commit SHA.
#
# Với ground truth nên giữ True.
# ============================================================

REQUIRE_PATCH_TAG = True


# ============================================================
# REGEX
# ============================================================

SHA40_RE = re.compile(
    r"(?<![0-9a-fA-F])"
    r"([0-9a-fA-F]{40})"
    r"(?![0-9a-fA-F])"
)

CVE_RE = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE,
)

CWE_RE = re.compile(
    r"^CWE-(\d+)$",
    re.IGNORECASE,
)


COMMIT_LINK_RE = re.compile(
    r"(?:"
    r"/commit/"
    r"|/commits/"
    r"|/-/commit/"
    r")"
    r"([0-9a-fA-F]{40})"
    r"(?:[/?#]|$)",
    re.IGNORECASE,
)


# ============================================================
# MISSING
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


def normalize_missing(df):

    for col in [
        "cve_id",
        "cwe_id",
    ]:

        if col not in df.columns:
            continue

        mask = (
            df[col]
            .apply(is_missing)
        )

        df.loc[
            mask,
            col
        ] = None

    return df


# ============================================================
# COMMIT SHA
# ============================================================

def extract_commit_sha(
    commit_link,
):

    if not isinstance(
        commit_link,
        str,
    ):
        return None

    commit_link = (
        commit_link.strip()
    )

    match = COMMIT_LINK_RE.search(
        commit_link
    )

    if not match:
        return None

    return (
        match.group(1)
        .lower()
    )


# ============================================================
# DOWNLOAD NVD YEAR FEED
# ============================================================

def download_file(
    url,
    destination,
):

    destination = Path(
        destination
    )

    if destination.exists():

        size_mb = (
            destination.stat().st_size
            /
            1024
            /
            1024
        )

        print(
            f"Cached: "
            f"{destination.name} "
            f"({size_mb:.1f} MB)"
        )

        return

    print(
        f"Downloading: "
        f"{url}"
    )

    tmp = Path(
        str(destination)
        +
        ".part"
    )

    with requests.get(
        url,
        stream=True,
        timeout=REQUEST_TIMEOUT,
    ) as response:

        response.raise_for_status()

        total = int(
            response.headers.get(
                "content-length",
                0,
            )
        )

        downloaded = 0

        with open(
            tmp,
            "wb",
        ) as f:

            for chunk in (
                response.iter_content(
                    chunk_size=
                    DOWNLOAD_CHUNK_SIZE
                )
            ):

                if not chunk:
                    continue

                f.write(
                    chunk
                )

                downloaded += len(
                    chunk
                )

                if total:

                    pct = (
                        downloaded
                        /
                        total
                        *
                        100
                    )

                    print(
                        f"\r  "
                        f"{downloaded/1024/1024:.1f}"
                        f"/"
                        f"{total/1024/1024:.1f}"
                        f" MB "
                        f"({pct:.1f}%)",
                        end="",
                        flush=True,
                    )

        print()

    tmp.replace(
        destination
    )


def download_nvd_feeds():

    NVD_CACHE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    files = []

    for year in range(
        START_YEAR,
        END_YEAR + 1,
    ):

        filename = (
            f"nvdcve-2.0-"
            f"{year}.json.gz"
        )

        url = (
            f"{NVD_FEED_BASE}/"
            f"{filename}"
        )

        destination = (
            NVD_CACHE_DIR
            /
            filename
        )

        download_file(
            url,
            destination,
        )

        files.append(
            destination
        )

    return files


# ============================================================
# EXTRACT CWE FROM NVD CVE
# ============================================================

def extract_nvd_cwes(
    cve,
):

    cwes = []

    weaknesses = cve.get(
        "weaknesses",
        []
    )

    if not isinstance(
        weaknesses,
        list,
    ):
        return []

    for weakness in weaknesses:

        if not isinstance(
            weakness,
            dict,
        ):
            continue

        descriptions = (
            weakness.get(
                "description",
                []
            )
        )

        if not isinstance(
            descriptions,
            list,
        ):
            continue

        for description in (
            descriptions
        ):

            if not isinstance(
                description,
                dict,
            ):
                continue

            value = (
                description.get(
                    "value"
                )
            )

            if not isinstance(
                value,
                str,
            ):
                continue

            value = (
                value.strip()
                .upper()
            )

            if not CWE_RE.fullmatch(
                value
            ):
                continue

            if value not in cwes:

                cwes.append(
                    value
                )

    return sorted(
        cwes
    )


# ============================================================
# PATCH TAG?
# ============================================================

def is_patch_reference(
    reference,
):

    tags = reference.get(
        "tags",
        []
    )

    if not isinstance(
        tags,
        list,
    ):
        return False

    return any(
        str(tag).lower()
        ==
        "patch"
        for tag in tags
    )


# ============================================================
# FIND TARGET SHAs IN NVD REFERENCE
# ============================================================

def shas_in_reference(
    url,
    target_shas,
):

    if not isinstance(
        url,
        str,
    ):
        return []

    found = []

    for match in SHA40_RE.findall(
        url
    ):

        sha = match.lower()

        if (
            sha in target_shas
            and
            sha not in found
        ):

            found.append(
                sha
            )

    return found


# ============================================================
# SCAN NVD
#
# Build:
#
# SHA -> evidence
# CVE -> CWE
# ============================================================

def scan_nvd(
    feed_files,
    target_shas,
):

    target_shas = set(
        target_shas
    )

    sha_matches = {}

    # Store even refs without Patch,
    # just for audit.
    sha_nonpatch_matches = {}

    cve_to_cwes = {}

    total_records = 0

    total_references = 0

    patch_references = 0

    matched_patch_refs = 0

    matched_nonpatch_refs = 0

    print(
        "\n"
        + "=" * 78
    )

    print(
        "SCAN NVD JSON 2.0"
    )

    print(
        "=" * 78
    )

    for feed_path in feed_files:

        print(
            f"\nReading: "
            f"{feed_path.name}"
        )

        try:

            with gzip.open(
                feed_path,
                "rt",
                encoding="utf-8",
            ) as f:

                data = json.load(
                    f
                )

        except Exception as e:

            print(
                f"ERROR reading "
                f"{feed_path}: {e}"
            )

            continue

        vulnerabilities = (
            data.get(
                "vulnerabilities",
                []
            )
        )

        print(
            f"Records: "
            f"{len(vulnerabilities):,}"
        )

        for item in vulnerabilities:

            total_records += 1

            if not isinstance(
                item,
                dict,
            ):
                continue

            cve = item.get(
                "cve",
                {}
            )

            if not isinstance(
                cve,
                dict,
            ):
                continue

            cve_id = cve.get(
                "id"
            )

            if not isinstance(
                cve_id,
                str,
            ):
                continue

            cve_id = (
                cve_id.strip()
                .upper()
            )

            if not CVE_RE.fullmatch(
                cve_id
            ):
                continue

            # =================================================
            # CVE -> CWE mapping
            # =================================================

            cwes = extract_nvd_cwes(
                cve
            )

            cve_to_cwes[
                cve_id
            ] = cwes

            # =================================================
            # References
            # =================================================

            references = (
                cve.get(
                    "references",
                    []
                )
            )

            if not isinstance(
                references,
                list,
            ):
                continue

            for reference in (
                references
            ):

                if not isinstance(
                    reference,
                    dict,
                ):
                    continue

                total_references += 1

                url = reference.get(
                    "url"
                )

                if not isinstance(
                    url,
                    str,
                ):
                    continue

                patch = is_patch_reference(
                    reference
                )

                if patch:
                    patch_references += 1

                found_shas = (
                    shas_in_reference(
                        url,
                        target_shas,
                    )
                )

                if not found_shas:
                    continue

                tags = reference.get(
                    "tags",
                    []
                )

                evidence = {
                    "cve":
                        cve_id,

                    "cwes":
                        cwes,

                    "url":
                        url,

                    "tags":
                        tags,
                }

                for sha in found_shas:

                    if patch:

                        sha_matches.setdefault(
                            sha,
                            []
                        )

                        if (
                            evidence
                            not in
                            sha_matches[sha]
                        ):

                            sha_matches[
                                sha
                            ].append(
                                evidence
                            )

                            matched_patch_refs += 1

                    else:

                        sha_nonpatch_matches.setdefault(
                            sha,
                            []
                        )

                        if (
                            evidence
                            not in
                            sha_nonpatch_matches[
                                sha
                            ]
                        ):

                            sha_nonpatch_matches[
                                sha
                            ].append(
                                evidence
                            )

                            matched_nonpatch_refs += 1

    print(
        "\n"
        + "=" * 78
    )

    print(
        "NVD SCAN SUMMARY"
    )

    print(
        "=" * 78
    )

    print(
        f"NVD records scanned:       "
        f"{total_records:,}"
    )

    print(
        f"References inspected:      "
        f"{total_references:,}"
    )

    print(
        f"References tagged Patch:   "
        f"{patch_references:,}"
    )

    print(
        f"Target SHA w/ Patch ref:   "
        f"{len(sha_matches):,}"
    )

    print(
        f"Target SHA w/ non-Patch:   "
        f"{len(sha_nonpatch_matches):,}"
    )

    print(
        f"Matched Patch evidences:   "
        f"{matched_patch_refs:,}"
    )

    print(
        f"Matched non-Patch refs:    "
        f"{matched_nonpatch_refs:,}"
    )

    return {
        "patch_matches":
            sha_matches,

        "nonpatch_matches":
            sha_nonpatch_matches,

        "cve_to_cwes":
            cve_to_cwes,
    }


# ============================================================
# UNIQUE CVEs
# ============================================================

def get_unique_cves(
    evidence,
):

    result = []

    for e in evidence:

        cve = e.get(
            "cve"
        )

        if (
            cve
            and
            cve not in result
        ):

            result.append(
                cve
            )

    return sorted(
        result
    )


# ============================================================
# UNIQUE CWEs
# ============================================================

def get_unique_cwes(
    evidence,
):

    result = []

    for e in evidence:

        for cwe in e.get(
            "cwes",
            []
        ):

            if cwe not in result:

                result.append(
                    cwe
                )

    return sorted(
        result
    )


# ============================================================
# APPLY METHOD 4
# ============================================================

def apply_nvd(
    df,
    scan_result,
):

    patch_matches = (
        scan_result[
            "patch_matches"
        ]
    )

    nonpatch_matches = (
        scan_result[
            "nonpatch_matches"
        ]
    )

    cve_to_cwes = (
        scan_result[
            "cve_to_cwes"
        ]
    )

    # ========================================================
    # SHA
    # ========================================================

    df[
        "commit_sha"
    ] = (
        df[
            "commit_link"
        ]
        .apply(
            extract_commit_sha
        )
    )

    # ========================================================
    # Audit fields
    # ========================================================

    df[
        "nvd_cve_candidates"
    ] = ""

    df[
        "nvd_cwe_candidates"
    ] = ""

    df[
        "nvd_patch_urls"
    ] = ""

    df[
        "nvd_status"
    ] = None

    # ========================================================
    # Counters
    # ========================================================

    new_cve = 0

    new_cwe_from_patch = 0

    ambiguous_cve = 0

    multi_cwe = 0

    nonpatch_only = 0

    no_match = 0

    # ========================================================
    # PART A
    # SHA -> CVE using NVD Patch references
    # ========================================================

    missing_cve_indices = (
        df.index[
            df[
                "cve_id"
            ].isna()
        ]
    )

    for idx in missing_cve_indices:

        sha = df.at[
            idx,
            "commit_sha"
        ]

        if not sha:

            df.at[
                idx,
                "nvd_status"
            ] = "no_sha40"

            continue

        evidence = (
            patch_matches.get(
                sha,
                []
            )
        )

        # ----------------------------------------------------
        # No Patch match
        # ----------------------------------------------------

        if not evidence:

            nonpatch = (
                nonpatch_matches.get(
                    sha,
                    []
                )
            )

            if nonpatch:

                cves = get_unique_cves(
                    nonpatch
                )

                df.at[
                    idx,
                    "nvd_cve_candidates"
                ] = ";".join(
                    cves
                )

                df.at[
                    idx,
                    "nvd_status"
                ] = (
                    "exact_sha_nonpatch_only"
                )

                nonpatch_only += 1

            else:

                df.at[
                    idx,
                    "nvd_status"
                ] = "no_exact_sha_reference"

                no_match += 1

            continue

        # ----------------------------------------------------
        # Patch match
        # ----------------------------------------------------

        cves = get_unique_cves(
            evidence
        )

        cwes = get_unique_cwes(
            evidence
        )

        urls = sorted({
            e.get(
                "url"
            )
            for e in evidence
            if e.get(
                "url"
            )
        })

        df.at[
            idx,
            "nvd_cve_candidates"
        ] = ";".join(
            cves
        )

        df.at[
            idx,
            "nvd_cwe_candidates"
        ] = ";".join(
            cwes
        )

        df.at[
            idx,
            "nvd_patch_urls"
        ] = ";".join(
            urls
        )

        # ----------------------------------------------------
        # 1 CVE only
        # ----------------------------------------------------

        if len(cves) == 1:

            cve = cves[0]

            df.at[
                idx,
                "cve_id"
            ] = cve

            df.at[
                idx,
                "cve_source"
            ] = (
                "nvd_patch_commit_exact"
            )

            new_cve += 1

            # ------------------------------------------------
            # Also CWE if currently missing
            # and exactly one CWE
            # ------------------------------------------------

            if (
                is_missing(
                    df.at[
                        idx,
                        "cwe_id"
                    ]
                )
                and
                len(cwes) == 1
            ):

                df.at[
                    idx,
                    "cwe_id"
                ] = cwes[0]

                df.at[
                    idx,
                    "cwe_source"
                ] = (
                    "nvd_patch_commit_exact"
                )

                new_cwe_from_patch += 1

            elif (
                is_missing(
                    df.at[
                        idx,
                        "cwe_id"
                    ]
                )
                and
                len(cwes) > 1
            ):

                multi_cwe += 1

            df.at[
                idx,
                "nvd_status"
            ] = "single_cve_filled"

        # ----------------------------------------------------
        # Multiple CVE
        # ----------------------------------------------------

        elif len(cves) > 1:

            df.at[
                idx,
                "nvd_status"
            ] = "multiple_cves_ambiguous"

            ambiguous_cve += 1

        else:

            df.at[
                idx,
                "nvd_status"
            ] = "patch_ref_without_cve"

    # ========================================================
    # PART B
    #
    # Existing/new CVE -> CWE via NVD
    #
    # Only if EXACTLY ONE numeric CWE.
    # ========================================================

    cwe_from_cve = 0

    cwe_ambiguous = 0

    missing_cwe_indices = (
        df.index[
            df[
                "cwe_id"
            ].isna()
            &
            df[
                "cve_id"
            ].notna()
        ]
    )

    for idx in missing_cwe_indices:

        cve = str(
            df.at[
                idx,
                "cve_id"
            ]
        ).strip().upper()

        cwes = (
            cve_to_cwes.get(
                cve,
                []
            )
        )

        if len(cwes) == 1:

            df.at[
                idx,
                "cwe_id"
            ] = cwes[0]

            df.at[
                idx,
                "cwe_source"
            ] = (
                "nvd_cve_exact"
            )

            cwe_from_cve += 1

        elif len(cwes) > 1:

            cwe_ambiguous += 1

    return {
        "df":
            df,

        "new_cve":
            new_cve,

        "new_cwe_from_patch":
            new_cwe_from_patch,

        "cwe_from_cve":
            cwe_from_cve,

        "ambiguous_cve":
            ambiguous_cve,

        "multi_cwe":
            multi_cwe,

        "cwe_ambiguous":
            cwe_ambiguous,

        "nonpatch_only":
            nonpatch_only,

        "no_match":
            no_match,
    }


# ============================================================
# PRINT EXAMPLE
# ============================================================

def print_example(
    before,
    after,
):

    samples = after[
        after[
            "cve_source"
        ]
        ==
        "nvd_patch_commit_exact"
    ]

    if len(samples) == 0:

        print(
            "\nKhông có sample mới "
            "từ NVD Patch reference."
        )

        return

    row = (
        samples.iloc[0]
    )

    idx = row.name

    print(
        "\n"
        + "=" * 78
    )

    print(
        "EXAMPLE - NVD PATCH REFERENCE"
    )

    print(
        "=" * 78
    )

    print(
        f"Index             : "
        f"{idx}"
    )

    print(
        f"Commit            : "
        f"{row['commit_link']}"
    )

    print(
        f"SHA               : "
        f"{row['commit_sha']}"
    )

    print(
        f"File              : "
        f"{row['file_name']}"
    )

    print(
        f"\nCVE trước         : "
        f"{before.at[idx, 'cve_id']}"
    )

    print(
        f"CVE sau           : "
        f"{row['cve_id']}"
    )

    print(
        f"CVE source        : "
        f"{row['cve_source']}"
    )

    print(
        f"\nCWE trước         : "
        f"{before.at[idx, 'cwe_id']}"
    )

    print(
        f"CWE sau           : "
        f"{row['cwe_id']}"
    )

    print(
        f"CWE source        : "
        f"{row['cwe_source']}"
    )

    print(
        f"\nNVD CVEs          : "
        f"{row['nvd_cve_candidates']}"
    )

    print(
        f"NVD CWEs          : "
        f"{row['nvd_cwe_candidates']}"
    )

    print(
        "\nNVD Patch URLs:"
    )

    print(
        row[
            "nvd_patch_urls"
        ]
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 78
    )

    print(
        "METHOD 4 - NVD EXACT PATCH COMMIT REFERENCE"
    )

    print(
        "=" * 78
    )

    # ========================================================
    # Load
    # ========================================================

    df = pd.read_parquet(
        INPUT_PARQUET
    )

    df = normalize_missing(
        df
    )

    before = df.copy()

    total = len(df)

    before_cve = (
        df[
            "cve_id"
        ].notna()
    )

    before_cwe = (
        df[
            "cwe_id"
        ].notna()
    )

    before_any = (
        before_cve
        |
        before_cwe
    )

    before_both = (
        before_cve
        &
        before_cwe
    )

    print(
        f"Total:                       "
        f"{total:,}"
    )

    print(
        f"Trước có CVE:               "
        f"{before_cve.sum():,}"
    )

    print(
        f"Trước có CWE:               "
        f"{before_cwe.sum():,}"
    )

    print(
        f"Trước có cả CVE + CWE:      "
        f"{before_both.sum():,}"
    )

    print(
        f"Trước có >=1:               "
        f"{before_any.sum():,}"
    )

    print(
        f"Trước thiếu cả hai:         "
        f"{(~before_any).sum():,}"
    )

    # ========================================================
    # Target SHAs:
    # only rows missing CVE
    # ========================================================

    target_sha_series = (
        df.loc[
            df[
                "cve_id"
            ].isna(),
            "commit_link"
        ]
        .apply(
            extract_commit_sha
        )
    )

    target_shas = set(
        target_sha_series
        .dropna()
        .tolist()
    )

    print(
        f"\nTarget unique SHA40:        "
        f"{len(target_shas):,}"
    )

    # ========================================================
    # Download NVD
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "DOWNLOAD/CACHE NVD FEEDS"
    )

    print(
        "=" * 78
    )

    feed_files = (
        download_nvd_feeds()
    )

    # ========================================================
    # Scan
    # ========================================================

    scan_result = scan_nvd(
        feed_files,
        target_shas,
    )

    # ========================================================
    # Apply
    # ========================================================

    result = apply_nvd(
        df,
        scan_result,
    )

    df = result[
        "df"
    ]

    # ========================================================
    # Final stats
    # ========================================================

    after_cve = (
        df[
            "cve_id"
        ].notna()
    )

    after_cwe = (
        df[
            "cwe_id"
        ].notna()
    )

    after_any = (
        after_cve
        |
        after_cwe
    )

    after_both = (
        after_cve
        &
        after_cwe
    )

    new_cve_mask = (
        ~before_cve
        &
        after_cve
    )

    new_cwe_mask = (
        ~before_cwe
        &
        after_cwe
    )

    rescued_mask = (
        ~before_any
        &
        after_any
    )

    newly_complete_mask = (
        ~before_both
        &
        after_both
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "METHOD 4 RESULT"
    )

    print(
        "=" * 78
    )

    print(
        f"CVE mới từ NVD Patch:       "
        f"{new_cve_mask.sum():,}"
    )

    print(
        f"CWE mới tổng cộng:          "
        f"{new_cwe_mask.sum():,}"
    )

    print(
        f"  CWE cùng Patch CVE:        "
        f"{result['new_cwe_from_patch']:,}"
    )

    print(
        f"  CWE từ CVE->NVD:           "
        f"{result['cwe_from_cve']:,}"
    )

    print(
        f"\nDòng thiếu cả 2 được cứu:   "
        f"{rescued_mask.sum():,}"
    )

    print(
        f"Dòng mới đủ CVE + CWE:      "
        f"{newly_complete_mask.sum():,}"
    )

    print(
        f"\nSHA có >1 CVE, không chọn:  "
        f"{result['ambiguous_cve']:,}"
    )

    print(
        f"Exact SHA nhưng non-Patch:  "
        f"{result['nonpatch_only']:,}"
    )

    print(
        f"CVE có >1 CWE, không chọn:  "
        f"{result['cwe_ambiguous']:,}"
    )

    print(
        "\n"
        f"Trước có >=1 nhãn:          "
        f"{before_any.sum():,}"
        f"/{total:,} "
        f"({before_any.sum()/total*100:.2f}%)"
    )

    print(
        f"Sau có >=1 nhãn:            "
        f"{after_any.sum():,}"
        f"/{total:,} "
        f"({after_any.sum()/total*100:.2f}%)"
    )

    print(
        f"Tăng sample có nhãn:        "
        f"+{after_any.sum()-before_any.sum():,}"
    )

    print(
        f"Vẫn thiếu cả hai:           "
        f"{(~after_any).sum():,}"
        f"/{total:,} "
        f"({(~after_any).sum()/total*100:.2f}%)"
    )

    print(
        f"\nCó cả CVE + CWE sau NVD:    "
        f"{after_both.sum():,}"
        f"/{total:,} "
        f"({after_both.sum()/total*100:.2f}%)"
    )

    # ========================================================
    # Sources
    # ========================================================

    print(
        "\nNguồn CVE:"
    )

    print(
        df[
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
        df[
            "cwe_source"
        ]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    # ========================================================
    # Flags
    # ========================================================

    df[
        "nvd_new_cve"
    ] = new_cve_mask

    df[
        "nvd_new_cwe"
    ] = new_cwe_mask

    df[
        "nvd_newly_rescued"
    ] = rescued_mask

    df[
        "has_vuln_label"
    ] = after_any

    # ========================================================
    # Example
    # ========================================================

    print_example(
        before,
        df,
    )

    # ========================================================
    # Save
    # ========================================================

    df.to_parquet(
        OUTPUT_PARQUET,
        index=False,
    )

    df.to_csv(
        OUTPUT_CSV,
        index=False,
    )

    audit_cols = [
        "file_name",

        "commit_link",
        "commit_sha",
        "commit_message",

        "cve_id",
        "cve_source",

        "cwe_id",
        "cwe_source",

        "nvd_cve_candidates",
        "nvd_cwe_candidates",
        "nvd_patch_urls",
        "nvd_status",

        "nvd_new_cve",
        "nvd_new_cwe",
        "nvd_newly_rescued",
    ]

    audit_cols = [
        col
        for col in audit_cols
        if col in df.columns
    ]

    df[
        audit_cols
    ].to_csv(
        OUTPUT_AUDIT,
        index=True,
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "SAVED"
    )

    print(
        "=" * 78
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