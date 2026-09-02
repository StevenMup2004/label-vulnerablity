import json
import re
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import requests


# ============================================================
# CONFIG
# ============================================================

INPUT_PARQUET = "TitanVul_recovery_2methods.parquet"

OUTPUT_PARQUET = "TitanVul_recovery_3methods_FIXED.parquet"
OUTPUT_CSV = "TitanVul_recovery_3methods_FIXED.csv"
OUTPUT_AUDIT = "TitanVul_osv_fixed_audit.csv"

# OSV full database dump
OSV_DATABASE_URL = (
    "https://storage.googleapis.com/"
    "osv-vulnerabilities/all.zip"
)

OSV_ZIP_FILE = Path("osv_all.zip")

# Cache chỉ dành cho target commits của lần scan này
FIXED_INDEX_CACHE = Path(
    "osv_fixed_commit_matches.json"
)

REQUEST_TIMEOUT = 120

DOWNLOAD_CHUNK_SIZE = 1024 * 1024  # 1 MB


# ============================================================
# OPTIONAL STRICTNESS
# ============================================================

# False:
#   chỉ cần exact fixed SHA match.
#
# True:
#   ngoài SHA còn yêu cầu repository của OSV tương thích
#   với repo trong commit_link.
#
# Khuyên để False trước vì TitanVul có thể dùng mirror/fork.
#
STRICT_REPO_MATCH = False


# ============================================================
# REGEX
# ============================================================

SHA40_RE = re.compile(
    r"^[0-9a-f]{40}$",
    re.IGNORECASE,
)

CVE_RE = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE,
)

# Hỗ trợ:
#
# github.com/a/b/commit/<sha>
# gitlab.com/a/b/-/commit/<sha>
# host/a/b/commits/<sha>
#
COMMIT_SHA_RE = re.compile(
    r"(?:/commit/|/commits/|/-/commit/)"
    r"([0-9a-fA-F]{40})"
    r"(?:[/?#]|$)",
    re.IGNORECASE,
)


# ============================================================
# MISSING VALUES
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

        mask = df[col].apply(
            is_missing
        )

        df.loc[
            mask,
            col
        ] = None

    return df


# ============================================================
# COMMIT SHA
# ============================================================

def extract_commit_sha(commit_link):

    if not isinstance(
        commit_link,
        str,
    ):
        return None

    commit_link = commit_link.strip()

    if not commit_link:
        return None

    match = COMMIT_SHA_RE.search(
        commit_link
    )

    if not match:
        return None

    sha = (
        match.group(1)
        .lower()
    )

    if not SHA40_RE.fullmatch(
        sha
    ):
        return None

    return sha


# ============================================================
# REPOSITORY NORMALIZATION
# ============================================================

def normalize_repo_url(url):

    if not isinstance(url, str):
        return None

    url = url.strip()

    if not url:
        return None

    # git@github.com:owner/repo.git
    if url.startswith("git@"):

        try:
            host_part, path = url.split(
                ":",
                1,
            )

            host = (
                host_part
                .split("@", 1)[1]
                .lower()
            )

            path = (
                path
                .strip("/")
            )

            if path.endswith(".git"):
                path = path[:-4]

            return (
                host
                + "/"
                + path.lower()
            )

        except Exception:
            return None

    # Add scheme if necessary
    if "://" not in url:
        url = "https://" + url

    try:

        parsed = urlparse(url)

        host = (
            parsed.netloc
            .lower()
        )

        path = (
            parsed.path
            .strip("/")
        )

        if path.endswith(".git"):
            path = path[:-4]

        # Commit URL:
        #
        # github.com/owner/repo/commit/...
        #
        pieces = path.split("/")

        # GitHub style
        if (
            len(pieces) >= 2
            and
            host
        ):

            # GitLab may have nested groups.
            #
            # For commit_link normalization we remove known
            # commit suffix rather than assuming owner/repo only.
            commit_markers = [
                "commit",
                "commits",
                "-",
            ]

            if "commit" in pieces:

                pos = pieces.index(
                    "commit"
                )

                pieces = pieces[:pos]

            elif "commits" in pieces:

                pos = pieces.index(
                    "commits"
                )

                pieces = pieces[:pos]

            elif (
                "-" in pieces
                and
                pieces.index("-")
                <
                len(pieces) - 1
                and
                pieces[
                    pieces.index("-") + 1
                ]
                ==
                "commit"
            ):

                pos = pieces.index(
                    "-"
                )

                pieces = pieces[:pos]

            path = "/".join(
                pieces
            )

        path = path.strip("/")

        if not host or not path:
            return None

        return (
            host
            + "/"
            + path.lower()
        )

    except Exception:
        return None


def repo_matches(
    titan_repo,
    osv_repo,
):

    if not titan_repo:
        return False

    if not osv_repo:
        return False

    a = normalize_repo_url(
        titan_repo
    )

    b = normalize_repo_url(
        osv_repo
    )

    if not a or not b:
        return False

    if a == b:
        return True

    # github.com/foo/bar
    # github.com/foo/bar.git
    # đã normalize ở trên.
    return False


# ============================================================
# EXTRACT CVEs FROM OSV RECORD
# ============================================================

def extract_record_cves(record):

    values = []

    osv_id = record.get(
        "id"
    )

    if isinstance(
        osv_id,
        str,
    ):
        values.append(
            osv_id
        )

    aliases = record.get(
        "aliases",
        []
    )

    if isinstance(
        aliases,
        list,
    ):

        values.extend(
            aliases
        )

    cves = []

    for value in values:

        if not isinstance(
            value,
            str,
        ):
            continue

        value = (
            value.strip()
            .upper()
        )

        if CVE_RE.fullmatch(
            value
        ):

            if value not in cves:

                cves.append(
                    value
                )

    return sorted(
        cves
    )


# ============================================================
# DOWNLOAD OSV DATABASE
# ============================================================

def download_osv_database():

    if OSV_ZIP_FILE.exists():

        size_mb = (
            OSV_ZIP_FILE.stat().st_size
            /
            1024
            /
            1024
        )

        print(
            f"OSV database exists: "
            f"{OSV_ZIP_FILE} "
            f"({size_mb:.1f} MB)"
        )

        return

    print(
        "\nDownloading OSV full database..."
    )

    print(
        OSV_DATABASE_URL
    )

    tmp_file = Path(
        str(OSV_ZIP_FILE)
        +
        ".part"
    )

    with requests.get(
        OSV_DATABASE_URL,
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
            tmp_file,
            "wb",
        ) as f:

            for chunk in response.iter_content(
                chunk_size=DOWNLOAD_CHUNK_SIZE
            ):

                if not chunk:
                    continue

                f.write(
                    chunk
                )

                downloaded += len(
                    chunk
                )

                if total > 0:

                    pct = (
                        downloaded
                        /
                        total
                        *
                        100
                    )

                    print(
                        f"\rDownloaded: "
                        f"{downloaded / 1024 / 1024:.1f} MB "
                        f"/ "
                        f"{total / 1024 / 1024:.1f} MB "
                        f"({pct:.1f}%)",
                        end="",
                        flush=True,
                    )

                else:

                    print(
                        f"\rDownloaded: "
                        f"{downloaded / 1024 / 1024:.1f} MB",
                        end="",
                        flush=True,
                    )

    print()

    tmp_file.replace(
        OSV_ZIP_FILE
    )

    print(
        f"Saved: {OSV_ZIP_FILE}"
    )


# ============================================================
# CACHE
# ============================================================

def load_fixed_cache():

    if not FIXED_INDEX_CACHE.exists():
        return {}

    try:

        with open(
            FIXED_INDEX_CACHE,
            "r",
            encoding="utf-8",
        ) as f:

            data = json.load(
                f
            )

        if isinstance(
            data,
            dict,
        ):
            return data

    except Exception as e:

        print(
            f"Warning: cannot read cache: "
            f"{e}"
        )

    return {}


def save_fixed_cache(
    data,
):

    tmp = Path(
        str(FIXED_INDEX_CACHE)
        +
        ".tmp"
    )

    with open(
        tmp,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=2,
        )

    tmp.replace(
        FIXED_INDEX_CACHE
    )


# ============================================================
# SCAN OSV DATABASE FOR EXACT FIXED SHA
# ============================================================

def scan_osv_fixed_commits(
    target_shas,
):

    target_shas = set(
        sha.lower()
        for sha in target_shas
    )

    # --------------------------------------------------------
    # Results:
    #
    # sha -> [
    #   {
    #      "osv_id": ...,
    #      "cves": [...],
    #      "repo": ...
    #   }
    # ]
    # --------------------------------------------------------

    matches = defaultdict(
        list
    )

    scanned = 0

    invalid_json = 0

    withdrawn = 0

    git_ranges = 0

    fixed_events = 0

    print(
        "\n"
        + "=" * 78
    )

    print(
        "SCAN OSV DATABASE FOR events[].fixed"
    )

    print(
        "=" * 78
    )

    with zipfile.ZipFile(
        OSV_ZIP_FILE,
        "r",
    ) as archive:

        names = [
            name
            for name
            in archive.namelist()
            if name.endswith(
                ".json"
            )
        ]

        total = len(
            names
        )

        print(
            f"OSV JSON records: "
            f"{total:,}"
        )

        for name in names:

            scanned += 1

            try:

                with archive.open(
                    name
                ) as f:

                    record = json.load(
                        f
                    )

            except Exception:

                invalid_json += 1

                continue

            # ------------------------------------------------
            # Withdrawn vulnerability: skip
            # ------------------------------------------------

            if record.get(
                "withdrawn"
            ):

                withdrawn += 1

                continue

            cves = (
                extract_record_cves(
                    record
                )
            )

            # Không có CVE alias thì không giúp pipeline này.
            if not cves:

                if (
                    scanned % 10000
                    ==
                    0
                ):

                    print(
                        f"\rScanned "
                        f"{scanned:,}/{total:,} "
                        f"| matched SHA "
                        f"{len(matches):,}",
                        end="",
                        flush=True,
                    )

                continue

            osv_id = record.get(
                "id"
            )

            affected_list = record.get(
                "affected",
                []
            )

            if not isinstance(
                affected_list,
                list,
            ):
                continue

            for affected in affected_list:

                if not isinstance(
                    affected,
                    dict,
                ):
                    continue

                ranges = affected.get(
                    "ranges",
                    []
                )

                if not isinstance(
                    ranges,
                    list,
                ):
                    continue

                for range_obj in ranges:

                    if not isinstance(
                        range_obj,
                        dict,
                    ):
                        continue

                    # ========================================
                    # ONLY GIT RANGES
                    # ========================================

                    if (
                        str(
                            range_obj.get(
                                "type",
                                ""
                            )
                        ).upper()
                        !=
                        "GIT"
                    ):
                        continue

                    git_ranges += 1

                    repo = range_obj.get(
                        "repo"
                    )

                    events = range_obj.get(
                        "events",
                        []
                    )

                    if not isinstance(
                        events,
                        list,
                    ):
                        continue

                    for event in events:

                        if not isinstance(
                            event,
                            dict,
                        ):
                            continue

                        fixed = event.get(
                            "fixed"
                        )

                        if not isinstance(
                            fixed,
                            str,
                        ):
                            continue

                        fixed = (
                            fixed.strip()
                            .lower()
                        )

                        if not SHA40_RE.fullmatch(
                            fixed
                        ):
                            continue

                        fixed_events += 1

                        # ====================================
                        # THE IMPORTANT CHECK
                        # ====================================

                        if fixed not in target_shas:
                            continue

                        evidence = {
                            "osv_id":
                                osv_id,

                            "cves":
                                cves,

                            "repo":
                                repo,

                            "record_file":
                                name,
                        }

                        # Prevent duplicate evidence
                        if (
                            evidence
                            not in
                            matches[fixed]
                        ):

                            matches[
                                fixed
                            ].append(
                                evidence
                            )

            if (
                scanned % 10000
                ==
                0
            ):

                print(
                    f"\rScanned "
                    f"{scanned:,}/{total:,} "
                    f"| matched SHA "
                    f"{len(matches):,}",
                    end="",
                    flush=True,
                )

    print()

    print(
        f"Scanned records:       "
        f"{scanned:,}"
    )

    print(
        f"Withdrawn skipped:     "
        f"{withdrawn:,}"
    )

    print(
        f"Invalid JSON:          "
        f"{invalid_json:,}"
    )

    print(
        f"GIT ranges inspected:  "
        f"{git_ranges:,}"
    )

    print(
        f"Fixed events inspected:"
        f" {fixed_events:,}"
    )

    print(
        f"Target SHA matched:    "
        f"{len(matches):,}"
    )

    return dict(
        matches
    )


# ============================================================
# GET DISTINCT CVEs FOR ONE SHA
# ============================================================

def distinct_cves(
    evidence_list,
):

    result = []

    for evidence in evidence_list:

        for cve in evidence.get(
            "cves",
            []
        ):

            if cve not in result:

                result.append(
                    cve
                )

    return sorted(
        result
    )


# ============================================================
# APPLY EXACT FIXED COMMIT MATCH
# ============================================================

def apply_fixed_matches(
    df,
    fixed_matches,
):

    if (
        "cve_source"
        not in df.columns
    ):

        df[
            "cve_source"
        ] = None

        df.loc[
            df[
                "cve_id"
            ].notna(),
            "cve_source"
        ] = "original"

    # ========================================================
    # Audit fields
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

    df[
        "osv_fixed_cve_candidates"
    ] = ""

    df[
        "osv_fixed_ids"
    ] = ""

    df[
        "osv_fixed_repos"
    ] = ""

    df[
        "osv_fixed_repo_match"
    ] = None

    df[
        "osv_fixed_status"
    ] = None

    filled = 0

    ambiguous = 0

    no_match = 0

    repo_rejected = 0

    no_sha = 0

    # Only rows currently missing CVE
    indices = df.index[
        df[
            "cve_id"
        ].isna()
    ]

    for idx in indices:

        sha = df.at[
            idx,
            "commit_sha"
        ]

        if not sha:

            df.at[
                idx,
                "osv_fixed_status"
            ] = "no_sha40"

            no_sha += 1

            continue

        evidence = fixed_matches.get(
            sha,
            []
        )

        if not evidence:

            df.at[
                idx,
                "osv_fixed_status"
            ] = "no_exact_fixed_match"

            no_match += 1

            continue

        # ====================================================
        # Repository evidence
        # ====================================================

        titan_link = df.at[
            idx,
            "commit_link"
        ]

        repos = sorted({
            str(
                x.get(
                    "repo"
                )
            )
            for x in evidence
            if x.get(
                "repo"
            )
        })

        repo_match = any(
            repo_matches(
                titan_link,
                repo,
            )
            for repo in repos
        )

        df.at[
            idx,
            "osv_fixed_repo_match"
        ] = repo_match

        df.at[
            idx,
            "osv_fixed_repos"
        ] = ";".join(
            repos
        )

        # ====================================================
        # Strict repo mode
        # ====================================================

        usable_evidence = evidence

        if STRICT_REPO_MATCH:

            usable_evidence = [
                x
                for x in evidence
                if repo_matches(
                    titan_link,
                    x.get(
                        "repo"
                    ),
                )
            ]

            if not usable_evidence:

                df.at[
                    idx,
                    "osv_fixed_status"
                ] = (
                    "fixed_sha_but_repo_mismatch"
                )

                repo_rejected += 1

                continue

        # ====================================================
        # Distinct CVEs
        # ====================================================

        cves = distinct_cves(
            usable_evidence
        )

        osv_ids = sorted({
            str(
                x.get(
                    "osv_id"
                )
            )
            for x in usable_evidence
            if x.get(
                "osv_id"
            )
        })

        df.at[
            idx,
            "osv_fixed_cve_candidates"
        ] = ";".join(
            cves
        )

        df.at[
            idx,
            "osv_fixed_ids"
        ] = ";".join(
            osv_ids
        )

        # ====================================================
        # No CVE alias
        # ====================================================

        if len(cves) == 0:

            df.at[
                idx,
                "osv_fixed_status"
            ] = "fixed_match_without_cve"

            continue

        # ====================================================
        # EXACTLY ONE CVE
        # ====================================================

        if len(cves) == 1:

            df.at[
                idx,
                "cve_id"
            ] = cves[0]

            df.at[
                idx,
                "cve_source"
            ] = (
                "osv_fixed_commit_exact"
            )

            df.at[
                idx,
                "osv_fixed_status"
            ] = (
                "single_cve_filled"
            )

            filled += 1

            continue

        # ====================================================
        # >1 CVE -> don't guess
        # ====================================================

        df.at[
            idx,
            "osv_fixed_status"
        ] = (
            "multiple_cves_ambiguous"
        )

        ambiguous += 1

    return {
        "df":
            df,

        "filled":
            filled,

        "ambiguous":
            ambiguous,

        "no_match":
            no_match,

        "repo_rejected":
            repo_rejected,

        "no_sha":
            no_sha,
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
        "osv_fixed_commit_exact"
    ]

    if len(samples) == 0:

        print(
            "\nKhông có sample mới "
            "được exact fixed-match."
        )

        return

    row = samples.iloc[0]

    idx = row.name

    print(
        "\n"
        + "=" * 78
    )

    print(
        "EXAMPLE - EXACT OSV FIXED COMMIT"
    )

    print(
        "=" * 78
    )

    print(
        f"Index            : {idx}"
    )

    print(
        f"Commit           : "
        f"{row['commit_link']}"
    )

    print(
        f"SHA              : "
        f"{row['commit_sha']}"
    )

    print(
        f"File             : "
        f"{row['file_name']}"
    )

    print(
        f"\nCVE trước        : "
        f"{before.at[idx, 'cve_id']}"
    )

    print(
        f"CVE sau          : "
        f"{row['cve_id']}"
    )

    print(
        f"CVE source       : "
        f"{row['cve_source']}"
    )

    print(
        f"\nOSV IDs          : "
        f"{row['osv_fixed_ids']}"
    )

    print(
        f"CVE candidates   : "
        f"{row['osv_fixed_cve_candidates']}"
    )

    print(
        f"OSV repos        : "
        f"{row['osv_fixed_repos']}"
    )

    print(
        f"Repo match       : "
        f"{row['osv_fixed_repo_match']}"
    )

    print(
        f"Status           : "
        f"{row['osv_fixed_status']}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 78
    )

    print(
        "METHOD 3 FIXED - OSV events.fixed == COMMIT SHA"
    )

    print(
        "=" * 78
    )

    # ========================================================
    # LOAD DATASET
    # ========================================================

    df = pd.read_parquet(
        INPUT_PARQUET
    )

    df = normalize_missing(
        df
    )

    before = df.copy()

    total = len(
        df
    )

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

    print(
        f"Total samples:             "
        f"{total:,}"
    )

    print(
        f"Trước Method 3 có CVE:     "
        f"{before_cve.sum():,}"
    )

    print(
        f"Trước Method 3 có CWE:     "
        f"{before_cwe.sum():,}"
    )

    print(
        f"Trước có >=1 nhãn:         "
        f"{before_any.sum():,}"
    )

    print(
        f"Trước thiếu cả hai:        "
        f"{(~before_any).sum():,}"
    )

    # ========================================================
    # TARGET SHAs:
    #
    # chỉ sample hiện vẫn thiếu CVE
    # ========================================================

    missing_cve = df[
        df[
            "cve_id"
        ].isna()
    ].copy()

    missing_cve[
        "commit_sha"
    ] = (
        missing_cve[
            "commit_link"
        ]
        .apply(
            extract_commit_sha
        )
    )

    target_shas = sorted({
        sha
        for sha in missing_cve[
            "commit_sha"
        ].dropna()
        if sha
    })

    print(
        f"\nDòng đang thiếu CVE:        "
        f"{len(missing_cve):,}"
    )

    print(
        f"Unique SHA40 cần tìm fix:   "
        f"{len(target_shas):,}"
    )

    # ========================================================
    # DOWNLOAD OSV DATABASE
    # ========================================================

    download_osv_database()

    # ========================================================
    # CACHE
    # ========================================================

    cached = load_fixed_cache()

    target_key = (
        ",".join(
            target_shas
        )
    )

    # Cache đơn giản:
    # chỉ reuse nếu target SHA set giống hệt.
    cache_targets = cached.get(
        "_target_shas"
    )

    if (
        isinstance(
            cache_targets,
            list,
        )
        and
        set(cache_targets)
        ==
        set(target_shas)
    ):

        print(
            "\nUsing cached exact fixed matches."
        )

        fixed_matches = cached.get(
            "matches",
            {}
        )

    else:

        fixed_matches = (
            scan_osv_fixed_commits(
                target_shas
            )
        )

        save_fixed_cache({
            "_target_shas":
                target_shas,

            "matches":
                fixed_matches,
        })

        print(
            f"Saved fixed-match cache: "
            f"{FIXED_INDEX_CACHE}"
        )

    # ========================================================
    # SUMMARY RAW FIX MATCHES
    # ========================================================

    single_cve_shas = 0

    multi_cve_shas = 0

    zero_cve_shas = 0

    for sha, evidence in (
        fixed_matches.items()
    ):

        cves = distinct_cves(
            evidence
        )

        if len(cves) == 1:

            single_cve_shas += 1

        elif len(cves) > 1:

            multi_cve_shas += 1

        else:

            zero_cve_shas += 1

    print(
        "\n"
        + "=" * 78
    )

    print(
        "OSV EXACT FIXED-COMMIT COVERAGE"
    )

    print(
        "=" * 78
    )

    print(
        f"Target SHA có fixed match:  "
        f"{len(fixed_matches):,}"
    )

    print(
        f"SHA có đúng 1 CVE:          "
        f"{single_cve_shas:,}"
    )

    print(
        f"SHA có >1 CVE:              "
        f"{multi_cve_shas:,}"
    )

    print(
        f"SHA fixed nhưng 0 CVE alias:"
        f" {zero_cve_shas:,}"
    )

    # ========================================================
    # APPLY
    # ========================================================

    result = apply_fixed_matches(
        df,
        fixed_matches,
    )

    df = result[
        "df"
    ]

    # ========================================================
    # AFTER STATS
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

    new_cve = (
        ~before_cve
        &
        after_cve
    )

    newly_rescued = (
        ~before_any
        &
        after_any
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "METHOD 3 RESULT"
    )

    print(
        "=" * 78
    )

    print(
        f"CVE mới exact fixed:        "
        f"{new_cve.sum():,}"
    )

    print(
        f"Dòng thiếu cả 2 được cứu:   "
        f"{newly_rescued.sum():,}"
    )

    print(
        f"Multiple CVE không chọn:    "
        f"{result['ambiguous']:,}"
    )

    if STRICT_REPO_MATCH:

        print(
            f"Repo mismatch bị loại:      "
            f"{result['repo_rejected']:,}"
        )

    print(
        f"\nTrước có >=1 nhãn:          "
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
        f"+{after_any.sum() - before_any.sum():,}"
    )

    print(
        f"Vẫn thiếu cả hai:           "
        f"{(~after_any).sum():,}"
        f"/{total:,} "
        f"({(~after_any).sum()/total*100:.2f}%)"
    )

    # ========================================================
    # SOURCE DISTRIBUTION
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
        "\nOSV fixed status:"
    )

    print(
        df.loc[
            before_cve == False,
            "osv_fixed_status"
        ]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    # ========================================================
    # FLAGS
    # ========================================================

    df[
        "osv_fixed_new_cve"
    ] = new_cve

    df[
        "osv_fixed_newly_rescued"
    ] = newly_rescued

    df[
        "has_vuln_label"
    ] = after_any

    # ========================================================
    # EXAMPLE
    # ========================================================

    print_example(
        before,
        df,
    )

    # ========================================================
    # SAVE
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

        "osv_fixed_ids",
        "osv_fixed_cve_candidates",
        "osv_fixed_repos",
        "osv_fixed_repo_match",
        "osv_fixed_status",

        "osv_fixed_new_cve",
        "osv_fixed_newly_rescued",
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