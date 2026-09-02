import io
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import pandas as pd
import requests


# ============================================================
# OPTIONAL FAST JSON
# ============================================================

try:
    import orjson

    def json_load_bytes(data):
        return orjson.loads(data)

    FAST_JSON = True

except ImportError:

    def json_load_bytes(data):
        return json.loads(data.decode("utf-8"))

    FAST_JSON = False


# ============================================================
# CONFIG
# ============================================================

INPUT_PARQUET = (
    "TitanVul_recovery_4methods_NVD.parquet"
)

OUTPUT_PARQUET = (
    "TitanVul_recovery_5methods_CVEORG.parquet"
)

OUTPUT_CSV = (
    "TitanVul_recovery_5methods_CVEORG.csv"
)

OUTPUT_AUDIT = (
    "TitanVul_cveorg_audit.csv"
)


# ============================================================
# CVELISTV5
# ============================================================

GITHUB_RELEASE_API = (
    "https://api.github.com/repos/"
    "CVEProject/cvelistV5/releases/latest"
)

# Fallback nếu GitHub Release API không dùng được
CVELIST_MAIN_ZIP_URL = (
    "https://github.com/"
    "CVEProject/cvelistV5/"
    "archive/refs/heads/main.zip"
)

CVELIST_ZIP = Path(
    "cvelistV5_latest.zip"
)

REQUEST_TIMEOUT = 180

DOWNLOAD_CHUNK_SIZE = (
    1024 * 1024
)


# ============================================================
# BEHAVIOUR
# ============================================================

# Ground-truth mode:
#
# True:
#   chỉ exact SHA reference có tag patch.
#
# False:
#   exact commit URL dù không có patch tag
#   cũng có thể auto-label.
#
# NÊN GIỮ TRUE.
#
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


# TitanVul commit URL
COMMIT_SHA_RE = re.compile(
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

    for column in [
        "cve_id",
        "cwe_id",
    ]:

        if column not in df.columns:
            continue

        mask = (
            df[column]
            .apply(is_missing)
        )

        df.loc[
            mask,
            column
        ] = None

    return df


# ============================================================
# TITANVUL COMMIT SHA
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

    if not commit_link:
        return None

    match = COMMIT_SHA_RE.search(
        commit_link
    )

    if match:

        return (
            match.group(1)
            .lower()
        )

    # --------------------------------------------------------
    # Fallback:
    #
    # git.kernel.org/.../commit/?id=<sha>
    # gitweb ... ?h=<sha>
    # --------------------------------------------------------

    matches = SHA40_RE.findall(
        commit_link
    )

    if len(matches) != 1:
        return None

    sha = matches[0].lower()

    lower = commit_link.lower()

    if (
        "commit" in lower
        or
        "commitdiff" in lower
        or
        "changeset" in lower
    ):

        return sha

    return None


# ============================================================
# DOWNLOAD HELPERS
# ============================================================

def download_stream(
    url,
    destination,
):

    destination = Path(
        destination
    )

    temp = Path(
        str(destination)
        +
        ".part"
    )

    print(
        f"Downloading:\n{url}"
    )

    headers = {
        "User-Agent":
            "TitanVul-CVE-Recovery/1.0",
    }

    with requests.get(
        url,
        stream=True,
        headers=headers,
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
            temp,
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

                f.write(chunk)

                downloaded += len(
                    chunk
                )

                if total:

                    percent = (
                        downloaded
                        /
                        total
                        *
                        100
                    )

                    print(
                        f"\r"
                        f"{downloaded/1024/1024:.1f}"
                        f"/"
                        f"{total/1024/1024:.1f}"
                        f" MB "
                        f"({percent:.1f}%)",
                        end="",
                        flush=True,
                    )

                else:

                    print(
                        f"\r"
                        f"{downloaded/1024/1024:.1f}"
                        f" MB",
                        end="",
                        flush=True,
                    )

    print()

    temp.replace(
        destination
    )


# ============================================================
# FIND LATEST CVELISTV5 RELEASE
# ============================================================

def get_latest_release_asset():

    headers = {
        "Accept":
            "application/vnd.github+json",

        "User-Agent":
            "TitanVul-CVE-Recovery/1.0",
    }

    try:

        response = requests.get(
            GITHUB_RELEASE_API,
            headers=headers,
            timeout=60,
        )

        response.raise_for_status()

        release = response.json()

        assets = release.get(
            "assets",
            []
        )

        candidates = []

        for asset in assets:

            name = str(
                asset.get(
                    "name",
                    ""
                )
            )

            url = asset.get(
                "browser_download_url"
            )

            if (
                url
                and
                name.endswith(
                    "_all_CVEs_at_midnight.zip"
                )
            ):

                candidates.append(
                    (
                        name,
                        url,
                    )
                )

        if candidates:

            candidates.sort()

            name, url = (
                candidates[-1]
            )

            print(
                f"Latest CVE List release: "
                f"{name}"
            )

            return url

    except Exception as e:

        print(
            f"Could not resolve latest "
            f"release: {e}"
        )

    return None


# ============================================================
# ENSURE CVELIST ZIP
# ============================================================

def ensure_cvelist_zip():

    if CVELIST_ZIP.exists():

        size_mb = (
            CVELIST_ZIP.stat().st_size
            /
            1024
            /
            1024
        )

        print(
            f"CVE List cache exists: "
            f"{CVELIST_ZIP} "
            f"({size_mb:.1f} MB)"
        )

        return

    print(
        "\n"
        + "=" * 78
    )

    print(
        "DOWNLOAD OFFICIAL CVE LIST V5"
    )

    print(
        "=" * 78
    )

    release_url = (
        get_latest_release_asset()
    )

    if release_url:

        try:

            download_stream(
                release_url,
                CVELIST_ZIP,
            )

            return

        except Exception as e:

            print(
                "\nRelease download failed:"
            )

            print(e)

            print(
                "\nFallback to GitHub "
                "main branch ZIP..."
            )

    download_stream(
        CVELIST_MAIN_ZIP_URL,
        CVELIST_ZIP,
    )


# ============================================================
# REFERENCE TAG
# ============================================================

def normalize_tag(tag):

    if not isinstance(
        tag,
        str,
    ):
        return ""

    return (
        tag.strip()
        .lower()
        .replace("_", "-")
    )


def reference_is_patch(
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

    for tag in tags:

        normalized = (
            normalize_tag(tag)
        )

        if normalized == "patch":
            return True

        # Legacy transformed reference tags,
        # e.g. x_refsource_PATCH
        if normalized.endswith(
            "-patch"
        ):
            return True

    return False


# ============================================================
# DOES URL LOOK LIKE A COMMIT REFERENCE?
# ============================================================

def looks_like_commit_url(
    url,
    sha,
):

    if not isinstance(
        url,
        str,
    ):
        return False

    lower = url.lower()

    sha = sha.lower()

    if sha not in lower:
        return False

    # GitHub / GitLab / Bitbucket-like
    patterns = [
        "/commit/",
        "/commits/",
        "/-/commit/",
        "/commitdiff/",
        "/commitdiff_plain/",
        "/changeset/",
    ]

    if any(
        p in lower
        for p in patterns
    ):

        return True

    # kernel cgit/gitweb style
    if "commit" in lower:

        try:

            parsed = urlparse(
                url
            )

            query = parse_qs(
                parsed.query
            )

            for key in [
                "id",
                "h",
                "hash",
                "commit",
            ]:

                for value in (
                    query.get(
                        key,
                        []
                    )
                ):

                    if (
                        sha
                        ==
                        str(value)
                        .lower()
                    ):

                        return True

        except Exception:
            pass

        # Even if query parser fails,
        # commit + exact SHA is meaningful.
        return True

    return False


# ============================================================
# TARGET SHA FOUND IN REFERENCE?
# ============================================================

def target_shas_in_reference(
    reference,
    target_shas,
):

    url = reference.get(
        "url"
    )

    if not isinstance(
        url,
        str,
    ):
        return []

    found = []

    for match in SHA40_RE.findall(
        url
    ):

        sha = (
            match.lower()
        )

        if sha not in target_shas:
            continue

        if not looks_like_commit_url(
            url,
            sha,
        ):
            continue

        if sha not in found:

            found.append(
                sha
            )

    return found


# ============================================================
# EXTRACT CWE FROM ONE CONTAINER
# ============================================================

def extract_cwes_from_container(
    container,
):

    if not isinstance(
        container,
        dict,
    ):
        return []

    result = []

    problem_types = (
        container.get(
            "problemTypes",
            []
        )
    )

    if not isinstance(
        problem_types,
        list,
    ):
        return []

    for problem in problem_types:

        if not isinstance(
            problem,
            dict,
        ):
            continue

        descriptions = (
            problem.get(
                "descriptions",
                []
            )
        )

        if not isinstance(
            descriptions,
            list,
        ):
            continue

        for description in descriptions:

            if not isinstance(
                description,
                dict,
            ):
                continue

            candidates = []

            # Modern CVE JSON 5.x
            cwe_id = description.get(
                "cweId"
            )

            if isinstance(
                cwe_id,
                str,
            ):

                candidates.append(
                    cwe_id
                )

            # Fallback:
            # "description": "CWE-787: ..."
            text = description.get(
                "description"
            )

            if isinstance(
                text,
                str,
            ):

                matches = re.findall(
                    r"\bCWE-\d+\b",
                    text,
                    re.IGNORECASE,
                )

                candidates.extend(
                    matches
                )

            for candidate in candidates:

                candidate = (
                    candidate.strip()
                    .upper()
                )

                if not CWE_RE.fullmatch(
                    candidate
                ):
                    continue

                if candidate not in result:

                    result.append(
                        candidate
                    )

    return sorted(
        result
    )


# ============================================================
# ALL CONTAINERS
# ============================================================

def get_record_containers(
    record,
):

    containers = record.get(
        "containers",
        {}
    )

    if not isinstance(
        containers,
        dict,
    ):
        return []

    result = []

    # ========================================================
    # CNA
    # ========================================================

    cna = containers.get(
        "cna"
    )

    if isinstance(
        cna,
        dict,
    ):

        provider = (
            cna.get(
                "providerMetadata",
                {}
            )
        )

        provider_name = None

        if isinstance(
            provider,
            dict,
        ):

            provider_name = (
                provider.get(
                    "shortName"
                )
            )

        result.append(
            (
                "cna",
                provider_name,
                cna,
            )
        )

    # ========================================================
    # ADP
    # ========================================================

    adps = containers.get(
        "adp",
        []
    )

    if isinstance(
        adps,
        list,
    ):

        for i, adp in enumerate(
            adps
        ):

            if not isinstance(
                adp,
                dict,
            ):
                continue

            provider = adp.get(
                "providerMetadata",
                {}
            )

            provider_name = None

            if isinstance(
                provider,
                dict,
            ):

                provider_name = (
                    provider.get(
                        "shortName"
                    )
                )

            if not provider_name:

                provider_name = (
                    adp.get(
                        "title"
                    )
                )

            result.append(
                (
                    f"adp[{i}]",
                    provider_name,
                    adp,
                )
            )

    return result


# ============================================================
# RECORD CVE
# ============================================================

def get_record_cve_id(
    record,
):

    metadata = record.get(
        "cveMetadata",
        {}
    )

    if not isinstance(
        metadata,
        dict,
    ):
        return None

    state = str(
        metadata.get(
            "state",
            ""
        )
    ).upper()

    if state == "REJECTED":
        return None

    cve = metadata.get(
        "cveId"
    )

    if not isinstance(
        cve,
        str,
    ):
        return None

    cve = (
        cve.strip()
        .upper()
    )

    if not CVE_RE.fullmatch(
        cve
    ):
        return None

    return cve


# ============================================================
# SCAN CVELISTV5
# ============================================================

def scan_cvelist(
    target_shas,
):

    target_shas = set(
        target_shas
    )

    # --------------------------------------------------------
    # Strong:
    # exact commit + patch tag
    # --------------------------------------------------------

    patch_matches = {}

    # --------------------------------------------------------
    # Exact commit reference,
    # but no patch tag.
    # Audit only.
    # --------------------------------------------------------

    nonpatch_matches = {}

    # CVE -> official CWE candidates
    cve_to_cwes = {}

    records_scanned = 0

    records_rejected = 0

    invalid_json = 0

    references_scanned = 0

    patch_refs = 0

    exact_patch_evidences = 0

    exact_nonpatch_evidences = 0

    print(
        "\n"
        + "=" * 78
    )

    print(
        "SCAN OFFICIAL CVE LIST V5"
    )

    print(
        "=" * 78
    )

    with zipfile.ZipFile(
        CVELIST_ZIP,
        "r",
    ) as archive:

        names = [
            name
            for name in archive.namelist()
            if (
                name.lower()
                .endswith(".json")
                and
                "/cves/" in (
                    "/" + name.lower()
                )
            )
        ]

        total_files = len(
            names
        )

        print(
            f"CVE JSON files: "
            f"{total_files:,}"
        )

        for name in names:

            records_scanned += 1

            try:

                with archive.open(
                    name,
                    "r",
                ) as f:

                    raw = f.read()

                record = (
                    json_load_bytes(
                        raw
                    )
                )

            except Exception:

                invalid_json += 1

                continue

            if not isinstance(
                record,
                dict,
            ):
                continue

            cve_id = (
                get_record_cve_id(
                    record
                )
            )

            if not cve_id:

                records_rejected += 1

                continue

            containers = (
                get_record_containers(
                    record
                )
            )

            # =================================================
            # CWE across CNA + ADP
            # =================================================

            all_cwes = []

            for (
                container_type,
                provider_name,
                container,
            ) in containers:

                container_cwes = (
                    extract_cwes_from_container(
                        container
                    )
                )

                for cwe in container_cwes:

                    if cwe not in all_cwes:

                        all_cwes.append(
                            cwe
                        )

            cve_to_cwes[
                cve_id
            ] = sorted(
                all_cwes
            )

            # =================================================
            # References across CNA + ADP
            # =================================================

            for (
                container_type,
                provider_name,
                container,
            ) in containers:

                references = (
                    container.get(
                        "references",
                        []
                    )
                )

                if not isinstance(
                    references,
                    list,
                ):
                    continue

                for reference in references:

                    if not isinstance(
                        reference,
                        dict,
                    ):
                        continue

                    references_scanned += 1

                    patch = (
                        reference_is_patch(
                            reference
                        )
                    )

                    if patch:

                        patch_refs += 1

                    found_shas = (
                        target_shas_in_reference(
                            reference,
                            target_shas,
                        )
                    )

                    if not found_shas:
                        continue

                    evidence = {
                        "cve":
                            cve_id,

                        "cwes":
                            sorted(
                                all_cwes
                            ),

                        "url":
                            reference.get(
                                "url"
                            ),

                        "name":
                            reference.get(
                                "name"
                            ),

                        "tags":
                            reference.get(
                                "tags",
                                []
                            ),

                        "container":
                            container_type,

                        "provider":
                            provider_name,
                    }

                    for sha in found_shas:

                        if patch:

                            patch_matches.setdefault(
                                sha,
                                []
                            )

                            if (
                                evidence
                                not in
                                patch_matches[
                                    sha
                                ]
                            ):

                                patch_matches[
                                    sha
                                ].append(
                                    evidence
                                )

                                exact_patch_evidences += 1

                        else:

                            nonpatch_matches.setdefault(
                                sha,
                                []
                            )

                            if (
                                evidence
                                not in
                                nonpatch_matches[
                                    sha
                                ]
                            ):

                                nonpatch_matches[
                                    sha
                                ].append(
                                    evidence
                                )

                                exact_nonpatch_evidences += 1

            # =================================================
            # Progress
            # =================================================

            if (
                records_scanned % 10000
                ==
                0
            ):

                print(
                    f"\rScanned "
                    f"{records_scanned:,}"
                    f"/{total_files:,} "
                    f"| patch SHA "
                    f"{len(patch_matches):,} "
                    f"| nonpatch SHA "
                    f"{len(nonpatch_matches):,}",
                    end="",
                    flush=True,
                )

    print()

    print(
        "\n"
        + "=" * 78
    )

    print(
        "CVE.ORG SCAN SUMMARY"
    )

    print(
        "=" * 78
    )

    print(
        f"Records scanned:            "
        f"{records_scanned:,}"
    )

    print(
        f"Rejected/skipped:           "
        f"{records_rejected:,}"
    )

    print(
        f"Invalid JSON:               "
        f"{invalid_json:,}"
    )

    print(
        f"References inspected:       "
        f"{references_scanned:,}"
    )

    print(
        f"References tagged patch:    "
        f"{patch_refs:,}"
    )

    print(
        f"Target SHA w/ patch ref:    "
        f"{len(patch_matches):,}"
    )

    print(
        f"Target SHA w/ nonpatch ref: "
        f"{len(nonpatch_matches):,}"
    )

    print(
        f"Exact patch evidences:      "
        f"{exact_patch_evidences:,}"
    )

    print(
        f"Exact nonpatch evidences:   "
        f"{exact_nonpatch_evidences:,}"
    )

    print(
        f"CVE -> CWE mappings:        "
        f"{len(cve_to_cwes):,}"
    )

    return {
        "patch_matches":
            patch_matches,

        "nonpatch_matches":
            nonpatch_matches,

        "cve_to_cwes":
            cve_to_cwes,
    }


# ============================================================
# UNIQUE LABELS
# ============================================================

def unique_cves(
    evidence_list,
):

    result = []

    for evidence in evidence_list:

        cve = evidence.get(
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


def unique_cwes(
    evidence_list,
):

    result = []

    for evidence in evidence_list:

        for cwe in evidence.get(
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
# APPLY METHOD 5
# ============================================================

def apply_cveorg(
    df,
    scan,
):

    patch_matches = (
        scan[
            "patch_matches"
        ]
    )

    nonpatch_matches = (
        scan[
            "nonpatch_matches"
        ]
    )

    cve_to_cwes = (
        scan[
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
    # Audit columns
    # ========================================================

    df[
        "cveorg_cve_candidates"
    ] = ""

    df[
        "cveorg_cwe_candidates"
    ] = ""

    df[
        "cveorg_patch_urls"
    ] = ""

    df[
        "cveorg_reference_containers"
    ] = ""

    df[
        "cveorg_status"
    ] = None

    # ========================================================
    # Counters
    # ========================================================

    new_cve = 0

    new_cwe_same_record = 0

    ambiguous_cve = 0

    nonpatch_only = 0

    no_exact_reference = 0

    # ========================================================
    # PART A:
    # missing CVE -> exact commit Patch reference
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
                "cveorg_status"
            ] = "no_sha40"

            continue

        strong = (
            patch_matches.get(
                sha,
                []
            )
        )

        broad = (
            nonpatch_matches.get(
                sha,
                []
            )
        )

        # ====================================================
        # No patch-tagged evidence
        # ====================================================

        if not strong:

            if broad:

                candidates = (
                    unique_cves(
                        broad
                    )
                )

                df.at[
                    idx,
                    "cveorg_cve_candidates"
                ] = ";".join(
                    candidates
                )

                df.at[
                    idx,
                    "cveorg_status"
                ] = (
                    "exact_commit_nonpatch_only"
                )

                nonpatch_only += 1

            else:

                df.at[
                    idx,
                    "cveorg_status"
                ] = (
                    "no_exact_commit_reference"
                )

                no_exact_reference += 1

            continue

        # ====================================================
        # Strong candidates
        # ====================================================

        cves = (
            unique_cves(
                strong
            )
        )

        cwes = (
            unique_cwes(
                strong
            )
        )

        urls = sorted({
            str(
                e.get(
                    "url"
                )
            )
            for e in strong
            if e.get(
                "url"
            )
        })

        containers = sorted({
            (
                str(
                    e.get(
                        "container"
                    )
                )
                +
                ":"
                +
                str(
                    e.get(
                        "provider"
                    )
                )
            )
            for e in strong
        })

        df.at[
            idx,
            "cveorg_cve_candidates"
        ] = ";".join(
            cves
        )

        df.at[
            idx,
            "cveorg_cwe_candidates"
        ] = ";".join(
            cwes
        )

        df.at[
            idx,
            "cveorg_patch_urls"
        ] = ";".join(
            urls
        )

        df.at[
            idx,
            "cveorg_reference_containers"
        ] = ";".join(
            containers
        )

        # ====================================================
        # Exactly one CVE
        # ====================================================

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
                "cveorg_patch_commit_exact"
            )

            new_cve += 1

            # ------------------------------------------------
            # Same CVE record also has exactly 1 CWE
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
                    "cveorg_patch_commit_exact"
                )

                new_cwe_same_record += 1

            df.at[
                idx,
                "cveorg_status"
            ] = "single_cve_filled"

        elif len(cves) > 1:

            df.at[
                idx,
                "cveorg_status"
            ] = (
                "multiple_cves_ambiguous"
            )

            ambiguous_cve += 1

        else:

            df.at[
                idx,
                "cveorg_status"
            ] = (
                "patch_reference_without_cve"
            )

    # ========================================================
    # PART B:
    #
    # Existing/new CVE -> CWE via official CVE Record
    #
    # Only exactly 1 CWE.
    # ========================================================

    cwe_from_cve = 0

    cwe_ambiguous = 0

    no_cwe_in_record = 0

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
                "cveorg_cve_exact"
            )

            cwe_from_cve += 1

        elif len(cwes) > 1:

            cwe_ambiguous += 1

        else:

            no_cwe_in_record += 1

    return {
        "df":
            df,

        "new_cve":
            new_cve,

        "new_cwe_same_record":
            new_cwe_same_record,

        "cwe_from_cve":
            cwe_from_cve,

        "ambiguous_cve":
            ambiguous_cve,

        "nonpatch_only":
            nonpatch_only,

        "no_exact_reference":
            no_exact_reference,

        "cwe_ambiguous":
            cwe_ambiguous,

        "no_cwe_in_record":
            no_cwe_in_record,
    }


# ============================================================
# EXAMPLE
# ============================================================

def print_example(
    before,
    after,
):

    sample = after[
        after[
            "cve_source"
        ]
        ==
        "cveorg_patch_commit_exact"
    ]

    if len(sample) == 0:

        print(
            "\nKhông có CVE mới từ "
            "CVE.org patch reference."
        )

        return

    row = (
        sample.iloc[0]
    )

    idx = row.name

    print(
        "\n"
        + "=" * 78
    )

    print(
        "EXAMPLE - CVE.ORG EXACT PATCH COMMIT"
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
        f"\nCVE candidates    : "
        f"{row['cveorg_cve_candidates']}"
    )

    print(
        f"CWE candidates    : "
        f"{row['cveorg_cwe_candidates']}"
    )

    print(
        f"Containers        : "
        f"{row['cveorg_reference_containers']}"
    )

    print(
        "\nPatch references:"
    )

    print(
        row[
            "cveorg_patch_urls"
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
        "METHOD 5 - CVE.ORG / CVELISTV5 "
        "EXACT PATCH COMMIT"
    )

    print(
        "=" * 78
    )

    print(
        f"Fast JSON parser: "
        f"{FAST_JSON}"
    )

    # ========================================================
    # LOAD
    # ========================================================

    df = pd.read_parquet(
        INPUT_PARQUET
    )

    df = normalize_missing(
        df
    )

    before = df.copy()

    total = len(df)

    # ========================================================
    # BEFORE STATS
    # ========================================================

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
        f"\nTotal:                      "
        f"{total:,}"
    )

    print(
        f"Trước có CVE:              "
        f"{before_cve.sum():,}"
    )

    print(
        f"Trước có CWE:              "
        f"{before_cwe.sum():,}"
    )

    print(
        f"Trước có cả CVE + CWE:     "
        f"{before_both.sum():,}"
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
    # TARGET SHA
    #
    # chỉ cần CVE cho những dòng còn thiếu CVE
    # ========================================================

    target_series = (
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
        target_series
        .dropna()
        .tolist()
    )

    print(
        f"\nTarget unique SHA40:       "
        f"{len(target_shas):,}"
    )

    # ========================================================
    # DOWNLOAD
    # ========================================================

    ensure_cvelist_zip()

    # ========================================================
    # SCAN
    # ========================================================

    scan = scan_cvelist(
        target_shas
    )

    # ========================================================
    # RAW SHA STATS
    # ========================================================

    patch_matches = (
        scan[
            "patch_matches"
        ]
    )

    nonpatch_matches = (
        scan[
            "nonpatch_matches"
        ]
    )

    one_cve_sha = 0
    multi_cve_sha = 0

    for sha, evidence in (
        patch_matches.items()
    ):

        cves = (
            unique_cves(
                evidence
            )
        )

        if len(cves) == 1:
            one_cve_sha += 1

        elif len(cves) > 1:
            multi_cve_sha += 1

    print(
        "\n"
        + "=" * 78
    )

    print(
        "CVE.ORG EXACT PATCH COVERAGE"
    )

    print(
        "=" * 78
    )

    print(
        f"SHA có patch evidence:      "
        f"{len(patch_matches):,}"
    )

    print(
        f"SHA có đúng 1 CVE:         "
        f"{one_cve_sha:,}"
    )

    print(
        f"SHA có >1 CVE:             "
        f"{multi_cve_sha:,}"
    )

    print(
        f"SHA exact nonpatch only*:  "
        f"{len(nonpatch_matches):,}"
    )

    print(
        "\n"
        "* nonpatch được audit nhưng "
        "không tự gán."
    )

    # ========================================================
    # APPLY
    # ========================================================

    result = apply_cveorg(
        df,
        scan,
    )

    df = result[
        "df"
    ]

    # ========================================================
    # AFTER
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

    complete_mask = (
        ~before_both
        &
        after_both
    )

    # ========================================================
    # RESULTS
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "METHOD 5 RESULT"
    )

    print(
        "=" * 78
    )

    print(
        f"CVE mới CVE.org Patch:     "
        f"{new_cve_mask.sum():,}"
    )

    print(
        f"CWE mới tổng cộng:         "
        f"{new_cwe_mask.sum():,}"
    )

    print(
        f"  CWE cùng patch record:    "
        f"{result['new_cwe_same_record']:,}"
    )

    print(
        f"  CWE từ CVE -> CVE.org:    "
        f"{result['cwe_from_cve']:,}"
    )

    print(
        f"\nDòng thiếu cả 2 được cứu:  "
        f"{rescued_mask.sum():,}"
    )

    print(
        f"Dòng mới đủ CVE + CWE:     "
        f"{complete_mask.sum():,}"
    )

    print(
        f"\n>1 CVE không tự chọn:      "
        f"{result['ambiguous_cve']:,}"
    )

    print(
        f"Exact commit nonpatch only: "
        f"{result['nonpatch_only']:,}"
    )

    print(
        f"CVE có >1 CWE:             "
        f"{result['cwe_ambiguous']:,}"
    )

    print(
        f"CVE record không có CWE:   "
        f"{result['no_cwe_in_record']:,}"
    )

    print(
        "\n"
        f"Trước có >=1 nhãn:         "
        f"{before_any.sum():,}"
        f"/{total:,} "
        f"("
        f"{before_any.sum()/total*100:.2f}%"
        f")"
    )

    print(
        f"Sau có >=1 nhãn:           "
        f"{after_any.sum():,}"
        f"/{total:,} "
        f"("
        f"{after_any.sum()/total*100:.2f}%"
        f")"
    )

    print(
        f"Tăng sample có nhãn:       "
        f"+"
        f"{after_any.sum()-before_any.sum():,}"
    )

    print(
        f"Vẫn thiếu cả hai:          "
        f"{(~after_any).sum():,}"
        f"/{total:,} "
        f"("
        f"{(~after_any).sum()/total*100:.2f}%"
        f")"
    )

    print(
        f"\nCó cả CVE + CWE:           "
        f"{after_both.sum():,}"
        f"/{total:,} "
        f"("
        f"{after_both.sum()/total*100:.2f}%"
        f")"
    )

    # ========================================================
    # SOURCES
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
    # FLAGS
    # ========================================================

    df[
        "cveorg_new_cve"
    ] = (
        new_cve_mask
    )

    df[
        "cveorg_new_cwe"
    ] = (
        new_cwe_mask
    )

    df[
        "cveorg_newly_rescued"
    ] = (
        rescued_mask
    )

    df[
        "has_vuln_label"
    ] = (
        after_any
    )

    # ========================================================
    # EXAMPLE
    # ========================================================

    print_example(
        before,
        df,
    )

    # ========================================================
    # SAVE FULL
    # ========================================================

    df.to_parquet(
        OUTPUT_PARQUET,
        index=False,
    )

    df.to_csv(
        OUTPUT_CSV,
        index=False,
    )

    # ========================================================
    # AUDIT
    # ========================================================

    audit_cols = [
        "file_name",

        "commit_link",
        "commit_sha",
        "commit_message",

        "cve_id",
        "cve_source",

        "cwe_id",
        "cwe_source",

        "cveorg_cve_candidates",
        "cveorg_cwe_candidates",
        "cveorg_patch_urls",
        "cveorg_reference_containers",
        "cveorg_status",

        "cveorg_new_cve",
        "cveorg_new_cwe",
        "cveorg_newly_rescued",
    ]

    audit_cols = [
        column
        for column in audit_cols
        if column in df.columns
    ]

    df[
        audit_cols
    ].to_csv(
        OUTPUT_AUDIT,
        index=True,
    )

    # ========================================================
    # SAVE NONPATCH CANDIDATES FOR MANUAL REVIEW
    # ========================================================

    nonpatch_review = df[
        df[
            "cveorg_status"
        ]
        ==
        "exact_commit_nonpatch_only"
    ].copy()

    nonpatch_review[
        audit_cols
    ].to_csv(
        "TitanVul_cveorg_nonpatch_review.csv",
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
        "TitanVul_cveorg_nonpatch_review.csv"
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