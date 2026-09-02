import gzip
import json
import re
import zipfile

from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import pandas as pd
import requests


# ============================================================
# OPTIONAL FAST JSON
# ============================================================

try:
    import orjson

    FAST_JSON = True

    def json_load_bytes(data):
        return orjson.loads(data)

except ImportError:
    FAST_JSON = False

    def json_load_bytes(data):
        return json.loads(
            data.decode("utf-8")
        )


# ============================================================
# CONFIG
# ============================================================

# ============================================================
# THƯ MỤC
#
# data/input   dữ liệu vào
# data/output  kết quả chính
# data/audit   file soi tay / review
# data/interim checkpoint giữa các method
# cache        DB đã tải + kết quả scan (đắt, đừng xoá)
# ============================================================

ROOT = Path(
    __file__
).resolve().parent

DATA_IN = ROOT / "data" / "input"

DATA_OUT = ROOT / "data" / "output"

DATA_AUDIT = ROOT / "data" / "audit"

DATA_INTERIM = ROOT / "data" / "interim"

CACHE = ROOT / "cache"

for _d in (
    DATA_IN,
    DATA_OUT,
    DATA_AUDIT,
    DATA_INTERIM,
    CACHE,
):
    _d.mkdir(
        parents=True,
        exist_ok=True,
    )


INPUT_PARQUET = (
    DATA_IN
    / "TitanVul_language_FINAL.parquet"
)

FINAL_PARQUET = (
    DATA_OUT
    / "TitanVul_recovery_ALL_FINAL.parquet"
)

FINAL_CSV = (
    DATA_OUT
    / "TitanVul_recovery_ALL_FINAL.csv"
)

FINAL_AUDIT = (
    DATA_AUDIT
    / "TitanVul_recovery_ALL_audit.csv"
)


# ============================================================
# SAME COMMIT MODE
#
# majority:
#   reproduce kết quả hiện tại của bạn.
#
# unambiguous:
#   chỉ propagate nếu commit map đúng 1 label.
#
# ============================================================

COMMIT_MODE = "majority"


# ============================================================
# SAVE INTERMEDIATE FILES
# ============================================================

SAVE_INTERMEDIATE = True


# ============================================================
# NETWORK
# ============================================================

REQUEST_TIMEOUT = 180

DOWNLOAD_CHUNK_SIZE = (
    1024 * 1024
)


# ============================================================
# OSV
# ============================================================

OSV_DATABASE_URL = (
    "https://storage.googleapis.com/"
    "osv-vulnerabilities/all.zip"
)

OSV_ZIP = (
    CACHE / "osv_all.zip"
)

OSV_FIXED_CACHE = (
    CACHE / "osv_fixed_commit_matches.json"
)

OSV_SCAN_CACHE = (
    CACHE / "osv_scan_cache.json.gz"
)


# ============================================================
# NVD
# ============================================================

NVD_FEED_BASE = (
    "https://nvd.nist.gov/"
    "feeds/json/cve/2.0"
)

NVD_DIR = (
    CACHE / "nvd_feeds"
)

NVD_START_YEAR = 2002

NVD_END_YEAR = (
    datetime.now().year
)

NVD_SCAN_CACHE = (
    CACHE / "nvd_scan_cache.json.gz"
)


# ============================================================
# CVE.ORG / cvelistV5
# ============================================================

CVELIST_URL = (
    "https://github.com/"
    "CVEProject/cvelistV5/"
    "archive/refs/heads/main.zip"
)

CVELIST_ZIP = (
    CACHE / "cvelistV5_latest.zip"
)

CVEORG_SCAN_CACHE = (
    CACHE / "cveorg_scan_cache.json.gz"
)


# ============================================================
# REGEX
# ============================================================

SHA40_RE = re.compile(
    r"(?<![0-9a-fA-F])"
    r"([0-9a-fA-F]{40})"
    r"(?![0-9a-fA-F])"
)


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


CVE_FULL_RE = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE,
)


CVE_MESSAGE_RE = re.compile(
    r"\bCVE[-_ ]?"
    r"(\d{4})"
    r"[-_ ]?"
    r"(\d{4,})"
    r"\b",
    re.IGNORECASE,
)


CWE_MESSAGE_RE = re.compile(
    r"\bCWE[-_ ]?"
    r"(\d{1,5})"
    r"\b",
    re.IGNORECASE,
)


CWE_FULL_RE = re.compile(
    r"^CWE-\d+$",
    re.IGNORECASE,
)


# ============================================================
# COMMIT URL -> SHA
#
# /commit/<sha>         github, gitlab, gitea
# /-/commit/<sha>       gitlab
# /+/<sha>              gitiles, android.googlesource
# /commitdiff/<sha>     cgit, gitweb
# ?id=<sha>             cgit
# ;h=<sha>              gitweb (git.php.net, git.kernel.org)
#
# Cho phép SHA ngắn 7..40: link github web thường bị cắt.
# ============================================================

COMMIT_PATH_RE = re.compile(
    r"(?:"
    r"/commit/"
    r"|/commits/"
    r"|/-/commit/"
    r"|/commitdiff/"
    r"|/commitdiff_plain/"
    r"|/changeset/"
    r"|/\+/"
    r")"
    r"([0-9a-fA-F]{7,40})"
    r"(?:\.(?:patch|diff))?"
    r"(?:[/?#]|$)",
    re.IGNORECASE,
)


COMMIT_QUERY_KEYS = (
    "id",
    "h",
    "hash",
    "commit",
    "rev",
    "revision",
)


SHA_ANY_RE = re.compile(
    r"^[0-9a-f]{7,40}$"
)


# ============================================================
# BACKPORT / CHERRY-PICK
#
# An toàn: cùng một thay đổi -> cùng CVE.
#
# CỐ Ý KHÔNG dùng "Fixes: <sha>" kiểu kernel:
# sha đó là commit GÂY RA bug, không phải commit vá.
# Propagate từ nó sẽ gán sai nhãn.
# ============================================================

CHERRY_PICK_RE = re.compile(
    r"(?:"
    r"cherry[\s\-]?picked?\s+from(?:\s+commit)?"
    r"|back[\s\-]?ported?\s+(?:of|from)(?:\s+commit)?"
    r"|upstream\s+commit"
    r"|imported\s+from\s+commit"
    r")"
    r"[\s:]+"
    r"([0-9a-fA-F]{7,40})"
    r"(?![0-9a-fA-F])",
    re.IGNORECASE,
)


# ============================================================
# LABEL NORMALIZE
#
# Vấn đề có thật trong TitanVul gốc:
#
#   cwe-089           -> CWE-89     (2,020 dòng lệch case/zero-pad)
#   CWE-94,CWE-94     -> CWE-94     (3,377 dòng ghép/lặp)
#   CWE-125,CWE-787   -> 2 CWE
#   NVD-CWE-noinfo    -> KHÔNG phải CWE (598 dòng)
#   'CVE-2014-3176, ' -> CVE-2014-3176
# ============================================================

CWE_TOKEN_RE = re.compile(
    r"CWE[-_ ]?0*(\d{1,5})",
    re.IGNORECASE,
)


CVE_TOKEN_RE = re.compile(
    r"CVE[-_ ]?"
    r"(\d{4})"
    r"[-_ ]?"
    r"(\d{4,})",
    re.IGNORECASE,
)


# ============================================================
# CACHE VERSION
#
# Bump khi CẤU TRÚC cache đổi -> buộc scan lại.
# ============================================================

OSV_CACHE_VERSION = 3

NVD_CACHE_VERSION = 3

CVEORG_CACHE_VERSION = 2


# ============================================================
# SOURCE -> CONFIDENCE
#
# gold   : nhãn gốc của dataset
# high   : commit vá chính xác, hoặc CVE ghi thẳng trong message
# medium : URL commit khớp SHA nhưng không có tag Patch,
#          hoặc suy ra qua backport / CVE->CWE không có primary
# ============================================================

SOURCE_CONFIDENCE = {
    "original": "gold",

    "commit_message_explicit": "high",

    "same_commit": "high",
    "same_commit_propagated": "high",

    "osv_fixed_commit_exact": "high",
    "osv_fix_reference_exact": "high",
    "osv_reference_exact": "medium",

    "nvd_patch_commit_exact": "high",
    "nvd_commit_reference_exact": "medium",

    "cveorg_patch_commit_exact": "high",
    "cveorg_commit_reference_exact": "medium",

    "nvd_cve_primary": "high",
    "nvd_evaluator_note": "high",
    "cveorg_cve_primary": "high",
    "osv_cve_cwe_ids": "high",
    "cve_cwe_single": "high",
    "cve_cwe_ambiguous": "medium",

    "backport_source_commit": "medium",
}


def confidence_of(source):

    if is_missing(source):
        return None

    return SOURCE_CONFIDENCE.get(
        str(source),
        "medium",
    )


# ============================================================
# CWE / CVE VALUE NORMALIZE
# ============================================================

def normalize_cwe_value(value):
    """
    'cwe-089'         -> ['CWE-89']
    'CWE-94,CWE-94'   -> ['CWE-94']
    'CWE-125,CWE-787' -> ['CWE-125', 'CWE-787']
    'NVD-CWE-noinfo'  -> []

    GIỮ THỨ TỰ XUẤT HIỆN, không sort theo số.

    Quan trọng: 'CWE-416, CWE-284, CWE-264' phải cho
    CWE-416 (Use After Free) làm nhãn chính, không phải
    CWE-264 (Permissions - chỉ là category). CWE liệt kê
    đầu tiên mới là weakness chính.
    """

    if not isinstance(
        value,
        str,
    ):
        return []

    result = []

    for number in CWE_TOKEN_RE.findall(
        value
    ):

        token = (
            f"CWE-{int(number)}"
        )

        if token not in result:

            result.append(
                token
            )

    return result


def normalize_cve_value(value):
    """
    'CVE-2014-3176, ' -> ['CVE-2014-3176']
    """

    if not isinstance(
        value,
        str,
    ):
        return []

    result = []

    for year, number in (
        CVE_TOKEN_RE.findall(
            value
        )
    ):

        token = (
            f"CVE-{year}-{number}"
        ).upper()

        if token not in result:

            result.append(
                token
            )

    return sorted(
        result
    )


# ============================================================
# COMMIT URL SHAPE
#
# Dùng chung cho NVD và CVE.org: chỉ nhận SHA khi URL
# thực sự trỏ tới một commit, không phải chỉ tình cờ
# chứa 40 ký tự hex.
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

    lower = (
        url.lower()
    )

    sha = (
        sha.lower()
    )

    if sha not in lower:
        return False

    patterns = [
        "/commit/",
        "/commits/",
        "/-/commit/",
        "/commitdiff/",
        "/commitdiff_plain/",
        "/changeset/",
        "/+/",
        "/patch/",
        "/pull/",
    ]

    if any(
        pattern in lower
        for pattern in patterns
    ):

        return True

    # --------------------------------------------------------
    # cgit / gitweb: ?id=SHA hoặc ;h=SHA
    # --------------------------------------------------------

    if (
        "commit" in lower
        or
        "changeset" in lower
    ):

        try:

            parsed = urlparse(
                url
            )

            query = parse_qs(
                parsed.query.replace(
                    ";",
                    "&",
                )
            )

            for key in COMMIT_QUERY_KEYS:

                for value in query.get(
                    key,
                    []
                ):

                    if (
                        str(value)
                        .lower()
                        ==
                        sha
                    ):

                        return True

        except Exception:
            pass

        # SHA đầy đủ + có chữ "commit" trong URL
        return True

    return False


# ============================================================
# SHA TARGETS
#
# Dataset có cả SHA 40 ký tự và SHA ngắn (7..39).
# OSV / NVD / CVE.org luôn ghi SHA 40.
#
# match() nhận SHA 40 của DB, trả về key target tương ứng.
# ============================================================

class ShaTargets:

    def __init__(
        self,
        shas,
    ):

        self.full = set()

        self.short_by_prefix = (
            defaultdict(list)
        )

        for sha in shas:

            if not isinstance(
                sha,
                str,
            ):
                continue

            sha = (
                sha.strip()
                .lower()
            )

            if not SHA_ANY_RE.fullmatch(
                sha
            ):
                continue

            if len(sha) == 40:

                self.full.add(
                    sha
                )

            else:

                bucket = (
                    self.short_by_prefix[
                        sha[:7]
                    ]
                )

                if sha not in bucket:

                    bucket.append(
                        sha
                    )

    def __len__(self):

        return (
            len(self.full)
            +
            sum(
                len(v)
                for v in (
                    self
                    .short_by_prefix
                    .values()
                )
            )
        )

    def keys(self):

        result = set(
            self.full
        )

        for bucket in (
            self
            .short_by_prefix
            .values()
        ):

            result.update(
                bucket
            )

        return sorted(
            result
        )

    def match(
        self,
        sha,
    ):

        if not isinstance(
            sha,
            str,
        ):
            return None

        sha = (
            sha.lower()
        )

        if sha in self.full:
            return sha

        for short in (
            self.short_by_prefix.get(
                sha[:7],
                (),
            )
        ):

            if sha.startswith(
                short
            ):
                return short

        return None


def cache_usable(
    cached,
    version,
    targets,
):
    """
    Dùng lại cache khi đúng version VÀ tập target cũ là
    siêu tập của tập target hiện tại.

    Pipeline càng vá được nhiều nhãn thì target càng nhỏ,
    nên các lần chạy sau gần như luôn dùng lại được cache.
    """

    if not isinstance(
        cached,
        dict,
    ):
        return False

    if (
        cached.get(
            "_cache_version"
        )
        !=
        version
    ):
        return False

    cached_targets = set(
        cached.get(
            "_target_shas",
            []
        )
    )

    return set(
        targets.keys()
    ).issubset(
        cached_targets
    )


# ============================================================
# BASIC HELPERS
# ============================================================

def is_missing(value):

    if value is None:
        return True

    if isinstance(value, str):

        value = value.strip()

        return value.lower() in {
            "",
            "nan",
            "none",
            "null",
            "unknown",
        }

    try:

        result = pd.isna(value)

        if isinstance(result, bool):
            return result

    except Exception:
        pass

    return False


def normalize_missing(df):

    for col in [
        "cve_id",
        "cwe_id",
    ]:

        if col not in df.columns:
            df[col] = None

        mask = (
            df[col]
            .apply(is_missing)
        )

        df.loc[
            mask,
            col
        ] = None

    return df


def normalize_labels(df):
    """
    Chuẩn hoá cve_id / cwe_id TRƯỚC mọi bước khác.

    Quan trọng vì Method 1 propagate theo GIÁ TRỊ nhãn:
    'cwe-089' và 'CWE-89' không chuẩn hoá sẽ bị coi là
    hai nhãn khác nhau -> tạo conflict giả.

    Giữ nguyên toàn bộ CWE tìm được ở cột cwe_id_all;
    cwe_id lấy CWE nhỏ nhất (ổn định, không phụ thuộc thứ tự).
    """

    df = normalize_missing(
        df
    )

    cve_fixed = 0
    cve_multi = 0
    cwe_fixed = 0
    cwe_dropped = 0
    cwe_multi = 0

    cwe_all_values = []

    cve_all_values = {}

    for idx in df.index:

        # ----------------------------------------------------
        # CVE
        # ----------------------------------------------------

        raw_cve = df.at[
            idx,
            "cve_id"
        ]

        if not is_missing(
            raw_cve
        ):

            values = (
                normalize_cve_value(
                    str(raw_cve)
                )
            )

            if not values:

                df.at[
                    idx,
                    "cve_id"
                ] = None

            else:

                cve_all_values[
                    idx
                ] = ";".join(
                    values
                )

                if (
                    values[0]
                    !=
                    str(raw_cve)
                ):

                    df.at[
                        idx,
                        "cve_id"
                    ] = values[0]

                    cve_fixed += 1

                    if len(values) > 1:
                        cve_multi += 1

        # ----------------------------------------------------
        # CWE
        # ----------------------------------------------------

        raw_cwe = df.at[
            idx,
            "cwe_id"
        ]

        if is_missing(
            raw_cwe
        ):

            cwe_all_values.append(
                ""
            )

            continue

        values = (
            normalize_cwe_value(
                str(raw_cwe)
            )
        )

        cwe_all_values.append(
            ";".join(
                values
            )
        )

        if not values:

            # NVD-CWE-noinfo / NVD-CWE-Other / unknown
            df.at[
                idx,
                "cwe_id"
            ] = None

            cwe_dropped += 1

            continue

        if len(values) > 1:
            cwe_multi += 1

        if (
            values[0]
            !=
            str(raw_cwe)
        ):

            df.at[
                idx,
                "cwe_id"
            ] = values[0]

            cwe_fixed += 1

    df["cwe_id_all"] = cwe_all_values

    df["cve_id_all"] = [
        cve_all_values.get(
            idx,
            ""
        )
        for idx in df.index
    ]

    print(
        "\n"
        + "=" * 78
    )

    print(
        "NORMALIZE LABELS"
    )

    print(
        "=" * 78
    )

    print(
        f"cve_id sửa dạng:          "
        f"{cve_fixed:,}"
    )

    print(
        f"cve_id nhiều CVE:         "
        f"{cve_multi:,}"
        f"  (cve_id_all giữ đủ)"
    )

    print(
        f"cwe_id sửa dạng:          "
        f"{cwe_fixed:,}"
    )

    print(
        f"cwe_id nhiều CWE:         "
        f"{cwe_multi:,}"
    )

    print(
        f"cwe_id bỏ (không phải CWE): "
        f"{cwe_dropped:,}"
    )

    return df


def initialize_sources(df):

    df["cve_source"] = None
    df["cwe_source"] = None

    df.loc[
        df["cve_id"].notna(),
        "cve_source"
    ] = "original"

    df.loc[
        df["cwe_id"].notna(),
        "cwe_source"
    ] = "original"

    return df


# ============================================================
# STATISTICS
# ============================================================

def label_stats(df):

    has_cve = (
        df["cve_id"].notna()
    )

    has_cwe = (
        df["cwe_id"].notna()
    )

    any_label = (
        has_cve
        |
        has_cwe
    )

    both = (
        has_cve
        &
        has_cwe
    )

    return {
        "cve":
            int(
                has_cve.sum()
            ),

        "cwe":
            int(
                has_cwe.sum()
            ),

        "any":
            int(
                any_label.sum()
            ),

        "both":
            int(
                both.sum()
            ),

        "missing_both":
            int(
                (~any_label).sum()
            ),
    }


def print_stats(
    title,
    df,
):

    stats = label_stats(
        df
    )

    total = len(df)

    print(
        "\n"
        + "=" * 78
    )

    print(title)

    print(
        "=" * 78
    )

    print(
        f"CVE:                 "
        f"{stats['cve']:,}"
    )

    print(
        f"CWE:                 "
        f"{stats['cwe']:,}"
    )

    print(
        f"CVE + CWE:           "
        f"{stats['both']:,}"
    )

    print(
        f">=1 label:           "
        f"{stats['any']:,}"
        f"/{total:,} "
        f"("
        f"{stats['any']/total*100:.2f}%"
        f")"
    )

    print(
        f"Missing both:        "
        f"{stats['missing_both']:,}"
        f"/{total:,} "
        f"("
        f"{stats['missing_both']/total*100:.2f}%"
        f")"
    )


def stage_diff(
    before,
    after,
):

    before_cve = (
        before["cve_id"].notna()
    )

    before_cwe = (
        before["cwe_id"].notna()
    )

    after_cve = (
        after["cve_id"].notna()
    )

    after_cwe = (
        after["cwe_id"].notna()
    )

    before_any = (
        before_cve
        |
        before_cwe
    )

    after_any = (
        after_cve
        |
        after_cwe
    )

    before_both = (
        before_cve
        &
        before_cwe
    )

    after_both = (
        after_cve
        &
        after_cwe
    )

    return {
        "new_cve":
            int(
                (
                    ~before_cve
                    &
                    after_cve
                ).sum()
            ),

        "new_cwe":
            int(
                (
                    ~before_cwe
                    &
                    after_cwe
                ).sum()
            ),

        "rescued":
            int(
                (
                    ~before_any
                    &
                    after_any
                ).sum()
            ),

        "new_complete":
            int(
                (
                    ~before_both
                    &
                    after_both
                ).sum()
            ),
    }


def print_stage_diff(
    title,
    before,
    after,
):

    diff = stage_diff(
        before,
        after,
    )

    print(
        "\n"
        + "-" * 78
    )

    print(title)

    print(
        "-" * 78
    )

    print(
        f"CVE mới:                 "
        f"{diff['new_cve']:,}"
    )

    print(
        f"CWE mới:                 "
        f"{diff['new_cwe']:,}"
    )

    print(
        f"Missing-both được cứu:    "
        f"{diff['rescued']:,}"
    )

    print(
        f"Mới đủ CVE + CWE:         "
        f"{diff['new_complete']:,}"
    )


def save_intermediate(
    df,
    filename,
):

    if not SAVE_INTERMEDIATE:
        return

    df.to_parquet(
        filename,
        index=False,
    )

    print(
        f"Saved intermediate: "
        f"{filename}"
    )


# ============================================================
# COMMIT SHA
# ============================================================

def extract_commit_sha(
    commit_link,
):
    """
    Trước đây bỏ sót:
      - android.googlesource.com/.../+/<sha>   527/527 dòng mất SHA
      - github.com/.../commit/<sha ngắn>       81 dòng
      - gitweb ;h=<sha>                        git.php.net, git.kernel.org

    Có thể trả về SHA ngắn (7..39). ShaTargets khớp theo prefix.
    """

    if not isinstance(
        commit_link,
        str,
    ):
        return None

    text = (
        commit_link.strip()
    )

    if not text:
        return None

    # --------------------------------------------------------
    # 1. đường dẫn commit tường minh
    # --------------------------------------------------------

    match = (
        COMMIT_PATH_RE.search(
            text
        )
    )

    if match:

        return (
            match.group(1)
            .lower()
        )

    lower = text.lower()

    if (
        "commit" not in lower
        and
        "changeset" not in lower
    ):
        return None

    # --------------------------------------------------------
    # 2. cgit / gitweb query
    #
    #    .../commit/?id=SHA
    #    /?p=php-src.git;a=commit;h=SHA
    # --------------------------------------------------------

    try:

        parsed = urlparse(
            text
        )

        query = parse_qs(
            parsed.query.replace(
                ";",
                "&",
            )
        )

        for key in COMMIT_QUERY_KEYS:

            for value in query.get(
                key,
                []
            ):

                value = (
                    str(value)
                    .strip()
                    .lower()
                )

                if SHA_ANY_RE.fullmatch(
                    value
                ):

                    return value

    except Exception:
        pass

    # --------------------------------------------------------
    # 3. đúng 1 SHA-40 trong URL
    # --------------------------------------------------------

    matches = (
        SHA40_RE.findall(
            text
        )
    )

    if len(matches) != 1:
        return None

    return (
        matches[0]
        .lower()
    )


def extract_alt_shas(
    message,
):
    """
    SHA của commit gốc khi dòng này là backport / cherry-pick.

    Dùng để tra DB bằng SHA gốc: cùng thay đổi -> cùng CVE.
    """

    if not isinstance(
        message,
        str,
    ):
        return []

    result = []

    for sha in (
        CHERRY_PICK_RE.findall(
            message
        )
    ):

        sha = sha.lower()

        if sha not in result:

            result.append(
                sha
            )

    return result


# ============================================================
# METHOD 1
# SAME COMMIT
# ============================================================

def build_same_commit_map(
    original_df,
    label_col,
):

    values_by_commit = (
        defaultdict(list)
    )

    for _, row in (
        original_df.iterrows()
    ):

        commit = row.get(
            "commit_link"
        )

        value = row.get(
            label_col
        )

        if not isinstance(
            commit,
            str,
        ):
            continue

        commit = (
            commit.strip()
        )

        if not commit:
            continue

        if is_missing(value):
            continue

        value = (
            str(value)
            .strip()
        )

        values_by_commit[
            commit
        ].append(
            value
        )

    mapping = {}

    conflicts = 0

    for commit, values in (
        values_by_commit.items()
    ):

        unique_values = list(
            dict.fromkeys(
                values
            )
        )

        if len(unique_values) > 1:
            conflicts += 1

        # ====================================================
        # UNAMBIGUOUS
        # ====================================================

        if COMMIT_MODE == "unambiguous":

            if len(unique_values) == 1:

                mapping[
                    commit
                ] = unique_values[0]

        # ====================================================
        # MAJORITY
        # ====================================================

        elif COMMIT_MODE == "majority":

            counts = Counter(
                values
            )

            winner = (
                counts
                .most_common(1)[0][0]
            )

            mapping[
                commit
            ] = winner

        else:

            raise ValueError(
                "COMMIT_MODE must be "
                "'majority' or "
                "'unambiguous'"
            )

    return (
        mapping,
        conflicts,
    )


def apply_same_commit(
    df,
    original_df,
):

    before = (
        df.copy()
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "METHOD 1 - SAME COMMIT"
    )

    print(
        "=" * 78
    )

    (
        cve_map,
        cve_conflicts,
    ) = build_same_commit_map(
        original_df,
        "cve_id",
    )

    (
        cwe_map,
        cwe_conflicts,
    ) = build_same_commit_map(
        original_df,
        "cwe_id",
    )

    print(
        f"commit -> CVE map: "
        f"{len(cve_map):,}"
    )

    print(
        f"commit -> CWE map: "
        f"{len(cwe_map):,}"
    )

    print(
        f"Commit >1 CVE:    "
        f"{cve_conflicts:,}"
    )

    print(
        f"Commit >1 CWE:    "
        f"{cwe_conflicts:,}"
    )

    for idx in df.index:

        commit = df.at[
            idx,
            "commit_link"
        ]

        if not isinstance(
            commit,
            str,
        ):
            continue

        commit = (
            commit.strip()
        )

        # CVE
        if (
            is_missing(
                df.at[
                    idx,
                    "cve_id"
                ]
            )
            and
            commit in cve_map
        ):

            df.at[
                idx,
                "cve_id"
            ] = cve_map[
                commit
            ]

            df.at[
                idx,
                "cve_source"
            ] = "same_commit"

        # CWE
        if (
            is_missing(
                df.at[
                    idx,
                    "cwe_id"
                ]
            )
            and
            commit in cwe_map
        ):

            df.at[
                idx,
                "cwe_id"
            ] = cwe_map[
                commit
            ]

            df.at[
                idx,
                "cwe_source"
            ] = "same_commit"

    print_stage_diff(
        "METHOD 1 RESULT",
        before,
        df,
    )

    return df


# ============================================================
# METHOD 2
# EXPLICIT LABEL IN COMMIT MESSAGE
# ============================================================

def extract_message_cves(
    text,
):

    if not isinstance(
        text,
        str,
    ):
        return []

    values = set()

    for year, number in (
        CVE_MESSAGE_RE.findall(
            text
        )
    ):

        values.add(
            (
                f"CVE-{year}-{number}"
            ).upper()
        )

    return sorted(
        values
    )


def extract_message_cwes(
    text,
):

    if not isinstance(
        text,
        str,
    ):
        return []

    values = set()

    for number in (
        CWE_MESSAGE_RE.findall(
            text
        )
    ):

        # normalize để 'CWE-089' và 'CWE-89' không thành hai nhãn
        values.update(
            normalize_cwe_value(
                f"CWE-{number}"
            )
        )
    return sorted(
        values
    )


def apply_commit_message(
    df,
):

    before = (
        df.copy()
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "METHOD 2 - EXPLICIT COMMIT MESSAGE"
    )

    print(
        "=" * 78
    )

    rows_with_cve = 0
    rows_with_cwe = 0

    multi_cve = 0
    multi_cwe = 0

    for idx in df.index:

        message = df.at[
            idx,
            "commit_message"
        ]

        cves = (
            extract_message_cves(
                message
            )
        )

        cwes = (
            extract_message_cwes(
                message
            )
        )

        if cves:
            rows_with_cve += 1

        if cwes:
            rows_with_cwe += 1

        if len(cves) > 1:
            multi_cve += 1

        if len(cwes) > 1:
            multi_cwe += 1

        # ====================================================
        # CVE
        # ====================================================

        if (
            is_missing(
                df.at[
                    idx,
                    "cve_id"
                ]
            )
            and
            len(cves) == 1
        ):

            df.at[
                idx,
                "cve_id"
            ] = cves[0]

            df.at[
                idx,
                "cve_source"
            ] = (
                "commit_message_explicit"
            )

        # ====================================================
        # CWE
        # ====================================================

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
                "commit_message_explicit"
            )

    print(
        f"Message >=1 CVE: "
        f"{rows_with_cve:,}"
    )

    print(
        f"Message >1 CVE:  "
        f"{multi_cve:,}"
    )

    print(
        f"Message >=1 CWE: "
        f"{rows_with_cwe:,}"
    )

    print(
        f"Message >1 CWE:  "
        f"{multi_cwe:,}"
    )

    print_stage_diff(
        "METHOD 2 RESULT",
        before,
        df,
    )

    return df


# ============================================================
# DOWNLOAD
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
            f"{destination} "
            f"({size_mb:.1f} MB)"
        )

        return

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp = Path(
        str(destination)
        +
        ".part"
    )

    headers = {
        "User-Agent":
            "TitanVul-Metadata-Recovery/1.0"
    }

    print(
        f"Downloading:\n"
        f"{url}"
    )

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
                        f"\r"
                        f"{downloaded/1024/1024:.1f}"
                        f"/"
                        f"{total/1024/1024:.1f}"
                        f" MB "
                        f"({pct:.1f}%)",
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
# CACHE HELPERS
# ============================================================

def save_json(
    path,
    data,
):

    path = Path(
        path
    )

    temp = Path(
        str(path)
        +
        ".tmp"
    )

    with open(
        temp,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            data,
            f,
            ensure_ascii=False,
        )

    temp.replace(
        path
    )


def load_json(
    path,
):

    path = Path(
        path
    )

    if not path.exists():
        return None

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:

            return json.load(
                f
            )

    except Exception as e:

        print(
            f"Warning cache read failed "
            f"{path}: {e}"
        )

        return None


def save_json_gz(
    path,
    data,
):

    path = Path(
        path
    )

    temp = Path(
        str(path)
        +
        ".tmp"
    )

    with gzip.open(
        temp,
        "wt",
        encoding="utf-8",
    ) as f:

        json.dump(
            data,
            f,
            ensure_ascii=False,
        )

    temp.replace(
        path
    )


def load_json_gz(
    path,
):

    path = Path(
        path
    )

    if not path.exists():
        return None

    try:

        with gzip.open(
            path,
            "rt",
            encoding="utf-8",
        ) as f:

            return json.load(
                f
            )

    except Exception as e:

        print(
            f"Warning cache read failed "
            f"{path}: {e}"
        )

        return None


# ============================================================
# SHARED: TARGET SHA + EVIDENCE
# ============================================================

def row_shas(
    df,
    idx,
):
    """
    [(sha, is_backport)] cho một dòng.

    is_backport=True nghĩa là SHA của commit GỐC lấy từ
    "cherry picked from commit ..." trong message.
    Nhãn suy ra từ đó chỉ đạt confidence medium.
    """

    result = []

    sha = df.at[
        idx,
        "commit_sha"
    ]

    if (
        isinstance(sha, str)
        and
        sha
    ):

        result.append(
            (sha, False)
        )

    alt = df.at[
        idx,
        "alt_commit_shas"
    ]

    if (
        isinstance(alt, str)
        and
        alt
    ):

        for value in alt.split(";"):

            value = value.strip()

            if (
                value
                and
                value != sha
            ):

                result.append(
                    (value, True)
                )

    return result


def build_targets(df):
    """SHA cần tra DB: dòng còn thiếu CVE, kèm SHA gốc của backport."""

    shas = []

    for idx in df.index[
        df["cve_id"].isna()
    ]:

        for sha, _ in row_shas(
            df,
            idx,
        ):

            shas.append(
                sha
            )

    return ShaTargets(
        shas
    )


def cves_of(evidence_list):

    result = set()

    for item in evidence_list:

        for cve in item.get(
            "cves",
            []
        ):

            if cve:

                result.add(
                    cve
                )

    return sorted(
        result
    )


def cwes_of(evidence_list):

    result = set()

    for item in evidence_list:

        for cwe in item.get(
            "cwes",
            []
        ):

            if cwe:

                result.add(
                    cwe
                )

    return sorted(
        result
    )


def urls_of(evidence_list):

    result = set()

    for item in evidence_list:

        url = item.get(
            "url"
        )

        if url:

            result.add(
                url
            )

    return sorted(
        result
    )


def tag_source(
    source,
    is_backport,
):
    """
    Nhãn suy ra qua commit gốc của backport -> hạ confidence
    bằng cách đổi tên source (confidence_of trả 'medium').
    """

    if is_backport:
        return f"{source}_via_backport"

    return source


# ============================================================
# METHOD 3
# OSV
#
# Trước đây CHỈ dùng ranges[].events[].fixed.
#
# Bổ sung:
#   references[] có URL commit chứa đúng SHA target
#     -> đo được: 134 SHA khớp so với 36 của events.fixed,
#        tức +98 SHA mới trên cùng tập target.
#   database_specific.cwe_ids  -> bảng CVE -> CWE.
#
# CỐ Ý KHÔNG fill từ events.introduced / limit /
# last_affected: đó không phải commit vá. Chỉ ghi làm
# candidate để audit.
# ============================================================

def extract_osv_cves(
    record,
):

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

    result = []

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

        if not CVE_FULL_RE.fullmatch(
            value
        ):
            continue

        if value not in result:

            result.append(
                value
            )

    return sorted(
        result
    )


def extract_osv_cwes(
    record,
):
    """
    GHSA và một số DB ghi CWE ở database_specific.cwe_ids,
    cả ở gốc record và trong từng affected[].
    """

    result = []

    holders = [
        record.get(
            "database_specific"
        )
    ]

    affected = record.get(
        "affected",
        []
    )

    if isinstance(
        affected,
        list,
    ):

        for item in affected:

            if isinstance(
                item,
                dict,
            ):

                holders.append(
                    item.get(
                        "database_specific"
                    )
                )

    for holder in holders:

        if not isinstance(
            holder,
            dict,
        ):
            continue

        # ----------------------------------------------------
        # dạng list: GHSA, PyPA, Go
        # ----------------------------------------------------

        for key in (
            "cwe_ids",
            "cweIds",
            "cwes",
        ):

            values = holder.get(
                key
            )

            if not isinstance(
                values,
                list,
            ):
                continue

            for value in values:

                if not isinstance(
                    value,
                    str,
                ):
                    continue

                for cwe in (
                    normalize_cwe_value(
                        value
                    )
                ):

                    if cwe not in result:

                        result.append(
                            cwe
                        )

        # ----------------------------------------------------
        # dạng dict {"id": "CWE-121", "desc": "..."}
        #
        # Key viết HOA. Trước đây bỏ sót -> mất 42 CVE, và
        # CWE ở đây thường CỤ THỂ HƠN nhãn của NVD
        # (NVD hay cho class CWE-119 hoặc hậu quả CWE-200,
        # còn đây cho CWE-121 / CWE-124 / CWE-126).
        # ----------------------------------------------------

        for key in (
            "CWE",
            "cwe",
        ):

            value = holder.get(
                key
            )

            if not isinstance(
                value,
                dict,
            ):
                continue

            for cwe in (
                normalize_cwe_value(
                    str(
                        value.get(
                            "id",
                            ""
                        )
                    )
                )
            ):

                if cwe not in result:

                    result.append(
                        cwe
                    )

    return sorted(
        result
    )


def scan_osv(
    targets,
):

    cached = load_json_gz(
        OSV_SCAN_CACHE
    )

    if cache_usable(
        cached,
        OSV_CACHE_VERSION,
        targets,
    ):

        print(
            "Using OSV scan cache."
        )

        return cached

    download_file(
        OSV_DATABASE_URL,
        OSV_ZIP,
    )

    fixed_matches = (
        defaultdict(list)
    )

    fix_ref_matches = (
        defaultdict(list)
    )

    ref_matches = (
        defaultdict(list)
    )

    weak_matches = (
        defaultdict(list)
    )

    cve_to_cwes = {}

    scanned = 0
    withdrawn = 0
    invalid = 0
    git_ranges = 0
    fixed_events = 0
    refs_seen = 0

    print(
        "\n"
        + "=" * 78
    )

    print(
        "SCAN OSV"
    )

    print(
        "=" * 78
    )

    with zipfile.ZipFile(
        OSV_ZIP,
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

                    record = (
                        json_load_bytes(
                            f.read()
                        )
                    )

            except Exception:
                invalid += 1
                continue

            if not isinstance(
                record,
                dict,
            ):
                invalid += 1
                continue

            if record.get(
                "withdrawn"
            ):

                withdrawn += 1
                continue

            cves = (
                extract_osv_cves(
                    record
                )
            )

            if not cves:
                continue

            # =================================================
            # CVE -> CWE
            # =================================================

            cwes = (
                extract_osv_cwes(
                    record
                )
            )

            if cwes:

                for cve in cves:

                    merged = set(
                        cve_to_cwes.get(
                            cve,
                            []
                        )
                    )

                    merged.update(
                        cwes
                    )

                    cve_to_cwes[
                        cve
                    ] = sorted(
                        merged
                    )

            # =================================================
            # REFERENCES
            # =================================================

            references = record.get(
                "references",
                []
            )

            if isinstance(
                references,
                list,
            ):

                for ref in references:

                    if not isinstance(
                        ref,
                        dict,
                    ):
                        continue

                    url = ref.get(
                        "url"
                    )

                    if not isinstance(
                        url,
                        str,
                    ):
                        continue

                    refs_seen += 1

                    ref_type = str(
                        ref.get(
                            "type",
                            ""
                        )
                    ).upper()

                    for raw in (
                        SHA40_RE.findall(
                            url
                        )
                    ):

                        key = targets.match(
                            raw.lower()
                        )

                        if not key:
                            continue

                        if not looks_like_commit_url(
                            url,
                            raw.lower(),
                        ):
                            continue

                        evidence = {
                            "osv_id":
                                record.get(
                                    "id"
                                ),

                            "cves":
                                cves,

                            "cwes":
                                cwes,

                            "url":
                                url,

                            "ref_type":
                                ref_type,
                        }

                        bucket = (
                            fix_ref_matches
                            if ref_type == "FIX"
                            else
                            ref_matches
                        )

                        if (
                            evidence
                            not in
                            bucket[key]
                        ):

                            bucket[
                                key
                            ].append(
                                evidence
                            )

            # =================================================
            # GIT RANGES
            # =================================================

            affected_list = (
                record.get(
                    "affected",
                    []
                )
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

                        for kind, value in (
                            event.items()
                        ):

                            if not isinstance(
                                value,
                                str,
                            ):
                                continue

                            value = (
                                value.strip()
                                .lower()
                            )

                            if not re.fullmatch(
                                r"[0-9a-f]{40}",
                                value,
                            ):
                                continue

                            key = targets.match(
                                value
                            )

                            if not key:
                                continue

                            evidence = {
                                "osv_id":
                                    record.get(
                                        "id"
                                    ),

                                "cves":
                                    cves,

                                "cwes":
                                    cwes,

                                "repo":
                                    repo,

                                "event":
                                    kind,
                            }

                            if kind == "fixed":

                                fixed_events += 1

                                bucket = fixed_matches

                            else:

                                bucket = weak_matches

                            if (
                                evidence
                                not in
                                bucket[key]
                            ):

                                bucket[
                                    key
                                ].append(
                                    evidence
                                )

            if (
                scanned % 20000
                ==
                0
            ):

                print(
                    f"\rOSV "
                    f"{scanned:,}"
                    f"/{total:,}"
                    f" | fixed "
                    f"{len(fixed_matches):,}"
                    f" | fix-ref "
                    f"{len(fix_ref_matches):,}"
                    f" | ref "
                    f"{len(ref_matches):,}",
                    end="",
                    flush=True,
                )

    print()

    print(
        f"Scanned:            "
        f"{scanned:,}"
    )

    print(
        f"Withdrawn:          "
        f"{withdrawn:,}"
    )

    print(
        f"Invalid:            "
        f"{invalid:,}"
    )

    print(
        f"GIT ranges:         "
        f"{git_ranges:,}"
    )

    print(
        f"Fixed events:       "
        f"{fixed_events:,}"
    )

    print(
        f"References seen:    "
        f"{refs_seen:,}"
    )

    print(
        f"SHA events.fixed:   "
        f"{len(fixed_matches):,}"
    )

    print(
        f"SHA ref type=FIX:   "
        f"{len(fix_ref_matches):,}"
    )

    print(
        f"SHA ref khác:       "
        f"{len(ref_matches):,}"
    )

    print(
        f"SHA event yếu:      "
        f"{len(weak_matches):,}"
        f"  (chỉ audit, không fill)"
    )

    print(
        f"CVE -> CWE:         "
        f"{len(cve_to_cwes):,}"
    )

    result = {
        "_cache_version":
            OSV_CACHE_VERSION,

        "_target_shas":
            targets.keys(),

        "fixed_matches":
            dict(
                fixed_matches
            ),

        "fix_ref_matches":
            dict(
                fix_ref_matches
            ),

        "ref_matches":
            dict(
                ref_matches
            ),

        "weak_matches":
            dict(
                weak_matches
            ),

        "cve_to_cwes":
            cve_to_cwes,
    }

    save_json_gz(
        OSV_SCAN_CACHE,
        result,
    )

    return result


def apply_osv(
    df,
):

    before = (
        df.copy()
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "METHOD 3 - OSV"
    )

    print(
        "=" * 78
    )

    targets = build_targets(
        df
    )

    print(
        f"Target SHA: "
        f"{len(targets):,}"
    )

    scan = scan_osv(
        targets
    )

    tiers = [
        (
            "fixed_matches",
            "osv_fixed_commit_exact",
        ),
        (
            "fix_ref_matches",
            "osv_fix_reference_exact",
        ),
        (
            "ref_matches",
            "osv_reference_exact",
        ),
    ]

    df["osv_cve_candidates"] = ""
    df["osv_status"] = None

    for idx in df.index[
        df["cve_id"].isna()
    ]:

        shas = row_shas(
            df,
            idx,
        )

        if not shas:
            continue

        filled = False
        candidates = set()
        status = "no_match"

        for bucket_name, source in tiers:

            bucket = scan[
                bucket_name
            ]

            for sha, is_backport in shas:

                evidence = bucket.get(
                    sha,
                    []
                )

                if not evidence:
                    continue

                cves = cves_of(
                    evidence
                )

                candidates.update(
                    cves
                )

                if filled:
                    continue

                if len(cves) == 1:

                    df.at[
                        idx,
                        "cve_id"
                    ] = cves[0]

                    df.at[
                        idx,
                        "cve_source"
                    ] = tag_source(
                        source,
                        is_backport,
                    )

                    status = (
                        "single_cve_filled"
                    )

                    filled = True

                else:

                    status = (
                        "multiple_cves_ambiguous"
                    )

        if not filled and candidates:

            status = (
                "multiple_cves_ambiguous"
            )

        if not candidates:

            weak = []

            for sha, _ in shas:

                weak.extend(
                    scan[
                        "weak_matches"
                    ].get(
                        sha,
                        []
                    )
                )

            if weak:

                candidates.update(
                    cves_of(
                        weak
                    )
                )

                status = (
                    "weak_event_only"
                )

        df.at[
            idx,
            "osv_cve_candidates"
        ] = ";".join(
            sorted(
                candidates
            )
        )

        df.at[
            idx,
            "osv_status"
        ] = status

    print_stage_diff(
        "METHOD 3 RESULT",
        before,
        df,
    )

    return (
        df,
        scan[
            "cve_to_cwes"
        ],
    )


# ============================================================
# METHOD 4
# NVD
#
# Trước đây CHỈ fill khi reference có tag "Patch".
#
# Bổ sung: reference KHÔNG có tag Patch nhưng URL thực sự
# là URL commit chứa đúng SHA target -> vẫn là bằng chứng
# đủ mạnh (đo được 109 dòng ở nhóm này bị bỏ).
#
# Bổ sung: tách CWE "Primary" khỏi "Secondary" để fill được
# cả khi một CVE có nhiều CWE.
# ============================================================

def ensure_nvd_feeds():

    NVD_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    files = []

    for year in range(
        NVD_START_YEAR,
        NVD_END_YEAR + 1,
    ):

        filename = (
            f"nvdcve-2.0-"
            f"{year}.json.gz"
        )

        path = (
            NVD_DIR
            /
            filename
        )

        url = (
            f"{NVD_FEED_BASE}/"
            f"{filename}"
        )

        download_file(
            url,
            path,
        )

        files.append(
            path
        )

    return files


def extract_nvd_cwes(
    cve_record,
):
    """
    -> (tất cả CWE, CWE có type=Primary)

    NVD-CWE-noinfo / NVD-CWE-Other bị normalize_cwe_value bỏ.
    """

    all_cwes = []
    primary_cwes = []

    weaknesses = (
        cve_record.get(
            "weaknesses",
            []
        )
    )

    if not isinstance(
        weaknesses,
        list,
    ):
        return (
            [],
            [],
        )

    for weakness in weaknesses:

        if not isinstance(
            weakness,
            dict,
        ):
            continue

        is_primary = (
            str(
                weakness.get(
                    "type",
                    ""
                )
            ).strip()
            .lower()
            ==
            "primary"
        )

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

        for description in descriptions:

            if not isinstance(
                description,
                dict,
            ):
                continue

            value = description.get(
                "value"
            )

            if not isinstance(
                value,
                str,
            ):
                continue

            for cwe in (
                normalize_cwe_value(
                    value
                )
            ):

                if cwe not in all_cwes:

                    all_cwes.append(
                        cwe
                    )

                if (
                    is_primary
                    and
                    cwe not in primary_cwes
                ):

                    primary_cwes.append(
                        cwe
                    )

    return (
        sorted(
            all_cwes
        ),
        sorted(
            primary_cwes
        ),
    )


def extract_nvd_evaluator_cwes(
    cve_record,
):
    """
    CWE ghi trong ghi chú của analyst NIST, KHÔNG nằm ở
    trường weaknesses.

    Ví dụ CVE-2016-1648: weaknesses = NVD-CWE-Other, nhưng
    evaluatorComment = '<a href="...416.html">CWE-416: Use
    After Free</a>'. Trang NVD hiện CWE-416 ở mục
    "Evaluator Description" - chính là nguồn này.

    Phủ 1,669 CVE trên toàn feed, phần lớn là CVE cũ mà NVD
    không điền weaknesses.
    """

    parts = []

    for field in (
        "evaluatorComment",
        "evaluatorImpact",
        "evaluatorSolution",
    ):

        value = cve_record.get(
            field
        )

        if isinstance(
            value,
            str,
        ):

            parts.append(
                value
            )

    if not parts:
        return []

    return normalize_cwe_value(
        " ".join(
            parts
        )
    )


def nvd_patch_ref(
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
        str(tag)
        .strip()
        .lower()
        ==
        "patch"
        for tag in tags
    )


def scan_nvd(
    targets,
):

    cached = load_json_gz(
        NVD_SCAN_CACHE
    )

    if cache_usable(
        cached,
        NVD_CACHE_VERSION,
        targets,
    ):

        print(
            "Using NVD scan cache."
        )

        return cached

    files = (
        ensure_nvd_feeds()
    )

    patch_matches = (
        defaultdict(list)
    )

    commit_matches = (
        defaultdict(list)
    )

    other_matches = (
        defaultdict(list)
    )

    cve_to_cwes = {}
    cve_to_primary = {}
    cve_to_evaluator = {}

    records = 0
    references = 0
    patch_refs = 0

    print(
        "\n"
        + "=" * 78
    )

    print(
        "SCAN NVD"
    )

    print(
        "=" * 78
    )

    for path in files:

        print(
            f"Reading: "
            f"{path.name}"
        )

        try:

            with gzip.open(
                path,
                "rt",
                encoding="utf-8",
            ) as f:

                data = json.load(
                    f
                )

        except Exception as e:

            print(
                f"ERROR reading "
                f"{path}: {e}"
            )

            continue

        vulnerabilities = (
            data.get(
                "vulnerabilities",
                []
            )
        )

        if not isinstance(
            vulnerabilities,
            list,
        ):
            continue

        for item in vulnerabilities:

            records += 1

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

            if not CVE_FULL_RE.fullmatch(
                cve_id
            ):
                continue

            # =================================================
            # CVE -> CWE
            # =================================================

            (
                cwes,
                primary,
            ) = extract_nvd_cwes(
                cve
            )

            cve_to_cwes[
                cve_id
            ] = cwes

            if primary:

                cve_to_primary[
                    cve_id
                ] = primary

            evaluator = (
                extract_nvd_evaluator_cwes(
                    cve
                )
            )

            if evaluator:

                cve_to_evaluator[
                    cve_id
                ] = evaluator

            # =================================================
            # REFERENCES
            # =================================================

            refs = cve.get(
                "references",
                []
            )

            if not isinstance(
                refs,
                list,
            ):
                continue

            for ref in refs:

                if not isinstance(
                    ref,
                    dict,
                ):
                    continue

                references += 1

                url = ref.get(
                    "url"
                )

                if not isinstance(
                    url,
                    str,
                ):
                    continue

                is_patch = (
                    nvd_patch_ref(
                        ref
                    )
                )

                if is_patch:
                    patch_refs += 1

                for raw in (
                    SHA40_RE.findall(
                        url
                    )
                ):

                    raw = raw.lower()

                    key = targets.match(
                        raw
                    )

                    if not key:
                        continue

                    evidence = {
                        "cves":
                            [cve_id],

                        "cwes":
                            cwes,

                        "primary_cwes":
                            primary,

                        "url":
                            url,

                        "tags":
                            ref.get(
                                "tags",
                                []
                            ),
                    }

                    if is_patch:

                        bucket = patch_matches

                    elif looks_like_commit_url(
                        url,
                        raw,
                    ):

                        bucket = commit_matches

                    else:

                        bucket = other_matches

                    if (
                        evidence
                        not in
                        bucket[key]
                    ):

                        bucket[
                            key
                        ].append(
                            evidence
                        )

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
        f"Records scanned:          "
        f"{records:,}"
    )

    print(
        f"References inspected:     "
        f"{references:,}"
    )

    print(
        f"References tagged Patch:  "
        f"{patch_refs:,}"
    )

    print(
        f"SHA w/ Patch ref:         "
        f"{len(patch_matches):,}"
    )

    print(
        f"SHA w/ commit URL only:   "
        f"{len(commit_matches):,}"
        f"  (trước đây bỏ)"
    )

    print(
        f"SHA w/ URL khác:          "
        f"{len(other_matches):,}"
        f"  (chỉ audit)"
    )

    print(
        f"CVE -> CWE:               "
        f"{len(cve_to_cwes):,}"
    )

    print(
        f"CVE -> CWE primary:       "
        f"{len(cve_to_primary):,}"
    )

    print(
        f"CVE -> CWE evaluator:     "
        f"{len(cve_to_evaluator):,}"
        f"  (ghi chú analyst NIST)"
    )

    result = {
        "_cache_version":
            NVD_CACHE_VERSION,

        "_target_shas":
            targets.keys(),

        "patch_matches":
            dict(
                patch_matches
            ),

        "commit_matches":
            dict(
                commit_matches
            ),

        "other_matches":
            dict(
                other_matches
            ),

        "cve_to_cwes":
            cve_to_cwes,

        "cve_to_primary":
            cve_to_primary,

        "cve_to_evaluator":
            cve_to_evaluator,
    }

    save_json_gz(
        NVD_SCAN_CACHE,
        result,
    )

    return result


def apply_nvd(
    df,
):

    before = (
        df.copy()
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "METHOD 4 - NVD"
    )

    print(
        "=" * 78
    )

    targets = build_targets(
        df
    )

    print(
        f"Target SHA: "
        f"{len(targets):,}"
    )

    scan = scan_nvd(
        targets
    )

    tiers = [
        (
            "patch_matches",
            "nvd_patch_commit_exact",
        ),
        (
            "commit_matches",
            "nvd_commit_reference_exact",
        ),
    ]

    df["nvd_cve_candidates"] = ""
    df["nvd_cwe_candidates"] = ""
    df["nvd_patch_urls"] = ""
    df["nvd_status"] = None

    for idx in df.index[
        df["cve_id"].isna()
    ]:

        shas = row_shas(
            df,
            idx,
        )

        if not shas:
            continue

        filled = False
        candidates = set()
        cwe_candidates = set()
        urls = set()
        status = "no_match"

        for bucket_name, source in tiers:

            bucket = scan[
                bucket_name
            ]

            for sha, is_backport in shas:

                evidence = bucket.get(
                    sha,
                    []
                )

                if not evidence:
                    continue

                cves = cves_of(
                    evidence
                )

                candidates.update(
                    cves
                )

                cwe_candidates.update(
                    cwes_of(
                        evidence
                    )
                )

                urls.update(
                    urls_of(
                        evidence
                    )
                )

                if filled:
                    continue

                if len(cves) != 1:

                    status = (
                        "multiple_cves_ambiguous"
                    )

                    continue

                df.at[
                    idx,
                    "cve_id"
                ] = cves[0]

                df.at[
                    idx,
                    "cve_source"
                ] = tag_source(
                    source,
                    is_backport,
                )

                status = (
                    "single_cve_filled"
                )

                filled = True

                # -----------------------------------------
                # CWE ngay từ chính bằng chứng này
                # -----------------------------------------

                primary = sorted({
                    cwe
                    for row in evidence
                    for cwe in row.get(
                        "primary_cwes",
                        []
                    )
                })

                chosen = (
                    primary
                    if len(primary) == 1
                    else
                    (
                        sorted(
                            cwes_of(
                                evidence
                            )
                        )
                    )
                )

                if (
                    is_missing(
                        df.at[
                            idx,
                            "cwe_id"
                        ]
                    )
                    and
                    len(chosen) == 1
                ):

                    df.at[
                        idx,
                        "cwe_id"
                    ] = chosen[0]

                    df.at[
                        idx,
                        "cwe_source"
                    ] = tag_source(
                        source,
                        is_backport,
                    )

        if not filled and candidates:

            status = (
                "multiple_cves_ambiguous"
            )

        if not candidates:

            other = []

            for sha, _ in shas:

                other.extend(
                    scan[
                        "other_matches"
                    ].get(
                        sha,
                        []
                    )
                )

            if other:

                candidates.update(
                    cves_of(
                        other
                    )
                )

                status = (
                    "sha_in_non_commit_url"
                )

        df.at[
            idx,
            "nvd_cve_candidates"
        ] = ";".join(
            sorted(
                candidates
            )
        )

        df.at[
            idx,
            "nvd_cwe_candidates"
        ] = ";".join(
            sorted(
                cwe_candidates
            )
        )

        df.at[
            idx,
            "nvd_patch_urls"
        ] = ";".join(
            sorted(
                urls
            )
        )

        df.at[
            idx,
            "nvd_status"
        ] = status

    print_stage_diff(
        "METHOD 4 RESULT",
        before,
        df,
    )

    return (
        df,
        scan[
            "cve_to_cwes"
        ],
        scan[
            "cve_to_primary"
        ],
        scan.get(
            "cve_to_evaluator",
            {}
        ),
    )


# ============================================================
# METHOD 5
# CVE.ORG / CVELISTV5
#
# BUG cũ: chỉ fill khi reference có tag "patch".
#
# Đo trên cache thật: 2,153,697 reference, chỉ 15,842 có tag
# patch, và exact_patch_evidences = 0 -> method này fill
# đúng 0 CVE. Phần lớn CNA không gắn tag.
#
# Sửa: URL dạng commit chứa ĐÚNG SHA target đã là bằng
# chứng đủ mạnh, không cần tag. Tag chỉ để phân tier.
# ============================================================

def cveorg_patch_ref(
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

        tag = (
            str(tag)
            .strip()
            .lower()
            .replace(
                "_",
                "-"
            )
        )

        if tag == "patch":
            return True

        if tag.endswith(
            "-patch"
        ):
            return True

    return False


def extract_cveorg_cwes(
    container,
):
    """
    -> (tất cả CWE, CWE primary)

    primary = CWE đầu tiên của problemTypes đầu tiên.
    Đó là quy ước của CVE Record Format cho weakness chính.
    """

    all_cwes = []
    primary_cwes = []

    if not isinstance(
        container,
        dict,
    ):
        return (
            [],
            [],
        )

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
        return (
            [],
            [],
        )

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

            text = description.get(
                "description"
            )

            if isinstance(
                text,
                str,
            ):

                candidates.append(
                    text
                )

            for candidate in candidates:

                for cwe in (
                    normalize_cwe_value(
                        candidate
                    )
                ):

                    if cwe not in all_cwes:

                        all_cwes.append(
                            cwe
                        )

                        if not primary_cwes:

                            primary_cwes.append(
                                cwe
                            )

    return (
        sorted(
            all_cwes
        ),
        sorted(
            primary_cwes
        ),
    )


def cveorg_containers(
    record,
):

    result = []

    if not isinstance(
        record,
        dict,
    ):
        return result

    containers = record.get(
        "containers",
        {}
    )

    if not isinstance(
        containers,
        dict,
    ):
        return result

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

        result.append(
            (
                "cna",
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

            if isinstance(
                adp,
                dict,
            ):

                result.append(
                    (
                        f"adp[{i}]",
                        adp,
                    )
                )

    return result


def scan_cveorg(
    targets,
):

    cached = load_json_gz(
        CVEORG_SCAN_CACHE
    )

    if cache_usable(
        cached,
        CVEORG_CACHE_VERSION,
        targets,
    ):

        print(
            "Using CVE.org scan cache."
        )

        return cached

    download_file(
        CVELIST_URL,
        CVELIST_ZIP,
    )

    patch_matches = (
        defaultdict(list)
    )

    commit_matches = (
        defaultdict(list)
    )

    cve_to_cwes = {}
    cve_to_primary = {}

    records = 0
    valid_records = 0
    rejected_records = 0
    invalid_json = 0
    invalid_shape = 0
    missing_metadata = 0
    references = 0
    patch_refs = 0

    print(
        "\n"
        + "=" * 78
    )

    print(
        "SCAN CVE.ORG / CVELISTV5"
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

        total = len(
            names
        )

        print(
            f"CVE JSON files: "
            f"{total:,}"
        )

        for name in names:

            records += 1

            try:

                with archive.open(
                    name
                ) as f:

                    record = (
                        json_load_bytes(
                            f.read()
                        )
                    )

            except Exception:

                invalid_json += 1
                continue

            # =================================================
            # Một số file có root = list.
            # Không gọi .get() trước khi chắc là dict.
            # =================================================

            if not isinstance(
                record,
                dict,
            ):

                invalid_shape += 1
                continue

            metadata = record.get(
                "cveMetadata",
                {}
            )

            if not isinstance(
                metadata,
                dict,
            ):

                invalid_shape += 1
                continue

            state = str(
                metadata.get(
                    "state",
                    ""
                )
            ).upper()

            if state == "REJECTED":

                rejected_records += 1
                continue

            cve_id = metadata.get(
                "cveId"
            )

            if not isinstance(
                cve_id,
                str,
            ):

                missing_metadata += 1
                continue

            cve_id = (
                cve_id
                .strip()
                .upper()
            )

            if not CVE_FULL_RE.fullmatch(
                cve_id
            ):

                missing_metadata += 1
                continue

            valid_records += 1

            containers = (
                cveorg_containers(
                    record
                )
            )

            # =================================================
            # CVE -> CWE
            #
            # primary lấy từ container CNA (ưu tiên), vì ADP
            # thường là CWE do bên thứ ba bổ sung.
            # =================================================

            all_cwes = []
            primary_cwes = []

            for (
                container_name,
                container,
            ) in containers:

                try:

                    (
                        found,
                        found_primary,
                    ) = extract_cveorg_cwes(
                        container
                    )

                except Exception:

                    found = []
                    found_primary = []

                for cwe in found:

                    if cwe not in all_cwes:

                        all_cwes.append(
                            cwe
                        )

                if (
                    container_name == "cna"
                    and
                    found_primary
                ):

                    primary_cwes = (
                        found_primary
                    )

            cve_to_cwes[
                cve_id
            ] = sorted(
                all_cwes
            )

            if primary_cwes:

                cve_to_primary[
                    cve_id
                ] = sorted(
                    primary_cwes
                )

            # =================================================
            # REFERENCES
            # =================================================

            for (
                container_name,
                container,
            ) in containers:

                refs = container.get(
                    "references",
                    []
                )

                if not isinstance(
                    refs,
                    list,
                ):
                    continue

                for ref in refs:

                    if not isinstance(
                        ref,
                        dict,
                    ):
                        continue

                    references += 1

                    url = ref.get(
                        "url"
                    )

                    if not isinstance(
                        url,
                        str,
                    ):
                        continue

                    url = (
                        url.strip()
                    )

                    if not url:
                        continue

                    is_patch = (
                        cveorg_patch_ref(
                            ref
                        )
                    )

                    if is_patch:
                        patch_refs += 1

                    for raw in (
                        SHA40_RE.findall(
                            url
                        )
                    ):

                        raw = raw.lower()

                        key = targets.match(
                            raw
                        )

                        if not key:
                            continue

                        # -----------------------------------
                        # chỉ nhận URL thực sự là commit
                        # -----------------------------------

                        if not looks_like_commit_url(
                            url,
                            raw,
                        ):
                            continue

                        evidence = {
                            "cves":
                                [cve_id],

                            "cwes":
                                sorted(
                                    all_cwes
                                ),

                            "primary_cwes":
                                sorted(
                                    primary_cwes
                                ),

                            "url":
                                url,

                            "tags":
                                ref.get(
                                    "tags",
                                    []
                                ),

                            "container":
                                container_name,
                        }

                        bucket = (
                            patch_matches
                            if is_patch
                            else
                            commit_matches
                        )

                        if (
                            evidence
                            not in
                            bucket[key]
                        ):

                            bucket[
                                key
                            ].append(
                                evidence
                            )

            if (
                records % 20000
                ==
                0
            ):

                print(
                    f"\rCVE.org "
                    f"{records:,}"
                    f"/{total:,}"
                    f" | patch SHA "
                    f"{len(patch_matches):,}"
                    f" | commit SHA "
                    f"{len(commit_matches):,}",
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
        f"Files scanned:            "
        f"{records:,}"
    )

    print(
        f"Valid CVE records:        "
        f"{valid_records:,}"
    )

    print(
        f"Rejected CVEs:            "
        f"{rejected_records:,}"
    )

    print(
        f"Invalid JSON:             "
        f"{invalid_json:,}"
    )

    print(
        f"Non-record JSON:          "
        f"{invalid_shape:,}"
    )

    print(
        f"Missing/bad metadata:     "
        f"{missing_metadata:,}"
    )

    print(
        f"References inspected:     "
        f"{references:,}"
    )

    print(
        f"References tagged patch:  "
        f"{patch_refs:,}"
    )

    print(
        f"SHA w/ patch ref:         "
        f"{len(patch_matches):,}"
    )

    print(
        f"SHA w/ commit URL only:   "
        f"{len(commit_matches):,}"
        f"  (trước đây bỏ)"
    )

    print(
        f"CVE -> CWE:               "
        f"{len(cve_to_cwes):,}"
    )

    print(
        f"CVE -> CWE primary:       "
        f"{len(cve_to_primary):,}"
    )

    result = {
        "_cache_version":
            CVEORG_CACHE_VERSION,

        "_target_shas":
            targets.keys(),

        "patch_matches":
            dict(
                patch_matches
            ),

        "commit_matches":
            dict(
                commit_matches
            ),

        "cve_to_cwes":
            cve_to_cwes,

        "cve_to_primary":
            cve_to_primary,
    }

    save_json_gz(
        CVEORG_SCAN_CACHE,
        result,
    )

    return result


def apply_cveorg(
    df,
):

    before = (
        df.copy()
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "METHOD 5 - CVE.ORG"
    )

    print(
        "=" * 78
    )

    targets = build_targets(
        df
    )

    print(
        f"Target SHA: "
        f"{len(targets):,}"
    )

    scan = scan_cveorg(
        targets
    )

    tiers = [
        (
            "patch_matches",
            "cveorg_patch_commit_exact",
        ),
        (
            "commit_matches",
            "cveorg_commit_reference_exact",
        ),
    ]

    df["cveorg_cve_candidates"] = ""
    df["cveorg_cwe_candidates"] = ""
    df["cveorg_patch_urls"] = ""
    df["cveorg_status"] = None

    for idx in df.index[
        df["cve_id"].isna()
    ]:

        shas = row_shas(
            df,
            idx,
        )

        if not shas:
            continue

        filled = False
        candidates = set()
        cwe_candidates = set()
        urls = set()
        status = "no_exact_commit_reference"

        for bucket_name, source in tiers:

            bucket = scan[
                bucket_name
            ]

            for sha, is_backport in shas:

                evidence = bucket.get(
                    sha,
                    []
                )

                if not evidence:
                    continue

                cves = cves_of(
                    evidence
                )

                candidates.update(
                    cves
                )

                cwe_candidates.update(
                    cwes_of(
                        evidence
                    )
                )

                urls.update(
                    urls_of(
                        evidence
                    )
                )

                if filled:
                    continue

                if len(cves) != 1:

                    status = (
                        "multiple_cves_ambiguous"
                    )

                    continue

                df.at[
                    idx,
                    "cve_id"
                ] = cves[0]

                df.at[
                    idx,
                    "cve_source"
                ] = tag_source(
                    source,
                    is_backport,
                )

                status = (
                    "single_cve_filled"
                )

                filled = True

                primary = sorted({
                    cwe
                    for row in evidence
                    for cwe in row.get(
                        "primary_cwes",
                        []
                    )
                })

                chosen = (
                    primary
                    if len(primary) == 1
                    else
                    sorted(
                        cwes_of(
                            evidence
                        )
                    )
                )

                if (
                    is_missing(
                        df.at[
                            idx,
                            "cwe_id"
                        ]
                    )
                    and
                    len(chosen) == 1
                ):

                    df.at[
                        idx,
                        "cwe_id"
                    ] = chosen[0]

                    df.at[
                        idx,
                        "cwe_source"
                    ] = tag_source(
                        source,
                        is_backport,
                    )

        if not filled and candidates:

            status = (
                "multiple_cves_ambiguous"
            )

        df.at[
            idx,
            "cveorg_cve_candidates"
        ] = ";".join(
            sorted(
                candidates
            )
        )

        df.at[
            idx,
            "cveorg_cwe_candidates"
        ] = ";".join(
            sorted(
                cwe_candidates
            )
        )

        df.at[
            idx,
            "cveorg_patch_urls"
        ] = ";".join(
            sorted(
                urls
            )
        )

        df.at[
            idx,
            "cveorg_status"
        ] = status

    print_stage_diff(
        "METHOD 5 RESULT",
        before,
        df,
    )

    return (
        df,
        scan[
            "cve_to_cwes"
        ],
        scan[
            "cve_to_primary"
        ],
    )


# ============================================================
# METHOD 6
# CVE -> CWE (gộp mọi nguồn)
#
# Trước đây Method 4 và 5 chỉ fill CWE khi CVE có ĐÚNG 1
# CWE, nên 738 dòng có CVE vẫn thiếu CWE.
#
# Ưu tiên:
#   1. primary CWE của NVD
#   2. primary CWE của CNA (CVE.org)
#   3. database_specific.cwe_ids của OSV
#   4. nếu toàn bộ nguồn chỉ cho đúng 1 CWE thì lấy
#   5. nhiều CWE, không có primary -> ghi candidates,
#      lấy CWE nhỏ nhất, confidence medium
# ============================================================

def apply_cve_to_cwe(
    df,
    nvd_primary,
    nvd_all,
    org_primary,
    org_all,
    osv_all,
    nvd_evaluator=None,
):

    before = (
        df.copy()
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "METHOD 6 - CVE -> CWE"
    )

    print(
        "=" * 78
    )

    if "cwe_candidates" not in df.columns:
        df["cwe_candidates"] = ""

    tiers = [
        (
            nvd_primary,
            "nvd_cve_primary",
        ),
        (
            org_primary,
            "cveorg_cve_primary",
        ),
        (
            nvd_evaluator or {},
            "nvd_evaluator_note",
        ),
        (
            osv_all,
            "osv_cve_cwe_ids",
        ),
    ]

    stats = Counter()

    # ========================================================
    # cwe_candidates điền cho MỌI dòng có CVE, kể cả dòng đã
    # có CWE - để so sánh được nhãn hiện tại với DB.
    # ========================================================

    for idx in df.index[
        df["cve_id"].notna()
        &
        df["cwe_id"].notna()
    ]:

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

        every = sorted(
            set(
                nvd_all.get(cve, [])
            )
            |
            set(
                org_all.get(cve, [])
            )
            |
            set(
                osv_all.get(cve, [])
            )
            |
            set(
                (nvd_evaluator or {}).get(cve, [])
            )
        )

        if every:

            df.at[
                idx,
                "cwe_candidates"
            ] = ";".join(
                every
            )

    indices = df.index[
        df["cwe_id"].isna()
        &
        df["cve_id"].notna()
    ]

    print(
        f"Dòng có CVE, thiếu CWE: "
        f"{len(indices):,}"
    )

    for idx in indices:

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

        every = sorted(
            set(
                nvd_all.get(
                    cve,
                    []
                )
            )
            |
            set(
                org_all.get(
                    cve,
                    []
                )
            )
            |
            set(
                osv_all.get(
                    cve,
                    []
                )
            )
            |
            set(
                (nvd_evaluator or {}).get(
                    cve,
                    []
                )
            )
        )

        df.at[
            idx,
            "cwe_candidates"
        ] = ";".join(
            every
        )

        chosen = None
        source = None

        for table, name in tiers:

            values = table.get(
                cve,
                []
            )

            if len(values) == 1:

                chosen = values[0]
                source = name

                break

        # ----------------------------------------------------
        # không có primary: chỉ lấy khi toàn bộ nguồn
        # đồng ý đúng 1 CWE
        # ----------------------------------------------------

        if chosen is None and len(every) == 1:

            chosen = every[0]
            source = "cve_cwe_single"

        # ----------------------------------------------------
        # nhiều CWE, không phân định được -> vẫn lấy nhưng
        # hạ confidence, và cwe_candidates giữ đủ thông tin
        # ----------------------------------------------------

        if chosen is None and len(every) > 1:

            chosen = every[0]
            source = "cve_cwe_ambiguous"

        if chosen is None:

            stats["no_cwe_in_any_db"] += 1
            continue

        df.at[
            idx,
            "cwe_id"
        ] = chosen

        df.at[
            idx,
            "cwe_source"
        ] = source

        stats[source] += 1

    for key, value in (
        stats.most_common()
    ):

        print(
            f"  {key:<26s} "
            f"{value:>7,}"
        )

    print_stage_diff(
        "METHOD 6 RESULT",
        before,
        df,
    )

    return df


# ============================================================
# METHOD 7
# PROPAGATE THEO COMMIT, LẶP TỚI KHI HỘI TỤ
#
# Method 1 chỉ chạy MỘT LẦN trên nhãn gốc, nên nhãn mới do
# Method 2..6 tìm ra không lan sang các dòng cùng commit.
#
# Khoá theo commit_sha (chuẩn hoá) thay vì chuỗi URL thô,
# vì cùng một commit có thể xuất hiện dưới nhiều dạng URL.
# ============================================================

def commit_key_series(df):

    keys = []

    for idx in df.index:

        sha = df.at[
            idx,
            "commit_sha"
        ]

        if (
            isinstance(sha, str)
            and
            sha
        ):

            keys.append(
                f"sha:{sha}"
            )

            continue

        link = df.at[
            idx,
            "commit_link"
        ]

        if (
            isinstance(link, str)
            and
            link.strip()
        ):

            keys.append(
                f"url:{link.strip()}"
            )

        else:

            # "" chứ KHÔNG phải None.
            # None ghi vào DataFrame thành NaN, và
            # bool(float("nan")) is True -> "if not key"
            # KHÔNG skip -> mọi dòng thiếu commit link bị
            # gom vào CÙNG một khoá và lan nhãn cho nhau.
            keys.append(
                ""
            )

    return keys


def propagate_same_commit(
    df,
    max_rounds=5,
):

    before = (
        df.copy()
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "METHOD 7 - PROPAGATE THEO COMMIT (LẶP)"
    )

    print(
        "=" * 78
    )

    commit_keys = (
        commit_key_series(
            df
        )
    )

    df["commit_key"] = commit_keys

    # dùng dict thay vì đọc lại cột: tránh mọi rủi ro
    # NaN/dtype khi round-trip qua DataFrame
    key_of = dict(
        zip(
            df.index,
            commit_keys,
        )
    )

    usable = sum(
        1
        for value in commit_keys
        if value
    )

    print(
        f"  dòng có khoá commit: "
        f"{usable:,}/{len(df):,}"
        f"  (bỏ {len(df) - usable:,} dòng "
        f"không có commit link)"
    )

    total_cve = 0
    total_cwe = 0

    for round_index in range(
        max_rounds
    ):

        maps = {}

        for col in [
            "cve_id",
            "cwe_id",
        ]:

            values_by_key = (
                defaultdict(Counter)
            )

            for idx in df.index:

                key = key_of.get(
                    idx
                )

                if (
                    not key
                    or
                    is_missing(key)
                ):
                    continue

                value = df.at[
                    idx,
                    col
                ]

                if is_missing(
                    value
                ):
                    continue

                values_by_key[
                    key
                ][
                    str(value).strip()
                ] += 1

            maps[col] = values_by_key

        changed_cve = 0
        changed_cwe = 0

        for idx in df.index:

            key = key_of.get(
                idx
            )

            if (
                not key
                or
                is_missing(key)
            ):
                continue

            for col, source_col in [
                (
                    "cve_id",
                    "cve_source",
                ),
                (
                    "cwe_id",
                    "cwe_source",
                ),
            ]:

                if not is_missing(
                    df.at[
                        idx,
                        col
                    ]
                ):
                    continue

                counts = maps[col].get(
                    key
                )

                if not counts:
                    continue

                if COMMIT_MODE == "unambiguous":

                    if len(counts) != 1:
                        continue

                winner = (
                    counts
                    .most_common(1)[0][0]
                )

                df.at[
                    idx,
                    col
                ] = winner

                df.at[
                    idx,
                    source_col
                ] = (
                    "same_commit_propagated"
                )

                if col == "cve_id":
                    changed_cve += 1
                else:
                    changed_cwe += 1

        total_cve += changed_cve
        total_cwe += changed_cwe

        print(
            f"  round {round_index + 1}: "
            f"+CVE {changed_cve:,}  "
            f"+CWE {changed_cwe:,}"
        )

        if (
            changed_cve == 0
            and
            changed_cwe == 0
        ):
            break

    print(
        f"  tổng: +CVE {total_cve:,}  "
        f"+CWE {total_cwe:,}"
    )

    print_stage_diff(
        "METHOD 7 RESULT",
        before,
        df,
    )

    return df


# ============================================================
# FINAL SAVE
# ============================================================

def save_final(
    df,
):

    df["has_cve"] = (
        df["cve_id"].notna()
    )

    df["has_cwe"] = (
        df["cwe_id"].notna()
    )

    df["has_vuln_label"] = (
        df["has_cve"]
        |
        df["has_cwe"]
    )

    df["has_both_cve_cwe"] = (
        df["has_cve"]
        &
        df["has_cwe"]
    )

    # ========================================================
    # CONFIDENCE
    #
    # Cần thiết vì pipeline giờ fill cả từ bằng chứng
    # medium (URL commit không có tag Patch, backport,
    # CVE nhiều CWE). Ai muốn tập nhãn sạch thì lọc
    # cve_confidence in ('gold', 'high').
    # ========================================================

    df["cve_confidence"] = (
        df["cve_source"]
        .apply(
            confidence_of
        )
    )

    df["cwe_confidence"] = (
        df["cwe_source"]
        .apply(
            confidence_of
        )
    )

    # ========================================================
    # FULL FILE
    # ========================================================

    df.to_parquet(
        FINAL_PARQUET,
        index=False,
    )

    df.to_csv(
        FINAL_CSV,
        index=False,
    )

    # ========================================================
    # AUDIT FILE
    # ========================================================

    audit_cols = [
        "file_name",
        "extension",
        "language",

        "commit_link",
        "commit_sha",
        "alt_commit_shas",
        "commit_message",

        "cve_id",
        "cve_id_all",
        "cve_source",
        "cve_confidence",

        "cwe_id",
        "cwe_id_all",
        "cwe_candidates",
        "cwe_source",
        "cwe_confidence",

        "osv_cve_candidates",
        "osv_status",

        "nvd_cve_candidates",
        "nvd_cwe_candidates",
        "nvd_patch_urls",
        "nvd_status",

        "cveorg_cve_candidates",
        "cveorg_cwe_candidates",
        "cveorg_patch_urls",
        "cveorg_status",

        "has_cve",
        "has_cwe",
        "has_vuln_label",
        "has_both_cve_cwe",
    ]

    audit_cols = [
        col
        for col in audit_cols
        if col in df.columns
    ]

    df[
        audit_cols
    ].to_csv(
        FINAL_AUDIT,
        index=True,
    )

    # ========================================================
    # MISSING BOTH
    # ========================================================

    missing = df[
        ~df["has_vuln_label"]
    ]

    missing.to_csv(
        DATA_AUDIT
        / "TitanVul_still_missing_both.csv",
        index=True,
    )

    # ========================================================
    # CẦN REVIEW TAY
    #
    # Có candidate nhưng không chốt được vì nhiều CVE.
    # Đây là chỗ đáng review tay nhất: bằng chứng đã có,
    # chỉ thiếu quyết định.
    # ========================================================

    status_cols = [
        col
        for col in [
            "osv_status",
            "nvd_status",
            "cveorg_status",
        ]
        if col in df.columns
    ]

    if status_cols:

        ambiguous = df[
            ~df["has_cve"]
            &
            df[status_cols]
            .eq(
                "multiple_cves_ambiguous"
            )
            .any(
                axis=1
            )
        ]

        ambiguous[
            audit_cols
        ].to_csv(
            DATA_AUDIT
            / "TitanVul_ambiguous_review.csv",
            index=True,
        )

        print(
            f"\nCần review tay "
            f"(có candidate, nhiều CVE): "
            f"{len(ambiguous):,}"
        )

    # ========================================================
    # CWE CONFLICT
    #
    # cwe_id hiện tại KHÔNG nằm trong danh sách CWE mà các DB
    # đưa ra cho cùng CVE đó. Thường là nhãn gốc cho class
    # (CWE-119) hoặc hậu quả (CWE-200) trong khi DB cho
    # weakness cụ thể (CWE-121 / CWE-126).
    #
    # CỐ Ý KHÔNG tự ghi đè nhãn gốc. Xuất ra để người dùng
    # quyết định.
    # ========================================================

    if "cwe_candidates" in df.columns:

        candidates = (
            df["cwe_candidates"]
            .fillna("")
            .astype(str)
        )

        in_candidates = pd.Series(
            [
                str(cwe) in str(cands).split(";")
                for cwe, cands in zip(
                    df["cwe_id"],
                    candidates,
                )
            ],
            index=df.index,
        )

        conflict = df[
            df["cwe_id"].notna()
            &
            (candidates != "")
            &
            ~in_candidates
        ]

        if len(conflict):

            conflict[
                audit_cols
            ].to_csv(
                DATA_AUDIT
                / "TitanVul_cwe_conflict_review.csv",
                index=True,
            )

            print(
                f"CWE lệch giữa nhãn hiện tại và DB: "
                f"{len(conflict):,}"
                f"  -> TitanVul_cwe_conflict_review.csv"
            )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 78
    )

    print(
        "TITANVUL - COMPLETE METADATA RECOVERY PIPELINE"
    )

    print(
        "=" * 78
    )

    print(
        f"Input:            "
        f"{INPUT_PARQUET}"
    )

    print(
        f"Commit mode:      "
        f"{COMMIT_MODE}"
    )

    print(
        f"Fast JSON/orjson: "
        f"{FAST_JSON}"
    )

    # ========================================================
    # LOAD + NORMALIZE
    # ========================================================

    df = pd.read_parquet(
        INPUT_PARQUET
    )

    df = normalize_labels(
        df
    )

    df = initialize_sources(
        df
    )

    # ========================================================
    # COMMIT SHA
    #
    # Tính MỘT LẦN ở đây, trước mọi method, để Method 1
    # cũng propagate được theo SHA.
    # ========================================================

    df["commit_sha"] = (
        df["commit_link"]
        .apply(
            extract_commit_sha
        )
    )

    df["alt_commit_shas"] = (
        df["commit_message"]
        .apply(
            lambda m: ";".join(
                extract_alt_shas(
                    m
                )
            )
        )
    )

    have_sha = int(
        df["commit_sha"]
        .notna()
        .sum()
    )

    have_alt = int(
        (
            df["alt_commit_shas"]
            .astype(str)
            != ""
        ).sum()
    )

    print(
        f"\ncommit_sha lấy được:  "
        f"{have_sha:,}/{len(df):,}"
    )

    print(
        f"dòng có SHA backport: "
        f"{have_alt:,}"
    )

    original_df = (
        df.copy()
    )

    original_stats = (
        label_stats(
            original_df
        )
    )

    print_stats(
        "ORIGINAL TITANVUL",
        df,
    )

    # ========================================================
    # METHOD 1 - SAME COMMIT (nhãn gốc)
    # ========================================================

    df = apply_same_commit(
        df,
        original_df,
    )

    # ========================================================
    # METHOD 2 - COMMIT MESSAGE
    # ========================================================

    df = apply_commit_message(
        df
    )

    print_stats(
        "AFTER METHOD 1 + 2",
        df,
    )

    save_intermediate(
        df,
        DATA_INTERIM
        / "TitanVul_recovery_2methods.parquet",
    )

    # ========================================================
    # METHOD 3 - OSV
    # ========================================================

    (
        df,
        osv_cwes,
    ) = apply_osv(
        df
    )

    print_stats(
        "AFTER METHOD 3 / OSV",
        df,
    )

    save_intermediate(
        df,
        DATA_INTERIM
        / "TitanVul_recovery_3methods_FIXED.parquet",
    )

    # ========================================================
    # METHOD 4 - NVD
    # ========================================================

    (
        df,
        nvd_cwes,
        nvd_primary,
        nvd_evaluator,
    ) = apply_nvd(
        df
    )

    print_stats(
        "AFTER METHOD 4 / NVD",
        df,
    )

    save_intermediate(
        df,
        DATA_INTERIM
        / "TitanVul_recovery_4methods_NVD.parquet",
    )

    # ========================================================
    # METHOD 5 - CVE.ORG
    # ========================================================

    (
        df,
        org_cwes,
        org_primary,
    ) = apply_cveorg(
        df
    )

    print_stats(
        "AFTER METHOD 5 / CVE.ORG",
        df,
    )

    save_intermediate(
        df,
        DATA_INTERIM
        / "TitanVul_recovery_5methods_CVEORG.parquet",
    )

    # ========================================================
    # METHOD 6 + 7
    #
    # Chạy xen kẽ: propagate sinh ra CVE mới -> CVE->CWE
    # có thêm việc; CVE->CWE sinh ra CWE mới -> propagate
    # lan tiếp. Hai vòng là đủ hội tụ.
    # ========================================================

    for pass_index in range(
        2
    ):

        print(
            f"\n### PASS {pass_index + 1} "
            f"(METHOD 6 + 7)"
        )

        df = apply_cve_to_cwe(
            df,
            nvd_primary,
            nvd_cwes,
            org_primary,
            org_cwes,
            osv_cwes,
            nvd_evaluator,
        )

        df = propagate_same_commit(
            df
        )

    print_stats(
        "AFTER METHOD 6 + 7",
        df,
    )

    # ========================================================
    # FINAL
    # ========================================================

    save_final(
        df
    )

    final_stats = (
        label_stats(
            df
        )
    )

    total = len(
        df
    )

    recovered = (
        final_stats["any"]
        -
        original_stats["any"]
    )

    print(
        "\n"
        + "=" * 78
    )

    print(
        "FINAL SUMMARY"
    )

    print(
        "=" * 78
    )

    print(
        f"Total samples:             "
        f"{total:,}"
    )

    print(
        f"Original >=1 label:        "
        f"{original_stats['any']:,}"
        f"/{total:,} "
        f"("
        f"{original_stats['any']/total*100:.2f}%"
        f")"
    )

    print(
        f"Final >=1 label:           "
        f"{final_stats['any']:,}"
        f"/{total:,} "
        f"("
        f"{final_stats['any']/total*100:.2f}%"
        f")"
    )

    print(
        f"Recovered new samples:     "
        f"+{recovered:,}"
    )

    print(
        f"\nFinal CVE:                "
        f"{final_stats['cve']:,}"
    )

    print(
        f"Final CWE:                 "
        f"{final_stats['cwe']:,}"
    )

    print(
        f"Final CVE + CWE:           "
        f"{final_stats['both']:,}"
        f"/{total:,} "
        f"("
        f"{final_stats['both']/total*100:.2f}%"
        f")"
    )

    print(
        f"Still missing both:        "
        f"{final_stats['missing_both']:,}"
        f"/{total:,} "
        f"("
        f"{final_stats['missing_both']/total*100:.2f}%"
        f")"
    )

    # ========================================================
    # SOURCE DISTRIBUTION
    # ========================================================

    for label, col in [
        (
            "CVE SOURCES",
            "cve_source",
        ),
        (
            "CWE SOURCES",
            "cwe_source",
        ),
        (
            "CVE CONFIDENCE",
            "cve_confidence",
        ),
        (
            "CWE CONFIDENCE",
            "cwe_confidence",
        ),
    ]:

        print(
            "\n"
            + "=" * 78
        )

        print(
            label
        )

        print(
            "=" * 78
        )

        print(
            df[col]
            .value_counts(
                dropna=False
            )
            .to_string()
        )

    # ========================================================
    # OUTPUT
    # ========================================================

    print(
        "\n"
        + "=" * 78
    )

    print(
        "OUTPUT FILES"
    )

    print(
        "=" * 78
    )

    for name in [
        FINAL_PARQUET,
        FINAL_CSV,
        FINAL_AUDIT,
        DATA_AUDIT / "TitanVul_still_missing_both.csv",
        DATA_AUDIT / "TitanVul_ambiguous_review.csv",
    ]:

        print(
            name
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