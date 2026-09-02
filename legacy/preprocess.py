import os
import re
import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse, unquote

import pandas as pd
from datasets import load_dataset


# ============================================================
# CONFIG
# ============================================================

DATASET_NAME = "yikun-li/TitanVul"
DATASET_SPLIT = "train"

WORKER_FILENAME = "linguist_worker.rb"

OUTPUT_PARQUET = "TitanVul_language_final.parquet"
OUTPUT_CSV = "TitanVul_language_final.csv"
OUTPUT_REVIEW = "TitanVul_language_review.csv"

MIN_CODE_LENGTH = 10

# ============================================================
# REPO LANGUAGE PRIOR
#
# Prior được HỌC từ chính các mẫu đã có nhãn chắc chắn
# (extension / file_name), gom theo repo trong commit_link.
#
# Đo bằng leave-one-out trên các mẫu đã có nhãn:
#
#   purity >= 1.00  -> 99.68%
#   purity >= 0.90  -> 98.94%
#   purity <  0.80  -> 63-71%   (không dùng)
#
# Vì vậy chỉ nhận prior khi purity >= 0.90.
# ============================================================

REPO_PRIOR_MIN_PURITY = 0.90

REPO_PRIOR_MIN_SUPPORT = 1


# ============================================================
# EXTENSION -> LANGUAGE
# ============================================================

EXT_TO_LANG = {
    # C
    "c": "C",

    # Header không phân biệt chắc chắn C/C++
    "h": "C/C++",

    # C++
    "cc": "C++",
    "cpp": "C++",
    "cxx": "C++",
    "hpp": "C++",
    "hh": "C++",
    "hxx": "C++",

    # Objective-C
    "m": "Objective-C",
    "mm": "Objective-C++",

    # Java
    "java": "Java",

    # Python
    "py": "Python",
    "pyw": "Python",

    # JavaScript
    "js": "JavaScript",
    "jsx": "JavaScript",
    "mjs": "JavaScript",
    "cjs": "JavaScript",

    # TypeScript
    "ts": "TypeScript",
    "tsx": "TypeScript",

    # PHP
    "php": "PHP",
    "phtml": "PHP",
    "php3": "PHP",
    "php4": "PHP",
    "php5": "PHP",

    # Go
    "go": "Go",

    # Kotlin
    "kt": "Kotlin",
    "kts": "Kotlin",

    # Ruby
    "rb": "Ruby",

    # C#
    "cs": "C#",

    # Swift
    "swift": "Swift",

    # Rust
    "rs": "Rust",

    # Scala
    "scala": "Scala",

    # Lua
    "lua": "Lua",

    # Perl
    "pl": "Perl",
    "pm": "Perl",

    # --------------------------------------------------------
    # BỔ SUNG
    #
    # Chủ yếu phục vụ việc đọc đường dẫn file từ
    # commit_link và commit_message ở STEP 3 / STEP 4.
    # --------------------------------------------------------

    # C++ (biến thể ít gặp)
    "c++": "C++",
    "h++": "C++",
    "ipp": "C++",
    "tpp": "C++",
    "inl": "C++",

    # PHP
    "inc": "PHP",

    # Python
    "pyx": "Python",
    "pxd": "Python",

    # Ruby
    "rake": "Ruby",

    # Perl
    "pod": "Perl",
    "t": "Perl",

    # Shell
    "sh": "Shell",
    "bash": "Shell",
    "zsh": "Shell",

    # Assembly
    "s": "Assembly",
    "asm": "Assembly",

    # Khác
    "erl": "Erlang",
    "hrl": "Erlang",
    "ex": "Elixir",
    "exs": "Elixir",
    "dart": "Dart",
    "groovy": "Groovy",
    "clj": "Clojure",
    "hs": "Haskell",
    "ml": "OCaml",
    "r": "R",
    "vb": "Visual Basic",
    "f": "Fortran",
    "f90": "Fortran",
    "d": "D",
    "nim": "Nim",
    "zig": "Zig",
}


# ============================================================
# LANGUAGE FAMILY
#
# Quan trọng:
# C và C++ được coi là cùng một family khi kiểm tra agreement.
# Nhưng final label vẫn giữ C hoặc C++.
# ============================================================

def language_family(language):
    if language in {
        "C",
        "C++",
        "C/C++",
    }:
        return "C/C++"

    return language


# ============================================================
# NORMALIZE EXTENSION
# ============================================================

def normalize_extension(ext):

    if ext is None:
        return None

    try:
        if pd.isna(ext):
            return None
    except Exception:
        pass

    ext = str(ext).strip().lower()

    if ext in {
        "",
        "nan",
        "none",
        "null",
        "unknown",
    }:
        return None

    ext = os.path.basename(ext)

    ext = ext.lstrip(".")

    if "." in ext:
        ext = ext.rsplit(".", 1)[-1]

    ext = ext.strip()

    return ext or None


# ============================================================
# EXTENSION FROM FILE NAME
# ============================================================

def extension_from_filename(filename):

    if filename is None:
        return None

    try:
        if pd.isna(filename):
            return None
    except Exception:
        pass

    filename = str(filename).strip()

    if not filename:
        return None

    basename = os.path.basename(filename)

    if "." not in basename:
        return None

    ext = basename.rsplit(".", 1)[-1]

    return normalize_extension(ext)


# ============================================================
# LANGUAGE FROM A FILE PATH
# ============================================================

def language_from_path(path):

    ext = extension_from_filename(path)

    if ext is None:
        return None

    return EXT_TO_LANG.get(ext)


# ============================================================
# REPO KEY FROM COMMIT LINK
#
# Hỗ trợ nhiều host:
#
#   github.com/<owner>/<repo>/commit/<sha>
#   git.kernel.org/.../linux.git/commit/?id=<sha>
#   git.php.net/?p=php-src.git;a=commit;h=<sha>
# ============================================================

def repo_key(commit_link):

    if not isinstance(commit_link, str):
        return None

    commit_link = commit_link.strip()

    if not commit_link:
        return None

    try:
        parsed = urlparse(commit_link)
    except Exception:
        return None

    host = parsed.netloc.lower()

    if not host:
        return None

    segments = [
        s for s in parsed.path.split("/") if s
    ]

    # GitHub / GitLab / Bitbucket: owner + repo
    if any(
        h in host
        for h in (
            "github.com",
            "gitlab.com",
            "bitbucket.org",
        )
    ):
        if len(segments) >= 2:
            return (
                f"{host}/"
                f"{segments[0]}/{segments[1]}"
            ).lower()

    # cgit / gitweb: ?p=<project>.git
    if parsed.query:

        match = re.search(
            r"p=([^;&]+)",
            parsed.query,
        )

        if match:
            return (
                f"{host}/{match.group(1)}"
            ).lower()

    # cgit: phần path TRƯỚC /commit/ (hoặc trước .git)
    # mới là repo thật.
    #
    #   /cgit/linux/kernel/git/torvalds/linux.git/commit/...
    #   -> cgit/linux/kernel/git/torvalds/linux
    if segments:

        cut = len(segments)

        for i, segment in enumerate(segments):

            if segment in {
                "commit",
                "commitdiff",
                "diff",
                "patch",
                "log",
                "tree",
                "blob",
            }:
                cut = i
                break

            if segment.endswith(".git"):
                cut = i + 1
                break

        selected = segments[:cut] or segments[:1]

        path = "/".join(selected)

        path = re.sub(r"\.git$", "", path)

        return f"{host}/{path}".lower()

    return host


# ============================================================
# PROJECT KEY
#
# Fallback khi repo_key không khớp:
# cùng một project được host ở nhiều nơi.
#
#   github.com/torvalds/linux        -> linux
#   git.kernel.org/.../linux.git     -> linux
# ============================================================

def project_key(commit_link):

    key = repo_key(commit_link)

    if key is None:
        return None

    key = re.sub(r"\.git\b", "", key)

    segments = [
        s for s in re.split(r"[/;]", key) if s
    ]

    if not segments:
        return None

    return segments[-1]


# ============================================================
# FILE PATH INSIDE A COMMIT LINK
#
# cgit đưa thẳng đường dẫn file vào URL:
#
#   .../commit/drivers/net/slip/slhc.c?id=<sha>
#
# Đây là đường dẫn THẬT của file bị sửa
# nên độ chính xác rất cao.
# ============================================================

def language_from_commit_link(commit_link):

    if not isinstance(commit_link, str):
        return None

    try:
        decoded = unquote(commit_link)
    except Exception:
        decoded = commit_link

    match = re.search(
        r"/commit/([^?#]+?)(?:\?|#|$)",
        decoded,
    )

    if not match:
        return None

    return language_from_path(
        match.group(1)
    )


# ============================================================
# FILE NAMES MENTIONED IN A COMMIT MESSAGE
#
# Cảnh báo quan trọng:
#
# Đo trên các mẫu đã có nhãn chắc chắn:
#
#   exact language : 68.2%   -> KHÔNG đủ tin
#   language family: 95.9%   -> đủ tin
#
# Vì vậy commit_message CHỈ được dùng để xác nhận
# FAMILY, không bao giờ dùng để đặt nhãn C vs C++.
# ============================================================

FILE_MENTION_PATTERN = re.compile(
    r"[\w][\w/\-\.]*\.([A-Za-z0-9\+]{1,6})\b"
)


def family_from_commit_message(message):

    if not isinstance(message, str):
        return None

    families = set()

    for match in FILE_MENTION_PATTERN.finditer(
        message
    ):

        language = language_from_path(
            match.group(0)
        )

        if language is not None:
            families.add(
                language_family(language)
            )

    # Nhắc tới nhiều ngôn ngữ khác nhau -> không kết luận
    if len(families) != 1:
        return None

    return families.pop()


# ============================================================
# LOAD TITANVUL
# ============================================================

def load_titanvul():

    print("Loading TitanVul...")

    ds = load_dataset(
        DATASET_NAME,
        split=DATASET_SPLIT,
    )

    df = ds.to_pandas()

    print(
        f"Loaded {len(df):,} samples"
    )

    print("\nColumns:")
    print(df.columns.tolist())

    return df


# ============================================================
# CHECK ENVIRONMENT
# ============================================================

def check_environment():

    ruby = shutil.which("ruby")

    if ruby is None:
        raise RuntimeError(
            "Ruby not found."
        )

    worker_path = (
        Path(__file__).resolve().parent
        / WORKER_FILENAME
    )

    if not worker_path.exists():
        raise FileNotFoundError(
            f"Missing worker: {worker_path}"
        )

    print(f"Ruby: {ruby}")
    print(
        f"Linguist worker: {worker_path}"
    )


# ============================================================
# GITHUB LINGUIST WORKER
# ============================================================

class LinguistWorker:

    def __init__(self):

        worker_path = (
            Path(__file__).resolve().parent
            / WORKER_FILENAME
        )

        self.process = subprocess.Popen(
            [
                "ruby",
                str(worker_path),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

    # --------------------------------------------------------
    # Detect one source-code snippet
    # --------------------------------------------------------

    def detect(self, idx, code):

        if not isinstance(code, str):
            return None

        code = code.strip()

        if len(code) < MIN_CODE_LENGTH:
            return None

        if self.process.poll() is not None:
            raise RuntimeError(
                "Linguist worker unexpectedly stopped."
            )

        request = {
            "id": int(idx),
            "code": code,
        }

        try:

            self.process.stdin.write(
                json.dumps(
                    request,
                    ensure_ascii=False,
                )
                + "\n"
            )

            self.process.stdin.flush()

            line = (
                self.process
                .stdout
                .readline()
            )

            if not line:
                return None

            response = json.loads(line)

            language = response.get(
                "language"
            )

            if not language:
                return None

            score = float(
                response.get(
                    "score",
                    0.0
                )
            )

            top3 = response.get(
                "top3",
                []
            )

            # =================================================
            # Margin = top1 - top2
            # =================================================

            if len(top3) >= 2:

                margin = (
                    float(top3[0][1])
                    -
                    float(top3[1][1])
                )

            elif len(top3) == 1:

                margin = float(
                    top3[0][1]
                )

            else:

                margin = 0.0

            return {
                "language": language,
                "score": score,
                "margin": margin,
                "top3": top3,
            }

        except Exception as e:

            print(
                f"\nLinguist error "
                f"at sample {idx}: {e}"
            )

            return None

    # --------------------------------------------------------
    # Close worker
    # --------------------------------------------------------

    def close(self):

        try:
            if self.process.stdin:
                self.process.stdin.close()

        except Exception:
            pass

        try:

            self.process.terminate()

            self.process.wait(
                timeout=5
            )

        except Exception:

            try:
                self.process.kill()

            except Exception:
                pass


# ============================================================
# CONFIDENCE
#
# Đây là heuristic của pipeline.
# Chưa phải threshold chính thức của GitHub Linguist.
# ============================================================

def get_confidence(
    score,
    margin,
    agreement,
):

    # --------------------------------------------------------
    # BEFORE và AFTER agreement
    # Exact agreement HOẶC C/C++ family agreement
    # --------------------------------------------------------

    if agreement:

        if (
            score >= 0.55
            and margin >= 0.15
        ):
            return "high"

        if (
            score >= 0.30
            and margin >= 0.08
        ):
            return "medium"

        return "low"

    # --------------------------------------------------------
    # Không agreement
    # --------------------------------------------------------

    if (
        score >= 0.70
        and margin >= 0.20
    ):
        return "high"

    if (
        score >= 0.50
        and margin >= 0.12
    ):
        return "medium"

    return "low"


# ============================================================
# CHOOSE STRONGER PREDICTION
# ============================================================

def prediction_strength(prediction):

    if prediction is None:
        return -1

    return (
        prediction["score"]
        +
        prediction["margin"]
    )


# ============================================================
# COMBINE BEFORE + AFTER
# ============================================================

def combine_predictions(
    before,
    after,
):

    # ========================================================
    # CASE 1
    # Both failed
    # ========================================================

    if (
        before is None
        and after is None
    ):

        return {
            "language": "Unknown",
            "language_family": "Unknown",

            "score": 0.0,
            "margin": 0.0,

            "confidence": "low",

            "agree": False,
            "exact_agree": False,

            "decision": "no_prediction",
        }

    # ========================================================
    # CASE 2
    # Before only
    # ========================================================

    if (
        before is not None
        and after is None
    ):

        confidence = get_confidence(
            before["score"],
            before["margin"],
            False,
        )

        return {
            "language":
                before["language"],

            "language_family":
                language_family(
                    before["language"]
                ),

            "score":
                before["score"],

            "margin":
                before["margin"],

            "confidence":
                confidence,

            "agree":
                False,

            "exact_agree":
                False,

            "decision":
                "before_only",
        }

    # ========================================================
    # CASE 3
    # After only
    # ========================================================

    if (
        before is None
        and after is not None
    ):

        confidence = get_confidence(
            after["score"],
            after["margin"],
            False,
        )

        return {
            "language":
                after["language"],

            "language_family":
                language_family(
                    after["language"]
                ),

            "score":
                after["score"],

            "margin":
                after["margin"],

            "confidence":
                confidence,

            "agree":
                False,

            "exact_agree":
                False,

            "decision":
                "after_only",
        }

    # ========================================================
    # Both have predictions
    # ========================================================

    before_language = before[
        "language"
    ]

    after_language = after[
        "language"
    ]

    before_family = language_family(
        before_language
    )

    after_family = language_family(
        after_language
    )

    # ========================================================
    # CASE 4
    # EXACT AGREEMENT
    #
    # C -> C
    # C++ -> C++
    # Java -> Java
    # ========================================================

    if (
        before_language
        ==
        after_language
    ):

        avg_score = (
            before["score"]
            +
            after["score"]
        ) / 2

        avg_margin = (
            before["margin"]
            +
            after["margin"]
        ) / 2

        confidence = get_confidence(
            avg_score,
            avg_margin,
            True,
        )

        return {
            "language":
                before_language,

            "language_family":
                before_family,

            "score":
                avg_score,

            "margin":
                avg_margin,

            "confidence":
                confidence,

            "agree":
                True,

            "exact_agree":
                True,

            "decision":
                "before_after_exact_agree",
        }

    # ========================================================
    # CASE 5
    # FAMILY AGREEMENT
    #
    # C -> C++
    # C++ -> C
    #
    # Đây là thay đổi bạn yêu cầu.
    # ========================================================

    if (
        before_family
        ==
        after_family
    ):

        avg_score = (
            before["score"]
            +
            after["score"]
        ) / 2

        avg_margin = (
            before["margin"]
            +
            after["margin"]
        ) / 2

        # ----------------------------------------------
        # Vẫn chọn C hoặc C++ cụ thể
        # prediction nào mạnh hơn.
        # ----------------------------------------------

        before_strength = (
            prediction_strength(
                before
            )
        )

        after_strength = (
            prediction_strength(
                after
            )
        )

        if (
            before_strength
            >=
            after_strength
        ):

            final_language = (
                before_language
            )

            decision = (
                "before_after_family_agree_"
                "choose_before"
            )

        else:

            final_language = (
                after_language
            )

            decision = (
                "before_after_family_agree_"
                "choose_after"
            )

        confidence = get_confidence(
            avg_score,
            avg_margin,
            True,
        )

        return {
            "language":
                final_language,

            "language_family":
                before_family,

            "score":
                avg_score,

            "margin":
                avg_margin,

            # C vs C++ vẫn là agreement
            "confidence":
                confidence,

            "agree":
                True,

            # Nhưng không phải exact
            "exact_agree":
                False,

            "decision":
                decision,
        }

    # ========================================================
    # CASE 6
    # Real disagreement
    #
    # Example:
    # C++ vs Java
    # Python vs JavaScript
    # ========================================================

    before_strength = (
        prediction_strength(
            before
        )
    )

    after_strength = (
        prediction_strength(
            after
        )
    )

    if (
        before_strength
        >=
        after_strength
    ):

        chosen = before

        decision = (
            "disagree_choose_before"
        )

    else:

        chosen = after

        decision = (
            "disagree_choose_after"
        )

    confidence = get_confidence(
        chosen["score"],
        chosen["margin"],
        False,
    )

    # Không cho HIGH nếu thực sự disagreement
    if confidence == "high":
        confidence = "medium"

    return {
        "language":
            chosen["language"],

        "language_family":
            language_family(
                chosen["language"]
            ),

        "score":
            chosen["score"],

        "margin":
            chosen["margin"],

        "confidence":
            confidence,

        "agree":
            False,

        "exact_agree":
            False,

        "decision":
            decision,
    }


# ============================================================
# INITIALIZE COLUMNS
# ============================================================

def initialize_columns(df):

    # ========================================================
    # Original extension
    # ========================================================

    df["extension_raw"] = (
        df["extension"]
    )

    df["extension_normalized"] = (
        df["extension"]
        .apply(
            normalize_extension
        )
    )

    # ========================================================
    # Final labels
    # ========================================================

    df["language"] = None

    df["language_family"] = None

    df["language_source"] = None

    df["language_confidence"] = None

    df["language_score"] = float(
        "nan"
    )

    df["language_margin"] = float(
        "nan"
    )

    # ========================================================
    # Linguist BEFORE
    # ========================================================

    df[
        "linguist_before_language"
    ] = None

    df[
        "linguist_before_family"
    ] = None

    df[
        "linguist_before_score"
    ] = float("nan")

    df[
        "linguist_before_margin"
    ] = float("nan")

    df[
        "linguist_before_top3"
    ] = None

    # ========================================================
    # Linguist AFTER
    # ========================================================

    df[
        "linguist_after_language"
    ] = None

    df[
        "linguist_after_family"
    ] = None

    df[
        "linguist_after_score"
    ] = float("nan")

    df[
        "linguist_after_margin"
    ] = float("nan")

    df[
        "linguist_after_top3"
    ] = None

    # ========================================================
    # Agreement
    # ========================================================

    # Family agreement:
    #
    # C vs C++ = True
    #
    df["linguist_agree"] = None

    # Exact agreement:
    #
    # C vs C++ = False
    #
    df[
        "linguist_exact_agree"
    ] = None

    df[
        "language_decision"
    ] = None

    df[
        "needs_language_review"
    ] = False

    # ========================================================
    # Repo prior
    # ========================================================

    df["repo_key"] = None

    df["project_key"] = None

    df["repo_prior_language"] = None

    df["repo_prior_purity"] = float("nan")

    df["repo_prior_support"] = float("nan")

    return df


# ============================================================
# STEP 1
# LABEL FROM EXTENSION
# ============================================================

def label_from_extension(df):

    print(
        "\n"
        + "=" * 70
    )

    print(
        "STEP 1 - EXTENSION"
    )

    print(
        "=" * 70
    )

    languages = (
        df[
            "extension_normalized"
        ]
        .map(
            EXT_TO_LANG
        )
    )

    valid = (
        languages.notna()
    )

    df.loc[
        valid,
        "language"
    ] = languages.loc[
        valid
    ]

    df.loc[
        valid,
        "language_family"
    ] = (
        languages.loc[
            valid
        ]
        .apply(
            language_family
        )
    )

    df.loc[
        valid,
        "language_source"
    ] = "extension"

    df.loc[
        valid,
        "language_confidence"
    ] = "high"

    df.loc[
        valid,
        "language_decision"
    ] = "extension"

    print(
        f"Detected: "
        f"{valid.sum():,}"
        f"/{len(df):,}"
    )

    return df


# ============================================================
# STEP 2
# LABEL FROM FILE NAME
# ============================================================

def label_from_filename(df):

    print(
        "\n"
        + "=" * 70
    )

    print(
        "STEP 2 - FILE NAME"
    )

    print(
        "=" * 70
    )

    unknown_indices = (
        df.index[
            df["language"].isna()
        ]
    )

    if len(
        unknown_indices
    ) == 0:

        print(
            "Nothing to recover."
        )

        return df

    filename_extensions = (
        df.loc[
            unknown_indices,
            "file_name"
        ]
        .apply(
            extension_from_filename
        )
    )

    filename_languages = (
        filename_extensions
        .map(
            EXT_TO_LANG
        )
    )

    valid_indices = (
        filename_languages[
            filename_languages.notna()
        ]
        .index
    )

    # --------------------------------------------------------
    # Extension
    # --------------------------------------------------------

    df.loc[
        valid_indices,
        "extension_normalized"
    ] = (
        filename_extensions.loc[
            valid_indices
        ]
    )

    # --------------------------------------------------------
    # Language
    # --------------------------------------------------------

    df.loc[
        valid_indices,
        "language"
    ] = (
        filename_languages.loc[
            valid_indices
        ]
    )

    # --------------------------------------------------------
    # Family
    # --------------------------------------------------------

    df.loc[
        valid_indices,
        "language_family"
    ] = (
        filename_languages.loc[
            valid_indices
        ]
        .apply(
            language_family
        )
    )

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    df.loc[
        valid_indices,
        "language_source"
    ] = "file_name"

    df.loc[
        valid_indices,
        "language_confidence"
    ] = "high"

    df.loc[
        valid_indices,
        "language_decision"
    ] = "file_name"

    print(
        f"Recovered: "
        f"{len(valid_indices):,}"
    )

    print(
        f"Remaining: "
        f"{df['language'].isna().sum():,}"
    )

    return df


# ============================================================
# STEP 3
# LABEL FROM PATH INSIDE COMMIT LINK
# ============================================================

def label_from_commit_link(df):

    print("\n" + "=" * 70)
    print("STEP 3 - COMMIT LINK PATH")
    print("=" * 70)

    if "commit_link" not in df.columns:
        print("No commit_link column.")
        return df

    unknown_indices = df.index[
        df["language"].isna()
    ]

    if len(unknown_indices) == 0:
        print("Nothing to recover.")
        return df

    languages = (
        df.loc[
            unknown_indices,
            "commit_link",
        ]
        .apply(language_from_commit_link)
    )

    valid_indices = languages[
        languages.notna()
    ].index

    df.loc[
        valid_indices,
        "language",
    ] = languages.loc[valid_indices]

    df.loc[
        valid_indices,
        "language_family",
    ] = (
        languages.loc[valid_indices]
        .apply(language_family)
    )

    df.loc[
        valid_indices,
        "language_source",
    ] = "commit_link_path"

    df.loc[
        valid_indices,
        "language_confidence",
    ] = "high"

    df.loc[
        valid_indices,
        "language_decision",
    ] = "commit_link_path"

    print(
        f"Recovered: {len(valid_indices):,}"
    )

    print(
        f"Remaining: "
        f"{df['language'].isna().sum():,}"
    )

    return df


# ============================================================
# BUILD REPO LANGUAGE PRIOR
#
# Học từ các mẫu ĐÃ có nhãn chắc chắn
# (extension / file_name / commit_link_path).
#
# Không bao giờ học từ nhãn do Linguist đoán,
# nếu không prior sẽ tự khuếch đại lỗi của chính nó.
# ============================================================

TRUSTED_SOURCES = {
    "extension",
    "file_name",
    "commit_link_path",
}


def build_language_prior(df, key_column):

    trusted = df[
        df["language_source"].isin(
            TRUSTED_SOURCES
        )
        & df[key_column].notna()
        & df["language"].notna()
    ]

    if len(trusted) == 0:
        return {}

    counts = (
        trusted
        .groupby([key_column, "language"])
        .size()
        .unstack(fill_value=0)
    )

    totals = counts.sum(axis=1)

    top_language = counts.idxmax(axis=1)

    top_count = counts.max(axis=1)

    purity = top_count / totals

    prior = {}

    for key in counts.index:

        if totals[key] < REPO_PRIOR_MIN_SUPPORT:
            continue

        if purity[key] < REPO_PRIOR_MIN_PURITY:
            continue

        prior[key] = {
            "language": top_language[key],
            "purity": float(purity[key]),
            "support": int(totals[key]),
        }

    return prior


def attach_repo_prior(df):

    print("\n" + "=" * 70)
    print("BUILD REPO LANGUAGE PRIOR")
    print("=" * 70)

    if "commit_link" not in df.columns:
        print("No commit_link column.")
        df["repo_prior_language"] = None
        df["repo_prior_purity"] = float("nan")
        df["repo_prior_support"] = float("nan")
        return df

    df["repo_key"] = (
        df["commit_link"].apply(repo_key)
    )

    df["project_key"] = (
        df["commit_link"].apply(project_key)
    )

    repo_prior = build_language_prior(
        df, "repo_key"
    )

    project_prior = build_language_prior(
        df, "project_key"
    )

    print(
        f"Repo groups (purity >= "
        f"{REPO_PRIOR_MIN_PURITY}): "
        f"{len(repo_prior):,}"
    )

    print(
        f"Project groups (fallback): "
        f"{len(project_prior):,}"
    )

    def lookup(row):

        entry = repo_prior.get(
            row["repo_key"]
        )

        if entry is None:
            entry = project_prior.get(
                row["project_key"]
            )

        if entry is None:
            return (
                None,
                float("nan"),
                float("nan"),
            )

        return (
            entry["language"],
            entry["purity"],
            entry["support"],
        )

    resolved = df.apply(
        lookup,
        axis=1,
        result_type="expand",
    )

    df["repo_prior_language"] = resolved[0]

    df["repo_prior_purity"] = resolved[1]

    df["repo_prior_support"] = resolved[2]

    unknown_mask = df["language"].isna()

    covered = (
        df.loc[
            unknown_mask,
            "repo_prior_language",
        ]
        .notna()
        .sum()
    )

    print(
        f"Prior covers "
        f"{covered:,}/"
        f"{int(unknown_mask.sum()):,} "
        f"unlabeled samples"
    )

    return df


# ============================================================
# STEP 4
# GITHUB LINGUIST
# ============================================================

def label_with_linguist(df):

    print(
        "\n"
        + "=" * 70
    )

    print(
        "STEP 4 - GITHUB LINGUIST"
    )

    print(
        "=" * 70
    )

    indices = (
        df.index[
            df[
                "language"
            ].isna()
        ]
        .tolist()
    )

    total = len(
        indices
    )

    print(
        f"Need inference: "
        f"{total:,}"
    )

    if total == 0:
        return df

    worker = (
        LinguistWorker()
    )

    try:

        for n, idx in enumerate(
            indices,
            start=1,
        ):

            # =================================================
            # BEFORE
            # =================================================

            before = (
                worker.detect(
                    idx,
                    df.at[
                        idx,
                        "func_before"
                    ],
                )
            )

            if before is not None:

                df.at[
                    idx,
                    "linguist_before_language"
                ] = (
                    before[
                        "language"
                    ]
                )

                df.at[
                    idx,
                    "linguist_before_family"
                ] = (
                    language_family(
                        before[
                            "language"
                        ]
                    )
                )

                df.at[
                    idx,
                    "linguist_before_score"
                ] = (
                    before[
                        "score"
                    ]
                )

                df.at[
                    idx,
                    "linguist_before_margin"
                ] = (
                    before[
                        "margin"
                    ]
                )

                df.at[
                    idx,
                    "linguist_before_top3"
                ] = json.dumps(
                    before[
                        "top3"
                    ],
                    ensure_ascii=False,
                )

            # =================================================
            # AFTER
            # =================================================

            after = (
                worker.detect(
                    idx,
                    df.at[
                        idx,
                        "func_after"
                    ],
                )
            )

            if after is not None:

                df.at[
                    idx,
                    "linguist_after_language"
                ] = (
                    after[
                        "language"
                    ]
                )

                df.at[
                    idx,
                    "linguist_after_family"
                ] = (
                    language_family(
                        after[
                            "language"
                        ]
                    )
                )

                df.at[
                    idx,
                    "linguist_after_score"
                ] = (
                    after[
                        "score"
                    ]
                )

                df.at[
                    idx,
                    "linguist_after_margin"
                ] = (
                    after[
                        "margin"
                    ]
                )

                df.at[
                    idx,
                    "linguist_after_top3"
                ] = json.dumps(
                    after[
                        "top3"
                    ],
                    ensure_ascii=False,
                )

            # =================================================
            # COMBINE
            # =================================================

            result = (
                combine_predictions(
                    before,
                    after,
                )
            )

            df.at[
                idx,
                "language"
            ] = result[
                "language"
            ]

            df.at[
                idx,
                "language_family"
            ] = result[
                "language_family"
            ]

            df.at[
                idx,
                "language_source"
            ] = "github_linguist"

            df.at[
                idx,
                "language_confidence"
            ] = result[
                "confidence"
            ]

            df.at[
                idx,
                "language_score"
            ] = result[
                "score"
            ]

            df.at[
                idx,
                "language_margin"
            ] = result[
                "margin"
            ]

            # =================================================
            # Agreement
            # =================================================

            df.at[
                idx,
                "linguist_agree"
            ] = result[
                "agree"
            ]

            df.at[
                idx,
                "linguist_exact_agree"
            ] = result[
                "exact_agree"
            ]

            df.at[
                idx,
                "language_decision"
            ] = result[
                "decision"
            ]

            # =================================================
            # REVIEW
            # =================================================

            needs_review = False

            # Low confidence
            if (
                result[
                    "confidence"
                ]
                ==
                "low"
            ):
                needs_review = True

            # REAL disagreement only.
            #
            # C vs C++ family agreement
            # KHÔNG bị đánh review ở đây.
            if (
                result[
                    "decision"
                ].startswith(
                    "disagree_"
                )
            ):
                needs_review = True

            if (
                result[
                    "language"
                ]
                ==
                "Unknown"
            ):
                needs_review = True

            df.at[
                idx,
                "needs_language_review"
            ] = (
                needs_review
            )

            # =================================================
            # PROGRESS
            # =================================================

            if (
                n % 100 == 0
                or
                n == total
            ):

                print(
                    f"\rProcessed "
                    f"{n:,}/{total:,}",
                    end="",
                    flush=True,
                )

        print()

    finally:

        worker.close()

    return df


# ============================================================
# STEP 5
# RECONCILE LINGUIST WITH REPO PRIOR
#
# Chỉ áp dụng cho các mẫu do Linguist đoán.
# Các mẫu đã có nhãn từ extension / file_name /
# commit_link_path KHÔNG bị đụng tới.
#
# Cơ sở:
#
#   repo prior : 98.9% (leave-one-out, purity >= 0.9)
#   linguist   : 93% số mẫu ở mức low confidence
#
# Nên khi hai bên mâu thuẫn, prior được ưu tiên.
# ============================================================

def reconcile_with_repo_prior(df):

    print("\n" + "=" * 70)
    print("STEP 5 - REPO PRIOR RECONCILIATION")
    print("=" * 70)

    target_indices = df.index[
        df["language_source"]
        == "github_linguist"
    ]

    if len(target_indices) == 0:
        print("Nothing to reconcile.")
        return df

    has_message = (
        "commit_message" in df.columns
    )

    counters = {
        "prior_confirms": 0,
        "prior_refines_family": 0,
        "prior_overrides": 0,
        "prior_fills_unknown": 0,
        "message_confirms": 0,
        "no_prior": 0,
    }

    for idx in target_indices:

        prior_language = df.at[
            idx, "repo_prior_language"
        ]

        linguist_language = df.at[
            idx, "language"
        ]

        # ----------------------------------------------------
        # Không có prior
        # Thử xác nhận FAMILY bằng commit_message
        # ----------------------------------------------------

        if not isinstance(
            prior_language, str
        ):

            counters["no_prior"] += 1

            if not has_message:
                continue

            message_family = (
                family_from_commit_message(
                    df.at[idx, "commit_message"]
                )
            )

            if message_family is None:
                continue

            if (
                linguist_language != "Unknown"
                and message_family
                == language_family(
                    linguist_language
                )
            ):

                counters["message_confirms"] += 1

                df.at[
                    idx, "language_source"
                ] = "linguist+commit_message"

                if (
                    df.at[
                        idx,
                        "language_confidence",
                    ]
                    == "low"
                ):
                    df.at[
                        idx,
                        "language_confidence",
                    ] = "medium"

            continue

        prior_family = language_family(
            prior_language
        )

        # ----------------------------------------------------
        # CASE A
        # Linguist thất bại -> prior điền vào
        # ----------------------------------------------------

        if linguist_language == "Unknown":

            counters["prior_fills_unknown"] += 1

            df.at[idx, "language"] = (
                prior_language
            )

            df.at[idx, "language_family"] = (
                prior_family
            )

            df.at[idx, "language_source"] = (
                "repo_prior"
            )

            df.at[
                idx, "language_confidence"
            ] = "medium"

            df.at[
                idx, "language_decision"
            ] = "repo_prior_fills_unknown"

            df.at[
                idx, "needs_language_review"
            ] = False

            continue

        linguist_family = language_family(
            linguist_language
        )

        # ----------------------------------------------------
        # CASE B
        # Hai bên khớp chính xác -> nâng confidence
        # ----------------------------------------------------

        if prior_language == linguist_language:

            counters["prior_confirms"] += 1

            df.at[
                idx, "language_source"
            ] = "linguist+repo_prior"

            df.at[
                idx, "language_confidence"
            ] = "high"

            df.at[
                idx, "language_decision"
            ] = (
                df.at[idx, "language_decision"]
                + "+repo_confirms"
            )

            df.at[
                idx, "needs_language_review"
            ] = False

            continue

        # ----------------------------------------------------
        # CASE C
        # Cùng family, khác nhãn cụ thể (C vs C++)
        #
        # Prior chính xác hơn ở mức nhãn cụ thể
        # nên lấy prior, nhưng chỉ để medium.
        # ----------------------------------------------------

        if prior_family == linguist_family:

            counters["prior_refines_family"] += 1

            df.at[idx, "language"] = (
                prior_language
            )

            df.at[idx, "language_family"] = (
                prior_family
            )

            df.at[
                idx, "language_source"
            ] = "linguist+repo_prior"

            df.at[
                idx, "language_confidence"
            ] = "medium"

            df.at[
                idx, "language_decision"
            ] = (
                df.at[idx, "language_decision"]
                + "+repo_refines"
            )

            df.at[
                idx, "needs_language_review"
            ] = False

            continue

        # ----------------------------------------------------
        # CASE D
        # Mâu thuẫn family thật sự.
        #
        # Prior thắng, nhưng LUÔN đánh dấu review.
        #
        # Kiểm chứng trên 229 mẫu mâu thuẫn:
        #
        #   ~204 mẫu prior ĐÚNG
        #     Linguist gán JavaScript cho code C
        #     (qemu, wireshark, libvncserver, mujs)
        #     với score chỉ 0.23-0.38.
        #
        #   ~25 mẫu prior SAI
        #     Repo đa ngôn ngữ như nodejs/node:
        #     prior = JavaScript nhưng hàm lại là
        #     C API thật (napi_*).
        #
        # Đã thử tách hai nhóm bằng purity của prior
        # (0.995 vs 0.998) và bằng top3 của Linguist
        # (183/184 vs 19/22) - cả hai đều KHÔNG tách
        # được. Nên chọn theo đa số và để con người
        # review toàn bộ nhóm này.
        # ----------------------------------------------------

        counters["prior_overrides"] += 1

        df.at[idx, "language"] = (
            prior_language
        )

        df.at[idx, "language_family"] = (
            prior_family
        )

        df.at[idx, "language_source"] = (
            "repo_prior"
        )

        df.at[
            idx, "language_confidence"
        ] = "medium"

        df.at[idx, "language_decision"] = (
            "repo_prior_overrides_linguist"
        )

        df.at[
            idx, "needs_language_review"
        ] = True

    print(
        f"Linguist samples: "
        f"{len(target_indices):,}"
    )

    for name, value in counters.items():
        print(f"  {name:24s} {value:,}")

    return df


# ============================================================
# FINALIZE
# ============================================================

def finalize_labels(df):

    df[
        "language"
    ] = (
        df[
            "language"
        ]
        .fillna(
            "Unknown"
        )
    )

    df[
        "language_family"
    ] = (
        df[
            "language_family"
        ]
        .fillna(
            "Unknown"
        )
    )

    df[
        "language_source"
    ] = (
        df[
            "language_source"
        ]
        .fillna(
            "unknown"
        )
    )

    df[
        "language_confidence"
    ] = (
        df[
            "language_confidence"
        ]
        .fillna(
            "low"
        )
    )

    df[
        "language_decision"
    ] = (
        df[
            "language_decision"
        ]
        .fillna(
            "unknown"
        )
    )

    unknown_mask = (
        df[
            "language"
        ]
        ==
        "Unknown"
    )

    df.loc[
        unknown_mask,
        "needs_language_review"
    ] = True

    return df


# ============================================================
# STATISTICS
# ============================================================

def print_statistics(df):

    # ========================================================
    # LANGUAGE DISTRIBUTION
    # ========================================================

    print(
        "\n"
        + "=" * 70
    )

    print(
        "FINAL LANGUAGE DISTRIBUTION"
    )

    print(
        "=" * 70
    )

    stats = (
        df[
            "language"
        ]
        .value_counts(
            dropna=False
        )
        .rename_axis(
            "language"
        )
        .reset_index(
            name="count"
        )
    )

    stats[
        "percent"
    ] = (
        stats[
            "count"
        ]
        /
        len(df)
        *
        100
    ).round(2)

    print(
        stats.to_string(
            index=False
        )
    )

    # ========================================================
    # LANGUAGE FAMILY
    # ========================================================

    print(
        "\n"
        + "=" * 70
    )

    print(
        "LANGUAGE FAMILY DISTRIBUTION"
    )

    print(
        "=" * 70
    )

    family_stats = (
        df[
            "language_family"
        ]
        .value_counts(
            dropna=False
        )
        .rename_axis(
            "family"
        )
        .reset_index(
            name="count"
        )
    )

    family_stats[
        "percent"
    ] = (
        family_stats[
            "count"
        ]
        /
        len(df)
        *
        100
    ).round(2)

    print(
        family_stats.to_string(
            index=False
        )
    )

    # ========================================================
    # SOURCE
    # ========================================================

    print(
        "\n"
        + "=" * 70
    )

    print(
        "LANGUAGE SOURCE"
    )

    print(
        "=" * 70
    )

    print(
        df[
            "language_source"
        ]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    # ========================================================
    # CONFIDENCE
    # ========================================================

    print(
        "\n"
        + "=" * 70
    )

    print(
        "CONFIDENCE"
    )

    print(
        "=" * 70
    )

    print(
        df[
            "language_confidence"
        ]
        .value_counts(
            dropna=False
        )
        .to_string()
    )

    # ========================================================
    # LINGUIST
    # ========================================================

    # Sau STEP 5, language_source có thể đã đổi thành
    # linguist+repo_prior / repo_prior / ...
    # nên lọc theo dấu vết linguist thay vì theo source.

    linguist_df = (
        df[
            df[
                "linguist_before_language"
            ].notna()
            |
            df[
                "linguist_after_language"
            ].notna()
        ]
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "GITHUB LINGUIST SAMPLES"
    )

    print(
        "=" * 70
    )

    print(
        f"{len(linguist_df):,}"
    )

    if (
        len(
            linguist_df
        )
        >
        0
    ):

        # ====================================================
        # FAMILY AGREEMENT
        # ====================================================

        print(
            "\nFamily agreement "
            "(C vs C++ = agreement):"
        )

        print(
            linguist_df[
                "linguist_agree"
            ]
            .value_counts(
                dropna=False
            )
            .to_string()
        )

        # ====================================================
        # EXACT AGREEMENT
        # ====================================================

        print(
            "\nExact agreement:"
        )

        print(
            linguist_df[
                "linguist_exact_agree"
            ]
            .value_counts(
                dropna=False
            )
            .to_string()
        )

        # ====================================================
        # C/C++ FAMILY ONLY
        # ====================================================

        c_family_agree = (
            linguist_df[
                linguist_df[
                    "language_decision"
                ]
                .str.startswith(
                    "before_after_family_agree",
                    na=False,
                )
            ]
        )

        print(
            "\nC/C++ family-only agreements:"
        )

        print(
            f"{len(c_family_agree):,}"
        )

        # ====================================================
        # DECISION
        # ====================================================

        print(
            "\nDecision:"
        )

        print(
            linguist_df[
                "language_decision"
            ]
            .value_counts(
                dropna=False
            )
            .to_string()
        )

        # ====================================================
        # INFERRED DISTRIBUTION
        # ====================================================

        print(
            "\nInferred language distribution:"
        )

        inferred = (
            linguist_df[
                "language"
            ]
            .value_counts()
            .rename_axis(
                "language"
            )
            .reset_index(
                name="count"
            )
        )

        inferred[
            "percent"
        ] = (
            inferred[
                "count"
            ]
            /
            len(
                linguist_df
            )
            *
            100
        ).round(2)

        print(
            inferred.to_string(
                index=False
            )
        )

    # ========================================================
    # REVIEW
    # ========================================================

    print(
        "\n"
        + "=" * 70
    )

    print(
        "NEEDS LANGUAGE REVIEW"
    )

    print(
        "=" * 70
    )

    review_count = int(
        df[
            "needs_language_review"
        ]
        .sum()
    )

    print(
        f"{review_count:,}"
        f"/{len(df):,} "
        f"("
        f"{review_count / len(df) * 100:.2f}"
        f"%)"
    )

    # ========================================================
    # UNKNOWN
    # ========================================================

    unknown_count = int(
        (
            df[
                "language"
            ]
            ==
            "Unknown"
        )
        .sum()
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "UNKNOWN LANGUAGE"
    )

    print(
        "=" * 70
    )

    print(
        f"{unknown_count:,}"
        f"/{len(df):,} "
        f"("
        f"{unknown_count / len(df) * 100:.2f}"
        f"%)"
    )


# ============================================================
# SAVE OUTPUTS
# ============================================================

def save_outputs(df):

    print(
        "\n"
        + "=" * 70
    )

    print(
        "SAVING"
    )

    print(
        "=" * 70
    )

    # Full parquet
    df.to_parquet(
        OUTPUT_PARQUET,
        index=False,
    )

    print(
        f"Saved: "
        f"{OUTPUT_PARQUET}"
    )

    # Full CSV
    df.to_csv(
        OUTPUT_CSV,
        index=False,
    )

    print(
        f"Saved: "
        f"{OUTPUT_CSV}"
    )

    # Review samples
    review_df = (
        df[
            df[
                "needs_language_review"
            ]
        ]
        .copy()
    )

    review_df.to_csv(
        OUTPUT_REVIEW,
        index=False,
    )

    print(
        f"Saved: "
        f"{OUTPUT_REVIEW}"
    )

    print(
        f"Review samples: "
        f"{len(review_df):,}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # Environment
    # ========================================================

    check_environment()

    # ========================================================
    # Load TitanVul
    # ========================================================

    df = (
        load_titanvul()
    )

    # ========================================================
    # Initialize
    # ========================================================

    df = (
        initialize_columns(
            df
        )
    )

    # ========================================================
    # Step 1
    # Extension
    # ========================================================

    df = (
        label_from_extension(
            df
        )
    )

    # ========================================================
    # Step 2
    # File name
    # ========================================================

    df = (
        label_from_filename(
            df
        )
    )

    # ========================================================
    # Step 3
    # File path inside commit link
    # ========================================================

    df = (
        label_from_commit_link(
            df
        )
    )

    # ========================================================
    # Repo language prior
    #
    # Phải build SAU step 3 để prior học được
    # từ mọi nhãn chắc chắn, nhưng TRƯỚC linguist
    # để prior không học từ nhãn suy đoán.
    # ========================================================

    df = (
        attach_repo_prior(
            df
        )
    )

    # ========================================================
    # Step 4
    # GitHub Linguist
    # ========================================================

    df = (
        label_with_linguist(
            df
        )
    )

    # ========================================================
    # Step 5
    # Reconcile with repo prior
    # ========================================================

    df = (
        reconcile_with_repo_prior(
            df
        )
    )

    # ========================================================
    # Finalize
    # ========================================================

    df = (
        finalize_labels(
            df
        )
    )

    # ========================================================
    # Statistics
    # ========================================================

    print_statistics(
        df
    )

    # ========================================================
    # Save
    # ========================================================

    save_outputs(
        df
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "DONE"
    )

    print(
        "=" * 70
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()