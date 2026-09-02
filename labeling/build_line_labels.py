"""
Sinh ground-truth mức dòng cho toàn bộ TitanVul, đa ngôn ngữ.

Thuật toán theo LineVD (Hin et al., MSR 2022), đã đối chiếu với
code gốc davidhin/linevd:

    vulnerable = removed  UNION  depadd

  removed = dòng bị xoá/sửa ở bản vulnerable
  depadd  = dòng phụ thuộc control/data vào các dòng ĐƯỢC THÊM
            ở bản fixed, lấy láng giềng VÔ HƯỚNG trong PDG của
            bản after rồi lọc theo dòng tồn tại ở bản before

Dòng nào ĐÃ CÓ nhãn dòng của BigVul thì dùng luôn nhãn đó,
pipeline chỉ suy nhãn cho phần BigVul không phủ. Nhãn BigVul
(text) được đổi sang số dòng trong hệ toạ độ hợp để cả hai
nguồn dùng chung một hệ - đối chiếu trước đó cho thấy 97.6%
trùng khít nên phép đổi này an toàn.

Chạy:
    python build_line_labels.py            # dùng cache nếu có
    python build_line_labels.py --all      # suy nhãn cả dòng đã có BigVul
    python build_line_labels.py --no-cache # tính lại toàn bộ
    python build_line_labels.py --limit 500

Ra:
    data/output/TitanVul_line_labels.parquet
    data/audit/TitanVul_line_labels_audit.csv
    data/audit/TitanVul_line_labels_failures.csv
    data/audit/TitanVul_line_labels_report.txt
    cache/linelabel_cache.parquet
"""

import argparse
import hashlib
import json
import os
import sys

from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

from linelabel import label_sample
from linelabel.diffalign import align, signature_lines
from linelabel.pdg import LineGraph
from linelabel.specs import resolve


ROOT = Path(
    __file__
).resolve().parent

DATA_OUT = ROOT / "data" / "output"

DATA_AUDIT = ROOT / "data" / "audit"

CACHE = ROOT / "cache"


# ưu tiên file đã có nhãn dòng BigVul để so sánh chéo được
INPUT_CANDIDATES = [
    DATA_OUT / "TitanVul_line_labels_bigvul.parquet",
    DATA_OUT / "TitanVul_cwe_labels_trainable.parquet",
]

def out_paths(tag):

    sfx = f"_{tag}" if tag else ""

    return (
        DATA_OUT
        / f"TitanVul_line_labels{sfx}.parquet",

        DATA_AUDIT
        / f"TitanVul_line_labels{sfx}_audit.csv",

        DATA_AUDIT
        / f"TitanVul_line_labels{sfx}_failures.csv",

        DATA_AUDIT
        / f"TitanVul_line_labels{sfx}_report.txt",
    )

CACHE_FILE = (
    CACHE / "linelabel_cache.parquet"
)

# PDG do Joern dựng sẵn (build_joern_graphs.py)
JOERN_CACHE = (
    CACHE / "joern_graphs.parquet"
)


# status coi là dùng được cho huấn luyện
USABLE = {
    "ok",
    "ok_add_only",
    "ok_delete_only",
    "ok_partial_parse",
    "ok_relabeled_lang",
    "ok_add_only_relabeled_lang",
    "ok_delete_only_relabeled_lang",
    "ok_partial_parse_relabeled_lang",
    "ok_clean_reparse",
    "ok_syntax_repair",

    # Joern là backend chính; joern_no_signal (0 edge) và
    # joern_empty (không ra dòng nào) vẫn bị loại.
    "joern_ok",
    "joern_add_only",
    "joern_delete_only",
}


# Nhãn removed-only: PDG không dùng được nên depadd bị bỏ,
# nhưng removed lấy thuần từ diff nên vẫn đúng.
#
# Đây CHÍNH LÀ hành vi của LineVD - ivdetect_evaluate.py:
#     try:
#         dep_add_lines = get_dep_add_lines(...)
#     except Exception:
#         dep_add_lines = []
#     return [id, {"removed": row["removed"], "depadd": dep_add_lines}]
# rồi linevd/__init__.py:107 lấy set(removed) + depadd.
# LineVD không loại mẫu, cũng không đánh dấu gì.
#
# Khác biệt: mình GẮN CỜ label_completeness để lọc được khi
# train/đánh giá, vì nhãn thiếu depadd -> recall thấp hơn.
REMOVED_ONLY = {
    "no_pdg_signal",
    "parse_error_at_anchor",
}

USABLE |= REMOVED_ONLY


# Tăng số này mỗi khi LOGIC gán nhãn đổi (diffalign, labels, pdg...).
# Nếu không, cache cũ sẽ được dùng lại và thay đổi code thành vô hiệu.
#   3 -> xoá comment trước khi diff + bỏ dòng rỗng khỏi nhãn
#   4 -> có thêm PDG Joern cho php/go/swift. Cache KHÔNG chứa
#        thông tin "mẫu này có graph Joern hay không", nên phải
#        tăng version, nếu không các mẫu đó vẫn trả kết quả
#        tree-sitter cũ.
LABEL_LOGIC_VERSION = 4


def joern_sig(
    jg,
):
    """
    Chữ ký của PDG Joern dùng cho mẫu này.

    Phải nằm trong khoá cache: nếu không, mẫu vừa được Joern
    xử lý xong vẫn trả về kết quả tree-sitter cũ trong cache.
    Đã mắc lỗi này hai lần nên đưa vào khoá thay vì trông vào
    việc nhớ tăng LABEL_LOGIC_VERSION.
    """

    if not jg:
        return "-"

    g = jg[0]

    return (
        f"{len(g.lines)}:"
        f"{g.n_cdg}:"
        f"{g.n_ddg}"
    )


def sample_key(
    before,
    after,
    language,
    ratio,
    minchg=0,
    jsig="-",
):
    """Khoá cache: phụ thuộc đầu vào + phiên bản logic -> tái lập được."""

    h = hashlib.sha1()

    for part in (
        before,
        after,
        language,
        f"r{ratio:.2f}",
        f"m{int(minchg)}",
        f"j{jsig}",
        f"v{LABEL_LOGIC_VERSION}",
    ):

        h.update(
            str(part).encode(
                "utf-8",
                "replace",
            )
        )

        h.update(b"\x00")

    return h.hexdigest()


def joern_key(
    before,
    after,
    language,
):
    """
    Khoá tra PDG của Joern.

    KHÁC sample_key: không chứa max_changed_ratio, vì graph của
    Joern chỉ phụ thuộc code, không phụ thuộc ngưỡng lọc diff.
    build_joern_graphs.py dùng đúng công thức này.
    """

    h = hashlib.sha1()

    for part in (
        before,
        after,
        language,
    ):

        h.update(
            str(part).encode(
                "utf-8",
                "replace",
            )
        )

        h.update(b"\x00")

    return h.hexdigest()


def line_texts(
    before_view,
    numbers,
):
    """Text của các dòng được gán nhãn, để audit bằng mắt."""

    lines = before_view.splitlines()

    out = []

    for n in numbers:

        if 1 <= n <= len(lines):

            out.append(
                lines[n - 1].strip()
            )

    return out


def to_str(numbers):

    return ";".join(
        str(n)
        for n in numbers
    )


# ============================================================
# NẠP PDG CỦA JOERN
# ============================================================

def load_joern_graphs():
    """
    -> dict key -> (LineGraph, set dòng có trong graph)

    Joern là backend CHÍNH. Mẫu nào có ở đây thì dùng, còn lại
    rơi về tree-sitter.

    offset: khi phải bọc scaffold (method trơ của Java/C#/JS),
    số dòng bị dịch 1 - trừ lại ngay tại đây.
    """

    if not JOERN_CACHE.exists():

        print(
            "  (không có joern_graphs.parquet "
            "-> chỉ dùng tree-sitter)"
        )

        return {}

    t = pd.read_parquet(
        JOERN_CACHE
    )

    out = {}

    for r in t.itertuples(
        index=False
    ):

        off = int(
            getattr(r, "offset", 0)
            or 0
        )

        # LineGraph tự trừ offset trong touch()/add(), nên
        # nạp số dòng theo đúng toạ độ Joern trả về
        g = LineGraph(
            offset=off
        )

        for ln in json.loads(r.lines):
            g.touch(int(ln))

        for a, b in json.loads(r.cdg):

            g.add(
                int(a),
                int(b),
                "cdg",
            )

        for a, b in json.loads(r.rd):

            g.add(
                int(a),
                int(b),
                "ddg",
            )

        out[r.key] = (
            g,
            set(g.lines),
        )

    print(
        f"  Joern PDG: {len(out):,} mẫu"
    )

    print(
        "  "
        + t["lang"]
        .value_counts()
        .to_string()
        .replace("\n", "\n  ")
    )

    return out


# ============================================================
# WORKER
# ============================================================

def process_row(args):

    (
        key,
        before,
        after,
        language,
        ratio,
        minchg,
        jg,
    ) = args

    r = label_sample(
        before,
        after,
        language,
        keep_views=True,
        max_changed_ratio=ratio,
        min_changed_lines=minchg,
        joern_graph=(
            jg[0]
            if jg
            else None
        ),
        joern_before_lines=(
            jg[1]
            if jg
            else None
        ),
    )

    return {
        "_key": key,

        "line_status": r.status,
        "line_confidence": r.confidence,
        "line_note": r.note,
        "line_lang": r.lang_key or "",
        "suspected_language": r.suspected_language,

        "vul_lines": to_str(
            r.vul_lines
        ),

        "removed_lines": to_str(
            r.removed
        ),

        "added_lines": to_str(
            r.added
        ),

        "depadd_lines": to_str(
            r.depadd
        ),

        "n_vul_lines": len(
            r.vul_lines
        ),

        "n_removed": len(r.removed),
        "n_added": len(r.added),
        "n_depadd": len(r.depadd),

        "n_union_lines": r.n_lines,
        "n_cdg_edges": r.n_cdg,
        "n_ddg_edges": r.n_ddg,
        "n_control_structs": r.n_control_structs,

        "vul_lines_text": "\n".join(
            line_texts(
                r.before_view,
                r.vul_lines,
            )
        ),
    }


# ============================================================
# MAIN
# ============================================================

def main():

    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--no-cache",
        action="store_true",
    )

    ap.add_argument(
        "--all",
        action="store_true",
        help="suy nhãn cả những dòng đã có nhãn BigVul",
    )

    ap.add_argument(
        "--limit",
        type=int,
        default=0,
    )

    ap.add_argument(
        "--max-changed-ratio",
        type=float,
        default=0.70,
        help="bỏ mẫu có tỉ lệ dòng đổi lớn hơn ngưỡng này. "
             "LineVD dùng 0.70 (helpers/datasets.py:206: "
             "dfv[dfv.mod_prop < 0.7])",
    )

    ap.add_argument(
        "--min-changed-lines",
        type=int,
        default=0,
        help="chỉ coi là viết lại hàm khi ĐỒNG THỜI đổi >= "
             "số dòng này. 0 = chỉ xét tỉ lệ, đúng LineVD. "
             "Cấu hình extended: 10",
    )

    ap.add_argument(
        "--tag",
        default="",
        help="hậu tố tên file, vd r70 / r80",
    )

    ap.add_argument(
        "--jobs",
        type=int,
        default=max(
            1,
            (os.cpu_count() or 2) - 1,
        ),
    )

    args = ap.parse_args()

    (
        OUT_PARQUET,
        OUT_AUDIT,
        OUT_FAIL,
        OUT_REPORT,
    ) = out_paths(
        args.tag
    )

    print("=" * 78)
    print("GROUND-TRUTH MỨC DÒNG - ĐA NGÔN NGỮ")
    print("=" * 78)

    print(
        f"Ngưỡng tỉ lệ dòng đổi: "
        f"{args.max_changed_ratio:.0%}"
        f"   | tag: {args.tag or '(không)'}"
    )

    src = next(
        (
            p
            for p in INPUT_CANDIDATES
            if p.exists()
        ),
        None,
    )

    if src is None:

        sys.exit(
            "Không thấy file đầu vào trong data/output/"
        )

    df = pd.read_parquet(
        src
    )

    print(
        f"Input : {src.name} "
        f"({len(df):,} dòng)"
    )

    if args.limit:

        df = df.head(
            args.limit
        ).copy()

        print(
            f"  --limit {args.limit}"
        )

    # ========================================================
    # CHỈ XỬ LÝ DÒNG BIGVUL KHÔNG PHỦ
    # ========================================================

    if "has_bigvul_lines" in df.columns:

        df["has_bigvul_lines"] = (
            df["has_bigvul_lines"]
            .fillna(False)
            .astype(bool)
        )

    else:

        df["has_bigvul_lines"] = False

    n_bv = int(
        df["has_bigvul_lines"].sum()
    )

    if args.all:

        target = df.index

        print(
            f"--all : suy nhãn cho cả "
            f"{len(df):,} dòng"
        )

    else:

        target = df.index[
            ~df["has_bigvul_lines"]
        ]

        print(
            f"Đã có nhãn BigVul     : "
            f"{n_bv:,}  -> dùng nhãn của BigVul"
        )

        print(
            f"Cần suy nhãn (còn lại): "
            f"{len(target):,}"
        )

    # ========================================================
    # KHOÁ + CACHE
    # ========================================================

    ratio = args.max_changed_ratio
    minchg = args.min_changed_lines

    joern = load_joern_graphs()

    df["_jkey"] = [
        joern_key(b, a, l)
        for b, a, l in zip(
            df["func_before"],
            df["func_after"],
            df["language"],
        )
    ]

    df["_key"] = [
        sample_key(
            b,
            a,
            l,
            ratio,
            minchg,
            joern_sig(
                joern.get(jk)
            ),
        )
        for b, a, l, jk in zip(
            df["func_before"],
            df["func_after"],
            df["language"],
            df["_jkey"],
        )
    ]

    cached = None

    if (
        not args.no_cache
        and
        CACHE_FILE.exists()
    ):

        cached = pd.read_parquet(
            CACHE_FILE
        )

        print(
            f"Cache : {CACHE_FILE.name} "
            f"({len(cached):,} mẫu)"
        )

    have = (
        set(cached["_key"])
        if cached is not None
        else set()
    )

    todo = df.loc[target]

    todo = todo[
        ~todo["_key"].isin(have)
    ]

    todo = todo.drop_duplicates(
        subset=["_key"]
    )

    print(
        f"Cần tính: {len(todo):,} mẫu "
        f"| dùng lại cache: "
        f"{len(df) - len(todo):,}"
    )

    results = []

    if len(todo):

        payload = [
            (
                k,
                b,
                a,
                l,
                ratio,
                minchg,
                joern.get(jk),
            )
            for k, jk, b, a, l in zip(
                todo["_key"],
                todo["_jkey"],
                todo["func_before"],
                todo["func_after"],
                todo["language"],
            )
        ]

        if args.jobs > 1:

            from multiprocessing import Pool

            print(
                f"Chạy song song "
                f"{args.jobs} process..."
            )

            with Pool(
                args.jobs
            ) as pool:

                for i, r in enumerate(
                    pool.imap_unordered(
                        process_row,
                        payload,
                        chunksize=64,
                    ),
                    1,
                ):

                    results.append(r)

                    if i % 2000 == 0:

                        print(
                            f"  {i:,}/{len(payload):,}",
                            flush=True,
                        )

        else:

            for i, item in enumerate(
                payload,
                1,
            ):

                results.append(
                    process_row(item)
                )

                if i % 2000 == 0:

                    print(
                        f"  {i:,}/{len(payload):,}",
                        flush=True,
                    )

    fresh = (
        pd.DataFrame(results)
        if results
        else pd.DataFrame()
    )

    table = (
        pd.concat(
            [
                c
                for c in (cached, fresh)
                if c is not None and len(c)
            ],
            ignore_index=True,
        )
        if (cached is not None or len(fresh))
        else fresh
    )

    table = table.drop_duplicates(
        subset=["_key"],
        keep="last",
    )

    CACHE.mkdir(
        parents=True,
        exist_ok=True,
    )

    table.to_parquet(
        CACHE_FILE,
        index=False,
    )

    print(
        f"Cache đã lưu: "
        f"{len(table):,} mẫu"
    )

    # ========================================================
    # GHÉP
    # ========================================================

    out = df.merge(
        table,
        on="_key",
        how="left",
    )

    # dòng không nằm trong target thì không có kết quả suy nhãn
    out["line_status"] = (
        out["line_status"]
        .fillna("skipped_has_bigvul")
    )

    out["derived_ok"] = (
        out["line_status"].isin(USABLE)
        &
        (out["n_vul_lines"].fillna(0) > 0)
    )

    # ========================================================
    # NHÃN BIGVUL -> SỐ DÒNG
    #
    # BigVul phát hành lines_before dưới dạng TEXT. Đổi sang
    # số dòng bằng cách khớp text trong before_view.
    #
    # QUAN TRỌNG: ở đây align() KHÔNG xoá comment
    # (drop_comments=False). Nhãn BigVul là ground-truth của
    # bộ gốc, phải giữ NGUYÊN. Xoá comment sẽ làm dòng
    #   Huff_transmit(...);   /* Transmit symbol */
    # không khớp text nữa, và làm mất cả dòng comment mà
    # BigVul cố ý gán nhãn -> đổi nhãn của người khác.
    #
    # Xoá comment chỉ áp dụng cho phần pipeline TỰ suy nhãn.
    # Vì vậy hai nguồn nằm ở hai hệ toạ độ khác nhau; cột
    # line_coord_space ghi rõ từng dòng thuộc hệ nào để còn
    # tái lập được.
    # ========================================================

    bv_nums = []
    bv_hit = []
    bv_nlines = []
    bv_text = []

    for _, r in out.iterrows():

        if not r["has_bigvul_lines"]:

            bv_nums.append("")
            bv_hit.append(0)
            bv_nlines.append(0)
            bv_text.append("")

            continue

        lk = resolve(
            r["language"]
        )

        want = {
            x.strip()
            for x in str(
                r.get(
                    "bigvul_lines_before",
                    "",
                )
            ).splitlines()
            if x.strip()
        }

        if not want or lk is None:

            bv_nums.append("")
            bv_hit.append(0)
            bv_nlines.append(0)
            bv_text.append("")

            continue

        try:

            al = align(
                r["func_before"],
                r["func_after"],
                lk,
                drop_comments=False,
            )

        except Exception:

            bv_nums.append("")
            bv_hit.append(0)
            bv_nlines.append(0)
            bv_text.append("")

            continue

        bview = al.before_view.splitlines()

        nums = [
            i
            for i, line in enumerate(
                bview,
                1,
            )
            if line.strip() in want
        ]

        bv_nums.append(
            to_str(nums)
        )

        bv_hit.append(
            len(nums)
        )

        bv_nlines.append(
            al.n_lines
        )

        bv_text.append(
            "\n".join(
                line_texts(
                    al.before_view,
                    nums,
                )
            )
        )

    out["bigvul_vul_lines"] = bv_nums
    out["n_bigvul_vul_lines"] = bv_hit

    # ========================================================
    # HỢP HAI NGUỒN
    # ========================================================

    use_bv = (
        out["has_bigvul_lines"]
        &
        (out["n_bigvul_vul_lines"] > 0)
    )

    out["line_label_source"] = ""

    out.loc[
        use_bv,
        "line_label_source"
    ] = "bigvul"

    out.loc[
        ~use_bv & out["derived_ok"],
        "line_label_source"
    ] = "derived"

    out["vul_lines_final"] = ""

    out.loc[
        use_bv,
        "vul_lines_final"
    ] = out.loc[
        use_bv,
        "bigvul_vul_lines"
    ]

    sel = ~use_bv & out["derived_ok"]

    out.loc[
        sel,
        "vul_lines_final"
    ] = out.loc[
        sel,
        "vul_lines"
    ]

    out["n_vul_lines_final"] = (
        out["vul_lines_final"]
        .apply(
            lambda s: (
                len(s.split(";"))
                if s
                else 0
            )
        )
    )

    out["has_line_label"] = (
        out["line_label_source"] != ""
    )

    # ========================================================
    # HỆ TOẠ ĐỘ DÒNG (để audit / tái lập)
    #
    #   raw         : align(drop_comments=False) - nhãn BigVul
    #   no_comments : align(drop_comments=True)  - pipeline suy
    #
    # Muốn dựng lại before_view của một dòng thì phải gọi
    # align() đúng chế độ ghi ở cột này.
    # ========================================================

    out["line_coord_space"] = ""

    out.loc[
        use_bv,
        "line_coord_space"
    ] = "raw"

    out.loc[
        sel,
        "line_coord_space"
    ] = "no_comments"

    # ========================================================
    # BẢN NHÃN BỎ DÒNG CHỮ KÝ HÀM
    #
    # vul_lines_final : chuẩn LineVD, KHÔNG đổi
    # vul_lines_nosig : bỏ dòng chữ ký khi nó CHỈ đến từ depadd
    #
    # Dòng chữ ký nằm trong `removed` thì GIỮ - patch sửa chữ ký
    # thật (thêm/bớt tham số) là lỗi thật.
    #
    # Dòng nhãn BigVul giữ nguyên hoàn toàn: nhãn của bộ gốc.
    # ========================================================

    nosig = []
    n_nosig = []
    n_sig_dropped = []

    for _, r in out.iterrows():

        final = str(
            r["vul_lines_final"]
        )

        if (
            not final
            or r["line_label_source"] != "derived"
        ):

            nosig.append(final)
            n_nosig.append(
                int(r["n_vul_lines_final"])
            )
            n_sig_dropped.append(0)

            continue

        lk = resolve(
            r["language"]
        )

        try:

            al = align(
                r["func_before"],
                r["func_after"],
                lk,
            )

        except Exception:

            nosig.append(final)
            n_nosig.append(
                int(r["n_vul_lines_final"])
            )
            n_sig_dropped.append(0)

            continue

        sig = signature_lines(
            al.before_view.splitlines()
        )

        rem = {
            int(x)
            for x in str(
                r["removed_lines"]
            ).split(";")
            if x.strip().isdigit()
        }

        keep = [
            int(x)
            for x in final.split(";")
            if x.strip().isdigit()
            and (
                int(x) not in sig
                or int(x) in rem
            )
        ]

        nosig.append(
            to_str(keep)
        )

        n_nosig.append(
            len(keep)
        )

        n_sig_dropped.append(
            int(r["n_vul_lines_final"])
            - len(keep)
        )

    out["vul_lines_nosig"] = nosig
    out["n_vul_lines_nosig"] = n_nosig
    out["n_sig_lines_dropped"] = n_sig_dropped

    # ========================================================
    # ĐÁNH SỐ LẠI THEO func_before
    #
    # LỖI ĐÃ SỬA: mọi cột *_lines cho tới đây đánh số trên
    # UNION VIEW của align() - view này chứa cả dòng của bản
    # after (giữ chỗ, bị comment). func_before trong file thì
    # KHÔNG có những dòng đó, nên từ dòng added đầu tiên trở đi
    # số bị trôi. Đo được: 77,9% mẫu có >=1 dòng nhãn lệch.
    #
    # al.before_real là vị trí (trong union) của các dòng thuộc
    # func_before, theo đúng thứ tự -> vị trí thứ k trong đó
    # chính là dòng k của func_before. Đã kiểm trên 4.000 mẫu:
    # số dòng khớp và text khớp 100%, ánh xạ kín, 0 dòng nhãn
    # nào rơi ra ngoài.
    #
    # Cột *_fb đánh số trên func_before  <- DÙNG CÁI NÀY
    # cột *_fa đánh số trên func_after
    # cột cũ giữ nguyên để tái lập được với line_coord_space.
    # ========================================================

    fb_cols = {
        # MẶC ĐỊNH đã bỏ dòng chữ ký hàm. Bản chuẩn LineVD
        # (giữ chữ ký) ở cột vul_lines_linevd_fb để đối chiếu.
        "vul_lines_fb": [],
        "vul_lines_linevd_fb": [],
        "removed_lines_fb": [],
        "depadd_lines_fb": [],
        "added_lines_fa": [],
    }

    for _, r in out.iterrows():

        lk = resolve(
            r["language"]
        )

        # nhãn BigVul dùng view RAW, nhãn pipeline dùng view đã
        # xoá comment -> phải align đúng chế độ của từng dòng
        raw = (
            r["line_coord_space"] == "raw"
        )

        al = None

        if lk is not None:

            try:

                al = align(
                    r["func_before"],
                    r["func_after"],
                    lk,
                    drop_comments=not raw,
                )

            except Exception:
                al = None

        if al is None:

            for k in fb_cols:
                fb_cols[k].append("")

            continue

        b_map = {
            u: i
            for i, u in enumerate(
                sorted(al.before_real),
                1,
            )
        }

        a_map = {
            u: i
            for i, u in enumerate(
                sorted(al.after_real),
                1,
            )
        }

        def remap(value, m):

            return to_str(
                [
                    m[n]
                    for n in (
                        int(x)
                        for x in str(value).split(";")
                        if x.strip().isdigit()
                    )
                    if n in m
                ]
            )

        # ĐỔI CHỖ có chủ ý: nhãn chính là bản ĐÃ BỎ dòng chữ ký.
        #
        # Node METHOD của Joern mang lineNumber dòng chữ ký và là
        # def của mọi tham số nên 85,5% mẫu dính. Nhãn gốc BigVul
        # đánh 0,00%, nhãn gốc SVEN 0,92%. Giữ nó trong nhãn chính
        # là sai - đó không phải dòng lỗi.
        fb_cols["vul_lines_fb"].append(
            remap(r["vul_lines_nosig"], b_map)
        )

        fb_cols["vul_lines_linevd_fb"].append(
            remap(r["vul_lines_final"], b_map)
        )

        fb_cols["removed_lines_fb"].append(
            remap(r["removed_lines"], b_map)
        )

        fb_cols["depadd_lines_fb"].append(
            remap(r["depadd_lines"], b_map)
        )

        fb_cols["added_lines_fa"].append(
            remap(r["added_lines"], a_map)
        )

    for k, v in fb_cols.items():
        out[k] = v

    out["n_vul_lines_fb"] = (
        out["vul_lines_fb"]
        .apply(
            lambda x: (
                len(x.split(";"))
                if x
                else 0
            )
        )
    )

    # ========================================================
    # ĐỘ ĐẦY ĐỦ CỦA NHÃN
    #
    #   bigvul       : nhãn của bộ gốc, giữ nguyên
    #   full         : removed + depadd (đủ theo LineVD)
    #   removed_only : PDG không dùng được -> chỉ có removed,
    #                  nhãn ĐÚNG nhưng THIẾU -> recall thấp
    # ========================================================

    out["label_completeness"] = ""

    out.loc[
        use_bv,
        "label_completeness"
    ] = "bigvul"

    out.loc[
        sel,
        "label_completeness"
    ] = "full"

    out.loc[
        sel
        &
        out["line_status"].isin(
            REMOVED_ONLY
        ),
        "label_completeness"
    ] = "removed_only"

    # Dòng BigVul không đi qua label_sample nên hai cột audit
    # này còn rỗng -> điền từ chính lần align raw ở trên.
    out.loc[
        use_bv,
        "n_union_lines"
    ] = pd.Series(
        bv_nlines,
        index=out.index,
    )[use_bv]

    out.loc[
        use_bv,
        "vul_lines_text"
    ] = pd.Series(
        bv_text,
        index=out.index,
    )[use_bv]

    report = build_report(
        out
    )

    print(report)

    OUT_REPORT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUT_REPORT.write_text(
        report,
        encoding="utf-8",
    )

    # ========================================================
    # GHI
    # ========================================================

    out = out.drop(
        columns=[
            c
            for c in ["_key", "_jkey"]
            if c in out.columns
        ]
    )

    out.to_parquet(
        OUT_PARQUET,
        index=False,
    )

    audit_cols = [
        c
        for c in [
            "file_name",
            "language",
            "cve_id",
            "cwe_label_final",
            "commit_sha",
            "line_status",
            "line_confidence",
            "line_lang",
            "suspected_language",
            "n_union_lines",
            "n_removed",
            "n_added",
            "n_depadd",
            "n_vul_lines",
            "n_cdg_edges",
            "n_ddg_edges",
            "n_control_structs",
            "vul_lines",
            "removed_lines",
            "added_lines",
            "depadd_lines",
            "vul_lines_text",
            "line_note",
            "line_label_source",
            "line_coord_space",
            "label_completeness",
            "vul_lines_final",
            "n_vul_lines_final",
            "vul_lines_nosig",
            "n_vul_lines_nosig",
            "n_sig_lines_dropped",
            "vul_lines_fb",
            "n_vul_lines_fb",
            "vul_lines_linevd_fb",
            "removed_lines_fb",
            "depadd_lines_fb",
            "added_lines_fa",
            "bigvul_vul_lines",
            "has_line_label",
            "derived_ok",
            "has_bigvul_lines",
            "bigvul_line_count",
        ]
        if c in out.columns
    ]

    out[audit_cols].to_csv(
        OUT_AUDIT,
        index=True,
    )

    out.loc[
        ~out["has_line_label"],
        audit_cols
    ].to_csv(
        OUT_FAIL,
        index=True,
    )

    print(
        "\n"
        + "=" * 78
    )

    print("OUTPUT")
    print("=" * 78)

    for p, n in [
        (
            OUT_PARQUET,
            len(out),
        ),
        (
            OUT_AUDIT,
            len(out),
        ),
        (
            OUT_FAIL,
            int((~out["has_line_label"]).sum()),
        ),
        (
            OUT_REPORT,
            0,
        ),
        (
            CACHE_FILE,
            len(table),
        ),
    ]:

        print(
            f"  {p.name:<44s} "
            f"{n:>7,} dòng"
            if n
            else f"  {p.name:<44s}"
        )

    print("\nDONE")


def build_report(out):

    L = []

    def w(s=""):
        L.append(s)

    n = len(out)

    usable = int(
        out["has_line_label"].sum()
    )

    w("\n" + "=" * 78)
    w("COVERAGE")
    w("=" * 78)

    n = len(out)

    n_bv = int(
        out["has_bigvul_lines"].sum()
    )

    n_target = n - n_bv

    from_bv = int(
        (out["line_label_source"] == "bigvul").sum()
    )

    from_dv = int(
        (out["line_label_source"] == "derived").sum()
    )

    usable = from_bv + from_dv

    w(
        f"Tổng mẫu                    : {n:,}"
    )

    w(
        f"  đã có nhãn BigVul         : {n_bv:,}"
        f"   -> dùng nhãn BigVul"
    )

    w(
        f"  cần pipeline suy nhãn     : {n_target:,}"
    )

    w("")

    w(
        f"Nhãn từ BigVul              : {from_bv:,}"
        f"  ({from_bv / max(n_bv, 1) * 100:.1f}% của {n_bv:,})"
    )

    w(
        f"Nhãn do pipeline suy ra     : {from_dv:,}"
        f"  ({from_dv / max(n_target, 1) * 100:.1f}% của {n_target:,})"
        f"   <- PHẦN MỚI"
    )

    w(
        f"TỔNG có nhãn dòng           : {usable:,}"
        f"/{n:,} ({usable / n * 100:.2f}%)"
    )

    w(
        f"Không nguồn nào             : {n - usable:,}"
    )

    sub = out[
        out["line_label_source"] == "derived"
    ]

    if len(sub):

        tot_vul = int(
            sub["n_vul_lines"].sum()
        )

        tot_lines = int(
            sub["n_union_lines"].sum()
        )

        w("")

        w(
            f"--- riêng phần pipeline suy ra "
            f"({len(sub):,} mẫu) ---"
        )

        if tot_lines:

            w(
                f"Tỉ lệ dòng lỗi/tổng dòng: "
                f"{tot_vul:,}/{tot_lines:,} = "
                f"{tot_vul / tot_lines * 100:.2f}%"
            )

        w(
            f"Dòng lỗi mỗi hàm: "
            f"trung vị {sub['n_vul_lines'].median():.0f}"
            f"  trung bình {sub['n_vul_lines'].mean():.1f}"
            f"  max {int(sub['n_vul_lines'].max())}"
        )

        w(
            f"  từ removed: "
            f"{int(sub['n_removed'].sum()):,}"
            f"  |  từ depadd: "
            f"{int(sub['n_depadd'].sum()):,}"
        )

    w("\n" + "=" * 78)
    w("STATUS")
    w("=" * 78)

    tgt = out[
        out["line_status"] != "skipped_has_bigvul"
    ]

    w(
        f"(chỉ tính {len(tgt):,} mẫu mà pipeline "
        f"thực sự xử lý)"
    )

    w("")

    n = max(len(tgt), 1)

    vc = tgt["line_status"].value_counts(
        dropna=False
    )

    for k, v in vc.items():

        flag = (
            "dùng được"
            if k in USABLE
            else "BỎ"
        )

        w(
            f"  {str(k):<24s} {v:>7,}  "
            f"({v / n * 100:5.2f}%)  {flag}"
        )

    w("\n" + "=" * 78)
    w("THEO NGÔN NGỮ")
    w("=" * 78)

    w(
        f"  {'ngôn ngữ':<14s}{'tổng':>7s}"
        f"{'dùng được':>11s}{'%':>7s}"
        f"{'dòng lỗi TB':>13s}{'cdg':>8s}{'ddg':>8s}"
    )

    w("  " + "-" * 68)

    g = tgt.groupby(
        "language",
        dropna=False,
    )

    rows = []

    for lang, part in g:

        ok = part[
            part["derived_ok"]
        ]

        rows.append(
            (
                len(part),
                str(lang),
                len(ok),
                (
                    ok["n_vul_lines"].mean()
                    if len(ok)
                    else 0
                ),
                (
                    ok["n_cdg_edges"].mean()
                    if len(ok)
                    else 0
                ),
                (
                    ok["n_ddg_edges"].mean()
                    if len(ok)
                    else 0
                ),
            )
        )

    for (
        tot,
        lang,
        ok,
        avg,
        cdg,
        ddg,
    ) in sorted(
        rows,
        reverse=True,
    ):

        w(
            f"  {lang:<14s}{tot:>7,}{ok:>11,}"
            f"{ok / tot * 100:>6.1f}%"
            f"{avg:>13.1f}{cdg:>8.1f}{ddg:>8.1f}"
        )

    w("\n" + "=" * 78)
    w("LÝ DO KHÔNG DÙNG ĐƯỢC, THEO NGÔN NGỮ")
    w("=" * 78)

    bad = tgt[~tgt["derived_ok"]]

    if len(bad):

        pivot = (
            bad.groupby(
                ["language", "line_status"]
            )
            .size()
            .unstack(
                fill_value=0
            )
        )

        w(
            pivot.to_string()
        )

    # ========================================================
    # ĐỐI CHIẾU BIGVUL
    # ========================================================

    if "bigvul_lines_before" in out.columns:

        w("\n" + "=" * 78)
        w("ĐỐI CHIẾU VỚI lines_before CỦA BIGVUL")
        w("=" * 78)

        w(
            "So tập TEXT dòng (đã strip, bỏ dòng rỗng) giữa"
        )
        w(
            "`removed` của pipeline này và `lines_before` của BigVul."
        )
        w("")

        # Chỉ so được khi pipeline THỰC SỰ suy nhãn cho dòng
        # đó. Ở chế độ mặc định các dòng có BigVul bị bỏ qua
        # nên phần này rỗng - chạy --all để có số đối chiếu.
        cmp_rows = out[
            out["has_bigvul_lines"]
            &
            out["derived_ok"]
            &
            out["removed_lines"].notna()
        ]

        exact = 0
        subset = 0
        overlap = 0
        disjoint = 0

        for _, r in cmp_rows.iterrows():

            bv = {
                x.strip()
                for x in str(
                    r["bigvul_lines_before"]
                ).splitlines()
                if x.strip()
            }

            mine_nums = [
                int(x)
                for x in str(
                    r["removed_lines"]
                ).split(";")
                if x
            ]

            al = align(
                r["func_before"],
                r["func_after"],
                resolve(r["language"])
                or "c",
            )

            bview = al.before_view.splitlines()

            mine = {
                bview[i - 1].strip()
                for i in mine_nums
                if 1 <= i <= len(bview)
                and bview[i - 1].strip()
            }

            if not bv or not mine:
                continue

            if mine == bv:
                exact += 1
            elif mine <= bv or bv <= mine:
                subset += 1
            elif mine & bv:
                overlap += 1
            else:
                disjoint += 1

        total = (
            exact + subset + overlap + disjoint
        )

        if total:

            w(
                f"  so được          : {total:,} mẫu"
            )

            w(
                f"  trùng khít       : {exact:,} "
                f"({exact / total * 100:.1f}%)"
            )

            w(
                f"  một bên là tập con: {subset:,} "
                f"({subset / total * 100:.1f}%)"
            )

            w(
                f"  giao nhau        : {overlap:,} "
                f"({overlap / total * 100:.1f}%)"
            )

            w(
                f"  rời nhau         : {disjoint:,} "
                f"({disjoint / total * 100:.1f}%)"
            )

            agree = exact + subset + overlap

            w(
                f"\n  => có giao nhau  : {agree:,}/{total:,} "
                f"= {agree / total * 100:.1f}%"
            )

        else:

            w(
                "  không có mẫu nào so được ở chế độ này "
                "(dòng có nhãn BigVul đã bị bỏ qua). "
                "Chạy --all để đối chiếu hai phương pháp."
            )

    w("\n" + "=" * 78)
    w("GIỚI HẠN ĐÃ BIẾT")
    w("=" * 78)

    for line in [
        "- reaching-def là XẤP XỈ theo cấu trúc cây, không có CFG",
        "  thật. Không mô hình hoá: goto, longjmp, exception nhảy xa,",
        "  con trỏ/alias, hàm sửa tham số qua tham chiếu.",
        "- CDG lấy predicate của cấu trúc bao quanh gần nhất, tương",
        "  đương post-dominance với code có cấu trúc, KHÔNG tương",
        "  đương khi có goto / switch fallthrough phức tạp.",
        "- depadd là láng giềng 1-hop VÔ HƯỚNG, giống LineVD, không",
        "  phải bao đóng bắc cầu.",
        "- diff đổi > 60% số dòng bị loại (diff_too_large) vì không",
        "  còn định vị được ở mức dòng.",
        "- mẫu parse lỗi chỉ giữ `removed` (không cần parse) và bị",
        "  hạ confidence; depadd bị bỏ.",
    ]:
        w(line)

    return "\n".join(L)


if __name__ == "__main__":
    main()
