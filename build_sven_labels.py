"""
Nhãn định vị mức dòng cho SVEN (eth-sri/sven), cùng phương pháp
đã dùng cho TitanVul.

SVEN đã cho sẵn `line_changes.deleted` / `.added` - đó chính là
phần `removed` và `added` của công thức LineVD. Việc còn thiếu là
`depadd`: các dòng trong bản before phụ thuộc control/data vào
những dòng được THÊM ở bản fixed.

    vulnerable = removed  UNION  depadd

Khác TitanVul ở hai chỗ:
  1. removed lấy THẲNG từ SVEN thay vì tự diff -> đối chiếu được
     removed tự suy với removed của họ (giống cách đã làm với BigVul)
  2. SVEN không có nhãn CWE rời rạc, `vul_type` đã là CWE

Chạy:
    python build_sven_labels.py
    python build_sven_labels.py --max-changed-ratio 0.80 --min-changed-lines 10
"""

import argparse
import glob
import json
import os
import sys

from collections import Counter
from pathlib import Path

import pandas as pd

from linelabel import label_sample
from linelabel.diffalign import align, signature_lines
from linelabel.pdg import LineGraph
from linelabel.specs import resolve


ROOT = Path(__file__).resolve().parent

SVEN_DIR = ROOT / "data" / "sven"

OUT_DIR = ROOT / "data" / "output"

AUDIT_DIR = ROOT / "data" / "audit"


# đuôi file -> ngôn ngữ
EXT_LANG = {
    ".py": "Python",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".C": "C++",
    ".cxx": "C++",
}


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
    "joern_ok",
    "joern_add_only",
    "joern_delete_only",
    # removed-only: PDG không dùng được nhưng removed vẫn đúng
    # (đúng hành vi LineVD, xem build_line_labels.py::REMOVED_ONLY)
    "no_pdg_signal",
    "parse_error_at_anchor",
}


REMOVED_ONLY = {
    "no_pdg_signal",
    "parse_error_at_anchor",
}


JOERN_CACHE = ROOT / "cache" / "sven_joern_graphs.parquet"


def sample_key(before, after, language):
    """Khoá tra PDG Joern - phải khớp build_joern_graphs.py."""

    import hashlib

    h = hashlib.sha1()

    for part in (before, after, language):
        h.update(str(part).encode("utf-8", "replace"))
        h.update(b"\x00")

    return h.hexdigest()


def load_joern():
    """-> dict key -> (LineGraph, set dòng)"""

    if not JOERN_CACHE.exists():

        print(
            "  (không có cache Joern -> dùng tree-sitter)"
        )

        return {}

    t = pd.read_parquet(JOERN_CACHE)

    out = {}

    for r in t.itertuples(index=False):

        g = LineGraph(
            offset=int(getattr(r, "offset", 0) or 0)
        )

        for ln in json.loads(r.lines):
            g.touch(int(ln))

        for a, b in json.loads(r.cdg):
            g.add(int(a), int(b), "cdg")

        for a, b in json.loads(r.rd):
            g.add(int(a), int(b), "ddg")

        out[r.key] = (g, set(g.lines))

    print(
        f"  PDG Joern: {len(out):,} mẫu  "
        + "  ".join(
            f"{k}:{v}"
            for k, v in t["lang"].value_counts().items()
        )
    )

    return out


def to_str(nums):

    return ";".join(
        str(n)
        for n in nums
    )


def load_sven():
    """Đọc data_train_val -> DataFrame."""

    rows = []

    for f in sorted(
        glob.glob(str(SVEN_DIR / "*" / "*.jsonl"))
    ):

        split = Path(f).parent.name

        for line in open(
            f,
            encoding="utf-8",
        ):

            d = json.loads(line)

            ext = os.path.splitext(
                d.get("file_name", "")
            )[1]

            lc = d.get("line_changes", {})

            rows.append(
                {
                    "split": split,
                    "func_name": d.get("func_name", ""),
                    "func_before": d["func_src_before"],
                    "func_after": d["func_src_after"],
                    "language": EXT_LANG.get(ext, ""),
                    "extension": ext,
                    "cwe_label_final": (
                        "CWE-"
                        + d["vul_type"]
                        .replace("cwe-", "")
                        .lstrip("0")
                    ),
                    "vul_type": d["vul_type"],
                    "file_name": d.get("file_name", ""),
                    "commit_link": d.get("commit_link", ""),
                    # nhãn gốc của SVEN, toạ độ func_src_before
                    "sven_deleted": to_str(
                        sorted(
                            x["line_no"]
                            for x in lc.get("deleted", [])
                        )
                    ),
                    "sven_added": to_str(
                        sorted(
                            x["line_no"]
                            for x in lc.get("added", [])
                        )
                    ),
                    "sven_deleted_text": "\n".join(
                        x["line"].strip()
                        for x in lc.get("deleted", [])
                    ),
                }
            )

    df = pd.DataFrame(rows)

    # project từ commit_link: github.com/OWNER/REPO/commit/...
    def proj(u):

        parts = str(u).split("/")

        return (
            "/".join(parts[1:3])
            if len(parts) > 2
            else ""
        )

    df["project_key"] = df["commit_link"].map(proj)

    return df


def main():

    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--max-changed-ratio",
        type=float,
        default=0.80,
    )

    ap.add_argument(
        "--min-changed-lines",
        type=int,
        default=10,
    )

    ap.add_argument(
        "--tag",
        default="sven",
    )

    args = ap.parse_args()

    print("=" * 74)
    print("NHÃN ĐỊNH VỊ MỨC DÒNG - SVEN")
    print("=" * 74)

    df = load_sven()

    print(
        f"đọc {len(df):,} mẫu  "
        f"| train {int((df['split'] == 'train').sum()):,}"
        f"  val {int((df['split'] == 'val').sum()):,}"
    )

    print(
        "ngôn ngữ: "
        + "  ".join(
            f"{k}:{v}"
            for k, v in df["language"]
            .value_counts()
            .items()
        )
    )

    # ========================================================
    # SUY NHÃN
    # ========================================================

    joern = load_joern()

    out = []

    for r in df.itertuples(index=False):

        jg = joern.get(
            sample_key(
                r.func_before,
                r.func_after,
                r.language,
            )
        )

        res = label_sample(
            r.func_before,
            r.func_after,
            r.language,
            keep_views=True,
            max_changed_ratio=args.max_changed_ratio,
            min_changed_lines=args.min_changed_lines,
            joern_graph=jg[0] if jg else None,
            joern_before_lines=jg[1] if jg else None,
        )

        out.append(res)

    df["backend"] = [
        "joern"
        if x.status.startswith("joern")
        else "tree-sitter"
        for x in out
    ]

    df["line_status"] = [x.status for x in out]
    df["line_confidence"] = [x.confidence for x in out]
    df["line_note"] = [x.note for x in out]
    df["line_lang"] = [x.lang_key or "" for x in out]

    df["n_union_lines"] = [x.n_lines for x in out]
    df["n_cdg_edges"] = [x.n_cdg for x in out]
    df["n_ddg_edges"] = [x.n_ddg for x in out]

    # ========================================================
    # ĐỔI VỀ TOẠ ĐỘ func_before
    #
    # label_sample trả số dòng trong UNION VIEW (có cả dòng của
    # bản after giữ chỗ). Người dùng cần số dòng trên chính
    # func_before -> quy đổi qua al.before_real.
    # ========================================================

    vul_fb = []
    rem_fb = []
    dep_fb = []
    add_fa = []

    for r, res in zip(
        df.itertuples(index=False),
        out,
    ):

        lk = resolve(r.language)

        if lk is None:

            vul_fb.append("")
            rem_fb.append("")
            dep_fb.append("")
            add_fa.append("")

            continue

        try:
            al = align(
                r.func_before,
                r.func_after,
                lk,
            )

        except Exception:

            vul_fb.append("")
            rem_fb.append("")
            dep_fb.append("")
            add_fa.append("")

            continue

        bmap = {
            u: i
            for i, u in enumerate(
                sorted(al.before_real),
                1,
            )
        }

        amap = {
            u: i
            for i, u in enumerate(
                sorted(al.after_real),
                1,
            )
        }

        def rm(ns, m):

            return to_str(
                [
                    m[n]
                    for n in ns
                    if n in m
                ]
            )

        vul_fb.append(rm(res.vul_lines, bmap))
        rem_fb.append(rm(res.removed, bmap))
        dep_fb.append(rm(res.depadd, bmap))
        add_fa.append(rm(res.added, amap))

    df["vul_lines_fb"] = vul_fb
    df["removed_lines_fb"] = rem_fb
    df["depadd_lines_fb"] = dep_fb
    df["added_lines_fa"] = add_fa

    for c in [
        "vul_lines_fb",
        "removed_lines_fb",
        "depadd_lines_fb",
    ]:
        df["n_" + c] = df[c].map(
            lambda s: len(s.split(";")) if s else 0
        )

    df["derived_ok"] = (
        df["line_status"].isin(USABLE)
        &
        (df["n_vul_lines_fb"] > 0)
    )

    df["label_completeness"] = ""

    df.loc[
        df["derived_ok"],
        "label_completeness"
    ] = "full"

    df.loc[
        df["derived_ok"]
        & df["line_status"].isin(REMOVED_ONLY),
        "label_completeness"
    ] = "removed_only"

    # ========================================================
    # HỢP VỚI NHÃN GỐC CỦA SVEN
    #
    # SVEN cho sẵn `deleted` (toạ độ func_before) - dùng làm
    # removed thay cho bản tự suy, rồi hợp với depadd.
    # ========================================================

    def merge(row):

        sv = {
            int(x)
            for x in str(row["sven_deleted"]).split(";")
            if x.strip().isdigit()
        }

        dep = {
            int(x)
            for x in str(row["depadd_lines_fb"]).split(";")
            if x.strip().isdigit()
        }

        return to_str(sorted(sv | dep))

    df["vul_lines_linevd"] = df.apply(
        merge,
        axis=1,
    )

    # ========================================================
    # BỎ DÒNG CHỮ KÝ HÀM
    #
    # Node METHOD / METHOD_PARAMETER_IN của Joern mang lineNumber
    # của dòng chữ ký và là def của MỌI tham số, nên gần như mọi
    # dòng `added` dùng tham số đều 1-hop tới nó. Đo trên SVEN:
    # 79,2% mẫu dính, 677 dòng (7,3%) chỉ đến từ depadd.
    #
    # Nhãn GỐC của SVEN đánh chữ ký 16/1743 = 0,92%, và cả 16 ca
    # đó là patch sửa thật danh sách tham số. Nên chữ ký nằm
    # trong `deleted` thì GIỮ, chỉ bỏ khi nó CHỈ đến từ depadd.
    #
    # LineVD gốc không bỏ (helpers/joern.py chỉ lọc COMMENT và
    # FILE) - đây là lệch CÓ CHỦ Ý. Bản chuẩn LineVD giữ ở cột
    # vul_lines_linevd để đối chiếu.
    # ========================================================

    drop_sig = []

    for r in df.itertuples(index=False):

        v = [
            int(x)
            for x in str(r.vul_lines_linevd).split(";")
            if x.strip().isdigit()
        ]

        if not v:
            drop_sig.append("")
            continue

        sig = signature_lines(
            r.func_before.splitlines()
        )

        rem = {
            int(x)
            for x in str(r.sven_deleted).split(";")
            if x.strip().isdigit()
        }

        drop_sig.append(
            to_str(
                [
                    n
                    for n in v
                    if n not in sig or n in rem
                ]
            )
        )

    df["vul_lines_final"] = drop_sig

    df["n_sig_lines_dropped"] = [
        len([x for x in str(a).split(";") if x])
        - len([x for x in str(b).split(";") if x])
        for a, b in zip(
            df["vul_lines_linevd"],
            df["vul_lines_final"],
        )
    ]

    df["n_vul_lines_final"] = df["vul_lines_final"].map(
        lambda s: len(s.split(";")) if s else 0
    )

    df["has_line_label"] = df["n_vul_lines_final"] > 0

    print(
        f"\nsuy nhãn được : "
        f"{int(df['derived_ok'].sum()):,}/{len(df):,}"
        f" ({df['derived_ok'].mean() * 100:.1f}%)"
    )

    print(
        f"có nhãn cuối  : "
        f"{int(df['has_line_label'].sum()):,}"
        f" ({df['has_line_label'].mean() * 100:.1f}%)"
    )

    print("\nstatus:")

    for k, v in (
        df["line_status"]
        .value_counts()
        .items()
    ):
        flag = (
            "dùng được"
            if k in USABLE
            else "BỎ"
        )

        print(
            f"  {k:<24}{v:>5}  "
            f"({v / len(df) * 100:5.1f}%)  {flag}"
        )

    # ========================================================
    # ĐỐI CHIẾU removed TỰ SUY vs deleted CỦA SVEN
    # ========================================================

    tp = fp = fn = 0
    exact = 0
    n_cmp = 0

    for r in df.itertuples(index=False):

        if not r.derived_ok:
            continue

        sv = {
            int(x)
            for x in str(r.sven_deleted).split(";")
            if x.strip().isdigit()
        }

        mine = {
            int(x)
            for x in str(r.removed_lines_fb).split(";")
            if x.strip().isdigit()
        }

        if not sv and not mine:
            continue

        n_cmp += 1

        tp += len(sv & mine)
        fp += len(mine - sv)
        fn += len(sv - mine)

        if sv == mine:
            exact += 1

    P = tp / max(tp + fp, 1)
    R = tp / max(tp + fn, 1)

    print(
        "\n"
        + "=" * 74
    )

    print("ĐỐI CHIẾU: removed tự suy  vs  deleted của SVEN")
    print("=" * 74)

    print(
        f"  so được          : {n_cmp:,} mẫu"
    )

    print(
        f"  trùng khít       : {exact:,}"
        f" ({exact / max(n_cmp, 1) * 100:.1f}%)"
    )

    print(
        f"  precision        : {P:.3f}"
        f"   recall: {R:.3f}"
        f"   F1: {2 * P * R / max(P + R, 1e-9):.3f}"
    )

    # ========================================================
    # THỐNG KÊ NHÃN
    # ========================================================

    lab = df[df["has_line_label"]]

    n_sv = sum(
        len([x for x in str(s).split(";") if x])
        for s in lab["sven_deleted"]
    )

    n_dep = int(lab["n_depadd_lines_fb"].sum())

    print(
        "\n"
        + "=" * 74
    )

    print("NHÃN CUỐI")
    print("=" * 74)

    print(
        f"  tổng dòng nhãn   : "
        f"{int(lab['n_vul_lines_final'].sum()):,}"
    )

    print(
        f"    từ removed (SVEN): {n_sv:,}"
    )

    print(
        f"    từ depadd        : {n_dep:,}"
    )

    print(
        f"  tỉ lệ dòng lỗi   : "
        f"{lab['n_vul_lines_final'].sum() / lab['n_union_lines'].sum() * 100:.2f}%"
    )

    print(
        f"  dòng lỗi/hàm     : "
        f"trung vị {lab['n_vul_lines_final'].median():.0f}"
        f"  trung bình {lab['n_vul_lines_final'].mean():.1f}"
    )

    print("\ntheo CWE:")

    for k, s in lab.groupby("cwe_label_final"):
        print(
            f"  {k:<10}{len(s):>5} mẫu"
            f"  {s['n_vul_lines_final'].sum():>6} dòng"
            f"  trung vị {s['n_vul_lines_final'].median():.0f}"
        )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    p = OUT_DIR / f"{args.tag}.parquet"

    df.to_parquet(p, index=False)

    print(f"\nĐÃ GHI: {p}  ({len(df):,} dòng)")


if __name__ == "__main__":
    main()
