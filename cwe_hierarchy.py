"""
Tìm TỔ TIÊN CAO NHẤT của mỗi CWE trong cây MITRE CWE-1000
(Research Concepts), rồi đối chiếu với bảng gộp thủ công.

Vì sao cần: dataset có 241 CWE khác nhau, đuôi rất dài (188 CWE
dưới 50 mẫu). Gộp theo cây MITRE cho một cách nhóm KHÁCH QUAN,
tái lập được, không phụ thuộc ý kiến của tôi.

Cây dùng: quan hệ ChildOf trong View-1000. Leo lên tới khi gặp
node không còn cha -> đó là Pillar.

Ba trường hợp phải xử lý riêng:
  - Category (CWE-119 kiểu cũ, 264, 399...) không nằm trong
    View-1000, dùng MemberOf thay ChildOf
  - CWE có NHIỀU cha (đa thừa kế) -> giữ tất cả đường, chọn
    pillar theo độ sâu ngắn nhất, ghi lại phần còn lại
  - CWE deprecated/không có trong catalog -> báo rõ

Chạy:
    python cwe_hierarchy.py                 # bảng pillar
    python cwe_hierarchy.py --file data/output/ext80.parquet
"""

import argparse
import re
import xml.etree.ElementTree as ET
import zipfile

from collections import defaultdict, deque
from pathlib import Path

import pandas as pd

from cwe_groups import GROUPS, group_of, is_precise


ROOT = Path(__file__).resolve().parent

CATALOG = ROOT / "cache" / "cwec_latest.xml.zip"

VIEW_RESEARCH = "1000"


def load_catalog():
    """
    -> (parents, names, kind)

    parents[id] = set id cha (ChildOf trong View-1000, hoặc
                  MemberOf nếu là Category)
    names[id]   = tên
    kind[id]    = 'weakness' | 'category' | 'view'
    """

    z = zipfile.ZipFile(CATALOG)

    xml = z.read(
        z.namelist()[0]
    )

    root = ET.fromstring(xml)

    ns = re.match(
        r"\{(.*)\}",
        root.tag,
    ).group(1)

    def tag(name):
        return f"{{{ns}}}{name}"

    parents = defaultdict(set)
    names = {}
    kind = {}
    abstraction = {}

    # ---- Weakness: dùng ChildOf, chỉ trong View-1000 ----
    for w in root.find(tag("Weaknesses")):

        wid = w.get("ID")

        names[wid] = w.get("Name")
        kind[wid] = "weakness"
        abstraction[wid] = w.get("Abstraction")

        rel = w.find(tag("Related_Weaknesses"))

        if rel is None:
            continue

        for r in rel:

            if r.get("Nature") != "ChildOf":
                continue

            # View_ID vắng mặt = áp dụng cho mọi view
            vid = r.get("View_ID")

            if vid not in (None, VIEW_RESEARCH):
                continue

            parents[wid].add(
                r.get("CWE_ID")
            )

    # ---- Category: không có ChildOf, dùng MemberOf ----
    for c in root.find(tag("Categories")):

        cid = c.get("ID")

        names[cid] = c.get("Name")
        kind[cid] = "category"

        rel = c.find(tag("Relationships"))

        if rel is None:
            continue

        for r in rel:

            if r.get("Nature") != "MemberOf":
                continue

            parents[cid].add(
                r.get("CWE_ID")
            )

    return parents, names, kind, abstraction


def top_ancestors(cid, parents, names, kind):
    """
    Leo lên tới các node không còn cha.

    -> (list pillar id theo độ sâu tăng dần, độ sâu, có đa cha
        hay không)
    """

    if cid not in parents and cid not in names:
        return [], -1, False

    seen = {cid}
    tops = []
    multi = False
    depth = {cid: 0}

    q = deque([cid])

    while q:

        cur = q.popleft()

        ps = {
            p
            for p in parents.get(cur, ())
            # bỏ cha là View/Category rỗng không có tên
            if p in names
        }

        if len(ps) > 1:
            multi = True

        if not ps:

            if cur != cid or cid in names:
                tops.append((depth[cur], cur))

            continue

        for p in ps:

            if p in seen:
                continue

            seen.add(p)
            depth[p] = depth[cur] + 1

            q.append(p)

    tops.sort()

    return (
        [t[1] for t in tops],
        (tops[0][0] if tops else -1),
        multi,
    )


def main():

    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--file",
        default="data/output/ext80.parquet",
    )

    ap.add_argument(
        "--top",
        type=int,
        default=0,
        help="chỉ in N CWE nhiều mẫu nhất",
    )

    args = ap.parse_args()

    parents, names, kind, abstraction = load_catalog()

    print(
        f"catalog: {len(names):,} node "
        f"({sum(1 for k in kind.values() if k == 'weakness'):,} "
        f"weakness, "
        f"{sum(1 for k in kind.values() if k == 'category'):,} "
        f"category)"
    )

    df = pd.read_parquet(
        args.file,
        columns=[
            "cwe_label_final",
            "has_line_label",
        ],
    )

    vc = (
        df[df["has_line_label"]]
        ["cwe_label_final"]
        .value_counts()
    )

    rows = []

    for label, n in vc.items():

        cid = str(label).replace("CWE-", "")

        tops, depth, multi = top_ancestors(
            cid,
            parents,
            names,
            kind,
        )

        rows.append(
            {
                "cwe": str(label),
                "n": int(n),
                "name": names.get(cid, "?"),
                "abstraction": abstraction.get(
                    cid,
                    kind.get(cid, "KHÔNG CÓ TRONG CATALOG"),
                ),
                "pillar": (
                    f"CWE-{tops[0]}"
                    if tops
                    else ""
                ),
                "pillar_name": (
                    names.get(tops[0], "")
                    if tops
                    else ""
                ),
                "depth": depth,
                "multi_parent": multi,
                "all_tops": ";".join(
                    f"CWE-{t}"
                    for t in tops
                ),
            }
        )

    t = pd.DataFrame(rows)

    out = ROOT / "data" / "audit" / "cwe_hierarchy.csv"

    out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    t.to_csv(
        out,
        index=False,
    )

    # ---------- báo cáo ----------
    print(
        f"\nCWE trong dataset: {len(t)} "
        f"| {int(t['n'].sum()):,} mẫu"
    )

    miss = t[t["pillar"] == ""]

    if len(miss):

        print(
            f"\nKHÔNG leo được lên pillar: "
            f"{len(miss)} CWE, {int(miss['n'].sum()):,} mẫu"
        )

        for _, r in miss.head(10).iterrows():

            print(
                f"   {r['cwe']:<12} {r['n']:>5,}  "
                f"{r['abstraction']}"
            )

    g = (
        t[t["pillar"] != ""]
        .groupby(["pillar", "pillar_name"])
        .agg(
            mau=("n", "sum"),
            so_cwe=("cwe", "count"),
        )
        .reset_index()
        .sort_values(
            "mau",
            ascending=False,
        )
    )

    tot = int(t["n"].sum())

    print(
        "\n"
        + "=" * 92
    )

    print("PILLAR (tổ tiên cao nhất trong CWE-1000)")
    print("=" * 92)

    print(
        f"  {'pillar':<11}{'mẫu':>8}{'%':>7}"
        f"{'#CWE':>7}  tên"
    )

    print("  " + "-" * 88)

    for _, r in g.iterrows():

        print(
            f"  {r['pillar']:<11}{r['mau']:>8,}"
            f"{r['mau'] / tot * 100:>6.1f}%"
            f"{r['so_cwe']:>7}  {r['pillar_name'][:52]}"
        )

    mp = t[t["multi_parent"]]

    print(
        f"\nCWE đa thừa kế (nhiều cha): {len(mp)}, "
        f"{int(mp['n'].sum()):,} mẫu "
        f"({mp['n'].sum() / tot * 100:.1f}%)"
    )

    print(
        f"  -> pillar chọn theo đường NGẮN NHẤT; "
        f"đường khác ở cột all_tops"
    )

    for _, r in mp.sort_values(
        "n",
        ascending=False,
    ).head(6).iterrows():

        print(
            f"   {r['cwe']:<11}{r['n']:>6,}  "
            f"{r['all_tops']}"
        )

    # ========================================================
    # ĐỐI CHIẾU: cây MITRE vs bảng gộp thủ công
    # ========================================================

    t["group"] = t["cwe"].map(group_of)
    t["precise"] = t["cwe"].map(is_precise)

    print(
        "\n"
        + "=" * 92
    )

    print("BẢNG GỘP THỦ CÔNG (cwe_groups.py)")
    print("=" * 92)

    print(
        f"  {'nhóm':<19}{'mẫu':>8}{'%':>7}"
        f"{'#CWE':>7}{'cụ thể':>9}{'category':>10}"
        f"  pillar MITRE chiếm đa số"
    )

    print("  " + "-" * 88)

    for g in GROUPS:

        sub = t[t["group"] == g]

        if not len(sub):
            continue

        n = int(sub["n"].sum())

        prec = int(
            sub[sub["precise"]]["n"].sum()
        )

        # pillar MITRE nào chiếm nhiều mẫu nhất trong nhóm này
        pv = (
            sub[sub["pillar"] != ""]
            .groupby(["pillar", "pillar_name"])
            ["n"]
            .sum()
            .sort_values(
                ascending=False,
            )
        )

        if len(pv):

            (pid, pname), pn = (
                pv.index[0],
                pv.iloc[0],
            )

            dom = (
                f"{pid} {pname[:30]} "
                f"({pn / n * 100:.0f}%)"
            )

        else:
            dom = "-"

        print(
            f"  {g:<19}{n:>8,}{n / tot * 100:>6.1f}%"
            f"{len(sub):>7}{prec:>9,}{n - prec:>10,}  {dom}"
        )

    # CWE nhiều mẫu nhất trong từng nhóm
    print(
        "\n"
        + "=" * 92
    )

    print("CWE ĐẠI DIỆN (nhiều mẫu nhất) TRONG TỪNG NHÓM")
    print("=" * 92)

    for g in GROUPS:

        sub = t[t["group"] == g].sort_values(
            "n",
            ascending=False,
        )

        if not len(sub):
            continue

        top3 = "  |  ".join(
            f"{r['cwe']} {r['n']:,} "
            f"({r['name'][:26]})"
            for _, r in sub.head(3).iterrows()
        )

        print(
            f"  {g:<19}{top3}"
        )

    t.to_csv(
        out,
        index=False,
    )

    print(
        f"\nĐÃ GHI: {out}"
    )

    if args.top:

        print(
            "\n"
            + t.head(args.top).to_string(
                index=False,
                max_colwidth=38,
            )
        )


if __name__ == "__main__":
    main()
