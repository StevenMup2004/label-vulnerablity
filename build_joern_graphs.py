"""
Dựng PDG bằng Joern cho toàn bộ TitanVul, chạy theo lô, có cache.

Joern là backend CHÍNH. tree-sitter chỉ dùng cho mẫu Joern không
xử lý được (ngôn ngữ không có frontend, hoặc Joern thất bại).

Vì sao phải theo lô: khởi động JVM + dựng CPG mất ~20-40s, nên
gọi từng hàm là không khả thi. Mỗi lô ghi N hàm ra một thư mục,
dựng một CPG, dump một lần.

Mỗi lô CHỈ MỘT NGÔN NGỮ: importCode của Joern chọn frontend theo
nội dung thư mục, trộn ngôn ngữ sẽ chọn sai.

Ra: cache/joern_graphs.parquet
    key | lines | cdg | rd     (cdg/rd là JSON list các cặp dòng)

Chạy:
    python build_joern_graphs.py --batch 300 --langs c,cpp
    python build_joern_graphs.py            # tất cả ngôn ngữ
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from collections import defaultdict
from pathlib import Path

import pandas as pd

from linelabel.diffalign import align
from linelabel.joernpdg import EXT
from linelabel.specs import resolve


ROOT = Path(
    __file__
).resolve().parent

DATA_OUT = ROOT / "data" / "output"

CACHE = ROOT / "cache"

JOERN_CACHE = (
    CACHE / "joern_graphs.parquet"
)

SCRIPT = (
    ROOT
    / "linelabel"
    / "joern"
    / "dump_pdg.sc"
)


# ============================================================
# SCAFFOLD CHO JOERN
#
# Nhiều mẫu TitanVul là METHOD TRƠ, tách khỏi class. Frontend
# javasrc2cpg / csharpsrc2cpg / kotlin2cpg đòi compilation unit
# đầy đủ nên thất bại. Đo được: Java 7/113 khi để trơ, chạy
# đúng khi bọc "class __W { ... }".
#
# Prefix luôn ĐÚNG MỘT DÒNG -> offset = 1, trừ lại khi dùng.
# ============================================================

JOERN_SCAFFOLD = {
    "java": [("class __W {", "}")],
    "csharp": [("class __W {", "}")],
    "kotlin": [("class __W {", "}")],
    "javascript": [
        ("var __o = {", "};"),
        ("class __W {", "}"),
    ],
    "typescript": [
        ("var __o = {", "};"),
        ("class __W {", "}"),
    ],
    "swift": [("class __W {", "}")],
    "ruby": [("class W", "end")],
    "cpp": [("struct __W {", "};")],
    "c": [("void __w(void) {", "}")],

    # php2cpg: không có <?php thì cả file bị coi là HTML thuần
    # -> CPG rỗng, không method nào.
    "php": [("<?php", "")],

    # gosrc2cpg: cần compilation unit có package.
    "go": [("package main", "")],
}


INPUT_CANDIDATES = [
    DATA_OUT / "TitanVul_line_labels_bigvul.parquet",
    DATA_OUT / "TitanVul_cwe_labels_trainable.parquet",
]


def find_tools():
    """
    Tìm joern-cli và JDK. Ưu tiên biến môi trường, sau đó dò
    trong scratchpad.
    """

    joern = os.environ.get(
        "JOERN_HOME"
    )

    java = os.environ.get(
        "JAVA_HOME"
    )

    if not joern:

        hits = sorted(
            Path("/tmp").glob(
                "claude-*/**/tools/joern-cli"
            )
        )

        if hits:
            joern = str(hits[-1])

    if not java:

        hits = sorted(
            Path("/tmp").glob(
                "claude-*/**/tools/jdk-21*"
            )
        )

        if hits:
            java = str(hits[-1])

    return joern, java


def sample_key(
    before,
    after,
    language,
):

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


def run_batch(
    items,
    lang_key,
    joern_home,
    java_home,
    timeout,
    wrap=None,
):
    """
    items: list (key, after_view)
    wrap : (prefix, suffix) hoặc None

    -> dict key -> {"lines":[...], "cdg":[[a,b]], "rd":[[a,b]],
                    "offset": int}
    """

    ext = EXT.get(
        lang_key
    )

    if ext is None:
        return {}

    tmp = Path(
        tempfile.mkdtemp(
            prefix="joern_",
        )
    )

    src = tmp / "src"
    src.mkdir()

    name_of = {}

    offset = 0

    if wrap is not None:

        prefix, suffix = wrap
        offset = 1

    for i, (key, code) in enumerate(
        items
    ):

        if wrap is not None:

            code = prefix + "\n" + code

            if suffix:
                code = code + "\n" + suffix

        fname = f"s{i:06d}{ext}"

        (src / fname).write_text(
            code,
            encoding="utf-8",
            errors="replace",
        )

        name_of[fname] = key

    out = tmp / "g.jsonl"

    env = dict(os.environ)

    if java_home:

        env["JAVA_HOME"] = java_home

        env["PATH"] = (
            f"{java_home}/bin:"
            + env.get("PATH", "")
        )

    env["JAVA_OPTS"] = env.get(
        "JAVA_OPTS",
        "-Xmx8g",
    )

    cmd = [
        str(Path(joern_home) / "joern"),
        "--script",
        str(SCRIPT),
        "--param",
        f"inputPath={src}",
        "--param",
        f"outFile={out}",
    ]

    result = {}

    try:

        # cwd = tmp để workspace/ của Joern nằm trong thư mục
        # tạm, không đụng lô khác
        subprocess.run(
            cmd,
            env=env,
            cwd=str(tmp),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    except subprocess.TimeoutExpired:

        shutil.rmtree(
            tmp,
            ignore_errors=True,
        )

        return {}

    if out.exists():

        with open(
            out,
            encoding="utf-8",
        ) as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                try:
                    rec = json.loads(line)
                except Exception:
                    continue

                fname = os.path.basename(
                    rec.get("file", "")
                )

                key = name_of.get(
                    fname
                )

                if key is None:
                    continue

                result[key] = {
                    "lines": rec.get(
                        "lines",
                        [],
                    ),
                    "cdg": rec.get(
                        "cdg",
                        [],
                    ),
                    "rd": rec.get(
                        "rd",
                        [],
                    ),
                    "offset": offset,
                }

    shutil.rmtree(
        tmp,
        ignore_errors=True,
    )

    return result


def run_batch_split(
    chunk,
    lang_key,
    joern_home,
    java_home,
    timeout,
    wrap,
    min_size=30,
    depth=0,
):
    """
    Joern dựng MỘT CPG cho cả lô, nên MỘT file lỗi làm chết
    toàn lô. Đo được thật: C# lô 247 file -> 0 kết quả, nhưng
    lô 150 file -> 37/39.

    Vì vậy: lô nào trả về rỗng thì chia đôi và thử lại, tới khi
    lô đủ nhỏ. Chỉ vài file hỏng bị mất thay vì cả lô.
    """

    got = run_batch(
        chunk,
        lang_key,
        joern_home,
        java_home,
        timeout,
        wrap=wrap,
    )

    # Giới hạn độ sâu: chia đôi chỉ đáng khi MỘT file phá cả
    # lô. Nếu cả lô đều hỏng thì chia đôi chỉ đốt thời gian -
    # đo được 483s cho một lô JS 120 file mà vẫn ra 0.
    if got or len(chunk) <= min_size or depth >= 3:
        return got

    mid = len(chunk) // 2

    left = run_batch_split(
        chunk[:mid],
        lang_key,
        joern_home,
        java_home,
        timeout,
        wrap,
        min_size,
        depth + 1,
    )

    right = run_batch_split(
        chunk[mid:],
        lang_key,
        joern_home,
        java_home,
        timeout,
        wrap,
        min_size,
        depth + 1,
    )

    left.update(right)

    return left


def main():

    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--batch",
        type=int,
        default=300,
    )

    ap.add_argument(
        "--langs",
        default="",
        help="lọc ngôn ngữ, vd c,cpp",
    )

    ap.add_argument(
        "--limit",
        type=int,
        default=0,
    )

    ap.add_argument(
        "--timeout",
        type=int,
        default=1800,
    )

    ap.add_argument(
        "--relabel-only",
        action="store_true",
        help="bỏ qua các lượt theo ngôn ngữ khai báo, chạy "
             "thẳng pass dò lại ngôn ngữ trên mẫu chưa có "
             "graph trong cache",
    )

    args = ap.parse_args()

    joern_home, java_home = find_tools()

    print("=" * 78)
    print("DỰNG PDG BẰNG JOERN")
    print("=" * 78)

    print(
        f"joern : {joern_home}"
    )

    print(
        f"java  : {java_home}"
    )

    if not joern_home or not Path(
        joern_home
    ).exists():

        sys.exit(
            "Không thấy joern-cli. "
            "Đặt JOERN_HOME."
        )

    src = next(
        (
            p
            for p in INPUT_CANDIDATES
            if p.exists()
        ),
        None,
    )

    df = pd.read_parquet(
        src
    )

    if args.limit:

        df = df.head(
            args.limit
        ).copy()

    print(
        f"input : {src.name} "
        f"({len(df):,} dòng)"
    )

    # ========================================================
    # CHUẨN BỊ: căn dòng, nhóm theo ngôn ngữ
    # ========================================================

    want = (
        {
            x.strip()
            for x in args.langs.split(",")
            if x.strip()
        }
        if args.langs
        else None
    )

    by_lang = defaultdict(list)

    seen = set()

    skipped_lang = defaultdict(int)

    for _, r in df.iterrows():

        lk = resolve(
            r["language"]
        )

        if lk is None or EXT.get(lk) is None:

            skipped_lang[
                str(r["language"])
            ] += 1

            continue

        if want and lk not in want:
            continue

        key = sample_key(
            r["func_before"],
            r["func_after"],
            r["language"],
        )

        if key in seen:
            continue

        seen.add(key)

        try:

            al = align(
                r["func_before"],
                r["func_after"],
                lk,
            )

        except Exception:
            continue

        if not al.after_view.strip():
            continue

        by_lang[lk].append(
            (key, al.after_view)
        )

    print(
        "\nsố mẫu theo ngôn ngữ (Joern hỗ trợ):"
    )

    for lk, items in sorted(
        by_lang.items(),
        key=lambda kv: -len(kv[1]),
    ):

        print(
            f"  {lk:<12s} {len(items):>7,}"
        )

    if skipped_lang:

        print(
            "\nJoern KHÔNG hỗ trợ "
            "(sẽ dùng tree-sitter):"
        )

        for lang, n in sorted(
            skipped_lang.items(),
            key=lambda kv: -kv[1],
        ):

            print(
                f"  {lang:<16s} {n:>6,}"
            )

    # ========================================================
    # CACHE ĐÃ CÓ
    # ========================================================

    have = {}

    if JOERN_CACHE.exists():

        old = pd.read_parquet(
            JOERN_CACHE
        )

        have = set(old["key"])

        print(
            f"\ncache: {len(have):,} mẫu đã có"
        )

    else:
        old = None

    rows = []

    # mẫu declared-lang không xử lý được -> thử dò lại ngôn ngữ
    leftover = []

    t0 = time.time()

    for lk, items in sorted(
        by_lang.items(),
        key=lambda kv: -len(kv[1]),
    ):

        todo = [
            it
            for it in items
            if it[0] not in have
        ]

        if not todo:
            continue

        if args.relabel_only:

            leftover.extend(
                (key, code, lk)
                for key, code in todo
            )

            continue

        print(
            f"\n--- {lk}: {len(todo):,} mẫu, "
            f"lô {args.batch} ---",
            flush=True,
        )

        # lượt 0: code trơ. lượt 1+: bọc scaffold cho phần
        # còn thất bại (method trơ cần compilation unit).
        attempts = [None] + JOERN_SCAFFOLD.get(
            lk,
            [],
        )

        remaining = list(todo)

        for attempt_i, wrap in enumerate(
            attempts
        ):

            if not remaining:
                break

            if attempt_i:

                print(
                    f"  lượt {attempt_i} "
                    f"(scaffold {wrap[0]!r}): "
                    f"{len(remaining):,} mẫu còn lại",
                    flush=True,
                )

            failed = []

            for start in range(
                0,
                len(remaining),
                args.batch,
            ):

                chunk = remaining[
                    start:start + args.batch
                ]

                tb = time.time()

                got = run_batch_split(
                    chunk,
                    lk,
                    joern_home,
                    java_home,
                    args.timeout,
                    wrap,
                )

                for key, code in chunk:

                    g = got.get(key)

                    # Joern vẫn sinh method <global> rỗng cho
                    # file không parse được (php thiếu <?php,
                    # C toàn macro...). Đó KHÔNG phải thành
                    # công: 0 edge và <=2 dòng -> đẩy sang
                    # lượt scaffold.
                    if (
                        g is None
                        or not g["lines"]
                        or (
                            not g["cdg"]
                            and not g["rd"]
                            and len(g["lines"]) <= 2
                        )
                    ):

                        failed.append(
                            (key, code)
                        )

                        continue

                    rows.append(
                        {
                            "key": key,
                            "lang": lk,
                            "offset": g.get(
                                "offset",
                                0,
                            ),
                            "lines": json.dumps(
                                g["lines"]
                            ),
                            "cdg": json.dumps(
                                g["cdg"]
                            ),
                            "rd": json.dumps(
                                g["rd"]
                            ),
                        }
                    )

                print(
                    f"  {start + len(chunk):>6,}"
                    f"/{len(remaining):,}"
                    f"  ok={len(got):>4}/{len(chunk)}"
                    f"  {time.time() - tb:>6.1f}s"
                    f"  (tổng {time.time() - t0:.0f}s)",
                    flush=True,
                )

            remaining = failed

        if remaining:

            print(
                f"  -> {len(remaining):,} mẫu {lk} "
                f"Joern KHÔNG xử lý được "
                f"(sẽ dùng tree-sitter)",
                flush=True,
            )

            # Có mẫu ghi sai ngôn ngữ (đo được: 11% mẫu
            # "JavaScript" thất bại thực chất là PHP, 4% là
            # C/C++). Giữ lại để thử frontend đúng ở pass cuối.
            leftover.extend(
                (key, code, lk)
                for key, code in remaining
            )

            # lưu dần để không mất công nếu dừng giữa đường
            if rows:

                fresh = pd.DataFrame(
                    rows
                )

                out = (
                    pd.concat(
                        [old, fresh],
                        ignore_index=True,
                    )
                    if old is not None
                    else fresh
                )

                out = out.drop_duplicates(
                    subset=["key"],
                    keep="last",
                )

                CACHE.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                out.to_parquet(
                    JOERN_CACHE,
                    index=False,
                )

    # Ghi những gì còn trong bộ đệm. Trước đây chỉ ghi bên
    # trong nhánh `if remaining:` nên ngôn ngữ cuối cùng mà
    # không có mẫu thất bại sẽ bị mất trắng (đã xảy ra với
    # swift: 13/13 thành công nhưng cache không có dòng nào).
    if rows:

        fresh = pd.DataFrame(rows)

        out = (
            pd.concat(
                [old, fresh],
                ignore_index=True,
            )
            if old is not None
            else fresh
        )

        out = out.drop_duplicates(
            subset=["key"],
            keep="last",
        )

        CACHE.mkdir(
            parents=True,
            exist_ok=True,
        )

        out.to_parquet(
            JOERN_CACHE,
            index=False,
        )

        old = out

        rows = []

    # ========================================================
    # PASS CUỐI: DÒ LẠI NGÔN NGỮ
    #
    # Một số mẫu ghi sai ngôn ngữ (đo trên nhóm "JavaScript"
    # thất bại: 11% thực chất PHP, 4% C/C++). Chạy lại bằng
    # frontend của ngôn ngữ dò được, nhưng GIỮ NGUYÊN key theo
    # ngôn ngữ khai báo để build_line_labels.py tra được.
    #
    # Prefix comment của mọi ngôn ngữ ở đây đều là "//" nên
    # after_view dùng chung được, không cần align lại.
    # ========================================================

    if leftover:

        from linelabel.labels import (
            suspect_language,
        )

        regroup = defaultdict(list)

        for key, code, declared in leftover:

            try:
                guess = suspect_language(
                    code,
                    declared,
                )

            except Exception:
                guess = None

            if (
                guess
                and guess != declared
                and EXT.get(guess)
            ):
                regroup[guess].append(
                    (key, code)
                )

        if regroup:

            print(
                f"\n=== pass dò lại ngôn ngữ: "
                f"{sum(len(v) for v in regroup.values()):,}"
                f"/{len(leftover):,} mẫu có ngôn ngữ khác ==="
            )

            for lk2, items2 in sorted(
                regroup.items(),
                key=lambda kv: -len(kv[1]),
            ):

                attempts2 = [
                    None
                ] + JOERN_SCAFFOLD.get(
                    lk2,
                    [],
                )

                rem2 = list(items2)

                for wrap2 in attempts2:

                    if not rem2:
                        break

                    fail2 = []

                    for st2 in range(
                        0,
                        len(rem2),
                        args.batch,
                    ):

                        ch2 = rem2[
                            st2:st2 + args.batch
                        ]

                        got2 = run_batch_split(
                            ch2,
                            lk2,
                            joern_home,
                            java_home,
                            args.timeout,
                            wrap2,
                        )

                        for key, code in ch2:

                            g = got2.get(key)

                            if (
                                g is None
                                or not g["lines"]
                            ):
                                fail2.append(
                                    (key, code)
                                )
                                continue

                            rows.append(
                                {
                                    "key": key,
                                    "lang": lk2
                                    + "_relabeled",
                                    "offset": g.get(
                                        "offset",
                                        0,
                                    ),
                                    "lines": json.dumps(
                                        g["lines"]
                                    ),
                                    "cdg": json.dumps(
                                        g["cdg"]
                                    ),
                                    "rd": json.dumps(
                                        g["rd"]
                                    ),
                                }
                            )

                    rem2 = fail2

                print(
                    f"  {lk2:<12} "
                    f"cứu được "
                    f"{len(items2) - len(rem2):,}"
                    f"/{len(items2):,}",
                    flush=True,
                )

            if rows:

                fresh = pd.DataFrame(rows)

                out = (
                    pd.concat(
                        [old, fresh],
                        ignore_index=True,
                    )
                    if old is not None
                    else fresh
                )

                out = out.drop_duplicates(
                    subset=["key"],
                    keep="last",
                )

                out.to_parquet(
                    JOERN_CACHE,
                    index=False,
                )

    print(
        f"\nxong {time.time() - t0:.0f}s"
    )

    if JOERN_CACHE.exists():

        final = pd.read_parquet(
            JOERN_CACHE
        )

        print(
            f"cache: {len(final):,} mẫu "
            f"-> {JOERN_CACHE}"
        )

        print(
            final["lang"]
            .value_counts()
            .to_string()
        )

    print("\nDONE")


if __name__ == "__main__":
    main()
