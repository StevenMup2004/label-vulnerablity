"""
Bước cuối: ghép thành nhãn mức dòng.

Công thức LineVD (đã xác minh trong sastvd/linevd/__init__.py:107
và sastvd/ivdetect/evaluate.py::get_dep_add_lines):

    vulnerable = removed  UNION  depadd

    depadd = láng giềng VÔ HƯỚNG (trong PDG của bản after) của
             các dòng added, sau đó LỌC chỉ giữ dòng có mặt
             trong graph của bản before.

Mọi mẫu đều được gắn `status` + `confidence`. Không phân tích
được thì trả về nhãn RỖNG kèm lý do, KHÔNG đoán.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .diffalign import align, is_blank_after_strip
from .pdg import Analyzer, LineGraph
from .repair import repair, variants
from .specs import resolve


# nhiều hơn ngưỡng này thì coi như diff tái cấu trúc, không
# còn định vị được lỗi ở mức dòng
# Ngưỡng do CHÚNG TA thêm, LineVD gốc KHÔNG có. Diff đổi quá
# nhiều dòng thì hàm coi như bị viết lại, nhãn mức dòng mất
# nghĩa. Truyền qua tham số để chạy được nhiều phiên bản.
MAX_CHANGED_RATIO = 0.70

# Số dòng đổi TỐI THIỂU để coi là "viết lại hàm".
# 0 = chỉ xét tỉ lệ, đúng như LineVD (helpers/datasets.py:206
# chỉ có `dfv[dfv.mod_prop < 0.7]`).
# Đặt > 0 cho cấu hình extended: hàm 2 dòng sửa 2 dòng không
# phải viết lại hàm, chỉ là hàm nhỏ.
MIN_CHANGED_LINES = 0

MAX_LINES = 8000

# ============================================================
# CỔNG KIỂM TRA GRAPH CỦA JOERN
#
# Khi Joern không parse nổi một file, nó vẫn tạo method stub
# (<global>) nên script dump vẫn ghi ra một "graph" - nhưng
# graph đó chỉ có 1-3 dòng và 0 edge.
#
# Đo trên dữ liệu thật:
#   joern_ok        : graph phủ 65% số dòng hàm, 110 edge
#   joern_add_only  : phủ 70%, 135 edge
#   joern_no_signal : phủ  2%,   0 edge   <- stub
#   joern_empty     : phủ  3%,   0 edge   <- stub
#
# Nên: chỉ tin graph Joern khi có edge VÀ phủ đủ số dòng.
# Không đạt -> rơi về tree-sitter.
# ============================================================

MIN_JOERN_COVERAGE = 0.20


@dataclass
class LineLabel:

    status: str
    confidence: str

    vul_lines: List[int] = field(default_factory=list)
    removed: List[int] = field(default_factory=list)
    added: List[int] = field(default_factory=list)
    depadd: List[int] = field(default_factory=list)

    n_lines: int = 0
    n_cdg: int = 0
    n_ddg: int = 0
    n_control_structs: int = 0

    lang_key: Optional[str] = None
    suspected_language: str = ""
    note: str = ""

    before_view: str = ""
    after_view: str = ""


_ANALYZERS = {}


def _analyzer(lang_key):

    if lang_key not in _ANALYZERS:

        _ANALYZERS[lang_key] = Analyzer(
            lang_key
        )

    return _ANALYZERS[lang_key]


# thứ tự thử khi nghi ngôn ngữ bị gán sai
PROBE_LANGS = (
    "c",
    "cpp",
    "java",
    "javascript",
    "python",
    "php",
    "go",
    "csharp",
)


def suspect_language(
    code,
    declared_key,
):
    """
    Nếu ngôn ngữ khai báo parse tệ mà ngôn ngữ khác parse
    sạch hơn RÕ RỆT thì trả tên ngôn ngữ đó.

    Chỉ để BÁO CÁO. Không tự đổi nhãn - việc đổi là quyết
    định của người dùng dataset.
    """

    best = None
    best_score = None

    for key in PROBE_LANGS:

        try:

            an = _analyzer(key)

            tree, src, off = an.parse_tolerant(
                code
            )

        except Exception:
            continue

        score = (
            an.count_errors(
                tree.root_node
            ),
            -an.count_code_nodes(
                tree.root_node
            ),
        )

        if key == declared_key:
            declared_score = score

        if best_score is None or score < best_score:
            best_score = score
            best = key

    try:
        declared_score
    except NameError:
        return None

    if best is None or best == declared_key:
        return None

    # phải sạch lỗi hẳn và nhiều node code hơn mới dám báo
    if (
        best_score[0] == 0
        and
        declared_score[0] > 0
        and
        best_score[1] < declared_score[1]
    ):
        return best

    return None


def _repair_and_analyze(
    an,
    al,
    keep_views,
    lang_key,
):
    """
    Cứu nhóm parse_error_at_anchor bằng cách sửa cú pháp.

    Hai đường:
      A. biến thể CẤU TRÚC (cân bằng brace, scaffold object
         literal cho JS) - offset đã biết
      B. vòng sửa từng DÒNG lỗi (bỏ token macro, thêm ';',
         MACRO { -> if (1) {) - giữ nguyên số dòng

    Thành công = lỗi KHÔNG còn chạm added lines.

    -> LineLabel hoặc None
    """

    best = None

    candidates = [
        (al.after_view, 0)
    ] + variants(
        al.after_view,
        lang_key,
    )

    for text, off in candidates:

        protected = {
            u + off
            for u in al.added
        }

        fixed, rounds = repair(
            an,
            text,
            protected,
            offset=off,
        )

        try:

            tree, src = an.parse(
                fixed
            )

        except Exception:
            continue

        err = an.error_lines(
            tree.root_node,
            off,
        )

        if err & set(al.added):
            continue

        # đạt: lỗi rời khỏi anchor
        best = (
            fixed,
            off,
            tree,
            src,
            err,
            rounds,
        )

        break

    if best is None:
        return None

    (
        fixed,
        off,
        tree,
        src,
        err,
        rounds,
    ) = best

    graph = LineGraph(
        offset=off
    )

    skip = an.comment_lines(
        tree.root_node,
        src,
    )

    n_ctrl = an.build_cdg(
        tree.root_node,
        src,
        graph,
        skip,
    )

    an.build_ddg(
        tree.root_node,
        src,
        graph,
        skip,
    )

    if graph.n_cdg + graph.n_ddg == 0:
        return None

    seeds = [
        u + off
        for u in al.added
    ]

    depadd = graph.neighbors_of(
        [
            s - off
            for s in seeds
        ]
    )

    depadd -= set(al.added)

    depadd -= {
        ln - off
        for ln in skip
    }

    depadd &= set(al.before_real)

    vul = drop_blank_lines(
        sorted(
            set(al.removed) | depadd
        ),
        al.before_view,
    )

    if not vul:
        return None

    return LineLabel(
        status="ok_syntax_repair",
        confidence="medium",
        vul_lines=vul,
        removed=sorted(al.removed),
        added=sorted(al.added),
        depadd=sorted(depadd),
        n_lines=al.n_lines,
        n_cdg=graph.n_cdg,
        n_ddg=graph.n_ddg,
        n_control_structs=n_ctrl,
        lang_key=lang_key,
        note=(
            f"sửa cú pháp {rounds} vòng "
            f"(macro/fragment), lỗi còn lại "
            f"{len(err)} dòng nhưng KHÔNG chạm anchor"
        ),
        before_view=al.before_view if keep_views else "",
        after_view=al.after_view if keep_views else "",
    )


def _clean_reparse(
    an,
    al,
    keep_views,
    lang_key,
):
    """
    Cứu nhóm mà after_view (đã comment-out dòng removed) parse
    lỗi ngay tại added lines, NHƯNG func_after nguyên bản lại
    parse sạch - tức chính việc comment làm hỏng cú pháp.

    Phân tích trên bản SẠCH rồi map số dòng về hệ toạ độ hợp
    bằng al.after_real: phần tử thứ k của after_real là số dòng
    hợp ứng với dòng thứ k của func_after.

    Đo được: chỉ 8% của parse_error_at_anchor thuộc nhóm này;
    92% còn lại là code gốc cũng lỗi (macro) nên vô vọng.

    -> LineLabel hoặc None nếu không cứu được.
    """

    after_real = al.after_real

    if not after_real:
        return None

    clean = "\n".join(
        [
            line
            for i, line in enumerate(
                al.after_view.splitlines(),
                1,
            )
            if i in set(after_real)
        ]
    )

    try:

        (
            tree,
            src,
            off,
        ) = an.parse_tolerant(
            clean
        )

    except Exception:
        return None

    if tree.root_node.has_error:
        return None

    # union line -> chỉ số dòng trong bản sạch (1-based)
    to_idx = {
        u: i
        for i, u in enumerate(
            after_real,
            1,
        )
    }

    graph = LineGraph(
        offset=off
    )

    skip = an.comment_lines(
        tree.root_node,
        src,
    )

    an.build_cdg(
        tree.root_node,
        src,
        graph,
        skip,
    )

    an.build_ddg(
        tree.root_node,
        src,
        graph,
        skip,
    )

    seeds = [
        to_idx[u]
        for u in al.added
        if u in to_idx
    ]

    if not seeds:
        return None

    dep_idx = graph.neighbors_of(
        seeds
    )

    dep_idx -= set(seeds)

    # map ngược về hệ toạ độ hợp
    depadd = {
        after_real[i - 1]
        for i in dep_idx
        if 1 <= i <= len(after_real)
    }

    depadd -= set(al.added)
    depadd &= set(al.before_real)

    vul = drop_blank_lines(
        sorted(
            set(al.removed) | depadd
        ),
        al.before_view,
    )

    if not vul:
        return None

    return LineLabel(
        status="ok_clean_reparse",
        confidence="medium",
        vul_lines=vul,
        removed=sorted(al.removed),
        added=sorted(al.added),
        depadd=sorted(depadd),
        n_lines=al.n_lines,
        n_cdg=graph.n_cdg,
        n_ddg=graph.n_ddg,
        lang_key=lang_key,
        note=(
            "after_view parse lỗi tại anchor nhưng func_after "
            "nguyên bản sạch -> phân tích bản sạch rồi map số "
            "dòng qua after_real"
        ),
        before_view=al.before_view if keep_views else "",
        after_view=al.after_view if keep_views else "",
    )


def drop_blank_lines(
    numbers,
    before_view,
):
    """
    Bỏ dòng rỗng khỏi nhãn.

    Sau strip_comments, dòng chỉ có comment trở thành rỗng.
    Paper nói rõ: "Commented lines are excluded in the code
    graph, and hence are not used for training or prediction."
    """

    lines = before_view.splitlines()

    return [
        n
        for n in numbers
        if 1 <= n <= len(lines)
        and not is_blank_after_strip(
            lines[n - 1]
        )
    ]


def _fail(
    status,
    note,
    lang_key=None,
    **kw
):

    return LineLabel(
        status=status,
        confidence="none",
        lang_key=lang_key,
        note=note,
        **kw
    )


def label_sample(
    func_before,
    func_after,
    language,
    keep_views=False,
    max_changed_ratio=None,
    min_changed_lines=None,
    _retry_lang=None,
    joern_graph=None,
    joern_before_lines=None,
):
    """
    Sinh nhãn dòng cho một mẫu.

    _retry_lang: dùng nội bộ. Khi ngôn ngữ khai báo parse tệ mà
    ngôn ngữ khác parse sạch, gọi lại chính hàm này bằng ngôn
    ngữ đó thay vì trả về thất bại.

    joern_graph: LineGraph dựng sẵn bởi Joern trên after_view.
    Nếu có thì DÙNG NÓ và bỏ qua toàn bộ đường tree-sitter -
    Joern có CFG thật nên reaching-def chính xác hơn. tree-sitter
    chỉ là fallback cho mẫu Joern không xử lý được.

    joern_before_lines: tập dòng có mặt trong graph của bản
    before, cũng do Joern dựng. Thiếu thì lấy từ diff.
    """

    if max_changed_ratio is None:
        max_changed_ratio = MAX_CHANGED_RATIO

    if min_changed_lines is None:
        min_changed_lines = MIN_CHANGED_LINES

    lang_key = (
        _retry_lang
        or
        resolve(
            language
        )
    )

    if lang_key is None:

        return _fail(
            "unsupported_language",
            f"không có adapter cho {language!r}",
        )

    if not isinstance(
        func_before,
        str,
    ) or not isinstance(
        func_after,
        str,
    ):

        return _fail(
            "missing_code",
            "thiếu func_before hoặc func_after",
            lang_key,
        )

    if not func_before.strip():

        return _fail(
            "missing_code",
            "func_before rỗng",
            lang_key,
        )

    # ========================================================
    # 1. căn dòng
    # ========================================================

    al = align(
        func_before,
        func_after,
        lang_key,
    )

    if al.n_lines == 0:

        return _fail(
            "missing_code",
            "không có dòng nào",
            lang_key,
        )

    if al.n_lines > MAX_LINES:

        return _fail(
            "too_large",
            f"{al.n_lines} dòng > {MAX_LINES}",
            lang_key,
            n_lines=al.n_lines,
        )

    if not al.removed and not al.added:

        return _fail(
            "no_change",
            "func_before giống func_after",
            lang_key,
            n_lines=al.n_lines,
        )

    changed = len(
        set(al.removed) | set(al.added)
    )

    if (
        changed / al.n_lines > max_changed_ratio
        and
        changed >= min_changed_lines
    ):

        return _fail(
            "diff_too_large",
            f"{changed}/{al.n_lines} dòng đổi "
            f"(> {max_changed_ratio:.0%}, "
            f">= {min_changed_lines} dòng) - "
            f"có thể là viết lại hàm",
            lang_key,
            n_lines=al.n_lines,
            removed=sorted(al.removed),
            added=sorted(al.added),
        )

    # ========================================================
    # 1b. NẾU CÓ GRAPH TỪ JOERN -> dùng luôn, bỏ tree-sitter
    # ========================================================

    if joern_graph is not None:

        n_edges = (
            joern_graph.n_cdg
            + joern_graph.n_ddg
        )

        coverage = (
            len(joern_graph.lines)
            / max(al.n_lines, 1)
        )

        if (
            n_edges == 0
            or
            coverage < MIN_JOERN_COVERAGE
        ):

            # graph stub -> bỏ, dùng tree-sitter
            joern_graph = None

    if joern_graph is not None:

        before_lines = (
            set(joern_before_lines)
            if joern_before_lines
            else set(al.before_real)
        )

        depadd = joern_graph.neighbors_of(
            al.added
        )

        depadd -= set(al.added)
        depadd &= before_lines

        vul = drop_blank_lines(
            sorted(
                set(al.removed) | depadd
            ),
            al.before_view,
        )

        if not al.added:

            status = "joern_delete_only"
            conf = "high"

        elif not al.removed:

            status = "joern_add_only"
            conf = "high"

        else:

            status = "joern_ok"
            conf = "high"

        # Joern có graph tốt nhưng không ra dòng nào -> KHÔNG
        # trả thất bại, để rơi xuống tree-sitter thử tiếp.
        if not vul:

            joern_graph = None

    if joern_graph is not None:

        return LineLabel(
            status=status,
            confidence=conf,
            vul_lines=vul,
            removed=sorted(al.removed),
            added=sorted(al.added),
            depadd=sorted(depadd),
            n_lines=al.n_lines,
            n_cdg=joern_graph.n_cdg,
            n_ddg=joern_graph.n_ddg,
            lang_key=lang_key,
            note="PDG do Joern dựng (CFG thật)",
            before_view=al.before_view if keep_views else "",
            after_view=al.after_view if keep_views else "",
        )

    an = _analyzer(
        lang_key
    )

    # ========================================================
    # 2. PDG của bản AFTER
    #
    # parse_tolerant: nếu snippet chỉ là thân method thì bọc
    # scaffold. offset được trừ lại trong LineGraph.
    # ========================================================

    try:

        (
            tree_a,
            src_a,
            off_a,
        ) = an.parse_tolerant(
            al.after_view
        )

    except Exception as e:

        return _fail(
            "parse_crash",
            f"{type(e).__name__} khi parse after",
            lang_key,
            n_lines=al.n_lines,
        )

    err_a = (
        an.error_lines(
            tree_a.root_node,
            off_a,
        )
        if tree_a.root_node.has_error
        else set()
    )

    # Chỉ bỏ depadd khi lỗi parse CHẠM vào chính các dòng
    # added - đó là điểm neo mà depadd phụ thuộc vào. Lỗi ở
    # nơi khác (thường do macro) không làm sai dependency
    # quanh anchor. Đo trên 400 mẫu: 82% lỗi không chạm added.
    anchor_broken = bool(
        err_a & set(al.added)
    )

    if anchor_broken:

        suspect = suspect_language(
            al.after_view,
            lang_key,
        )

        salvaged = _clean_reparse(
            an,
            al,
            keep_views,
            lang_key,
        )

        if salvaged is not None:
            return salvaged

        salvaged = _repair_and_analyze(
            an,
            al,
            keep_views,
            lang_key,
        )

        if salvaged is not None:
            return salvaged

        if suspect and _retry_lang is None:

            # chạy lại bằng ngôn ngữ parse sạch hơn
            retry = label_sample(
                func_before,
                func_after,
                language,
                keep_views=keep_views,
                max_changed_ratio=max_changed_ratio,
                min_changed_lines=min_changed_lines,
                _retry_lang=suspect,
            )

            retry.suspected_language = suspect

            if retry.status.startswith("ok"):

                retry.status = (
                    retry.status
                    + "_relabeled_lang"
                )

                retry.note = (
                    f"khai báo {language!r} parse lỗi tại "
                    f"anchor; dùng {suspect!r} thì sạch "
                    f"-> phân tích bằng {suspect!r}. "
                    + retry.note
                ).strip()

                return retry

            return LineLabel(
                status="language_mismatch",
                confidence="none",
                vul_lines=[],
                removed=sorted(al.removed),
                added=sorted(al.added),
                depadd=[],
                n_lines=al.n_lines,
                lang_key=lang_key,
                suspected_language=suspect,
                note=(
                    f"nghi ngôn ngữ sai (gợi ý {suspect!r}) "
                    f"nhưng chạy lại vẫn không ra nhãn"
                ),
                before_view=al.before_view if keep_views else "",
                after_view=al.after_view if keep_views else "",
            )

        return LineLabel(
            status="parse_error_at_anchor",
            confidence="low" if al.removed else "none",
            vul_lines=sorted(al.removed),
            removed=sorted(al.removed),
            added=sorted(al.added),
            depadd=[],
            n_lines=al.n_lines,
            lang_key=lang_key,
            note="ERROR node phủ lên dòng added -> bỏ depadd, "
                 "chỉ giữ removed (removed chỉ cần diff)",
            before_view=al.before_view if keep_views else "",
            after_view=al.after_view if keep_views else "",
        )

    graph = LineGraph(
        offset=off_a
    )

    skip_a = an.comment_lines(
        tree_a.root_node,
        src_a,
    )

    skip_a = {
        ln - off_a
        for ln in skip_a
        if ln - off_a >= 1
    }

    skip_graph_a = {
        ln + off_a
        for ln in skip_a
    }

    n_ctrl = an.build_cdg(
        tree_a.root_node,
        src_a,
        graph,
        skip_graph_a,
    )

    an.build_ddg(
        tree_a.root_node,
        src_a,
        graph,
        skip_graph_a,
    )

    # ========================================================
    # 3. graph của bản BEFORE, chỉ để biết dòng nào tồn tại
    # ========================================================

    try:

        (
            tree_b,
            src_b,
            off_b,
        ) = an.parse_tolerant(
            al.before_view
        )

    except Exception:

        tree_b = None
        off_b = 0

    before_note = ""

    if tree_b is None:

        before_lines = set(
            al.before_real
        )

        before_note = (
            "parse before thất bại -> dùng tập dòng từ diff"
        )

    else:

        gb = LineGraph(
            offset=off_b
        )

        skip_b = an.comment_lines(
            tree_b.root_node,
            src_b,
        )

        an.build_cdg(
            tree_b.root_node,
            src_b,
            gb,
            skip_b,
        )

        an.build_ddg(
            tree_b.root_node,
            src_b,
            gb,
            skip_b,
        )

        before_lines = (
            gb.lines
            or set(al.before_real)
        )

        if tree_b.root_node.has_error:

            before_note = (
                "cây before có ERROR ngoài vùng anchor"
            )

    # ========================================================
    # 4. depadd
    # ========================================================

    depadd = graph.neighbors_of(
        al.added
    )

    depadd -= set(al.added)
    depadd -= skip_a

    # chỉ giữ dòng tồn tại ở bản before (LineVD làm y vậy)
    depadd &= before_lines

    vul = drop_blank_lines(
        sorted(
            set(al.removed) | depadd
        ),
        al.before_view,
    )

    # ========================================================
    # 5. tin cậy
    # ========================================================

    has_signal = (
        graph.n_cdg + graph.n_ddg
    ) > 0

    if not al.added:

        status = "ok_delete_only"
        conf = "high"
        note = "fix chỉ xoá dòng -> depadd rỗng theo định nghĩa"

    elif not has_signal:

        status = "no_pdg_signal"
        conf = "low"
        note = (
            "parse được nhưng analyzer không tìm ra "
            "edge control/data nào -> depadd không đáng tin"
        )

    elif not al.removed and not depadd:

        status = "add_only_no_dep"
        conf = "low"
        note = (
            "fix chỉ thêm dòng và không tìm được "
            "dependency -> không có dòng nào để gán"
        )

    elif not al.removed:

        status = "ok_add_only"
        conf = "medium"
        note = "fix chỉ thêm dòng -> nhãn hoàn toàn từ depadd"

    elif err_a:

        status = "ok_partial_parse"
        conf = "medium"
        note = (
            f"{len(err_a)} dòng ERROR ngoài vùng anchor "
            f"(thường do macro) -> vẫn dùng depadd"
        )

    else:

        status = "ok"
        conf = "high"
        note = ""

    if before_note:
        note = (note + " | " + before_note).strip(" |")

    return LineLabel(
        status=status,
        confidence=conf,
        vul_lines=vul,
        removed=sorted(al.removed),
        added=sorted(al.added),
        depadd=sorted(depadd),
        n_lines=al.n_lines,
        n_cdg=graph.n_cdg,
        n_ddg=graph.n_ddg,
        n_control_structs=n_ctrl,
        lang_key=lang_key,
        note=note,
        before_view=al.before_view if keep_views else "",
        after_view=al.after_view if keep_views else "",
    )
