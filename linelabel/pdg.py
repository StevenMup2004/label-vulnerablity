"""
Dựng PDG ở mức DÒNG từ cây tree-sitter.

PDG = CDG (control dependency) hợp DDG (data dependency), giống
LineVD: sastvd/helpers/joern.py::rdg lọc đúng
`REACHING_DEF | CDG`, rồi ivdetect/helpers.py nhân đôi edge theo
hai chiều (`pd.concat([edgesline, edgesline_reverse])`), tức PDG
được dùng như đồ thị VÔ HƯỚNG.

Khác biệt so với LineVD, nói rõ để không nhận vơ:

  LineVD dùng Joern -> CPG đầy đủ, reaching-def tính trên CFG thật,
  chỉ cho C/C++.

  Ở đây dùng tree-sitter -> chỉ có cây cú pháp, không có CFG. Vì vậy
  reaching-def được xấp xỉ bằng duyệt cấu trúc: đi tuần tự trong
  từng block, rẽ nhánh thì fork rồi hợp lại, vòng lặp thì duyệt
  thân hai lượt để bắt def theo back-edge.

  Xấp xỉ này KHÔNG mô hình hoá: goto, longjmp, exception nhảy xa,
  con trỏ/alias, gọi hàm làm thay đổi tham số. Những mẫu đó bị
  đánh dấu ở reliability chứ không lặng lẽ gán nhãn.
"""

from collections import defaultdict

from tree_sitter_language_pack import get_parser

from .specs import SPECS


MAX_LOOP_PASSES = 2


# ============================================================
# SCAFFOLD
#
# Nhiều mẫu trong TitanVul chỉ là THÂN method, tách khỏi class
# nên không parse độc lập được (vd JS "foo(a, b) {" ở mức
# top-level). Bọc thêm một dòng để cứu.
#
# Prefix luôn đúng MỘT dòng -> offset = 1, trừ lại khi ghi
# số dòng vào graph.
# ============================================================

SCAFFOLDS = {
    # PHP: snippet thường THIẾU '<?php' -> tree-sitter parse
    # thành 'text' (chế độ HTML): không báo lỗi nhưng cũng
    # không có node code nào. Phải thêm tag trước.
    "php": [
        ("<?php", ""),
        ("<?php class __W {", "}"),
    ],
    "javascript": [
        ("class __W {", "}"),
        ("function __w() {", "}"),
    ],
    "typescript": [
        ("class __W {", "}"),
        ("function __w() {", "}"),
    ],
    "java": [("class __W {", "}")],
    "csharp": [("class __W {", "}")],
    "scala": [("class __W {", "}")],
    "kotlin": [("class __W {", "}")],
    "ruby": [("class W", "end")],
    "cpp": [("struct __W {", "};")],
    "objc": [("@implementation __W", "@end")],
    "swift": [("class __W {", "}")],
}


class LineGraph:
    """
    PDG mức dòng: edge vô hướng, kèm loại (cdg/ddg).

    offset: khi phải bọc code vào scaffold để parse được
    (snippet chỉ có thân method), số dòng bị dịch. Trừ ngay ở
    đây để mọi số dòng ra ngoài đều thuộc hệ toạ độ gốc.
    """

    def __init__(
        self,
        offset=0,
    ):

        self.offset = offset

        self.neighbors = defaultdict(set)

        self.cdg = defaultdict(set)
        self.ddg = defaultdict(set)

        self.lines = set()

        self.n_cdg = 0
        self.n_ddg = 0

    def add(
        self,
        a,
        b,
        kind,
    ):

        if a is not None:
            a -= self.offset

        if b is not None:
            b -= self.offset

        if (
            a is None
            or
            b is None
            or
            a == b
            or
            a < 1
            or
            b < 1
        ):
            return

        self.lines.add(a)
        self.lines.add(b)

        bucket = (
            self.cdg
            if kind == "cdg"
            else self.ddg
        )

        if b not in bucket[a]:

            if kind == "cdg":
                self.n_cdg += 1
            else:
                self.n_ddg += 1

        # vô hướng
        bucket[a].add(b)
        bucket[b].add(a)

        self.neighbors[a].add(b)
        self.neighbors[b].add(a)

    def touch(
        self,
        line,
    ):
        """Ghi nhận dòng có mặt trong graph dù chưa có edge."""

        if line is not None:

            line -= self.offset

            if line >= 1:
                self.lines.add(line)

    def neighbors_of(
        self,
        seeds,
    ):

        result = set()

        for s in seeds:

            result |= self.neighbors.get(
                s,
                set(),
            )

        return result


# ============================================================
# TIỆN ÍCH CÂY
# ============================================================

def _line(node):
    """Dòng 1-indexed nơi node bắt đầu."""

    return node.start_point[0] + 1


def _text(
    node,
    src,
):

    return src[
        node.start_byte:node.end_byte
    ].decode(
        "utf-8",
        "replace",
    )


def _has_error(node):

    return (
        node.has_error
        if hasattr(node, "has_error")
        else False
    )


class Analyzer:
    """
    Adapter cho một ngôn ngữ. Toàn bộ hiểu biết về ngôn ngữ nằm
    trong spec; logic dựng graph dùng chung.
    """

    def __init__(
        self,
        lang_key,
    ):

        self.lang = lang_key
        self.spec = SPECS[lang_key]
        self.parser = get_parser(
            lang_key
        )

        self.ctrl = self.spec["control"]

        self.assign = set(
            self.spec["assign"]
        )

        self.declare = set(
            self.spec["declare"]
        )

        self.param = set(
            self.spec["param"]
        )

        self.incdec = set(
            self.spec["incdec"]
        )

        self.ident = set(
            self.spec["ident"]
        )

        self.comment = set(
            self.spec["comment"]
        )

        self.string = set(
            self.spec["string"]
        )

    # --------------------------------------------------------

    def parse(
        self,
        code,
    ):

        src = code.encode(
            "utf-8",
            "replace",
        )

        return (
            self.parser.parse(src),
            src,
        )

    def parse_tolerant(
        self,
        code,
    ):
        """
        -> (tree, src, offset)

        Hai lý do phải bọc scaffold:

        1. snippet chỉ là thân method -> lỗi cú pháp ở top-level
        2. PHP thiếu '<?php' -> parse thành 'text', KHÔNG lỗi
           nhưng cũng không có node code nào

        Nên tiêu chí chọn là (ít lỗi, nhiều node code), không
        chỉ dựa vào has_error.
        """

        def score(
            t,
        ):
            """
            (không có node code, số lỗi, -số node code)

            Tiêu chí ĐẦU TIÊN là "có node code hay không".
            Bản PHP ở chế độ text có 0 lỗi nhưng 0 node code -
            nếu xếp theo số lỗi trước thì nó luôn thắng bản
            thêm '<?php' (có lỗi nhưng hiểu được code). Đó là
            bug đã gặp thật trên 148 mẫu PHP.
            """

            nc = self.count_code_nodes(
                t.root_node
            )

            return (
                0 if nc > 0 else 1,
                self.count_errors(
                    t.root_node
                ),
                -nc,
            )

        candidates = []

        tree, src = self.parse(
            code
        )

        candidates.append(
            score(tree) + (0, tree, src)
        )

        if candidates[0][:2] == (0, 0):

            # có node code và sạch lỗi -> dùng luôn
            return (
                tree,
                src,
                0,
            )

        for prefix, suffix in SCAFFOLDS.get(
            self.lang,
            [],
        ):

            wrapped = prefix + "\n" + code

            if suffix:
                wrapped += "\n" + suffix

            tw, sw = self.parse(
                wrapped
            )

            candidates.append(
                score(tw) + (1, tw, sw)
            )

        candidates.sort(
            key=lambda x: x[:3]
        )

        (
            _,
            _,
            _,
            off,
            tree,
            src,
        ) = candidates[0]

        return (
            tree,
            src,
            off,
        )

    def count_code_nodes(
        self,
        root,
    ):
        """
        Số node "mang nghĩa code". Bằng 0 nghĩa là parser không
        thực sự hiểu đoạn này (vd PHP ở chế độ text).
        """

        interesting = (
            self.assign
            | self.declare
            | self.param
            | set(self.ctrl.keys())
            | set(self.spec["func"])
        )

        n = 0
        stack = [root]

        while stack:

            x = stack.pop()

            if x.type in interesting:
                n += 1

            stack.extend(
                x.children
            )

        return n

    @staticmethod
    def count_errors(root):

        n = 0
        stack = [root]

        while stack:

            x = stack.pop()

            if x.type == "ERROR" or x.is_missing:
                n += 1
                continue

            stack.extend(
                x.children
            )

        return n

    @staticmethod
    def error_lines(
        root,
        offset=0,
    ):
        """Dòng bị ERROR/MISSING, trong hệ toạ độ gốc."""

        out = set()
        stack = [root]

        while stack:

            x = stack.pop()

            if x.type == "ERROR" or x.is_missing:

                for ln in range(
                    x.start_point[0] + 1,
                    x.end_point[0] + 2,
                ):

                    ln -= offset

                    if ln >= 1:
                        out.add(ln)

                continue

            stack.extend(
                x.children
            )

        return out

    # --------------------------------------------------------

    def comment_lines(
        self,
        root,
        src,
    ):
        """Dòng là comment -> loại khỏi graph, giống LineVD."""

        out = set()

        stack = [root]

        while stack:

            n = stack.pop()

            if n.type in self.comment:

                for ln in range(
                    n.start_point[0] + 1,
                    n.end_point[0] + 2,
                ):
                    out.add(ln)

                continue

            stack.extend(
                n.children
            )

        return out

    # --------------------------------------------------------

    def idents(
        self,
        node,
        src,
        skip_strings=True,
    ):
        """Danh định xuất hiện trong node -> {(tên, dòng)}."""

        out = set()

        stack = [node]

        while stack:

            n = stack.pop()

            if n.type in self.comment:
                continue

            if (
                skip_strings
                and
                n.type in self.string
            ):
                continue

            if n.type in self.ident:

                out.add(
                    (
                        _text(n, src),
                        _line(n),
                    )
                )

                continue

            stack.extend(
                n.children
            )

        return out

    # --------------------------------------------------------

    def defs_of(
        self,
        node,
        src,
    ):
        """
        Biến được ĐỊNH NGHĨA bởi node này (nếu có), kèm dòng.

        Chỉ lấy danh định ở phía trái phép gán / tên declarator,
        không lấy toàn bộ biểu thức.
        """

        out = set()

        t = node.type

        if t in self.assign:

            left = node.child_by_field_name(
                "left"
            )

            if left is None:

                left = node.child_by_field_name(
                    "name"
                )

            if left is None and node.children:
                left = node.children[0]

            if left is not None:

                out |= self.idents(
                    left,
                    src,
                )

        elif t in self.declare:

            name = node.child_by_field_name(
                "declarator"
            )

            if name is None:

                name = node.child_by_field_name(
                    "name"
                )

            if name is None:

                name = node.child_by_field_name(
                    "pattern"
                )

            if name is not None:

                out |= self.idents(
                    name,
                    src,
                )

            else:

                # declaration bọc nhiều declarator
                for c in node.children:

                    if c.type in self.declare:

                        out |= self.defs_of(
                            c,
                            src,
                        )

        elif t in self.param:

            name = node.child_by_field_name(
                "declarator"
            )

            if name is None:

                name = node.child_by_field_name(
                    "name"
                )

            if name is not None:

                out |= self.idents(
                    name,
                    src,
                )

            else:

                ids = sorted(
                    self.idents(
                        node,
                        src,
                    )
                )

                if ids:
                    out.add(ids[-1])

        elif t in self.incdec:

            arg = node.child_by_field_name(
                "argument"
            )

            if arg is not None:

                out |= self.idents(
                    arg,
                    src,
                )

        return out

    # ========================================================
    # CONTROL DEPENDENCY
    # ========================================================

    def _predicate_lines(
        self,
        node,
        spec_cond,
    ):
        """Dòng chứa predicate của một cấu trúc điều khiển."""

        if spec_cond:

            cond = node.child_by_field_name(
                spec_cond
            )

            if cond is not None:

                return set(
                    range(
                        cond.start_point[0] + 1,
                        cond.end_point[0] + 2,
                    )
                )

        # fallback: dòng mở đầu của cấu trúc
        return {_line(node)}

    def _body_nodes(
        self,
        node,
        spec_body,
    ):
        """Node thân của cấu trúc điều khiển."""

        if spec_body:

            body = node.child_by_field_name(
                spec_body
            )

            if body is not None:
                return [body]

        # fallback: mọi con trừ phần predicate ở dòng đầu
        head = _line(node)

        return [
            c
            for c in node.children
            if c.end_point[0] + 1 > head
        ]

    def build_cdg(
        self,
        root,
        src,
        graph,
        skip_lines,
    ):
        """
        Một dòng phụ thuộc điều khiển vào predicate của cấu trúc
        điều khiển bao quanh GẦN NHẤT.

        Đây là xấp xỉ của CDG dựa trên post-dominance mà Joern
        dùng. Với code có cấu trúc, hai cách trùng nhau. Với
        goto / fallthrough phức tạp thì không - đã ghi ở docstring.
        """

        found = 0

        def visit(
            node,
            enclosing,
        ):

            nonlocal found

            if node.type in self.comment:
                return

            ln = _line(node)

            if (
                enclosing
                and
                ln not in skip_lines
            ):

                for p in enclosing:

                    if p not in skip_lines:

                        graph.add(
                            p,
                            ln,
                            "cdg",
                        )

            spec = self.ctrl.get(
                node.type
            )

            if spec is None:

                for c in node.children:

                    visit(
                        c,
                        enclosing,
                    )

                return

            found += 1

            spec_cond, spec_body = spec

            preds = self._predicate_lines(
                node,
                spec_cond,
            )

            preds = {
                p
                for p in preds
                if p not in skip_lines
            }

            bodies = self._body_nodes(
                node,
                spec_body,
            )

            # dùng node.id, KHÔNG dùng id() của Python
            body_ids = {
                b.id
                for b in bodies
            }

            for c in node.children:

                if c.id in body_ids:

                    visit(
                        c,
                        preds or enclosing,
                    )

                else:

                    visit(
                        c,
                        enclosing,
                    )

        visit(
            root,
            set(),
        )

        return found

    # ========================================================
    # DATA DEPENDENCY (reaching-def xấp xỉ theo cấu trúc)
    # ========================================================

    def build_ddg(
        self,
        root,
        src,
        graph,
        skip_lines,
    ):
        """
        Duyệt theo cấu trúc, giữ map biến -> {dòng định nghĩa}.

        - tuần tự : def sau ghi đè def trước
        - rẽ nhánh: fork map cho từng nhánh rồi HỢP lại
        - vòng lặp: duyệt thân MAX_LOOP_PASSES lượt để bắt back-edge

        Mỗi lần một dòng ĐỌC biến v, nối dòng đó với mọi dòng
        đang định nghĩa v (edge ddg).
        """

        n_edges = [0]

        def merge(maps):

            out = defaultdict(set)

            for m in maps:

                for k, v in m.items():
                    out[k] |= v

            return out

        def handle_stmt(
            node,
            env,
        ):
            """Xử lý một node lá-ish: nối use->def rồi cập nhật def."""

            defs = self.defs_of(
                node,
                src,
            )

            def_names = {
                name
                for name, _ in defs
            }

            # USE: mọi ident trong node, trừ ident chỉ là tên bị gán
            uses = self.idents(
                node,
                src,
            )

            for name, ln in uses:

                if ln in skip_lines:
                    continue

                # ident nằm đúng vị trí def thuần thì không tính use
                if (
                    (name, ln) in defs
                    and
                    node.type in self.declare
                ):
                    continue

                for dl in env.get(
                    name,
                    set(),
                ):

                    if dl in skip_lines:
                        continue

                    graph.add(
                        dl,
                        ln,
                        "ddg",
                    )

                    n_edges[0] += 1

            for name, ln in defs:

                if ln in skip_lines:
                    continue

                env[name] = {ln}

            for name in def_names:
                graph.touch(
                    _line(node)
                )

        def walk(
            node,
            env,
        ):
            """Duyệt có cấu trúc; env bị sửa tại chỗ."""

            if node.type in self.comment:
                return

            spec = self.ctrl.get(
                node.type
            )

            # ------------------------------------------------
            # cấu trúc điều khiển: xử lý predicate rồi các nhánh
            # ------------------------------------------------

            if spec is not None:

                spec_cond, spec_body = spec

                cond = (
                    node.child_by_field_name(
                        spec_cond
                    )
                    if spec_cond
                    else None
                )

                if cond is not None:

                    handle_stmt(
                        cond,
                        env,
                    )

                bodies = self._body_nodes(
                    node,
                    spec_body,
                )

                # dùng node.id, KHÔNG dùng id() của Python:
                # binding tree-sitter tạo object mới mỗi lần
                # truy cập .children nên id() không bao giờ khớp.
                body_ids = {
                    b.id
                    for b in bodies
                }

                # phần không thuộc thân (init/update của for, ...)
                for c in node.children:

                    if c.id not in body_ids and (
                        cond is None or c.id != cond.id
                    ):

                        if self.ctrl.get(
                            c.type
                        ) is None:

                            handle_stmt(
                                c,
                                env,
                            )

                        else:

                            walk(
                                c,
                                env,
                            )

                is_loop = any(
                    k in node.type
                    for k in (
                        "while",
                        "for",
                        "loop",
                        "do_statement",
                        "until",
                    )
                )

                passes = (
                    MAX_LOOP_PASSES
                    if is_loop
                    else 1
                )

                branch_envs = []

                for _ in range(
                    passes
                ):

                    for b in bodies:

                        sub = defaultdict(
                            set
                        )

                        sub.update(
                            {
                                k: set(v)
                                for k, v in env.items()
                            }
                        )

                        walk(
                            b,
                            sub,
                        )

                        branch_envs.append(
                            sub
                        )

                    if is_loop and branch_envs:

                        env.update(
                            merge(
                                [env]
                                + branch_envs
                            )
                        )

                if branch_envs:

                    merged = merge(
                        [env]
                        + branch_envs
                    )

                    env.clear()
                    env.update(merged)

                return

            # ------------------------------------------------
            # node thường
            # ------------------------------------------------

            interesting = (
                node.type in self.assign
                or
                node.type in self.declare
                or
                node.type in self.param
                or
                node.type in self.incdec
            )

            if interesting or not node.children:

                handle_stmt(
                    node,
                    env,
                )

                # vẫn đi sâu để bắt def lồng bên trong
                for c in node.children:

                    if (
                        self.ctrl.get(
                            c.type
                        )
                        is not None
                    ):

                        walk(
                            c,
                            env,
                        )

                return

            for c in node.children:

                walk(
                    c,
                    env,
                )

        env = defaultdict(set)

        walk(
            root,
            env,
        )

        return n_edges[0]
