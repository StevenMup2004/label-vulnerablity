"""
Bước 1: căn dòng giữa func_before và func_after.

Ý tưởng lấy từ LineVD (davidhin/linevd, sastvd/helpers/git.py::allfunc):
chạy diff với context ĐỦ LỚN để thân diff chính là hợp của hai bản.
Nhờ vậy mọi số dòng dùng chung một hệ toạ độ.

LineVD dùng `git diff --no-index -U<lớn>`. Ở đây dùng difflib để
không phụ thuộc git và chạy nhanh hơn khi xử lý hàng chục nghìn mẫu.

Dòng của bản kia KHÔNG bị xoá mà bị COMMENT-OUT. Cách này của LineVD,
và nó quan trọng: comment vẫn giữ chỗ để số dòng khớp nhau, nhưng
analyzer bỏ qua comment nên không sinh node trong graph.
"""

import difflib
import re

from dataclasses import dataclass, field
from typing import List


# ============================================================
# COMMENT PREFIX THEO NGÔN NGỮ
#
# Phải comment được bằng prefix một dòng, nếu không sẽ làm
# hỏng cú pháp bản kia.
# ============================================================

LINE_COMMENT = {
    "c": "//",
    "cpp": "//",
    "java": "//",
    "javascript": "//",
    "typescript": "//",
    "csharp": "//",
    "go": "//",
    "rust": "//",
    "scala": "//",
    "kotlin": "//",
    "php": "//",
    "python": "#",
    "ruby": "#",
    "perl": "#",
}


@dataclass
class Aligned:
    """Hai bản đã căn dòng, dùng chung hệ số dòng 1-indexed."""

    before_view: str
    after_view: str

    added: List[int] = field(default_factory=list)
    removed: List[int] = field(default_factory=list)

    n_lines: int = 0

    # dòng thực sự có nội dung ở mỗi bản (không phải comment giữ chỗ)
    before_real: List[int] = field(default_factory=list)
    after_real: List[int] = field(default_factory=list)


def align(
    func_before,
    func_after,
    language,
    drop_comments=True,
):
    """
    -> Aligned

    added   = số dòng chỉ có ở bản after  (dòng vá thêm vào)
    removed = số dòng chỉ có ở bản before (dòng bị xoá/sửa)

    Dòng bị SỬA xuất hiện ở CẢ HAI danh sách, đúng như LineVD:
    difflib trả opcode 'replace' -> vừa removed vừa added.
    """

    prefix = LINE_COMMENT.get(
        language,
        "//",
    )

    # LineVD xoá comment TRƯỚC khi diff (helpers/datasets.py).
    # Không làm thì thay đổi chỉ ở comment cũng thành dòng lỗi.
    if drop_comments:

        func_before = strip_comments(
            func_before,
            language,
        )

        func_after = strip_comments(
            func_after,
            language,
        )

    before_lines = (
        func_before.splitlines()
        if isinstance(func_before, str)
        else []
    )

    after_lines = (
        func_after.splitlines()
        if isinstance(func_after, str)
        else []
    )

    matcher = difflib.SequenceMatcher(
        None,
        before_lines,
        after_lines,
        autojunk=False,
    )

    before_view = []
    after_view = []

    added = []
    removed = []

    before_real = []
    after_real = []

    def emit(
        text_before,
        text_after,
    ):
        """Thêm một dòng vào hệ toạ độ chung, trả số dòng 1-indexed."""

        before_view.append(
            text_before
        )

        after_view.append(
            text_after
        )

        return len(before_view)

    for (
        tag,
        i1,
        i2,
        j1,
        j2,
    ) in matcher.get_opcodes():

        if tag == "equal":

            for offset in range(
                i2 - i1
            ):

                text = before_lines[
                    i1 + offset
                ]

                num = emit(
                    text,
                    text,
                )

                before_real.append(num)
                after_real.append(num)

            continue

        # ----------------------------------------------------
        # replace / delete: dòng của bản before
        # ----------------------------------------------------

        if tag in (
            "replace",
            "delete",
        ):

            for offset in range(
                i2 - i1
            ):

                text = before_lines[
                    i1 + offset
                ]

                num = emit(
                    text,
                    f"{prefix} {text}",
                )

                removed.append(num)
                before_real.append(num)

        # ----------------------------------------------------
        # replace / insert: dòng của bản after
        # ----------------------------------------------------

        if tag in (
            "replace",
            "insert",
        ):

            for offset in range(
                j2 - j1
            ):

                text = after_lines[
                    j1 + offset
                ]

                num = emit(
                    f"{prefix} {text}",
                    text,
                )

                added.append(num)
                after_real.append(num)

    return Aligned(
        before_view="\n".join(
            before_view
        ),
        after_view="\n".join(
            after_view
        ),
        added=added,
        removed=removed,
        n_lines=len(before_view),
        before_real=before_real,
        after_real=after_real,
    )


# ============================================================
# XOÁ COMMENT TRƯỚC KHI DIFF
#
# LineVD làm việc này ở helpers/datasets.py:165-166 (gọi
# remove_comments lên func_before/func_after) TRƯỚC khi diff.
# Nếu không làm, thay đổi chỉ ở comment cũng bị tính là dòng
# lỗi. Đo trên dữ liệu thật: 2.74% dòng nhãn là comment,
# ảnh hưởng 11.9% mẫu.
#
# KHÁC LineVD một điểm cố ý: họ dùng re.sub với DOTALL nên
# block comment nhiều dòng bị co lại, làm ĐỔI SỐ DÒNG. Ở đây
# giữ nguyên số dòng (thay nội dung comment bằng khoảng trắng)
# để số dòng trong nhãn vẫn khớp func_before gốc của bạn.
# ============================================================

# ngôn ngữ dùng // và /* */
_C_LIKE_COMMENT = {
    "c", "cpp", "objc", "java", "javascript", "typescript",
    "csharp", "go", "rust", "scala", "kotlin", "swift", "php",
}

# ngôn ngữ dùng #
_HASH_COMMENT = {
    "python", "ruby", "perl",
}


# String literal KHÔNG được vắt qua dòng: một dấu nháy lẻ
# (lifetime Rust `&'a`, dấu nháy trong tiếng Anh "user's" ở comment)
# sẽ mở string giả và ăn luôn comment của các dòng sau.
_STR = (
    r"'(?:\\.|[^\\'\n])*'"
    r"|\"(?:\\.|[^\\\"\n])*\""
)


_C_PATTERN = re.compile(
    _STR
    + r"|//[^\n]*"
    + r"|/\*.*?\*/",
    re.DOTALL,
)


_HASH_PATTERN = re.compile(
    _STR
    + r"|#[^\n]*",
    re.DOTALL,
)


def _blank_keep_lines(text):
    """Thay text bằng khoảng trắng nhưng GIỮ nguyên số \\n."""

    return "\n" * text.count("\n")


def strip_comments(
    code,
    language,
):
    """
    Xoá comment, giữ nguyên số dòng và giữ nguyên string literal.

    PHP dùng cả // /* */ và #, nên xử lý hai lượt.
    """

    if not isinstance(
        code,
        str,
    ):
        return code

    def repl(m):

        s = m.group(0)

        # string literal -> giữ nguyên
        if s[:1] in ("'", '"'):
            return s

        return _blank_keep_lines(s)

    if language in _C_LIKE_COMMENT:

        code = _C_PATTERN.sub(
            repl,
            code,
        )

        if language == "php":

            code = _HASH_PATTERN.sub(
                repl,
                code,
            )

        return code

    if language in _HASH_COMMENT:

        return _HASH_PATTERN.sub(
            repl,
            code,
        )

    return code


def is_blank_after_strip(
    line,
):
    """Dòng rỗng sau khi xoá comment -> không dùng làm nhãn."""

    return not line.strip()


def signature_lines(
    lines,
):
    """
    Dòng thuộc phần KHAI BÁO hàm (chữ ký).

    Vì sao cần: node METHOD / METHOD_PARAMETER_IN của Joern mang
    lineNumber của dòng chữ ký và là def của mọi tham số, nên
    gần như mọi dòng `added` dùng tham số đều 1-hop tới nó ->
    85,5% mẫu có chữ ký trong depadd. Nhãn gốc BigVul (dựa trên
    diff) đánh 0,00%.

    LineVD KHÔNG loại (helpers/joern.py chỉ bỏ COMMENT và FILE,
    get_func_graph.scala export toàn bộ cpg.graph.V), nên đây là
    lệch CÓ CHỦ Ý, để ở cột riêng chứ không sửa vul_lines_final.

    Cách xác định: từ dòng không rỗng đầu tiên, mở rộng khi
    ngoặc đơn còn chưa đóng (chữ ký nhiều dòng), cộng thêm dòng
    chỉ có "{" ngay sau. Không dựa vào cú pháp riêng ngôn ngữ
    nào nên dùng được cho cả 17 ngôn ngữ.
    """

    n = len(lines)

    s = next(
        (
            i
            for i, t in enumerate(
                lines,
                1,
            )
            if t.strip()
        ),
        None,
    )

    if s is None:
        return set()

    sig = {s}

    depth = (
        lines[s - 1].count("(")
        -
        lines[s - 1].count(")")
    )

    i = s

    # chữ ký nhiều dòng: nới tối đa 7 dòng để không ăn vào thân
    while (
        depth > 0
        and i < n
        and i - s < 7
    ):

        i += 1

        sig.add(i)

        depth += (
            lines[i - 1].count("(")
            -
            lines[i - 1].count(")")
        )

    # dòng chỉ chứa "{" ngay sau chữ ký
    k = i + 1

    while (
        k <= n
        and not lines[k - 1].strip()
    ):
        k += 1

    if (
        k <= n
        and lines[k - 1].strip() == "{"
    ):
        sig.add(k)

    return sig
