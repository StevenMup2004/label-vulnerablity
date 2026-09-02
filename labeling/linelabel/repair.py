"""
Sửa chữa cú pháp để cứu nhóm parse_error_at_anchor.

Vì sao cần: tree-sitter không có preprocessor, nên code C/C++
dùng macro sẽ parse lỗi. Và nhiều mẫu TitanVul là FRAGMENT
(chữ ký hàm nhiều dòng bị cắt, method của object literal JS).

Nguyên tắc bắt buộc:

  1. Mọi biến đổi phải GIỮ NGUYÊN SỐ DÒNG. Nhãn là số dòng, đổi
     số dòng là sai nhãn. Scaffold thì offset đúng 1 dòng và
     được trừ lại.

  2. KHÔNG bao giờ làm rỗng dòng thuộc `added`. Đó là anchor mà
     depadd dựa vào; mất danh định trên đó là mất dependency.

  3. Chỉ sửa dòng ĐANG BÁO LỖI, không sửa tràn lan.

  4. Tiêu chí thành công KHÔNG phải "0 lỗi" mà là "lỗi không còn
     chạm vào added". Đủ để depadd quanh anchor đáng tin.

Đo trên 699 mẫu parse_error_at_anchor:
  C 422 | JavaScript 161 | C++ 53 | C/C++ 17 | Scala 13 | PHP 9
  40% lệch số brace -> fragment
"""

import re


# token kiểu thuộc tính của compiler / kernel
ATTR_TOKEN = re.compile(
    r"\b(__\w+|_[A-Z]\w*_)\b"
)

# macro juxtaposed: TSRMLS_CC, ZEND_NUM_ARGS, _U_ ...
CAPS_TOKEN = re.compile(
    r"\b([A-Z][A-Z0-9_]{2,})\b(?!\s*\()"
)

# dòng dạng  NAME(...)  thiếu dấu ; cuối
CALL_NO_SEMI = re.compile(
    r"^(\s*[A-Za-z_]\w*\s*\(.*\))\s*$"
)

# dòng dạng  MACRO(...) {   -> macro mở block
MACRO_BLOCK = re.compile(
    r"^(\s*)([A-Za-z_]\w*)\s*(\(.*\))?\s*\{\s*$"
)

KEYWORDS = {
    "if", "for", "while", "switch", "do", "else",
    "try", "catch", "function", "return", "case",
    "default", "struct", "union", "enum", "class",
}


C_LIKE = {
    "c",
    "cpp",
    "objc",
    "java",
    "csharp",
    "javascript",
    "typescript",
    "php",
    "go",
    "rust",
    "scala",
    "kotlin",
    "swift",
}


def _keep_len(
    old,
    new,
):
    """Chặn mọi biến đổi làm đổi số dòng."""

    return (
        new
        if new.count("\n") == old.count("\n")
        else old
    )


# ============================================================
# BIẾN ĐỔI TRÊN MỘT DÒNG
# ============================================================

def fix_line(
    line,
    protected,
):
    """
    Thử sửa một dòng đang báo lỗi.

    protected=True: dòng thuộc `added`, không được làm rỗng,
    chỉ cho phép bỏ token macro.

    -> list các phương án, ưu tiên giảm dần.
    """

    out = []

    stripped = line.strip()

    if not stripped:
        return out

    # ---- bỏ token thuộc tính: char __user *p -> char  *p ----
    a = ATTR_TOKEN.sub(
        " ",
        line,
    )

    if a != line:
        out.append(a)

    # ---- bỏ macro ALL_CAPS đứng trơ (TSRMLS_CC, _U_) ----
    b = CAPS_TOKEN.sub(
        " ",
        line,
    )

    if b != line:
        out.append(b)

    if a != line and b != a:

        out.append(
            CAPS_TOKEN.sub(
                " ",
                a,
            )
        )

    # ---- macro mở block: FORC3 { -> if (1) { ----
    m = MACRO_BLOCK.match(
        line
    )

    if m and m.group(2) not in KEYWORDS:

        out.append(
            f"{m.group(1)}if (1) {{"
        )

    # ---- NAME(...) thiếu ; ----
    m = CALL_NO_SEMI.match(
        line
    )

    if m:

        out.append(
            m.group(1) + ";"
        )

    # ---- cuối cùng: vô hiệu hoá dòng (chỉ nếu KHÔNG protected) ----
    if not protected:

        # giữ brace để không làm lệch cấu trúc
        braces = "".join(
            ch
            for ch in line
            if ch in "{}"
        )

        out.append(
            braces + ";"
            if braces
            else ";"
        )

    return out


# ============================================================
# CÂN BẰNG BRACE
# ============================================================

def balance(code):
    """
    -> list (text, offset)

    Fragment thường lệch brace. Thêm closer ở CUỐI (offset 0)
    hoặc opener ở ĐẦU trên đúng một dòng (offset 1).
    """

    out = []

    opens = code.count("{")
    closes = code.count("}")

    if opens > closes:

        out.append(
            (
                code
                + "\n"
                + "}" * (opens - closes),
                0,
            )
        )

    elif closes > opens:

        out.append(
            (
                "if (1) {" * (closes - opens)
                + "\n"
                + code,
                1,
            )
        )

    return out


# ============================================================
# SCAFFOLD BỔ SUNG
#
# JS: 161/699 là method của object literal
#     ("init: function() {") -> phải bọc trong {...}
# ============================================================

EXTRA_SCAFFOLDS = {
    "javascript": [
        ("var __o = {", "};"),
        ("var __o = { __k:", "};"),
    ],
    "typescript": [
        ("var __o = {", "};"),
    ],
    "c": [
        ("void __w(void) {", "}"),
    ],
    "cpp": [
        ("void __w(void) {", "}"),
    ],
    "objc": [
        ("void __w(void) {", "}"),
    ],
    "scala": [
        ("object __W {", "}"),
    ],
}


def variants(
    code,
    lang,
):
    """
    -> list (text, offset): các biến thể CẤU TRÚC để thử parse,
    ngoài bản gốc.
    """

    out = []

    out.extend(
        balance(code)
    )

    for prefix, suffix in (
        EXTRA_SCAFFOLDS.get(
            lang,
            [],
        )
    ):

        text = prefix + "\n" + code

        if suffix:
            text += "\n" + suffix

        out.append(
            (text, 1)
        )

        # kết hợp scaffold + cân bằng brace
        for balanced, off in balance(
            code
        ):

            t2 = prefix + "\n" + balanced

            if suffix:
                t2 += "\n" + suffix

            out.append(
                (t2, 1)
            )

    return out


# ============================================================
# VÒNG SỬA CHỮA
# ============================================================

MAX_ROUNDS = 3

# quá nhiều dòng lỗi thì code hỏng hẳn, sửa vô vọng
MAX_ERR_LINES = 25

# mỗi vòng chỉ thử tối đa số dòng này; dòng lỗi đầu tiên
# thường là nguyên nhân gốc, các dòng sau là hệ quả
MAX_FIX_PER_ROUND = 6


def repair(
    an,
    code,
    protected_lines,
    offset=0,
):
    """
    Sửa dần các dòng báo lỗi tới khi lỗi không còn chạm
    protected_lines, hoặc không tiến triển thêm.

    an              : Analyzer
    code            : text cần sửa (hệ toạ độ của chính nó)
    protected_lines : số dòng KHÔNG được làm rỗng (added),
                      trong hệ toạ độ của code
    -> (text, n_rounds) ; text có thể chính là code nếu bó tay
    """

    if an.lang not in C_LIKE:
        return (code, 0)

    current = code

    for round_index in range(
        MAX_ROUNDS
    ):

        tree, src = an.parse(
            current
        )

        err = an.error_lines(
            tree.root_node
        )

        if not err:
            return (current, round_index)

        if not (err & protected_lines):
            return (current, round_index)

        if len(err) > MAX_ERR_LINES:
            return (current, round_index)

        lines = current.splitlines()
        changed = False

        # Sửa NHIỀU dòng trong CÙNG một vòng rồi mới parse lại.
        # Bản trước sửa 1 dòng/vòng -> hàng trăm lần parse mỗi
        # mẫu, chậm gấp bội mà không khá hơn.
        for ln in sorted(err)[:MAX_FIX_PER_ROUND]:

            if not (1 <= ln <= len(lines)):
                continue

            options = fix_line(
                lines[ln - 1],
                ln in protected_lines,
            )

            base = len(err)

            for opt in options:

                trial = list(lines)
                trial[ln - 1] = opt
                text = "\n".join(trial)

                if text.count("\n") != current.count("\n"):
                    continue

                t2, _ = an.parse(text)
                e2 = an.error_lines(t2.root_node)

                if (
                    len(e2) < base
                    or
                    not (e2 & protected_lines)
                ):

                    lines = trial
                    current = text
                    changed = True

                    if not (e2 & protected_lines):
                        return (
                            current,
                            round_index + 1,
                        )

                    break

        if not changed:
            break

    return (current, MAX_ROUNDS)
