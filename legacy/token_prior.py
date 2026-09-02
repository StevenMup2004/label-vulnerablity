"""
Nguồn tín hiệu thứ tư: TOKEN PRIOR.

Ý tưởng: tên hàm và tên kiểu tiết lộ hệ sinh thái, mà hệ
sinh thái thì gắn chặt với ngôn ngữ.

    VALUE / rb_scan_args / INT2FIX  -> Ruby C API   -> C
    GHashTable / gchar / g_free     -> GLib         -> C
    apr_status_t / conn_rec         -> Apache APR   -> C
    PyObject / Py_INCREF            -> Python C API -> C
    v8:: / Local< / Isolate         -> V8           -> C++

Bảng token KHÔNG hardcode mà HỌC từ các mẫu đã có nhãn
chắc chắn: mỗi token được thống kê phân bố ngôn ngữ, chỉ
giữ lại token gần như luôn đi cùng một ngôn ngữ.

Đây là tín hiệu độc lập với rule cú pháp: rule đọc ngữ
pháp, token prior đọc từ vựng. Một đoạn code C viết theo
phong cách lạ có thể qua mặt rule nhưng vẫn lộ ra ở tên API.

CẢNH BÁO khi đánh giá: token đặc thù của một repo
(rb_scan_args chỉ có ở ruby/*) sẽ khiến việc đo bị thổi
phồng nếu train và test dùng chung repo. Vì vậy toàn bộ
việc đo ở đây tách theo REPO, không tách ngẫu nhiên.
"""

import re
import math
from collections import defaultdict


TOKEN_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

MAX_CHARS = 5000

# Từ khoá dùng chung nhiều ngôn ngữ -> không mang thông tin
STOPWORDS = {
    "the", "and", "for", "not", "int", "char", "void", "long",
    "float", "double", "short", "unsigned", "signed", "const",
    "static", "return", "sizeof", "struct", "union", "enum",
    "typedef", "else", "while", "break", "continue", "switch",
    "case", "default", "goto", "null", "true", "false", "NULL",
    "TRUE", "FALSE", "if", "do", "new", "delete", "this", "self",
    "def", "end", "class", "public", "private", "protected",
    "function", "var", "let", "value", "data", "size", "len",
    "buf", "buffer", "result", "error", "err", "ret", "res",
    "tmp", "temp", "index", "count", "num", "str", "string",
    "name", "type", "flags", "flag", "state", "status", "code",
    "get", "set", "add", "remove", "init", "free", "alloc",
    "read", "write", "open", "close", "start", "stop", "next",
    "prev", "first", "last", "list", "item", "node", "head",
    "tail", "key", "val", "out", "in", "off", "offset", "ptr",
    "pos", "end_", "max", "min", "args", "argv", "argc",
}

MIN_SUPPORT = 8

MIN_PURITY = 0.97


# ============================================================
# NGƯỠNG TIN CẬY
#
# Đo bằng 4-fold CHIA THEO REPO trên 30.898 mẫu có nhãn
# chắc chắn: token của repo trong test set hoàn toàn
# không xuất hiện khi xây bảng token. Nhờ vậy con số dưới
# đây là mức áp dụng cho repo LẠ, không phải kết quả
# học thuộc tên riêng của repo.
#
# Precision tổng: 96.5%
#
# C#, JavaScript, PHP bị loại vì không đạt 97%
# (94.9% / 92.3% / 84.2%) ở bất kỳ ngưỡng nào.
# ============================================================

TOKEN_MIN_MARGIN = {
    "C/C++": 0,    # 97.29%  (n=14.496)
    "Java": 3,     # 97.23%  (n= 7.402)
    "Python": 0,   # 98.49%  (n=   729)
    "Ruby": 0,     # 99.36%  (n=   156)
}


def is_confident(result):

    if result is None:
        return False

    group = result["group"]

    if group not in TOKEN_MIN_MARGIN:
        return False

    return result["margin"] >= TOKEN_MIN_MARGIN[group]


def tokenize(code):

    if not isinstance(code, str):
        return set()

    tokens = set()

    for match in TOKEN_PATTERN.finditer(code[:MAX_CHARS]):

        token = match.group(0)

        if token in STOPWORDS:
            continue

        if token.lower() in STOPWORDS:
            continue

        tokens.add(token)

    return tokens


def build_token_prior(
    codes,
    labels,
    min_support=MIN_SUPPORT,
    min_purity=MIN_PURITY,
):
    """
    codes  : iterable các đoạn code
    labels : nhãn nhóm tương ứng

    Trả về dict token -> (nhóm, purity, support)
    """

    counts = defaultdict(lambda: defaultdict(int))

    for code, label in zip(codes, labels):

        if not isinstance(label, str):
            continue

        for token in tokenize(code):
            counts[token][label] += 1

    prior = {}

    for token, distribution in counts.items():

        total = sum(distribution.values())

        if total < min_support:
            continue

        best_label = max(
            distribution, key=distribution.get
        )

        purity = distribution[best_label] / total

        if purity < min_purity:
            continue

        prior[token] = (best_label, purity, total)

    return prior


def classify(code, prior):
    """
    Bỏ phiếu có trọng số.

    Trọng số = log(support) * purity, để token hiếm
    không lấn át token đã thấy nhiều lần.

    Trả về None hoặc dict {group, score, margin, hits}
    """

    scores = defaultdict(float)

    hits = 0

    for token in tokenize(code):

        entry = prior.get(token)

        if entry is None:
            continue

        label, purity, support = entry

        scores[label] += math.log1p(support) * purity

        hits += 1

    if not scores:
        return None

    ranked = sorted(
        scores.items(), key=lambda kv: kv[1], reverse=True
    )

    top_label, top_score = ranked[0]

    second = ranked[1][1] if len(ranked) > 1 else 0.0

    return {
        "group": top_label,
        "score": top_score,
        "margin": top_score - second,
        "hits": hits,
    }
