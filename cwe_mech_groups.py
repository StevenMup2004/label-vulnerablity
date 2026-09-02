"""
Gán NHÓM CƠ CHẾ LỖI cho mẫu TitanVul — đa nhãn, phủ 100%.

Ba nguyên tắc:

1. ĐA NHÃN. Một hàm có thể vừa UAF vừa lỗi kiểm quyền. 8,9% mẫu
   nhận nhiều hơn một nhóm; ép về một nhãn là mất thông tin.

2. BỎ TỔ TIÊN TRƯỚC KHI GÁN. `CWE-476;CWE-703` không phải hai
   lỗi — CWE-703 chỉ là pillar cha của CWE-476. Không lọc thì
   sinh nhóm ma. Lọc rồi thì 3.788 mẫu nhiều CWE còn 2.796.

3. BẰNG CHỨNG CỤ THỂ THẮNG NHÃN CHUNG CHUNG. Quy tắc cũ trong
   build_cwe_labels.py là `label = existing[0]` — lấy CWE đầu
   tiên theo thứ tự trong dataset nguồn. Đo được 1.437 mẫu
   (37,9% nhóm nhiều nhãn) mang nhãn TỆ HƠN nhãn có sẵn ngay
   bên cạnh: CWE-119;CWE-787 -> chọn 119, CWE-401;CWE-703 ->
   chọn 703. Ở đây ưu tiên ứng viên cụ thể nhất.

CWE-20 và các category rỗng nghĩa (19, 254, 17, 16, 21...) bị
loại khỏi vai trò nguồn tri thức: "Improper Input Validation"
không phải cơ chế, tràn biên do thiếu validate cũng CWE-20 mà
XSS cũng CWE-20. Chúng bị bắt định tuyến bằng bằng chứng.

Cần: cache/cwec_latest.xml.zip (tải bởi cwe_hierarchy.py)
"""

import re
import zipfile
import xml.etree.ElementTree as ET

from collections import defaultdict, deque
from pathlib import Path

from cwe_groups import GROUPS, group_of, is_precise, parse


ROOT = Path(__file__).resolve().parent

CATALOG = ROOT / "cache" / "cwec_latest.xml.zip"


# CWE không mang thông tin cơ chế -> không dùng làm nguồn tri thức
NO_MECHANISM = {
    16, 17, 18, 19, 20, 21, 254, 255, 388, 664, 691, 693,
    707, 710, 1103, 1173, 1284, 1287,
}


# ============================================================
# TỪ ĐIỂN CƠ CHẾ (soạn từ định nghĩa CWE, áp lên commit
# message + mô tả CVE). Precision đo trên tập có CWE cụ thể
# ghi ở cuối mỗi dòng.
# ============================================================

TEXT_STRONG = [
    # (regex, nhóm, precision đo được)
    (r'sql injection|sqli\b|prepared statement|parameteri[sz]ed quer',
     "injection", 0.96),
    (r'cross[- ]site scripting|\bxss\b|html escap|innerhtml',
     "injection", 0.95),
    (r'out[- ]of[- ]bounds|buffer over(flow|read|run)|overread|'
     r'oob[ _-]?(read|write)|heap overflow|stack overflow|'
     r'bounds check|off[- ]by[- ]one|array index|index out of',
     "mem_spatial", 0.82),
    (r'deseriali[sz]|unsafe (pickle|yaml|unmarshal)|'
     r'object injection|prototype pollution|gadget chain',
     "injection", 0.81),
    (r'path traversal|directory traversal|\.\./|zip[- ]slip|'
     r'symlink attack|arbitrary file (read|write|overwrite)|'
     r'canonical path',
     "path_file", 0.79),
    (r'use[- ]after[- ]free|double[- ]free|dangling pointer|'
     r'freed memory|after free|premature free',
     "mem_lifetime", 0.75),
    (r'memory leak|resource leak|leak(s|ed|ing)? (memory|fd|'
     r'file descriptor|handle)|not freed|fail(s|ed)? to free',
     "mem_lifetime", 0.68),
    (r'integer overflow|integer underflow|signed(ness)? (error|issue)|'
     r'wrap[- ]?around|divide by zero|division by zero|truncat\w+',
     "numeric", 0.65),
    (r'\bssrf\b|server[- ]side request forgery|\bcsrf\b|'
     r'cross[- ]site request forgery|open redirect|session fixation|'
     r'clickjacking',
     "web_session", 0.65),
    (r'null[- ]pointer|null deref|nullptr|dereferenc\w* null|'
     r'check for null|missing null',
     "null_deref", 0.59),
    (r'race condition|data race|toctou|time[- ]of[- ]check|deadlock|'
     r'concurren\w+|not (thread|atomic)|missing lock',
     "concurrency", 0.58),
]

# ĐÃ LOẠI, vì đo thấy vô dụng:
#   'denial of service|dos'  -> bắn 25,6% dataset, chỉ 30% đúng
#                               (có trong hầu hết mô tả CVE)
#   'arbitrary code execution|rce' -> 26% đúng (xuất hiện cả
#                               trong CVE hỏng bộ nhớ)

TEXT_WEAK = [
    (r'\btls\b|\bssl\b|certificate (validation|verif)|'
     r'weak (cipher|hash|random)|predictable|insecure random|'
     r'constant[- ]time|timing attack|signature verif', "crypto"),
    (r'permission check|privilege escalation|access control|'
     r'authoriz\w+|unauthori[sz]ed|missing (auth|permission)|'
     r'bypass.{0,20}(auth|check|restriction)', "access_control"),
    (r'information (leak|disclosure|exposure)|sensitive (data|information)|'
     r'expose\w* .{0,15}(memory|kernel|address)|kaslr', "info_exposure"),
    (r'authentication|credential|password|login bypass|'
     r'session (token|hijack)|api key', "access_control"),
    (r'error handling|return value (not|un)checked|ignore\w* (error|return)|'
     r'assertion failure|reachable assert|unhandled exception', "error_handling"),
    (r'uninitiali[sz]ed|not initiali[sz]ed|garbage value', "mem_lifetime"),
    (r'input validation|missing check|sanity check|malformed input',
     "mem_spatial"),
]


# ============================================================
# MẪU HÌNH CODE — chỉ API/cú pháp dùng chung nhiều project.
#
# Cố tình KHÔNG học từ khoá tự động: đo log-odds trên dòng lỗi
# cho ra `gss_union_ctx_id_t`, `rlc_throw`, `mpt_verify_adapter`
# - tức định danh riêng của Linux/KRB5/TensorFlow, không phải
# dấu hiệu lỗi. Nhóm sẽ "giống nhau" vì cùng project chứ không
# vì cùng cơ chế.
# ============================================================

CODE_PATTERNS = [
    (r'\b(memcpy|memmove|strcpy|strcat|sprintf|vsprintf|bcopy|wcscpy|'
     r'strncpy|snprintf|copy_from_user|copy_to_user|alloca)\s*\(',
     "mem_spatial"),
    (r'\b(SSL|TLS|EVP_|RSA|AES|SHA|MD5|HMAC|cipher|encrypt|decrypt|'
     r'X509)\w*', "crypto"),
    (r'\b(SELECT|INSERT|UPDATE|DELETE|WHERE|query|execute|prepare)\b',
     "injection"),
    (r'\b(open|fopen|realpath|readlink|basename|dirname|mkdir|unlink|'
     r'rename|chdir)\s*\(|\.\./', "path_file"),
    (r'\b(lock|unlock|mutex|spin_lock|atomic|rcu_|synchronized|'
     r'pthread)\w*', "concurrency"),
    (r'\b(capable|permission|allow|deny|access|priv|uid|gid|role|'
     r'admin|auth)\w*', "access_control"),
    (r'\b(free|kfree|vfree|g_free|release|unref|dispose|destroy)\s*[\(\s]',
     "mem_lifetime"),
    (r'(==\s*NULL|!=\s*NULL|is\s+None|==\s*null|!=\s*null)', "null_deref"),
    (r'(\+|\*|<<)\s*(sizeof|[0-9]+)|\boverflow\b', "numeric"),
    (r'\[\s*[a-z_][a-z0-9_]*\s*(\+|-|\*)', "mem_spatial"),
    (r'\b(errno|goto\s+(err|fail|out|cleanup)|assert|BUG_ON|WARN_ON)\b',
     "error_handling"),
]


def _c(pairs):
    return [
        (re.compile(p, re.I), g)
        for p, g, *_ in pairs
    ]


_STRONG = _c(TEXT_STRONG)
_WEAK = _c(TEXT_WEAK)
_CODE = _c(CODE_PATTERNS)


# ============================================================
# CÂY CWE — để bỏ ứng viên là tổ tiên
# ============================================================

_ANC_CACHE = {}
_PARENTS = None


def _load_parents():

    global _PARENTS

    if _PARENTS is not None:
        return _PARENTS

    par = defaultdict(set)

    z = zipfile.ZipFile(CATALOG)

    root = ET.fromstring(
        z.read(z.namelist()[0])
    )

    ns = re.match(
        r"\{(.*)\}",
        root.tag,
    ).group(1)

    for w in root.find(f"{{{ns}}}Weaknesses"):

        rel = w.find(
            f"{{{ns}}}Related_Weaknesses"
        )

        if rel is None:
            continue

        for r in rel:

            if (
                r.get("Nature") == "ChildOf"
                and r.get("View_ID") in (None, "1000")
            ):
                par[w.get("ID")].add(
                    r.get("CWE_ID")
                )

    _PARENTS = par

    return par


def ancestors(cwe_num):
    """Tất cả tổ tiên trong View-1000, dạng chuỗi id."""

    c = str(cwe_num)

    if c in _ANC_CACHE:
        return _ANC_CACHE[c]

    par = _load_parents()

    seen = {c}
    out = set()
    q = deque([c])

    while q:

        for p in par.get(q.popleft(), ()):

            if p in seen:
                continue

            seen.add(p)
            out.add(p)
            q.append(p)

    _ANC_CACHE[c] = out

    return out


def split_cwes(value):
    """'CWE-125;CWE-787' -> ['CWE-125','CWE-787'], giữ thứ tự."""

    out = []

    for x in str(value).replace(",", ";").split(";"):

        x = x.strip().upper()

        if x.startswith("CWE-") and x not in out:
            out.append(x)

    return out


def prune_ancestors(cwes):
    """
    Bỏ ứng viên là tổ tiên của ứng viên khác trong cùng tập.

    CWE-476;CWE-703 -> CWE-476   (703 là pillar cha)
    CWE-119;CWE-787 -> CWE-787   (119 là class cha)
    CWE-416;CWE-502 -> giữ cả hai (không có quan hệ)
    """

    ids = [
        c.replace("CWE-", "")
        for c in cwes
    ]

    return [
        "CWE-" + c
        for c in ids
        if not any(
            c in ancestors(o)
            for o in ids
            if o != c
        )
    ]


def informative(cwe):
    """CWE có mang thông tin cơ chế không."""

    n = parse(cwe)

    return (
        n is not None
        and n not in NO_MECHANISM
        and group_of(cwe) != "other"
    )


def _first_match(patterns, text):

    for rx, g in patterns:

        if rx.search(text):
            return g

    return None


def assign(
    cwe_all,
    commit_message="",
    cve_description="",
    vul_lines_text="",
    func_before="",
):
    """
    -> (nhóm chính, tất cả nhóm, tầng quyết định, CWE đã lọc)

    Thang bằng chứng, dừng ở tầng đầu tiên có kết quả:
      1 CWE cụ thể (weakness thật)     75,5%
      2 cụm từ cơ chế MẠNH trong text   8,3%
      3 CWE category CÓ thông tin       8,9%
      4 cụm từ cơ chế yếu               2,2%
      5 mẫu hình code trên dòng lỗi     3,5%
      6 mẫu hình code trên toàn hàm     1,1%
      -> còn lại: gọi resolve_residual()

    Tầng 2 đặt TRƯỚC tầng 3 có chủ ý: bằng chứng về CHÍNH mẫu
    đó mạnh hơn một nhãn CWE cấp category.
    """

    pruned = prune_ancestors(
        split_cwes(cwe_all)
    )

    text = f"{commit_message}\n{cve_description}"

    primary = None
    tier = None

    good = [
        c
        for c in pruned
        if informative(c) and is_precise(c)
    ]

    if good:
        primary, tier = group_of(good[0]), "1_cwe_cụ_thể"

    if primary is None:

        g = _first_match(_STRONG, text)

        if g:
            primary, tier = g, "2_text_mạnh"

    if primary is None:

        cat = [
            c
            for c in pruned
            if informative(c)
        ]

        if cat:
            primary, tier = group_of(cat[0]), "3_cwe_category"

    if primary is None:

        g = _first_match(_WEAK, text)

        if g:
            primary, tier = g, "4_text_yếu"

    if primary is None:

        g = _first_match(
            _CODE,
            str(vul_lines_text),
        )

        if g:
            primary, tier = g, "5_code_dòng_lỗi"

    if primary is None:

        g = _first_match(
            _CODE,
            str(func_before)[:6000],
        )

        if g:
            primary, tier = g, "6_code_toàn_hàm"

    groups = {
        group_of(c)
        for c in pruned
        if informative(c)
    }

    groups.discard("other")

    if primary:
        groups.add(primary)

    return (
        primary,
        sorted(groups),
        tier or "7_chưa",
        pruned,
    )


# ============================================================
# CHẺ NHÓM BỘ NHỚ THEO MẪU HÌNH CODE
#
# mem_spatial chiếm 27,7% - lớn quá. Chẻ theo CÁCH LỖI XẢY RA
# chứ không theo hậu quả:
#   mem_copy  : lỗi ở THAM SỐ KÍCH THƯỚC của memcpy/strcpy/...
#   mem_index : lỗi ở BIÊN CHỈ SỐ / số học địa chỉ
# Hai loại này người vá sửa khác nhau.
#
# KHÔNG chẻ theo đọc/ghi (CWE-125 vs CWE-787) vì code gần
# như giống hệt - chẻ vậy là chẻ bừa cho đều, không giữ được
# đặc trưng chung của nhóm.
# ============================================================

_COPY_API = re.compile(
    r'\b(memcpy|memmove|strcpy|strcat|sprintf|vsprintf|bcopy|wcscpy|'
    r'strncpy|snprintf|copy_from_user|copy_to_user|alloca|'
    r'CopyMemory|RtlCopyMemory)\s*\(',
    re.I,
)


def split_memory(group, func_before):

    if group != "mem_spatial":
        return group

    return (
        "mem_copy"
        if _COPY_API.search(str(func_before)[:6000])
        else "mem_index"
    )
