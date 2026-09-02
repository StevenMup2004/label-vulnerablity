"""
Rule-based language detector.

Dùng để quét các mẫu còn lại trong needs_language_review,
nơi Linguist không chắc chắn và repo prior không có
hoặc mâu thuẫn.

Tín hiệu ở đây là CÚ PHÁP CỦA CHÍNH ĐOẠN CODE,
độc lập hoàn toàn với extension và với repo prior,
nên nó là một "nhân chứng thứ ba" thật sự.

Thiết kế hai tầng:

    Tầng 1: xác định FAMILY
            (C-family / JavaScript / Java / Python / ...)

    Tầng 2: trong C-family mới tách C vs C++ vs Objective-C

Lý do tách tầng: nhầm C thành Java là lỗi nặng,
còn nhầm C thành C++ là lỗi nhẹ. Hai loại lỗi này
cần ngưỡng khác nhau.
"""

import re


# ============================================================
# SIGNATURE
#
# weight cao = dấu hiệu càng đặc thù cho ngôn ngữ đó
# và càng hiếm xuất hiện ở ngôn ngữ khác.
# ============================================================

def _c(pattern):
    return re.compile(pattern, re.MULTILINE)


# ------------------------------------------------------------
# TẦNG 1 - FAMILY
# ------------------------------------------------------------

FAMILY_SIGNATURES = {

    "C/C++": [
        (_c(r"^\s*#\s*include\s*[<\"]"), 5),
        (_c(r"^\s*#\s*(define|ifdef|ifndef|endif|pragma)\b"), 3),
        (_c(r"\bstruct\s+\w+\s*\*"), 3),
        (_c(r"\b(unsigned|signed)\s+(char|int|long|short)\b"), 3),
        (_c(r"\b(size_t|uint\d+_t|int\d+_t|u8|u16|u32|u64)\b"), 3),
        (_c(r"\bNULL\b"), 2),
        (_c(r"\bsizeof\s*\("), 3),
        (_c(r"\b(malloc|calloc|realloc|free|memcpy|memset|strlen|strcmp)\s*\("), 3),
        (_c(r"^\s*(static|extern|inline)\s+\w+"), 2),
        (_c(r"\bgoto\s+\w+\s*;"), 2),
        (_c(r"\bchar\s*\*"), 2),
        (_c(r"\bvoid\s*\*"), 2),
        (_c(r"\b(int|void|char|long|short|float|double)\s+\**\w+\s*\("), 2),
        # Khai báo tham số kiểu C: "int argc," / "VALUE *argv," /
        # "xmlParserCtxtPtr ctxt)". Weight thấp vì Java/C#
        # cũng viết "int x," được.
        (_c(r"\b(int|unsigned|char|void|long|short|float|double|size_t)"
            r"\s+\**\w+\s*[,)]"), 2),
        # _t và _T: typval_T, size_t, xmlChar_t...
        (_c(r"\b\w+_[tT]\s+\**\w+\s*[,);=]"), 2),
        (_c(r"\b\w+Ptr\s+\w+\s*[,);=]"), 2),

        # ----------------------------------------------------
        # C++ HIỆN ĐẠI
        #
        # Các dấu hiệu trên đều là của C thuần. Code C++
        # dùng std::/::/this-> thì không khớp cái nào,
        # nên tầng 1 từng câm hoàn toàn trên
        #   const std::string& get_id() const
        #   QPDF_Stream::replaceDict(QPDFObjectHandle d)
        #   void SimpleModule::runPull()
        # ----------------------------------------------------
        # Khai báo con trỏ với kiểu tự định nghĩa:
        #   GHashTable *headers;   Test *test,
        #   conn_rec *c)           BYTE **buffer,
        # Java/C#/JS/Python đều không có cú pháp này.
        (_c(r"^\s*\w+\s+\*+\w+\s*[;,=)]"), 3),
        (_c(r"\(\s*\w+\s+\*+\w+\s*[,)]"), 3),
        (_c(r",\s*\w+\s+\*+\w+\s*[,)]"), 3),

        (_c(r"\bstd::"), 5),
        # định nghĩa hàm thành viên ngoài class: Foo::bar(
        (_c(r"\b\w+::~?\w+\s*\("), 4),
        (_c(r"\bthis->\w+"), 4),
        # hàm thành viên const: ") const {"
        (_c(r"\)\s*const\s*(\{|$)"), 4),
        # tham chiếu C++: "const Foo& x" / "Foo const& x"
        (_c(r"\bconst\s+\w+\s*&\s*\w+"), 3),
        (_c(r"^\s*(inline|virtual|explicit|static)\s+\w+.*::"), 4),
    ],

    "JavaScript": [
        (_c(r"\bfunction\s*\w*\s*\([^)]*\)\s*\{"), 4),
        (_c(r"\b(var|let|const)\s+\w+\s*="), 4),
        (_c(r"=>\s*\{"), 4),
        (_c(r"\brequire\s*\(\s*['\"]"), 5),
        (_c(r"\bmodule\.exports\b"), 5),
        (_c(r"\bthis\.\w+\s*="), 2),
        (_c(r"\.prototype\.\w+"), 5),
        (_c(r"===|!=="), 4),
        (_c(r"\btypeof\s+\w+"), 3),
        (_c(r"\bundefined\b"), 3),
        (_c(r"\b(async\s+function|await\s+\w+)"), 3),
        (_c(r"\bnew\s+Promise\b"), 4),
        (_c(r"\bconsole\.(log|error|warn)\b"), 4),
        (_c(r"\bJSON\.(parse|stringify)\b"), 3),
    ],

    "Java": [
        (_c(r"^\s*import\s+java(x)?\."), 6),
        (_c(r"^\s*package\s+[\w\.]+\s*;"), 4),
        (_c(r"@Override\b"), 6),
        (_c(r"\b(public|private|protected)\s+(static\s+)?(final\s+)?"
            r"(void|int|boolean|String|long|double)\b"), 4),
        (_c(r"\bString\s*\[\]\s*\w+"), 4),
        (_c(r"\bSystem\.(out|err)\."), 5),
        (_c(r"\bnew\s+[A-Z]\w*\s*\("), 2),
        (_c(r"\bthrows\s+\w*Exception\b"), 4),
        (_c(r"\bextends\s+\w+|\bimplements\s+\w+"), 3),
        (_c(r"\bfinal\s+\w+\s+\w+\s*="), 2),
    ],

    "Python": [
        (_c(r"^\s*def\s+\w+\s*\([^)]*\)\s*:"), 6),
        (_c(r"^\s*class\s+\w+\s*(\([^)]*\))?\s*:"), 5),
        (_c(r"^\s*(from\s+[\w\.]+\s+)?import\s+\w+"), 4),
        (_c(r"\bself\.\w+"), 4),
        (_c(r"^\s*(if|for|while|try|else|elif|except|with)\b[^{]*:\s*$"), 3),
        (_c(r"\b(True|False|None)\b"), 3),
        (_c(r"^\s*@\w+\s*$"), 2),
        (_c(r"\bprint\s*\("), 1),
        (_c(r"\braise\s+\w*(Error|Exception)\b"), 3),
    ],

    # PHP chỉ được nhận diện qua sigil "$".
    #
    # Không dùng "->method()" hay "::method()" làm dấu hiệu:
    # C++ cũng viết obj->method() và Class::method(),
    # điều này từng khiến 906 mẫu C++ bị gán nhầm thành PHP.
    "PHP": [
        (_c(r"<\?php"), 8),
        (_c(r"\$\w+\s*="), 5),
        (_c(r"\$this\s*->"), 8),
        (_c(r"\bfunction\s+\w+\s*\([^)]*\$"), 6),
        (_c(r"\becho\s+[\$'\"]"), 4),
        (_c(r"\barray\s*\(|\[\s*['\"]\w+['\"]\s*\]\s*="), 2),
        (_c(r"\bpublic\s+function\b"), 5),
        (_c(r"\b(isset|unset|empty)\s*\(\s*\$"), 6),
        (_c(r"\bforeach\s*\(\s*\$"), 6),
    ],

    "Go": [
        (_c(r"^\s*func\s+(\(\s*\w+\s+\*?\w+\s*\)\s*)?\w+\s*\("), 6),
        (_c(r":="), 5),
        (_c(r"^\s*package\s+\w+\s*$"), 5),
        (_c(r"\bif\s+err\s*!=\s*nil\b"), 6),
        (_c(r"\bnil\b"), 2),
        (_c(r"^\s*import\s*\("), 3),
        (_c(r"\bdefer\s+\w+"), 4),
        (_c(r"\bfmt\.\w+"), 4),
    ],

    "Ruby": [
        (_c(r"^\s*def\s+\w+[?!]?\s*(\([^)]*\))?\s*$"), 5),
        (_c(r"^\s*end\s*$"), 4),
        (_c(r"@\w+\s*="), 3),
        (_c(r"\bdo\s*\|\w+"), 5),
        (_c(r"\brequire\s+['\"]"), 3),
        (_c(r"\bnil\b"), 2),
        (_c(r"\.each\b|\.map\b"), 2),
        (_c(r"^\s*(attr_accessor|attr_reader|module)\b"), 5),
    ],

    # C# rất giống Java nên cần các dấu hiệu mà Java
    # KHÔNG có: get/set property, using, var...new,
    # string thường, readonly/internal/sealed, ??.
    "C#": [
        (_c(r"^\s*using\s+System"), 8),
        (_c(r"^\s*using\s+[\w\.]+\s*;"), 3),
        (_c(r"^\s*namespace\s+[\w\.]+"), 4),
        (_c(r"\bpublic\s+(sealed\s+|partial\s+|abstract\s+)?class\b"), 2),
        # (?<!::) để không dính std::string của C++
        (_c(r"(?<!:)\bstring\s+\w+\s*[=;,)]"), 5),
        (_c(r"\bvar\s+\w+\s*=\s*new\b"), 6),
        (_c(r"\{\s*get\s*;\s*(private\s+)?set\s*;\s*\}"), 8),
        (_c(r"\bConsole\.\w+"), 6),
        # "virtual" đã bỏ: đó là từ khoá C++, không đặc thù C#
        (_c(r"\b(readonly|internal|sealed)\s+\w+"), 5),
        (_c(r"\boverride\s+\w+"), 2),
        (_c(r"\bforeach\s*\(\s*var\b"), 7),
        (_c(r"\bobject\s+\w+\s*[=;,)]"), 3),
        (_c(r"\?\?"), 3),
        # IEnumerable là C#; List/Dictionary thì Java cũng có
        (_c(r"\bIEnumerable\s*<"), 5),
    ],

    "TypeScript": [
        (_c(r"^\s*(export\s+)?interface\s+\w+\s*\{"), 7),
        # (?<!:) để không dính std::string / std::void_t của C++
        (_c(r"(?<!:):\s*(string|number|boolean|any|unknown)\b"), 6),
        (_c(r"^\s*(export\s+)?type\s+\w+\s*="), 6),
        (_c(r"\b(private|public|protected|readonly)\s+\w+\s*:"), 6),
        (_c(r"^\s*import\s+.*\bfrom\s+['\"]"), 4),
        (_c(r"\bexport\s+(default\s+|const\s+|function\s+|class\s+)"), 4),
        # generic call "foo<Bar>(" đã bỏ: trùng với template
        # và static_cast<T>() của C++
        (_c(r"\bas\s+(string|number|any|unknown)\b"), 5),
        (_c(r"\benum\s+\w+\s*\{"), 5),
    ],

    "Scala": [
        (_c(r"^\s*(case\s+)?class\s+\w+\s*\("), 5),
        (_c(r"^\s*(private\s+|protected\s+)?def\s+\w+.*[:=]"), 5),
        (_c(r"\bval\s+\w+\s*[:=]"), 7),
        (_c(r"\bvar\s+\w+\s*:\s*\w+\s*="), 3),
        (_c(r"^\s*object\s+\w+"), 7),
        (_c(r"^\s*(trait|sealed)\s+\w+"), 6),
        (_c(r"=>\s*\w+|\bmatch\s*\{"), 2),
        (_c(r"\bOption\[|\bSeq\[|\bList\["), 6),
        (_c(r"^\s*import\s+scala\."), 8),
    ],

    "Rust": [
        (_c(r"^\s*(pub\s+)?fn\s+\w+"), 6),
        (_c(r"\blet\s+mut\b"), 6),
        (_c(r"\bimpl\s+\w+"), 5),
        # "&str" phải đứng ở vị trí KIỂU (sau : hoặc ->).
        # Nếu không, nó khớp cả C: rb_scan_args(..., &str, &sg)
        # trong đó &str chỉ là địa chỉ của biến tên str.
        (_c(r"(?::|->)\s*&(?:'\w+\s+)?str\b|\bString::"), 4),
        (_c(r"\bmatch\s+\w+\s*\{"), 2),
        (_c(r"\bOption<|\bResult<"), 5),
        (_c(r"\bunwrap\(\)|\bexpect\("), 4),
        (_c(r"^\s*use\s+[\w:]+;"), 3),
    ],

    "Perl": [
        (_c(r"^\s*sub\s+\w+\s*\{"), 5),
        (_c(r"\bmy\s+[\$@%]\w+"), 6),
        (_c(r"[\$@%]\w+\s*="), 3),
        (_c(r"=~\s*[ms]?/"), 5),
        (_c(r"\buse\s+strict\b"), 6),
        (_c(r"\bqw\s*\("), 4),
    ],

    "Swift": [
        (_c(r"^\s*(public\s+|private\s+)?func\s+\w+"), 5),
        (_c(r"\blet\s+\w+\s*(:|=)"), 4),
        (_c(r"\bvar\s+\w+\s*:\s*\w+"), 4),
        (_c(r"\bguard\s+\w+"), 5),
        (_c(r"\bimport\s+(Foundation|UIKit|Swift)"), 6),
        (_c(r"\?\?|\w+\?\."), 2),
    ],
}


# ------------------------------------------------------------
# TẦNG 2 - C vs C++ vs Objective-C
#
# Logic: C là mặc định của C-family.
# C++ và Objective-C phải TỰ CHỨNG MINH bằng
# cú pháp mà C thuần không thể có.
# ------------------------------------------------------------

CPP_SIGNATURES = [
    (_c(r"\bstd::"), 6),
    (_c(r"\btemplate\s*<"), 6),
    (_c(r"^\s*namespace\s+\w+|\busing\s+namespace\b"), 6),
    (_c(r"\b(public|private|protected)\s*:"), 5),
    (_c(r"\bnullptr\b"), 6),
    (_c(r"\bclass\s+\w+\s*(:\s*(public|private|protected)\s+\w+)?\s*\{"), 5),
    (_c(r"\b\w+::\w+"), 4),
    (_c(r"\bvirtual\s+\w+"), 5),
    (_c(r"\boperator\s*(\[\]|\(\)|[-+*/=<>!]+)\s*\("), 5),
    (_c(r"\bnew\s+\w+(\s*\[|\s*\(|\s*;)"), 4),
    (_c(r"\bdelete\s+(\[\]\s*)?\w+"), 5),
    (_c(r"\bcatch\s*\(|\bthrow\s+\w+"), 4),
    (_c(r"\b(static_cast|dynamic_cast|reinterpret_cast|const_cast)\s*<"), 6),
    (_c(r"\b(constexpr|explicit|friend|typename|mutable)\b"), 4),
    (_c(r"\bbool\s+\w+\s*=\s*(true|false)\b"), 2),
    (_c(r"&\s*\w+\s*[,)]"), 1),
]

OBJC_SIGNATURES = [
    (_c(r"^\s*[-+]\s*\(\s*\w+\s*\**\s*\)\s*\w+"), 8),
    (_c(r"@(interface|implementation|end|property|synthesize)\b"), 8),
    (_c(r"\[\s*\w+\s+\w+(:|\s*\])"), 3),
    (_c(r"\bNS(String|Array|Dictionary|Object|Error)\b"), 6),
    (_c(r"@\"[^\"]*\""), 5),
    (_c(r"\bnil\b|\bYES\b|\bNO\b"), 2),
]


# ============================================================
# SCORING
# ============================================================

def _score(code, signatures):

    total = 0
    hits = 0

    for pattern, weight in signatures:

        found = pattern.search(code)

        if found:
            total += weight
            hits += 1

    return total, hits


MAX_CODE_CHARS = 20000


def detect_language(code):
    """
    Trả về dict hoặc None:

        {
            "language": str,
            "family":   str,
            "score":    int,
            "margin":   int,
            "runner_up": str | None,
        }
    """

    if not isinstance(code, str):
        return None

    code = code.strip()

    if len(code) < 30:
        return None

    # Cắt bớt cho nhanh; chữ ký ngôn ngữ luôn xuất hiện sớm
    code = code[:MAX_CODE_CHARS]

    # --------------------------------------------------------
    # TẦNG 1 - family
    # --------------------------------------------------------

    scores = {}

    for family, signatures in FAMILY_SIGNATURES.items():
        total, hits = _score(code, signatures)
        if total > 0:
            scores[family] = total

    if not scores:
        return None

    ranked = sorted(
        scores.items(),
        key=lambda kv: kv[1],
        reverse=True,
    )

    best_family, best_score = ranked[0]

    runner_up = ranked[1][0] if len(ranked) > 1 else None
    runner_score = ranked[1][1] if len(ranked) > 1 else 0

    margin = best_score - runner_score

    # --------------------------------------------------------
    # TẦNG 2 - chỉ áp dụng bên trong C-family
    # --------------------------------------------------------

    language = best_family

    if best_family == "C/C++":

        objc_score, _ = _score(code, OBJC_SIGNATURES)
        cpp_score, _ = _score(code, CPP_SIGNATURES)

        if objc_score >= 8 and objc_score > cpp_score:
            language = "Objective-C"

        elif cpp_score >= 8:
            language = "C++"

        else:
            language = "C"

    return {
        "language": language,
        "family": best_family,
        "score": best_score,
        "margin": margin,
        "runner_up": runner_up,
    }


# ============================================================
# FAMILY OF A LANGUAGE LABEL
# ============================================================

def family_of(language):

    if language in {"C", "C++", "C/C++", "Objective-C", "Objective-C++"}:
        return "C/C++"

    return language


# ============================================================
# NGƯỠNG TIN CẬY
#
# Đo trên 30.792 mẫu có nhãn chắc chắn từ extension.
#
# Hai mức khác nhau vì hai việc khác nhau:
#
#   CONFIRM  - chỉ củng cố nhãn đã có  -> cần precision ~97%
#   OVERRIDE - sửa lại nhãn đã có      -> cần precision ~99%
#
# Scala và TypeScript bị loại hoàn toàn:
# không đạt nổi 97% ở bất kỳ ngưỡng nào
# (TypeScript gần như luôn bị đọc thành JavaScript,
#  điều này đúng về bản chất nhưng sai về nhãn).
# ============================================================

CONFIRM_MIN_MARGIN = {
    "C/C++": 0,
    "Java": 0,
    "Go": 0,
    "Python": 3,
    "Ruby": 3,
    "C#": 6,
    "Rust": 6,
    "JavaScript": 8,
    "PHP": 26,
}

# Đo riêng trên các mẫu mà func_before và func_after
# ĐỒNG THUẬN family (28.593 mẫu), margin lấy bên nhỏ hơn.
#
# Con số kèm theo là precision đạt được tại ngưỡng đó.
OVERRIDE_MIN_MARGIN = {
    "C/C++": 3,       # 99.29% tại margin>=1; lấy 3 cho chắc
    "Java": 3,        # 99.78%
    "Python": 4,      # 99.79%
    "Ruby": 5,        # 100.00%
    "Go": 1,          # 99.42%
    "Rust": 6,        # 100.00%
    "C#": 8,          # 100.00%
    "JavaScript": 14,  # 99.33%
    "PHP": 26,        # 100.00%
}


# ============================================================
# NGƯỠNG Ở MỨC NHÓM
#
# Dùng khi KHÔNG cần phân biệt C với C++.
#
# Khác hai bảng trên ở hai điểm:
#   - nhãn đích là nhóm, nên C vs C++ không còn tính là sai
#   - không đòi func_before và func_after đồng thuận,
#     chỉ lấy bên có margin lớn hơn
#
# Nhờ vậy độ phủ tăng lên 94.9% số mẫu
# mà precision vẫn >= 97%.
#
# Scala và TypeScript vẫn bị loại (28.7% / 31.7%).
# ============================================================

GROUP_MIN_MARGIN = {
    "C/C++": 1,        # 98.71%  (n=16.945)
    "Java": 0,         # 99.31%  (n= 7.409)
    "Go": 0,           # 99.42%  (n=   173)
    "Python": 3,       # 98.96%  (n= 1.533)
    "Ruby": 3,         # 98.82%  (n=   338)
    "C#": 6,           # 100.00% (n=    58)
    "Rust": 6,         # 100.00% (n=    26)
    "JavaScript": 10,  # 97.53%  (n=   851)
    "PHP": 26,         # 97.73%  (n=    44)
}


def detect_with_agreement(code_before, code_after):
    """
    Chạy detector trên CẢ func_before và func_after.

    Chỉ trả kết quả khi hai bên đồng thuận family.
    Margin lấy giá trị NHỎ HƠN của hai bên
    (nguyên tắc mắt xích yếu nhất).

    Trả về None nếu hai bên không đồng thuận.
    """

    before = detect_language(code_before)
    after = detect_language(code_after)

    # Chỉ có một bên đọc được -> vẫn dùng nhưng không có
    # đồng thuận, đánh dấu agreement=False
    if before is None and after is None:
        return None

    if before is None or after is None:
        single = before or after
        return {
            "language": single["language"],
            "family": single["family"],
            "margin": single["margin"],
            "agreement": False,
        }

    if before["family"] != after["family"]:
        return None

    # Cùng family; nhãn cụ thể lấy theo bên có margin lớn hơn
    stronger = (
        before
        if before["margin"] >= after["margin"]
        else after
    )

    return {
        "language": stronger["language"],
        "family": before["family"],
        "margin": min(before["margin"], after["margin"]),
        "agreement": True,
    }


def is_confident(result, thresholds):
    """
    result: output của detect_with_agreement
    thresholds: CONFIRM_MIN_MARGIN hoặc OVERRIDE_MIN_MARGIN
    """

    if result is None:
        return False

    family = result["family"]

    if family not in thresholds:
        return False

    return result["margin"] >= thresholds[family]
