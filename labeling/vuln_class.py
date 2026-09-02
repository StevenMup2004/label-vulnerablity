"""
Phân loại lỗ hổng thành 5 lớp, cho bài toán vulnerability localization.

    BND  Boundary & Overflow Errors     CWE-118 Range Error + CWE-682
    NTR  Improper Neutralization        CWE-707
    PRT  Protection & Check Failure     CWE-693 + CWE-703
    LFC  Resource Lifecycle Errors      CWE-664

NGUYÊN TẮC THIẾT KẾ

1. Đơn vị nguyên tử là 40 category của view CWE-699, KHÔNG phải
   danh sách CWE tự liệt kê. Nhờ vậy CWE lạ / CWE mới vẫn có chỗ.

2. Mỗi phép gộp biện minh bằng CÂU HỎI mà bộ định vị phải trả
   lời khi đọc code, không bằng số mẫu. Không có ngưỡng, không
   có "gộp vì nhóm này ít mẫu quá".

3. Mất cân bằng là tính chất của DỮ LIỆU, không phải của
   taxonomy. Trên TitanVul (76% C/C++) BND chiếm 41%; trên toàn
   catalog MITRE nó chỉ 7,6%. Chữa lệch bằng class weight /
   oversampling lúc train, đừng định nghĩa lại lớp.

ĐÃ KIỂM CHỨNG
    - phủ 953/953 CWE còn hiệu lực của catalog MITRE
      (16 cái không phân được đều là DEPRECATED)
    - phủ 20.830/20.870 = 99,81% mẫu có nhãn dòng của TitanVul
      (40 mẫu sót là CWE-17/18 "DEPRECATED: Code", không mang
       thông tin nên để unknown thay vì đoán)

CHƯA KIỂM CHỨNG
    Phủ được mọi CWE KHÔNG có nghĩa model generalize sang CWE
    chưa gặp. 188 CWE có dưới 50 mẫu. Cần leave-one-CWE-out để
    kết luận, chưa chạy.

Cần: cache/cwec_latest.xml.zip  (cwe_hierarchy.py tải về)

Dùng:
    python vuln_class.py data/output/ext80.parquet
    python vuln_class.py data/output/joern70.parquet

    from vuln_class import VulnClassifier
    vc = VulnClassifier()
    vc.classify("CWE-125")          -> ("BND", "2_category_699")
    vc.classify_many("CWE-416;CWE-502")  -> (["LFC","NTR"], ...)
"""

import re
import sys
import zipfile
import xml.etree.ElementTree as ET

from collections import Counter, defaultdict, deque
from pathlib import Path


ROOT = Path(__file__).resolve().parent

CATALOG = ROOT / "cache" / "cwec_latest.xml.zip"

CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


def ensure_catalog(path=CATALOG):
    """Tải catalog CWE nếu chưa có. ~2 MB."""

    path = Path(path)

    if path.exists():
        return path

    import urllib.request

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(
        f"tải catalog CWE -> {path}"
    )

    urllib.request.urlretrieve(
        CATALOG_URL,
        path,
    )

    return path


# ============================================================
# 5 LỚP
# ============================================================

CLASS_NAME = {
    "BND": "Boundary & Overflow Errors",
    "NTR": "Improper Neutralization",
    "PRT": "Protection & Check Failure",
    "LFC": "Resource Lifecycle Errors",
}


CLASS_QUESTION = {
    "BND": "Đại lượng này có chặn trên không? "
           "(chỉ số, kích thước, số vòng lặp, lượng cấp phát)",
    "NTR": "Dữ liệu không tin cậy có tới sink mà chưa "
           "qua xử lý không?",
    "PRT": "Một kiểm tra bắt buộc có bị thiếu hoặc sai không?",
    "LFC": "Ở dòng này, tài nguyên đang ở trạng thái nào? "
           "(đã free chưa, đã khởi tạo chưa, ai đang giữ)",
}


# ------------------------------------------------------------
# 40 category CWE-699 -> 5 lớp.
#
# BND và LFC cùng là lỗi bộ nhớ nhưng tách theo trục kinh điển
# spatial / temporal: BND là ghi-đọc SAI CHỖ, LFC là dùng SAI LÚC.
#
# Numeric Errors vào BND vì integer overflow trong các bộ CVE
# hầu hết dẫn tới sai tham số kích thước rồi tràn biên - vẫn là
# câu hỏi "có chặn trên không".
#
# Error Conditions / Handler / API Errors vào PRT vì "không kiểm
# giá trị trả về" và "không kiểm quyền" là cùng một mẫu hình:
# một kiểm tra bắt buộc bị thiếu.
# ------------------------------------------------------------

CATEGORY_TO_CLASS = {
    # --- BND ---
    "1218": "BND",   # Memory Buffer Errors
    "189":  "BND",   # Numeric Errors

    # --- LFC ---
    "399":  "LFC",   # Resource Management Errors
    "465":  "LFC",   # Pointer Issues
    "452":  "LFC",   # Initialization and Cleanup Errors
    "411":  "LFC",   # Resource Locking Problems
    "557":  "LFC",   # Concurrency Issues
    "387":  "LFC",   # Signal Errors

    # --- NTR ---
    "137":  "NTR",   # Data Neutralization Issues
    "133":  "NTR",   # String Errors
    "1215": "NTR",   # Data Validation Issues
    "1219": "NTR",   # File Handling Issues

    # --- PRT ---
    "1211": "PRT",   # Authentication Errors
    "1212": "PRT",   # Authorization Errors
    "1210": "PRT",   # Audit / Logging Errors
    "255":  "PRT",   # Credentials Management Errors
    "417":  "PRT",   # Communication Channel Errors
    "310":  "PRT",   # Cryptographic Issues
    "320":  "PRT",   # Key Management Errors
    "1216": "PRT",   # Lockout Mechanism Errors
    "275":  "PRT",   # Permission Issues
    "265":  "PRT",   # Privilege Issues
    "355":  "PRT",   # User Interface Security Issues
    "1217": "PRT",   # User Session Errors
    "199":  "PRT",   # Information Management Errors
    "1213": "PRT",   # Random Number Issues: CWE-330/331/338 đều
                     # là "giá trị ngẫu nhiên không đủ mạnh" -
                     # lỗi mật mã, không phải logic sai
    "389":  "PRT",   # Error Conditions, Return Values, Status Codes
    "429":  "PRT",   # Handler Errors
    "1228": "PRT",   # API / Function Errors

    # Data Integrity Issues: cả 13 member đều là lỗi THIẾU/SAI
    # KIỂM CHỨNG - Improper Verification of Cryptographic
    # Signature (347), Improper Validation of Integrity Check
    # Value (354), Origin Validation Error (346), Download of
    # Code Without Integrity Check (494)... Không cái nào là
    # "logic sai". Đúng định nghĩa PRT.
    "1214": "PRT",   # Data Integrity Issues

    # --- LOG ---
    "136":  "BND",   # Type Errors
    "569":  "BND",   # Expression Issues
    "1227":  "PRT",   # Encapsulation Issues

    "19":  "BND",   # Data Processing Errors
    "438":  "NTR",   # Behavioral Problems
    "840":  "PRT",   # Business Logic Errors
    "371":  "LFC",   # State Issues
    "1006":  "PRT",   # Bad Coding Practices
    "1226":  "BND",   # Complexity Issues
    "1225":  "PRT",   # Documentation Issues
}


# ------------------------------------------------------------
# Lưới an toàn: pillar CWE-1000 -> lớp. Mọi CWE đều có pillar,
# kể cả CWE phần cứng hay CWE MITRE thêm sau này.
# ------------------------------------------------------------

# Node mức 2 dưới pillar CWE-664. Pillar 664 ôm hơn nửa cây
# CWE nên quá thô: deserialization (CWE-502), path traversal
# (CWE-706) và use-after-free (CWE-825) đều rơi vào đó. Chặn
# ở mức 2 trước khi chạm pillar. Vẫn là quy tắc theo NODE nên
# mọi con cháu của node đó được xử lý, không phải liệt kê CWE.
SUBTREE_TO_CLASS = {
    "913": "NTR",   # Improper Control of Dynamically-Managed Code
    "706": "NTR",   # Use of Incorrectly-Resolved Name or Reference
    "610": "NTR",   # Externally Controlled Reference to a Resource
    "668": "PRT",   # Exposure of Resource to Wrong Sphere
    "922": "PRT",   # Insecure Storage of Sensitive Information
    "118": "BND",   # Incorrect Access of Indexable Resource
    "666": "LFC",   # Operation on Resource in Wrong Phase of Lifetime
    "404": "LFC",   # Improper Resource Shutdown or Release
    "662": "LFC",   # Improper Synchronization
    "665": "LFC",   # Improper Initialization
    "672": "LFC",   # Operation on a Resource after Expiration
    "825": "LFC",   # Expired Pointer Dereference
    "911": "LFC",   # Improper Update of Reference Count
    # Định nghĩa BND ghi rõ "số vòng lặp, lượng cấp phát", nên
    # nhóm không-có-chặn-trên phải về BND, không phải LOG/LFC.
    "400": "BND",   # Uncontrolled Resource Consumption
    "834": "BND",   # Excessive Iteration (cha của 835, 674)
    "407": "BND",   # Inefficient Algorithmic Complexity (cha 1333)
}


PILLAR_TO_CLASS = {
    "664": "LFC",
    "682": "BND",
    "707": "NTR",
    "284": "PRT",
    "693": "PRT",
    "703": "PRT",
    "691": "LFC",
    "710": "PRT",
    "697": "BND",
    "435": "NTR",
}


# ------------------------------------------------------------
# OVERRIDE - phần DUY NHẤT là phán đoán của người viết.
# Chỉ dùng khi cây CWE cho kết quả sai NGHĨA, hoặc khi node đã
# bị khai tử và rút sạch liên kết nên không leo được.
# Không dòng nào dựa trên số mẫu.
# ------------------------------------------------------------

OVERRIDE = {
    "384": ("PRT", "session fixation là lỗi quản lý phiên; cây "
                   "MITRE xếp qua CWE-610 sang pillar 664 (LFC) "
                   "là sai nghĩa"),
    "264": ("PRT", "category cũ 'Permissions, Privileges, and "
                   "Access Controls', đã bị rút sạch member"),
    "16":  ("PRT", "category cũ 'Configuration': sai cấu hình "
                   "= cơ chế bảo vệ không được bật"),
    "21":  ("NTR", "category cũ 'Pathname Traversal and "
                   "Equivalence Errors' -> File Handling"),
    "534": ("PRT", "'Information Exposure Through Debug Log'"),
}


# CWE-399 "Resource Management Errors" là category THÙNG RÁC:
# nó chứa cả CWE-908 (uninitialized) lẫn CWE-502 (deserialization
# of untrusted data) - hai cơ chế không liên quan gì nhau. Nếu
# nhận nó ngay thì mọi CWE rơi vào đó đều bị gán chung một lớp.
#
# Xử lý: khi CWE-699 CHỈ cho biết một CWE thuộc 399, hoãn lại,
# đi tìm bằng chứng cụ thể hơn ở cây ChildOf trước; hết đường
# mới quay về 399. Đây là quy tắc, không phải danh sách tay.
CATCH_ALL = {
    "399",   # Resource Management Errors: chứa cả CWE-908
             # (uninitialized) lẫn CWE-502 (deserialization)
    "19",    # Data Processing Errors: chứa cả CWE-611 (XXE)
             # lẫn đủ thứ khác không liên quan
    "438",   # Behavioral Problems: CWE-835 (infinite loop, n=150)
             # nằm chung CWE-444 (HTTP request smuggling, n=44)
}


# CWE không mang thông tin -> unknown, KHÔNG đoán
NO_INFO = {
    "17",   # DEPRECATED: Code
    "18",   # DEPRECATED: Source Code
}


_REDIRECT = re.compile(
    r"(?:duplicate of|transferred to|replaced by)\s+CWE-(\d+)",
    re.I,
)


# Lớp LOG "Logic & State Errors" ĐÃ BỎ.
#
# Nó từng là lớp thứ 5 nhưng soi ra thì không mẫu nào trong đó
# thật sự là "logic sai": CWE-444 (HTTP smuggling) là NTR,
# CWE-843 (type confusion) là BND, CWE-358 ("Improperly
# Implemented Security Check") là PRT. Nó chỉ là chỗ mọi thứ
# rơi vào khi quy tắc phân loại hỏng - sửa hết lỗi thì nó teo
# từ 1.429 xuống 267 mẫu rồi biến mất.
#
# 12 category CWE-699 trước đây trỏ vào nó đã được phân về 4
# lớp theo nghĩa, không theo số lượng.


def _pick(classes):
    """
    Chọn 1 lớp để BÁO CÁO khi có nhiều ứng viên.

    Chỉ dùng cho cột vuln_class (phân tầng/thống kê). Khi train
    phải dùng vuln_class_all - CWE thuộc nhiều category nghĩa là
    MITRE thấy nó có nhiều mặt, mẫu đó vào cả hai expert.
    """

    return sorted(classes)[0] if classes else None


class VulnClassifier:
    """Phân loại CWE -> 1 trong 5 lớp, bằng cây MITRE."""

    def __init__(self, catalog=CATALOG):

        z = zipfile.ZipFile(
            ensure_catalog(catalog)
        )

        root = ET.fromstring(
            z.read(z.namelist()[0])
        )

        ns = re.match(
            r"\{(.*)\}",
            root.tag,
        ).group(1)

        def tag(x):
            return f"{{{ns}}}{x}"

        self.name = {}
        self.text = {}
        self.parent = defaultdict(set)
        self.child = defaultdict(set)
        self.cat699 = defaultdict(set)

        for w in root.find(tag("Weaknesses")):

            i = w.get("ID")

            self.name[i] = w.get("Name")

            dd = w.find(tag("Description"))

            self.text[i] = (
                (dd.text or "")
                if dd is not None
                else ""
            )

            rel = w.find(tag("Related_Weaknesses"))

            if rel is None:
                continue

            for r in rel:

                if (
                    r.get("Nature") == "ChildOf"
                    and r.get("View_ID") in (None, "1000")
                ):
                    p = r.get("CWE_ID")

                    self.parent[i].add(p)
                    self.child[p].add(i)

        for c in root.find(tag("Categories")):

            i = c.get("ID")

            self.name[i] = c.get("Name")

            s = c.find(tag("Summary"))

            self.text[i] = (
                (s.text or "")
                if s is not None
                else ""
            )

            rel = c.find(tag("Relationships"))

            if rel is None:
                continue

            for x in rel:

                m = x.get("CWE_ID")

                # category cũng có con -> cần cho lượt leo xuống
                self.child[i].add(m)

                if x.get("View_ID") == "699":
                    self.cat699[m].add(i)

    # --------------------------------------------------------

    @staticmethod
    def _num(cwe):

        return (
            str(cwe)
            .strip()
            .upper()
            .replace("CWE-", "")
        )

    def _redirect(self, cid):
        """CWE deprecated -> CWE thay thế, đọc từ chính mô tả."""

        if not str(
            self.name.get(cid, "")
        ).startswith("DEPRECATED"):
            return None

        m = _REDIRECT.search(
            self.text.get(cid, "") or ""
        )

        return m.group(1) if m else None

    def _direct(self, cid):
        """Lớp suy được ngay: bản thân là category, hoặc là member."""

        if cid in CATEGORY_TO_CLASS:
            return {CATEGORY_TO_CLASS[cid]}

        cats = {
            x
            for x in self.cat699.get(cid, ())
            if x in CATEGORY_TO_CLASS
        }

        # chỉ thuộc category thùng rác -> hoãn, tìm bằng chứng
        # cụ thể hơn ở lượt leo cây
        if cats and cats <= CATCH_ALL:
            return set()

        return {
            CATEGORY_TO_CLASS[x]
            for x in cats
        }

    def classify(self, cwe, max_depth=6):
        """
        -> (TẬP mã lớp, tên quy tắc đã quyết định)

        Trả về TẬP chứ không ép về một lớp: khi CWE-699 xếp một
        weakness vào nhiều category (CWE-639 Authorization Bypass
        thuộc cả Authorization Errors lẫn Business Logic Errors)
        thì MITRE đang nói nó có nhiều mặt. Ép về một lớp bằng
        tie-break là bịa. Mẫu đó vào tập fine-tune của cả hai
        expert.

        Thang quy tắc, dừng ở cái đầu tiên có kết quả:
          0 không thông tin  -> None
          0 override
          1 deprecated redirect
          2 category CWE-699 trực tiếp
          3 leo LÊN cha
          4 leo XUỐNG con (bỏ phiếu đa số)
          5 pillar CWE-1000
        """

        cid = self._num(cwe)

        if not cid.isdigit():
            return set(), "6_không_hợp_lệ"

        if cid in NO_INFO:
            return set(), "0_không_thông_tin"

        if cid in OVERRIDE:
            return {OVERRIDE[cid][0]}, "0_override"

        r = self._redirect(cid)

        if r:
            c, _ = self.classify(r, max_depth)
            return c, "1_deprecated_redirect"

        # Cha TRỰC TIẾP thuộc bảng node mức 2 thì tin nó hơn
        # category CWE-699: node mức 2 do mình chọn theo nghĩa,
        # còn category là cách MITRE xếp theo vòng đời phát
        # triển nên hay mâu thuẫn (CWE-770 "Allocation Without
        # Limits" bị xếp vào cả Resource Management lẫn
        # Business Logic Errors; cha của nó là CWE-400 nói rõ
        # hơn nhiều).
        near = {
            SUBTREE_TO_CLASS[p]
            for p in self.parent.get(cid, ())
            if p in SUBTREE_TO_CLASS
        }

        if near:
            return near, "2a_cha_node2"

        t = self._direct(cid)

        if t:
            return t, "2_category_699"

        # bản thân nó là node mức 2 / pillar
        if cid in SUBTREE_TO_CLASS:
            return {SUBTREE_TO_CLASS[cid]}, "2_node_mức2"

        if cid in PILLAR_TO_CLASS:
            return {PILLAR_TO_CLASS[cid]}, "2_pillar_1000"

        seen = {cid}
        q = deque([(cid, 0)])

        while q:

            cur, d = q.popleft()

            if d >= max_depth:
                continue

            for p in self.parent.get(cur, ()):

                if p in seen:
                    continue

                seen.add(p)

                t = self._direct(p)

                if t:
                    return t, "3_leo_lên"

                if p in SUBTREE_TO_CLASS:
                    return (
                        {SUBTREE_TO_CLASS[p]},
                        "3_leo_lên_node2",
                    )

                q.append((p, d + 1))

        seen = {cid}
        q = deque([(cid, 0)])
        votes = Counter()

        while q:

            cur, d = q.popleft()

            if d >= max_depth:
                continue

            for k in self.child.get(cur, ()):

                if k in seen:
                    continue

                seen.add(k)

                t = self._direct(k)

                if t:
                    for x in t:
                        votes[x] += 1
                else:
                    q.append((k, d + 1))

        if votes:

            best = max(votes.values())

            return (
                {
                    k
                    for k, v in votes.items()
                    if v == best
                },
                "4_leo_xuống",
            )

        seen = {cid}
        q = deque([cid])

        while q:

            cur = q.popleft()

            for p in self.parent.get(cur, ()):

                if p in seen:
                    continue

                seen.add(p)

                if p in SUBTREE_TO_CLASS:
                    return (
                        {SUBTREE_TO_CLASS[p]},
                        "5_node_mức2",
                    )

                if p in PILLAR_TO_CLASS:
                    return (
                        {PILLAR_TO_CLASS[p]},
                        "5_pillar_1000",
                    )

                q.append(p)

        if cid in SUBTREE_TO_CLASS:
            return {SUBTREE_TO_CLASS[cid]}, "5_node_mức2"

        if cid in PILLAR_TO_CLASS:
            return {PILLAR_TO_CLASS[cid]}, "5_pillar_1000"

        # hết đường -> chấp nhận category thùng rác
        fallback = {
            x
            for x in self.cat699.get(cid, ())
            if x in CATCH_ALL
        }

        if fallback:
            return (
                {CATEGORY_TO_CLASS[sorted(fallback)[0]]},
                "5b_catch_all",
            )

        return set(), "6_không_phân_được"

    def classify_one(self, cwe, max_depth=6):
        """Bản 1 lớp, CHỈ dùng để phân tầng báo cáo."""

        t, how = self.classify(cwe, max_depth)

        return _pick(t), how

    def classify_many(self, value):
        """
        Đa nhãn. Nhận '  CWE-416;CWE-502  ' hoặc list.

        -> (lớp chính, list mọi lớp, quy tắc của lớp chính)

        Lớp chính = của CWE đầu tiên phân được. Nên truyền cột
        cwe_pruned (đã bỏ ứng viên là tổ tiên của ứng viên khác),
        vì CWE-476;CWE-703 không phải hai lỗi - 703 chỉ là pillar
        cha của 476.
        """

        if isinstance(value, str):
            items = re.split(r"[;,\s]+", value)
        else:
            items = list(value or [])

        cwes = [
            x.strip()
            for x in items
            if str(x).strip().upper().startswith("CWE-")
        ]

        primary = None
        rule = "6_không_phân_được"
        found = []

        for c in cwes:

            ks, how = self.classify(c)

            if not ks:
                continue

            found.extend(ks)

            if primary is None:
                primary, rule = _pick(ks), how

        return primary, sorted(set(found)), rule


# ============================================================
# CLI: thêm cột vào parquet
# ============================================================

def main():

    import pandas as pd

    path = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else "data/output/ext80.parquet"
    )

    vc = VulnClassifier()

    df = pd.read_parquet(path)

    src = (
        df["cwe_pruned"]
        if "cwe_pruned" in df.columns
        else df["cwe_label_final"]
    )

    cache = {}

    def run(v):

        key = str(v)

        if key not in cache:
            cache[key] = vc.classify_many(v)

        return cache[key]

    out = src.map(run)

    df["vuln_class"] = out.map(lambda x: x[0])

    df["vuln_class_all"] = out.map(
        lambda x: ";".join(x[1])
    )

    df["vuln_class_rule"] = out.map(lambda x: x[2])

    df["vuln_class_name"] = df["vuln_class"].map(
        CLASS_NAME
    )

    df["n_vuln_class"] = df["vuln_class_all"].map(
        lambda s: len(s.split(";")) if s else 0
    )

    lab = (
        df[df["has_line_label"]]
        if "has_line_label" in df.columns
        else df
    )

    n = len(lab)

    ok = int(lab["vuln_class"].notna().sum())

    print(f"{path.name}: {len(df):,} dòng")

    print(
        f"mẫu có nhãn dòng : {n:,}  | "
        f"phân được {ok:,} = {ok / n * 100:.2f}%  | "
        f"sót {n - ok}"
    )

    print("\nQUY TẮC QUYẾT ĐỊNH")

    for k, v in (
        lab["vuln_class_rule"]
        .value_counts()
        .sort_index()
        .items()
    ):
        print(f"  {k:<24}{v:>8,}{v / n * 100:>7.1f}%")

    print("\nLỚP (chính | kể cả đa nhãn)")

    p = lab["vuln_class"].value_counts()

    m = Counter(
        x
        for s in lab["vuln_class_all"]
        for x in s.split(";")
        if x
    )

    for k in CLASS_NAME:
        print(
            f"  {k}  {CLASS_NAME[k]:<28}"
            f"{p.get(k, 0):>7,}{p.get(k, 0) / n * 100:>6.1f}%"
            f"{m[k]:>8,}{m[k] / n * 100:>6.1f}%"
        )

    print(
        f"\n  lệch max/min (đa nhãn): "
        f"{max(m.values()) / min(m.values()):.1f}x"
    )

    print(
        f"  mẫu đa nhãn: "
        f"{int((lab['n_vuln_class'] > 1).sum()):,}"
    )

    df.to_parquet(path, index=False)

    print(f"\nĐÃ GHI: {path}")

    rows = []

    for c in sorted(
        lab["cwe_label_final"].dropna().unique()
    ):
        ks, how = vc.classify(c)

        k = _pick(ks)

        rows.append(
            {
                "cwe": c,
                "name": vc.name.get(
                    VulnClassifier._num(c),
                    "?",
                ),
                "n": int(
                    (lab["cwe_label_final"] == c).sum()
                ),
                "vuln_class": k,
                "vuln_class_all": ";".join(sorted(ks)),
                "vuln_class_name": CLASS_NAME.get(k, ""),
                "rule": how,
            }
        )

    a = Path("data/audit") / f"vuln_class_{path.stem}.csv"

    a.parent.mkdir(parents=True, exist_ok=True)

    (
        pd.DataFrame(rows)
        .sort_values("n", ascending=False)
        .to_csv(a, index=False)
    )

    print(f"audit theo CWE: {a}")


if __name__ == "__main__":
    main()
