"""
Phân loại lỗ hổng theo taxonomy CWE-699, KHÔNG fit theo dữ liệu.

Vì sao bỏ cách cũ: bảng gộp trước đây (cwe_groups.py /
cwe_mech_groups.py) quyết định gộp dựa trên SỐ MẪU trong
TitanVul - gộp Information + Control vì chúng chỉ có 801 và
686 mẫu, chẻ Resource vì nó chiếm 54%, ngưỡng 500 lấy từ kích
thước TitanVul, và một tầng gán nhóm theo project đa số. Tất
cả những thứ đó không transfer sang bộ dữ liệu khác.

Ở đây taxonomy được ĐỊNH NGHĨA TRƯỚC, độc lập dữ liệu:

  7 loại = phân hoạch đầy đủ 40 category của view CWE-699,
           lấy từ SecureReviewer (ICSE'26) Table 1
  4 nhóm = gộp 7 loại, mỗi phép gộp biện minh bằng TÊN
           CATEGORY chứ không bằng số mẫu

Cân bằng là tính chất của DỮ LIỆU, không phải của taxonomy.
Trên TitanVul (76% C/C++) Resource chiếm 47%; trên dữ liệu
Python/JS của SecureReviewer nó chỉ 6%. Cùng taxonomy. Chữa
lệch ở vòng train (class weight / oversampling), đừng chữa
bằng cách định nghĩa lại lớp.

Cần: cache/cwec_latest.xml.zip (cwe_hierarchy.py tải về)
"""

import re
import zipfile
import xml.etree.ElementTree as ET

from collections import Counter, defaultdict, deque
from pathlib import Path


ROOT = Path(__file__).resolve().parent

CATALOG = ROOT / "cache" / "cwec_latest.xml.zip"


# ============================================================
# 7 LOẠI = phân hoạch 40 category của CWE-699
# (SecureReviewer ICSE'26, Table 1 - 40/40 category có mặt)
# ============================================================

TYPE_TO_CATEGORIES = {
    "Exception Handling": [
        "389",   # Error Conditions, Return Values, Status Codes
        "429",   # Handler Errors
        "1228",  # API / Function Errors
    ],
    "Concurrency": [
        "557",   # Concurrency Issues
        "387",   # Signal Errors
    ],
    "Input Validation": [
        "1215",  # Data Validation Issues
        "133",   # String Errors
        "137",   # Data Neutralization Issues
    ],
    "Access Control & Info Sec": [
        "1211",  # Authentication Errors
        "1212",  # Authorization Errors
        "1210",  # Audit / Logging Errors
        "255",   # Credentials Management Errors
        "417",   # Communication Channel Errors
        "310",   # Cryptographic Issues
        "320",   # Key Management Errors
        "1216",  # Lockout Mechanism Errors
        "275",   # Permission Issues
        "265",   # Privilege Issues
        "355",   # User Interface Security Issues
        "1217",  # User Session Errors
        "199",   # Information Management Errors
    ],
    "Resource Management": [
        "1218",  # Memory Buffer Errors
        "411",   # Resource Locking Problems
        "465",   # Pointer Issues
        "452",   # Initialization and Cleanup Errors
        "1219",  # File Handling Issues
        "399",   # Resource Management Errors
    ],
    "State Management": [
        "1006",  # Bad Coding Practices
        "438",   # Behavioral Problems
        "840",   # Business Logic Errors
        "1226",  # Complexity Issues
        "1225",  # Documentation Issues
        "371",   # State Issues
    ],
    "Type and Data Handling": [
        "1214",  # Data Integrity Issues
        "1227",  # Encapsulation Issues
        "569",   # Expression Issues
        "1213",  # Random Number Issues
        "189",   # Numeric Errors
        "136",   # Type Errors
        "19",    # Data Processing Errors
    ],
}


CATEGORY_TO_TYPE = {
    c: t
    for t, cs in TYPE_TO_CATEGORIES.items()
    for c in cs
}


# ============================================================
# 7 -> 4. Mỗi phép gộp biện minh bằng TÊN CATEGORY bên trong,
# không bằng số mẫu.
# ============================================================

TYPE_TO_GROUP = {
    # "Resource Locking Problems" (CWE-411) đã nằm trong
    # Resource Management, còn "Concurrency Issues" (CWE-557)
    # lại là loại riêng -> cùng hiện tượng bị chẻ đôi.
    "Resource Management": "Resource",
    "Concurrency": "Resource",

    # "Data Validation Issues" / "Data Integrity Issues" /
    # "Data Processing Errors" - ba category tên gần trùng
    # nhau bị xếp ở hai loại khác nhau.
    "Input Validation": "Data",
    "Type and Data Handling": "Data",

    # "Handler Errors" / "State Issues" / "Behavioral Problems"
    # - đều là "chương trình làm sai bước tiếp theo".
    "Exception Handling": "Behavior",
    "State Management": "Behavior",

    "Access Control & Info Sec": "Policy",
}


# ============================================================
# OVERRIDE - phần DUY NHẤT là phán đoán của tôi.
#
# Chỉ dùng khi cây CWE cho kết quả sai về NGHĨA, hoặc khi node
# bị khai tử và đã bị rút sạch liên kết nên không leo được.
# Mỗi dòng kèm lý do. KHÔNG dòng nào dựa trên số mẫu.
# ============================================================

OVERRIDE = {
    # cây để CWE-384 dưới CWE-610 -> pillar CWE-664 -> Resource,
    # nhưng session fixation là lỗi quản lý phiên
    "384": ("Access Control & Info Sec",
            "session fixation là lỗi quản lý phiên, không phải "
            "quản lý tài nguyên (cây MITRE xếp qua CWE-610)"),

    # category NVD đời cũ, đã bị rút sạch member -> không leo được
    "264": ("Access Control & Info Sec",
            "category cũ 'Permissions, Privileges, and Access "
            "Controls' - tên đã nói rõ"),
    "16":  ("State Management",
            "category cũ 'Configuration'"),
    "21":  ("Resource Management",
            "category cũ 'Pathname Traversal' -> File Handling"),
    "534": ("Access Control & Info Sec",
            "'Information Exposure Through Debug Log'"),
}


# CWE không mang thông tin gì -> để unknown, KHÔNG đoán
NO_INFO = {
    "17",   # DEPRECATED: Code
    "18",   # DEPRECATED: Source Code
}


# ============================================================
# PILLAR CWE-1000 -> 7 loại. Lưới an toàn cuối cùng: mọi CWE
# đều có pillar, kể cả CWE phần cứng hoặc CWE mới MITRE thêm.
# ============================================================

PILLAR_TO_TYPE = {
    "284": "Access Control & Info Sec",
    "693": "Access Control & Info Sec",
    "664": "Resource Management",
    "682": "Type and Data Handling",
    "697": "Type and Data Handling",
    "691": "State Management",
    "710": "State Management",
    "435": "State Management",
    "703": "Exception Handling",
    "707": "Input Validation",
}


_DEPRECATED_REDIRECT = re.compile(
    r"(?:duplicate of|transferred to|replaced by)\s+CWE-(\d+)",
    re.I,
)


class Catalog:
    """Cây CWE nạp từ cwec_latest.xml.zip."""

    def __init__(self, path=CATALOG):

        z = zipfile.ZipFile(path)

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

            d = w.find(tag("Description"))

            self.text[i] = (
                d.text or ""
                if d is not None
                else ""
            )

            rel = w.find(
                tag("Related_Weaknesses")
            )

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
                s.text or ""
                if s is not None
                else ""
            )

            rel = c.find(tag("Relationships"))

            if rel is None:
                continue

            for x in rel:

                m = x.get("CWE_ID")

                # category cũng có con, cần cho lượt leo xuống
                self.child[i].add(m)

                if x.get("View_ID") == "699":
                    self.cat699[m].add(i)

    # --------------------------------------------------------

    def redirect(self, cid):
        """CWE deprecated -> CWE thay thế, đọc từ chính mô tả."""

        if not str(
            self.name.get(cid, "")
        ).startswith("DEPRECATED"):
            return None

        m = _DEPRECATED_REDIRECT.search(
            self.text.get(cid, "") or ""
        )

        return m.group(1) if m else None

    def direct(self, cid):
        """Loại suy ra trực tiếp: bản thân là category, hoặc là member."""

        if cid in CATEGORY_TO_TYPE:
            return {CATEGORY_TO_TYPE[cid]}

        return {
            CATEGORY_TO_TYPE[x]
            for x in self.cat699.get(cid, ())
            if x in CATEGORY_TO_TYPE
        }

    def classify(self, cwe, max_depth=6):
        """
        -> (set 7-loại, tên quy tắc đã quyết định)

        Thứ tự: override -> redirect -> category trực tiếp ->
        leo lên cha -> leo xuống con (đa số) -> pillar CWE-1000
        """

        cid = (
            str(cwe)
            .strip()
            .upper()
            .replace("CWE-", "")
        )

        if cid in NO_INFO:
            return set(), "0_không_thông_tin"

        if cid in OVERRIDE:
            return {OVERRIDE[cid][0]}, "0_override"

        r = self.redirect(cid)

        if r:
            t, _ = self.classify(r, max_depth)
            return t, "1_deprecated_redirect"

        t = self.direct(cid)

        if t:
            return t, "2_category_699"

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

                t = self.direct(p)

                if t:
                    return t, "3_leo_lên"

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

                t = self.direct(k)

                if t:
                    for x in t:
                        votes[x] += 1
                else:
                    q.append((k, d + 1))

        if votes:

            top = max(votes.values())

            return (
                {
                    x
                    for x, v in votes.items()
                    if v == top
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

                if p in PILLAR_TO_TYPE:
                    return (
                        {PILLAR_TO_TYPE[p]},
                        "5_pillar_1000",
                    )

                q.append(p)

        if cid in PILLAR_TO_TYPE:
            return {PILLAR_TO_TYPE[cid]}, "5_pillar_1000"

        return set(), "6_không_phân_được"


def group_of(vtype):
    """7 loại -> 4 nhóm."""

    return TYPE_TO_GROUP.get(vtype)
