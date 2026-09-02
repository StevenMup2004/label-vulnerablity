"""
Gộp CWE thành nhóm theo DẤU HIỆU Ở MỨC CODE.

Vì sao không dùng cây MITRE: chạy cwe_hierarchy.py cho thấy
pillar CWE-664 nuốt 50,7% dataset (93 CWE, 10.584 mẫu), và
CWE-476 (null deref) rơi vào CWE-710 "Improper Adherence to
Coding Standards" - vô nghĩa với bài toán định vị dòng. Bảng
dưới gộp theo cái mà bộ định vị phải NHẬN RA, nên CWE cùng
nhóm chia sẻ mẫu hình code.

Vài quyết định lệch khỏi cây MITRE, có chủ ý:
  - 476 đứng riêng (1.006 mẫu, mẫu hình thiếu check NULL rất
    đặc trưng, trộn với UAF sẽ làm mờ tín hiệu)
  - 193 off-by-one -> mem_spatial theo HẬU QUẢ, dù MITRE để
    dưới lỗi số học
  - 843 type confusion, 134 format string -> theo hậu quả
  - 352/384/613/601 tách khỏi access_control thành web_session
    (lỗi luồng request web, không phải lỗi kiểm tra quyền)
  - 918 SSRF -> injection (kẻ tấn công điều khiển URL)
"""

GROUPS = {
    "mem_spatial":      "Bộ nhớ - ngoài biên (đọc/ghi)",
    "mem_lifetime":     "Bộ nhớ/tài nguyên - vòng đời",
    "null_deref":       "Null pointer dereference",
    "numeric":          "Lỗi số học",
    "injection":        "Injection / neutralization",
    "path_file":        "Đường dẫn & tài nguyên file",
    "access_control":   "Kiểm soát truy cập & xác thực",
    "web_session":      "Phiên web / request forgery",
    "crypto":           "Mật mã & bí mật",
    "concurrency":      "Tương tranh",
    "dos_resource":     "Cạn kiệt tài nguyên / DoS",
    "error_handling":   "Xử lý lỗi & luồng điều khiển",
    "info_exposure":    "Lộ thông tin",
    "input_validation": "Kiểm tra đầu vào (chung chung)",
    "other":            "Khác / nhãn không đủ cụ thể",
}


_RAW = {
    "mem_spatial": [125, 787, 119, 120, 121, 122, 123, 124, 126, 127, 128,
                    129, 131, 170, 193, 680, 786, 788, 805, 806, 823, 843],
    "mem_lifetime": [416, 415, 401, 399, 404, 457, 459, 590, 626, 665, 666,
                     672, 761, 762, 763, 772, 824, 825, 908, 909, 911, 1341],
    "null_deref": [476, 690],
    "numeric": [190, 191, 189, 194, 195, 196, 197, 369, 466, 681, 682, 1339],
    "injection": [74, 77, 78, 79, 80, 88, 89, 90, 91, 93, 94, 96, 113, 116,
                  117, 134, 150, 159, 172, 173, 176, 184, 185, 228, 235, 444,
                  470, 502, 565, 611, 913, 915, 917, 918, 943, 1236, 1321],
    "path_file": [22, 23, 29, 36, 41, 59, 61, 73, 98, 377, 378, 379, 426,
                  427, 428, 434, 552, 620, 641],
    "access_control": [250, 264, 266, 269, 270, 271, 273, 275, 276, 280, 281,
                       284, 285, 287, 288, 290, 294, 303, 305, 306, 307, 425,
                       521, 522, 639, 640, 732, 749, 798, 842, 862, 863, 1187],
    "web_session": [346, 352, 384, 601, 613, 942, 1021, 1275],
    "crypto": [295, 297, 310, 311, 312, 319, 320, 321, 322, 323, 325, 326,
               327, 328, 330, 331, 335, 337, 338, 344, 345, 347, 354, 358,
               759, 760, 916],
    "concurrency": [362, 364, 365, 366, 367, 543, 662, 667, 833, 1088, 1223],
    "dos_resource": [400, 405, 406, 407, 409, 606, 674, 770, 774, 776, 789,
                     834, 835, 920, 1050, 1333],
    "error_handling": [241, 248, 252, 253, 388, 390, 391, 393, 436, 460, 617,
                       636, 670, 684, 696, 703, 704, 705, 706, 754, 755, 1077],
    "info_exposure": [200, 203, 208, 209, 212, 213, 215, 226, 359, 402, 497,
                      524, 526, 532, 534, 538, 668, 922, 924, 1258],
    "input_validation": [20, 1173, 1284, 1287],
}


CWE_TO_GROUP = {
    cwe: g
    for g, cwes in _RAW.items()
    for cwe in cwes
}


# CWE ở cấp CATEGORY/CLASS: vẫn gộp được nhưng nhãn KHÔNG đủ
# cụ thể để đánh giá chi tiết. 27,8% dataset rơi vào đây, riêng
# CWE-20 đã là 1.570 mẫu - "Improper Input Validation" là nhãn
# thùng rác, tràn biên do thiếu validate cũng CWE-20, XSS cũng
# CWE-20. Lọc `cwe_label_precise == True` khi báo cáo kết quả.
IMPRECISE = {
    16, 17, 18, 19, 20, 21, 119, 189, 254, 255, 264, 284, 310, 399,
    404, 664, 668, 674, 691, 693, 703, 707, 710, 834, 1103, 1173,
}


def parse(label):
    """'CWE-125' -> 125 ; giá trị lạ -> None"""

    try:
        return int(
            str(label)
            .strip()
            .upper()
            .replace("CWE-", "")
        )

    except Exception:
        return None


def group_of(label):

    n = parse(label)

    if n is None:
        return "other"

    return CWE_TO_GROUP.get(n, "other")


def is_precise(label):

    n = parse(label)

    if n is None:
        return False

    return n not in IMPRECISE
