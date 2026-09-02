"""
Sinh ground-truth mức dòng cho TitanVul, đa ngôn ngữ.

Thuật toán theo LineVD (Hin et al., MSR 2022) - đã đối chiếu
với code gốc davidhin/linevd, không sao chép code:

    vulnerable = removed  UNION  depadd

Kiến trúc:

    diffalign.py  căn func_before/func_after về một hệ số dòng,
                  comment-out dòng của bản kia (cách của LineVD)
    specs.py      đặc tả node-type cho từng ngôn ngữ - CHỈ chỗ này
                  biết ngôn ngữ cụ thể
    pdg.py        dựng CDG + DDG mức dòng từ cây tree-sitter
    labels.py     ghép nhãn + cổng tin cậy

Khác LineVD: LineVD dùng Joern (chỉ C/C++, có CFG thật). Ở đây
dùng tree-sitter cho 14 ngôn ngữ, reaching-def xấp xỉ theo cấu
trúc. Mẫu nào không phân tích đáng tin thì báo status chứ không
gán nhãn đoán.
"""

from .labels import LineLabel, label_sample
from .specs import LANGUAGE_ALIAS, SPECS, resolve

__all__ = [
    "LineLabel",
    "label_sample",
    "resolve",
    "SPECS",
    "LANGUAGE_ALIAS",
]
