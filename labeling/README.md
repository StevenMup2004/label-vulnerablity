# Sinh nhãn định vị lỗ hổng ở MỨC DÒNG — đa ngôn ngữ

Thư mục này khép kín. Bê nguyên sang máy/dự án khác là chạy được.

## Phương pháp

Theo LineVD (Hin et al., MSR 2022), đã đối chiếu với code gốc
`davidhin/linevd`:

    vulnerable = removed  UNION  depadd

    removed = dòng bị xoá/sửa ở bản vulnerable (thuần từ diff)
    depadd  = dòng trong bản before phụ thuộc control/data vào
              các dòng ĐƯỢC THÊM ở bản fixed — láng giềng 1-hop
              VÔ HƯỚNG trong PDG (REACHING_DEF ∪ CDG) của bản
              after, rồi lọc theo dòng có mặt ở bản before

Khác LineVD: hỗ trợ 17 ngôn ngữ thay vì chỉ C, dùng Joern làm
backend chính và tree-sitter làm dự phòng, xoá comment trước khi
diff, và báo rõ mẫu nào không phân tích được thay vì đoán.

## Cấu trúc

    linelabel/            LÕI — không phụ thuộc pandas
      diffalign.py        căn dòng union + xoá comment giữ số dòng
      labels.py           label_sample(): công thức LineVD
      pdg.py              analyzer tree-sitter, LineGraph, CDG/DDG
      specs.py            node-type spec cho 17 ngôn ngữ
      repair.py           sửa cú pháp để cứu mẫu parse lỗi
      joernpdg.py         bọc joern-cli (chỉ cần nếu dùng Joern)
      joern/dump_pdg.sc   script Scala dump PDG mức dòng

    build_joern_graphs.py   dựng cache PDG bằng Joern (tuỳ chọn)
    build_sven_labels.py    driver ĐƠN GIẢN NHẤT — đọc jsonl → parquet
    build_line_labels.py    driver đầy đủ — cache, đa tiến trình
    take_bigvul_lines.py    ghép nhãn dòng gốc của BigVul
    vuln_class.py           phân loại lỗ hổng 4 lớp từ CWE

## Cài

    pip install -r requirements.txt

Chỉ cần thêm nếu dựng PDG bằng Joern:

  - Joern v4.0.609 + JDK 21, đặt JOERN_HOME / JAVA_HOME
  - PHP 8.3 CÓ nạp extension `phar` và `tokenizer` (nếu xử lý PHP).
    Thiếu hai extension đó thì php-parser.phar rơi vào stub
    Extract_Phar, $argv mất scope, parser chết mà KHÔNG báo lỗi
    rõ — CPG rỗng, dễ tưởng nhầm là Joern không hỗ trợ PHP.

Không có Joern thì mọi thứ vẫn chạy bằng tree-sitter, nhưng đo
được recall của tree-sitter chỉ ~33% so với Joern.

## Dùng nhanh

```python
from linelabel import label_sample
from linelabel.diffalign import align
from linelabel.specs import resolve

r = label_sample(func_before, func_after, "C",
                 max_changed_ratio=0.80,
                 min_changed_lines=10)

# r.vul_lines / r.removed / r.depadd nằm ở toạ độ UNION VIEW,
# KHÔNG phải func_before. Phải quy đổi:
al = align(func_before, func_after, resolve("C"))
bmap = {u: i for i, u in enumerate(sorted(al.before_real), 1)}
vul_fb = [bmap[n] for n in r.vul_lines if n in bmap]
```

**Bước quy đổi cuối là bắt buộc.** Union view chứa cả dòng của bản
after (bị comment-out giữ chỗ) nên số dòng lệch so với func_before
từ dòng added đầu tiên trở đi. Đo trên TitanVul: 77,9% mẫu bị lệch
nếu bỏ qua bước này.

## Chạy driver

```bash
# SVEN
python build_sven_labels.py --max-changed-ratio 0.80 --min-changed-lines 10

# bộ khác, có cache + đa tiến trình
python build_line_labels.py --max-changed-ratio 0.80 --min-changed-lines 10 \
       --tag ext80 --jobs 12

# PDG bằng Joern (chạy TRƯỚC driver để có cache)
python build_joern_graphs.py --langs c,cpp,java,javascript,python,php,go,ruby,csharp
python build_joern_graphs.py --relabel-only      # dò lại ngôn ngữ ghi sai

# phân loại 4 lớp (BND/NTR/PRT/LFC), tự tải catalog CWE
python vuln_class.py <file.parquet>
```

## Tham số

    --max-changed-ratio   bỏ mẫu đổi quá tỉ lệ này (viết lại hàm).
                          0.70 = đúng LineVD (helpers/datasets.py:206)
    --min-changed-lines   chỉ coi là viết lại khi ĐỒNG THỜI đổi >=
                          số dòng này. 0 = đúng LineVD. 10 = bản nới,
                          tránh giết hàm 2 dòng sửa 2 dòng.

## Cache tự vô hiệu

`build_line_labels.py` băm khoá cache từ (func_before, func_after,
language, ratio, min_changed_lines, LABEL_LOGIC_VERSION, joern_sig).

`joern_sig` là chữ ký PDG (số dòng + số edge) nên khi dựng thêm
graph Joern mới, cache tự hết hiệu lực đúng những mẫu đó.

**Nếu sửa LOGIC trong diffalign/labels/pdg thì PHẢI tăng
`LABEL_LOGIC_VERSION`**, không thì kết quả cũ được dùng lại và thay
đổi thành vô hiệu. Đã mắc lỗi này ba lần.

## Đã kiểm chứng

Phần `removed` (thuần diff) đối chiếu với hai bộ nhãn độc lập:

    vs BigVul lines_before   P=0,934  R=0,919  (2.344 mẫu)
    vs SVEN line_changes     P=0,972  R=0,984  (677 mẫu, trùng khít 95,9%)

Mật độ nhãn:

    TitanVul   13,0%
    SCRBench   12,9%   (human-verified, AgenticSCR)

Phần `depadd` KHÔNG cross-validate được — không có ground truth nào
cho nó. Nó chiếm ~70-84% tổng dòng nhãn tuỳ bộ dữ liệu. Khi báo cáo
nên tách hai phần: `removed_lines_fb` (đã kiểm) và `depadd_lines_fb`
(chưa kiểm).

## Giới hạn đã biết

- tree-sitter dùng reaching-def XẤP XỈ theo cấu trúc cây, không có
  CFG thật: không mô hình hoá goto, longjmp, exception nhảy xa,
  con trỏ/alias. Joern không bị.
- depadd là láng giềng 1-hop vô hướng, giống LineVD, không phải bao
  đóng bắc cầu.
- 85,5% mẫu có dòng CHỮ KÝ HÀM trong depadd, vì node METHOD của
  Joern mang lineNumber dòng chữ ký và là def của mọi tham số.
  LineVD cũng vậy (helpers/joern.py chỉ bỏ COMMENT và FILE) nhưng
  chưa ai đo. Nhãn gốc BigVul đánh 0,00%. build_line_labels.py xuất
  thêm cột `vul_lines_nosig_fb` đã bỏ dòng này.
- Joern không xử lý được Rust (cần cargo+rustc), Scala/Lua/Perl
  (không có frontend source). Chúng rơi về tree-sitter.

## Chia train/test

Phải chia theo `project_key`. Chia ngẫu nhiên sẽ rò rỉ: trên TitanVul
riêng Linux chiếm 13% dataset, top-10 project chiếm 34,9%, và các hàm
gần trùng nhau của cùng project sẽ nằm cả ở train lẫn test.
