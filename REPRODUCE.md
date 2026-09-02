# Tái lập trên máy khác

## 1. Cần copy gì

### Bắt buộc — code (~250 KB)

```
full_process.py            khôi phục CVE/CWE (7 phương pháp)
build_cwe_labels.py        thang 9 nguồn -> cwe_label_final
take_bigvul_lines.py       lấy nhãn dòng gốc của BigVul
build_joern_graphs.py      dựng PDG bằng Joern
build_line_labels.py       sinh nhãn dòng
vuln_class.py              phân loại 4 lớp (BND/NTR/PRT/LFC)
cwe_hierarchy.py           tải + phân tích cây CWE
linelabel/                 __init__ diffalign labels pdg specs repair joernpdg
linelabel/joern/dump_pdg.sc
```

Bỏ qua: `cwe_groups.py`, `cwe_mech_groups.py`, `add_cwe_groups.py`,
`vuln_type.py`, `add_vuln_type.py` — các bản phân loại cũ đã bị thay.

### Bắt buộc — dữ liệu (~740 MB)

```
data/input/TitanVul_language_FINAL.parquet     90 MB   đầu vào gốc
data/output/TitanVul_line_labels_bigvul.parquet 66 MB  đã có nhãn BigVul
data/output/ext80.parquet                      76 MB   KẾT QUẢ (ratio .80, K=10)
data/output/joern70.parquet                    75 MB   KẾT QUẢ (ratio .70, LineVD)
cache/joern_graphs.parquet                     37 MB   PDG Joern - RẤT ĐẮT nếu mất
cache/linelabel_cache.parquet                  43 MB   cache nhãn dòng
cache/cwec_latest.xml.zip                       2 MB   catalog MITRE
cache/bigvul/                                1128 MB   chỉ cần nếu chạy lại take_bigvul_lines.py
```

Nếu chỉ cần DÙNG nhãn (không chạy lại pipeline): copy `ext80.parquet`
hoặc `joern70.parquet` là đủ. 76 MB.

### Chỉ cần nếu chạy lại full_process.py (~2.3 GB)

```
cache/osv_all.zip              1440 MB
cache/cvelistV5_latest.zip      616 MB
cache/nvd_feeds/                214 MB
cache/*_scan_cache.json.gz      các cache quét
```

Ba file này tải lại được từ nguồn gốc (OSV, CVE.org, NVD) nhưng mất
vài giờ. Nhãn CVE/CWE đã nằm sẵn trong parquet đầu ra nên thường
không cần chạy lại.

## 2. Môi trường

```bash
python -m venv venv
venv/bin/pip install pandas pyarrow tree_sitter tree_sitter_language_pack requests
```

Chỉ cần thêm nếu DỰNG LẠI PDG (`build_joern_graphs.py`):

- **Joern v4.0.609** + **JDK 21** — đặt `JOERN_HOME`, `JAVA_HOME`
- **PHP 8.3** có nạp extension `phar` và `tokenizer`.
  php2cpg gọi `php` qua PATH; thiếu hai extension đó thì
  `php-parser.phar` rơi vào stub `Extract_Phar`, `$argv` mất scope,
  parser chết mà KHÔNG báo lỗi rõ - CPG rỗng.

  ```bash
  # bản giải nén không cần quyền root
  apt-get download php8.3-cli php8.3-common
  dpkg -x php8.3-cli_*.deb root; dpkg -x php8.3-common_*.deb root
  cat > php <<'SH'
  #!/bin/sh
  exec "$PWD/root/usr/bin/php8.3" \
    -d extension_dir="$PWD/root/usr/lib/php/20230831" \
    -d extension=phar.so -d extension=tokenizer.so \
    -d extension=ctype.so -d extension=iconv.so "$@"
  SH
  chmod +x php && export PATH="$PWD:$PATH"
  ```

Rust / Objective-C / Scala / Lua: Joern không xử lý được (rust2cpg cần
cargo+rustc, không có frontend cho scala/lua). Chúng rơi về tree-sitter.

## 3. Thứ tự chạy

```bash
# (tuỳ chọn) khôi phục CVE/CWE - cần các cache lớn
python full_process.py
python build_cwe_labels.py

# nhãn dòng gốc của BigVul
python take_bigvul_lines.py

# PDG bằng Joern - cần Joern + JDK + PHP; bỏ qua nếu đã có
# cache/joern_graphs.parquet
python build_joern_graphs.py --langs c,cpp,java,javascript,python,php,go,ruby,csharp,typescript,swift
python build_joern_graphs.py --relabel-only     # dò lại ngôn ngữ ghi sai

# nhãn dòng - dùng cache nên chạy ~2 phút nếu cache còn
python build_line_labels.py --max-changed-ratio 0.80 --min-changed-lines 10 --tag ext80
python build_line_labels.py --max-changed-ratio 0.70 --min-changed-lines 0  --tag joern70

# phân loại 4 lớp
python cwe_hierarchy.py          # tải cache/cwec_latest.xml.zip nếu chưa có
python vuln_class.py data/output/ext80.parquet
python vuln_class.py data/output/joern70.parquet
```

## 4. Cache tự vô hiệu

`build_line_labels.py` băm khoá cache từ `(func_before, func_after,
language, ratio, min_changed_lines, LABEL_LOGIC_VERSION, joern_sig)`.

`joern_sig` là chữ ký PDG (số dòng + số edge). Nhờ vậy khi dựng thêm
graph Joern mới thì cache tự hết hiệu lực đúng những mẫu đó. Nếu sửa
LOGIC gán nhãn (diffalign/labels/pdg) thì **phải tăng
`LABEL_LOGIC_VERSION`** trong `build_line_labels.py`, không thì kết
quả cũ được dùng lại và thay đổi thành vô hiệu.

## 5. Kiểm tra tái lập đúng

```
ext80.parquet     21.720 dòng, 20.870 có nhãn dòng (96,09%)
joern70.parquet   21.720 dòng, 20.061 có nhãn dòng (92,36%)
vuln_class        BND 7.632 / NTR 5.004 / PRT 4.283 / LFC 3.911, sót 40
removed vs BigVul P=0,934  R=0,919
tỉ lệ dòng lỗi    13,0%   (SCRBench human-verified: 12,9%)
```

## 6. Cột dùng khi train

```
vul_lines_fb        nhãn chính, đánh số trên func_before
vul_lines_nosig_fb  bản bỏ dòng chữ ký hàm
removed_lines_fb    P=0,93 - nên đánh trọng số cao
depadd_lines_fb     chưa cross-validate được - trọng số thấp hơn
vuln_class_all      4 lớp, đa nhãn
label_completeness  full / bigvul / removed_only
line_status         joern_* = PDG thật; ok_* = tree-sitter (recall 32,9%)
project_key         BẮT BUỘC chia train/test theo cột này
```

Hai bẫy:

- Cột KHÔNG có hậu tố `_fb` nằm ở hệ toạ độ union (có cả dòng của bản
  after), **đừng ánh xạ vào `func_before`** - 77,9% mẫu sẽ lệch.
- Chia ngẫu nhiên sẽ rò rỉ: Linux chiếm 13% dataset, top-10 project
  chiếm 34,9%.
