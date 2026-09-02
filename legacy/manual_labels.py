"""
Nhãn gán tay cho 43 mẫu cuối cùng.

Đây là các mẫu chỉ còn đúng một nguồn tín hiệu: không có
commit_link để dựng repo prior, code lại là macro hoặc
dùng API lạ nên rule cú pháp và token prior đều không
đủ chắc.

Từng mẫu đã được đọc trực tiếp. Căn cứ ghi kèm bên dưới
là hệ sinh thái nhận ra được từ tên hàm / tên kiểu.

Kết luận chung: cả 43 mẫu đều thuộc nhóm C/C++.
Không mẫu nào thực sự là JavaScript, Python hay Go.

Điểm đáng chú ý là 8 mẫu đang bị gán SAI nhóm. Chúng đều
rơi vào một kiểu: hàm không có chữ ký kiểu C nhìn thấy
được, vì thân hàm nằm trong macro.

    DECLAREContigPutFunc(putcontig8bitYCbCr41tile)   libtiff
    WRITE_JSON_ELEMENT(ArrStart)                     open62541
    reset_scroll_region(NCURSES_SP_DCL0)             ncurses

Không có kiểu trả về, không có tham số có kiểu, không có
con trỏ. Rule cú pháp không có gì để bám. Đây là giới hạn
thật của phương pháp, không phải thiếu regex.
"""

# idx -> (nhóm, căn cứ)
MANUAL_LABELS = {

    # ========================================================
    # 8 MẪU BỊ GÁN SAI - sửa lại
    # ========================================================

    2338:  ("C/C++", "libtiff DECLAREContigPutFunc macro, int32/YCbCrtoRGB"),
    3776:  ("C/C++", "libtiff DECLAREContigPutFunc macro, uint32* cp1"),
    18705: ("C/C++", "libtiff DECLAREContigPutFunc macro, YCbCrtoRGB"),
    26090: ("C/C++", "ncurses reset_scroll_region, NCURSES_SP_DCL0/TPARM_2"),

    13552: ("C/C++", "ceph MonCapParser, Boost.Spirit qi:: - C++"),

    17633: ("C/C++", "postgres SocketBackend, StringInfo/pq_getbyte/ereport"),
    22715: ("C/C++", "postgres RecoveryConflictInterrupt, ProcSignalReason"),
    17915: ("C/C++", "little-cms AddConversion, cmsBool/cmsPipeline/cmsMAT3"),

    # ========================================================
    # 35 MẪU ĐÃ ĐÚNG - xác nhận bằng mắt
    # ========================================================

    # ncurses (C)
    1234:  ("C/C++", "ncurses drv_initpair, TERMINAL_CONTROL_BLOCK/SCREEN"),
    21246: ("C/C++", "ncurses drv_setcolor, NCURSES_SP_OUTC"),
    23509: ("C/C++", "ncurses scroll_idl, NCURSES_CH_T/NCURSES_PUTP2"),

    # Ruby C extension (C)
    4857:  ("C/C++", "ruby/date C ext, VALUE/rb_scan_args/INT2FIX"),
    8734:  ("C/C++", "ruby/date C ext, VALUE/rb_scan_args"),
    17243: ("C/C++", "ruby/date C ext, VALUE/rb_str_new2"),
    22018: ("C/C++", "ruby/date C ext, VALUE/rb_scan_args"),
    27938: ("C/C++", "ruby/date C ext, VALUE/rb_scan_args"),
    30967: ("C/C++", "ruby/date C ext, VALUE/rb_scan_args"),
    31378: ("C/C++", "ruby/date C ext, VALUE/rb_scan_args"),
    32064: ("C/C++", "ruby/date C ext, VALUE/Qtrue/INT2FIX"),
    34054: ("C/C++", "ruby/date C ext, VALUE/d_new_by_frags"),
    34285: ("C/C++", "ruby/date C ext, VALUE/dt_new_by_frags"),
    36996: ("C/C++", "ruby/date C ext, VALUE/rb_scan_args"),
    38058: ("C/C++", "ruby/date C ext, VALUE/Qtrue"),
    17825: ("C/C++", "ruby/tk C ext, VALUE/rb_obj_class/NIL_P"),
    25893: ("C/C++", "ruby/openssl C ext, ossl_x509name_cmp/INT2FIX"),
    28503: ("C/C++", "ruby fiddle C ext, StringValueCStr/RTLD_NEXT"),

    # GLib / GNOME (C)
    5517:  ("C/C++", "vte vte_sequence_handler_multiple, VteTerminal/G_MAXLONG"),
    17388: ("C/C++", "libcroco cr_input_read_byte, guchar/g_return_val_if_fail"),

    # C++ thuần
    10430: ("C/C++", "CGAL SM_io_parser<Decorator_>::read_face - template C++"),
    11402: ("C/C++", "libdxfrw dwgCompressor::litLength18 - C++"),
    32213: ("C/C++", "libdxfrw dwgCompressor::longCompressionOffset - C++"),
    13217: ("C/C++", "envoy TEST_F gtest, Http::TestRequestHeaderMapImpl - C++"),
    38135: ("C/C++", "envoy TEST_F gtest, Http::Headers::get() - C++"),

    # C khác
    5521:  ("C/C++", "X11 x_catch_free_colors, Display*/XErrorEvent*"),
    6270:  ("C/C++", "zziplib zzip_mem_disk_findfirst, ZZIP_MEM_DISK*"),
    15306: ("C/C++", "ghostscript zsetstrokecolorspace, i_ctx_t*/check_estack"),
    26081: ("C/C++", "ghostscript zsetstrokecolor, i_ctx_t*"),
    20056: ("C/C++", "open62541 WRITE_JSON_ELEMENT macro, ctx->commaNeeded"),
    23631: ("C/C++", "open62541 WRITE_JSON_ELEMENT macro, writeChar"),
    23747: ("C/C++", "postgres _equalConstraint, COMPARE_SCALAR_FIELD macro"),
    25745: ("C/C++", "GNU grep prtok, char const*/fprintf/NOTCHAR"),
    27188: ("C/C++", "test printf %p, PTR1_ZEROES macro - C"),
    34158: ("C/C++", "aubio new_aubio_filterbank, uint_t/AUBIO_NEW"),
}
