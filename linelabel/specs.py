"""
Đặc tả node-type cho từng ngôn ngữ.

Đây là chỗ duy nhất chứa kiến thức riêng của từng ngôn ngữ.
pdg.py hoàn toàn không biết mình đang phân tích ngôn ngữ nào.

Grammar tree-sitter đặt tên khá thống nhất (if_statement,
while_statement, assignment_expression, identifier, comment...),
nên DEFAULT phủ được phần lớn. Chỉ override chỗ thật sự khác.

Mỗi spec khai báo:

  control   node type mở ra một vùng phụ thuộc điều khiển.
            Cần biết đâu là ĐIỀU KIỆN (predicate) và đâu là THÂN.
            Khai báo bằng tên field của grammar; thiếu field thì
            fallback: predicate = dòng đầu của node, thân = phần còn lại.

  assign    node type gán giá trị -> định nghĩa biến ở phía trái.
  declare   node type khai báo biến.
  param     node type tham số hàm (định nghĩa ở dòng đầu hàm).
  incdec    node type ++/-- (vừa đọc vừa ghi).
  ident     node type của một danh định.
  comment   node type comment -> LOẠI khỏi graph (giống LineVD).
  func      node type định nghĩa hàm.
  string    node type literal chuỗi -> không lấy ident bên trong.
"""

DEFAULT = {
    "control": {
        "if_statement": ("condition", "consequence"),
        "while_statement": ("condition", "body"),
        "for_statement": (None, "body"),
        "do_statement": ("condition", "body"),
        "switch_statement": ("value", "body"),
        "switch_expression": ("value", "body"),
        "try_statement": (None, "body"),
        "catch_clause": (None, "body"),
        "case_statement": (None, None),
        "else_clause": (None, None),
        "for_range_loop": (None, "body"),
        "labeled_statement": (None, None),
    },

    "assign": (
        "assignment_expression",
        "assignment",
        "augmented_assignment_expression",
        "augmented_assignment",
        "compound_assignment_expr",
        "short_var_declaration",
        "assignment_statement",
    ),

    "declare": (
        "declaration",
        "init_declarator",
        "variable_declaration",
        "variable_declarator",
        "local_variable_declaration",
        "let_declaration",
        "lexical_declaration",
        "var_declaration",
        "field_declaration",
        "const_declaration",
    ),

    "param": (
        "parameter_declaration",
        "parameter",
        "formal_parameter",
        "required_parameter",
        "optional_parameter",
        "simple_parameter",
        "typed_parameter",
        "identifier_pattern",
    ),

    "incdec": (
        "update_expression",
        "unary_expression",
        "postfix_expression",
        "prefix_expression",
    ),

    "ident": (
        "identifier",
        "field_identifier",
        "type_identifier",
        "variable_name",
        "name",
        "simple_identifier",
        "shorthand_property_identifier",
    ),

    "comment": (
        "comment",
        "line_comment",
        "block_comment",
        "shebang",
    ),

    "func": (
        "function_definition",
        "function_declaration",
        "method_definition",
        "method_declaration",
        "function_item",
        "constructor_declaration",
        "function_declarator",
        "lambda",
        "arrow_function",
    ),

    "string": (
        "string_literal",
        "string",
        "raw_string_literal",
        "char_literal",
        "character_literal",
        "interpreted_string_literal",
        "encapsed_string",
        "template_string",
    ),
}


def _merge(**over):
    """Tạo spec mới từ DEFAULT, gộp thêm/ghi đè."""

    spec = {
        k: (
            dict(v)
            if isinstance(v, dict)
            else tuple(v)
        )
        for k, v in DEFAULT.items()
    }

    for key, value in over.items():

        if isinstance(
            value,
            dict,
        ):

            spec[key] = {
                **spec[key],
                **value,
            }

        else:

            spec[key] = tuple(
                spec[key]
            ) + tuple(
                value
            )

    return spec


# ============================================================
# OVERRIDE THEO NGÔN NGỮ
# ============================================================

SPECS = {

    "c": _merge(),

    "cpp": _merge(
        control={
            "for_range_loop": (None, "body"),
        },
    ),

    "java": _merge(
        control={
            "enhanced_for_statement": (None, "body"),
            "synchronized_statement": (None, "body"),
        },
        declare=(
            "local_variable_declaration",
        ),
    ),

    "csharp": _merge(
        control={
            "foreach_statement": (None, "body"),
            "using_statement": (None, "body"),
            "lock_statement": (None, "body"),
        },
        declare=(
            "variable_declaration",
            "variable_declarator",
        ),
    ),

    "javascript": _merge(
        control={
            "for_in_statement": (None, "body"),
            "for_of_statement": (None, "body"),
        },
        declare=(
            "variable_declarator",
        ),
    ),

    "typescript": _merge(
        control={
            "for_in_statement": (None, "body"),
        },
        declare=(
            "variable_declarator",
        ),
    ),

    # Python: khối theo thụt lề, field 'body' là block
    "python": _merge(
        control={
            "if_statement": ("condition", "consequence"),
            "while_statement": ("condition", "body"),
            "for_statement": (None, "body"),
            "with_statement": (None, "body"),
            "try_statement": (None, "body"),
            "except_clause": (None, None),
            "elif_clause": ("condition", "consequence"),
            "else_clause": (None, "body"),
            "match_statement": ("subject", "body"),
            "case_clause": (None, None),
        },
        assign=(
            "assignment",
            "augmented_assignment",
        ),
        param=(
            "default_parameter",
            "typed_default_parameter",
            "list_splat_pattern",
            "dictionary_splat_pattern",
        ),
        func=(
            "function_definition",
        ),
    ),

    "ruby": _merge(
        control={
            "if": ("condition", "consequence"),
            "unless": ("condition", "consequence"),
            "while": ("condition", "body"),
            "until": ("condition", "body"),
            "for": (None, "body"),
            "case": ("value", None),
            "when": (None, "body"),
            "begin": (None, None),
            "rescue": (None, "body"),
            "do_block": (None, None),
            "block": (None, None),
        },
        assign=(
            "assignment",
            "operator_assignment",
        ),
        func=(
            "method",
            "singleton_method",
        ),
        ident=(
            "instance_variable",
            "global_variable",
            "class_variable",
        ),
    ),

    "go": _merge(
        control={
            "if_statement": ("condition", "consequence"),
            "for_statement": (None, "body"),
            "expression_switch_statement": ("value", None),
            "type_switch_statement": (None, None),
            "select_statement": (None, None),
            "expression_case": (None, None),
            "default_case": (None, None),
        },
        assign=(
            "assignment_statement",
            "short_var_declaration",
            "inc_statement",
            "dec_statement",
        ),
        declare=(
            "var_declaration",
            "var_spec",
            "const_spec",
        ),
        func=(
            "function_declaration",
            "method_declaration",
            "func_literal",
        ),
    ),

    "php": _merge(
        control={
            "if_statement": ("condition", "body"),
            "else_if_clause": ("condition", "body"),
            "else_clause": (None, "body"),
            "while_statement": ("condition", "body"),
            "do_statement": ("condition", "body"),
            "for_statement": (None, "body"),
            "foreach_statement": (None, "body"),
            "switch_statement": ("condition", "body"),
            "case_statement": (None, None),
            "try_statement": (None, "body"),
            "catch_clause": (None, "body"),
        },
        assign=(
            "assignment_expression",
            "augmented_assignment_expression",
        ),
        ident=(
            "variable_name",
        ),
        func=(
            "function_definition",
            "method_declaration",
            "anonymous_function",
        ),
    ),

    "rust": _merge(
        control={
            "if_expression": ("condition", "consequence"),
            "while_expression": ("condition", "body"),
            "loop_expression": (None, "body"),
            "for_expression": (None, "body"),
            "match_expression": ("value", "body"),
            "match_arm": (None, None),
            "else_clause": (None, None),
        },
        assign=(
            "assignment_expression",
            "compound_assignment_expr",
        ),
        declare=(
            "let_declaration",
        ),
        func=(
            "function_item",
            "closure_expression",
        ),
    ),

    "scala": _merge(
        control={
            "if_expression": ("condition", "consequence"),
            "while_expression": ("condition", "body"),
            "for_expression": (None, "body"),
            "match_expression": ("value", "body"),
            "case_clause": (None, "body"),
            "try_expression": (None, "body"),
        },
        assign=(
            "assignment_expression",
        ),
        declare=(
            "val_definition",
            "var_definition",
            "val_declaration",
            "var_declaration",
        ),
        func=(
            "function_definition",
            "function_declaration",
        ),
    ),

    "kotlin": _merge(
        control={
            "if_expression": ("condition", "consequence"),
            "while_statement": ("condition", "body"),
            "for_statement": (None, "body"),
            "when_expression": (None, None),
            "when_entry": (None, None),
            "try_expression": (None, "body"),
        },
        declare=(
            "property_declaration",
        ),
        func=(
            "function_declaration",
        ),
    ),

    # Objective-C: cú pháp C mở rộng
    "objc": _merge(
        control={
            "for_in_statement": (None, "body"),
            "@autoreleasepool_statement": (None, None),
        },
        assign=(
            "assignment_expression",
        ),
        declare=(
            "declaration",
            "init_declarator",
        ),
        func=(
            "function_definition",
            "method_definition",
            "class_implementation",
        ),
    ),

    "swift": _merge(
        control={
            "if_statement": (None, None),
            "guard_statement": (None, None),
            "while_statement": (None, None),
            "for_statement": (None, None),
            "repeat_while_statement": (None, None),
            "switch_statement": (None, None),
            "switch_entry": (None, None),
            "do_statement": (None, None),
            "catch_block": (None, None),
        },
        assign=(
            "assignment",
        ),
        declare=(
            "property_declaration",
        ),
        param=(
            "parameter",
        ),
        func=(
            "function_declaration",
            "init_declaration",
            "lambda_literal",
        ),
        ident=(
            "simple_identifier",
        ),
    ),

    "lua": _merge(
        control={
            "if_statement": ("condition", "consequence"),
            "elseif_statement": ("condition", "consequence"),
            "else_statement": (None, None),
            "while_statement": ("condition", "body"),
            "repeat_statement": ("condition", "body"),
            "for_statement": (None, "body"),
            "for_numeric_clause": (None, None),
            "for_generic_clause": (None, None),
        },
        assign=(
            "assignment_statement",
            "variable_assignment",
        ),
        declare=(
            "local_variable_declaration",
            "variable_declaration",
        ),
        func=(
            "function_declaration",
            "function_definition",
            "local_function_declaration",
        ),
        comment=(
            "comment",
        ),
    ),

    "perl": _merge(
        control={
            "conditional_statement": (None, None),
            "loop_statement": (None, None),
        },
        ident=(
            "scalar_variable",
            "array_variable",
            "hash_variable",
        ),
    ),
}


# ============================================================
# ÁNH XẠ TÊN NGÔN NGỮ CỦA TITANVUL -> PARSER
# ============================================================

LANGUAGE_ALIAS = {
    "c": "c",
    "c++": "cpp",
    "cpp": "cpp",
    "c/c++": "c",
    "java": "java",
    "javascript": "javascript",
    "typescript": "typescript",
    "python": "python",
    "php": "php",
    "ruby": "ruby",
    "go": "go",
    "c#": "csharp",
    "csharp": "csharp",
    "rust": "rust",
    "scala": "scala",
    "kotlin": "kotlin",
    "perl": "perl",
    "objective-c": "objc",
    "objective-c++": "objc",
    "objectivec": "objc",
    "objc": "objc",
    "swift": "swift",
    "lua": "lua",
}


def resolve(language):
    """
    Tên ngôn ngữ trong TitanVul -> khoá parser, hoặc None nếu
    KHÔNG hỗ trợ. Trả None là cố ý: dòng đó sẽ bị đánh
    unsupported_language chứ không gán nhãn đoán.
    """

    if not isinstance(
        language,
        str,
    ):
        return None

    return LANGUAGE_ALIAS.get(
        language.strip().lower()
    )
