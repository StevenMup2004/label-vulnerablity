"""
Backend PDG dùng Joern — thay cho tree-sitter.

Vì sao cần: tree-sitter chỉ có cây cú pháp, nên reaching-def của
pdg.py là XẤP XỈ theo cấu trúc, và code C/C++ nhiều macro thì
parse lỗi. Joern dựng CPG có CFG thật và frontend C/C++ của nó
(Eclipse CDT ở chế độ fuzzy) dung sai macro tốt.

Đây chính là công cụ LineVD dùng:
  sastvd/helpers/joern.py::rdg lọc REACHING_DEF | CDG
  -> khớp đúng những gì lấy ở đây.

Khác biệt duy nhất còn lại so với LineVD: họ chỉ chạy C/C++
(Big-Vul), còn đây chạy mọi frontend Joern có.

Chiến lược batch: Joern khởi động JVM mất ~15-20s nên KHÔNG gọi
từng hàm. Ghi cả lô ra một thư mục, dựng một CPG, rồi dump toàn
bộ node/edge một lần.
"""

import json
import os
import shutil
import subprocess
import tempfile

from collections import defaultdict
from pathlib import Path

from .pdg import LineGraph


# ============================================================
# NGÔN NGỮ -> ĐUÔI FILE
#
# Joern chọn frontend theo đuôi file, nên đuôi phải đúng.
# ============================================================

EXT = {
    "c": ".c",
    "cpp": ".cpp",
    "objc": ".m",
    "java": ".java",
    "javascript": ".js",
    "typescript": ".ts",
    "python": ".py",
    "php": ".php",
    "ruby": ".rb",
    "go": ".go",
    "csharp": ".cs",
    "kotlin": ".kt",
    "swift": ".swift",
    "rust": ".rs",
    "scala": None,
    "lua": None,
    "perl": None,
}


# frontend Joern dùng cho từng đuôi; điền sau khi dò được
# joern-cli thực tế (xem probe_frontends()).
JOERN_LANG = {
    ".c": "c",
    ".cpp": "c",
    ".m": "c",
    ".java": "javasrc",
    ".js": "jssrc",
    ".ts": "jssrc",
    ".py": "pythonsrc",
    ".php": "php",
    ".rb": "rubysrc",
    ".go": "go",
    ".cs": "csharpsrc",
    ".kt": "kotlin",
    ".swift": "swiftsrc",
    ".rs": "rust",
}


def supported(lang_key):
    """Joern có frontend cho ngôn ngữ này không."""

    return EXT.get(lang_key) is not None


class JoernRunner:
    """
    Bọc joern-cli. Giữ đường dẫn + biến môi trường Java.
    """

    def __init__(
        self,
        joern_home,
        java_home=None,
        timeout=1800,
    ):

        self.home = Path(
            joern_home
        )

        self.timeout = timeout

        self.env = dict(
            os.environ
        )

        if java_home:

            self.env["JAVA_HOME"] = str(
                java_home
            )

            self.env["PATH"] = (
                f"{java_home}/bin:"
                + self.env.get("PATH", "")
            )

        # bớt log ồn của Joern
        self.env.setdefault(
            "JAVA_OPTS",
            "-Xmx8g",
        )

    # --------------------------------------------------------

    def _bin(
        self,
        name,
    ):

        p = self.home / name

        if p.exists():
            return str(p)

        raise FileNotFoundError(
            f"không thấy {p}"
        )

    # --------------------------------------------------------

    def run_batch(
        self,
        items,
        script_path,
        workdir=None,
    ):
        """
        items: list (key, code, lang_key)

        Ghi mỗi item thành một file trong thư mục tạm, dựng CPG,
        rồi chạy script Joern dump node/edge ra JSONL.

        -> dict key -> LineGraph
        """

        tmp = Path(
            workdir
            or tempfile.mkdtemp(
                prefix="joern_batch_"
            )
        )

        src = tmp / "src"

        src.mkdir(
            parents=True,
            exist_ok=True,
        )

        # tên file mã hoá key để map ngược
        name_of = {}

        for i, (
            key,
            code,
            lang_key,
        ) in enumerate(
            items
        ):

            ext = EXT.get(
                lang_key
            )

            if ext is None:
                continue

            fname = f"s{i:06d}{ext}"

            (src / fname).write_text(
                code,
                encoding="utf-8",
                errors="replace",
            )

            name_of[fname] = key

        if not name_of:
            return {}

        out = tmp / "graph.jsonl"

        cmd = [
            self._bin("joern"),
            "--script",
            str(script_path),
            "--param",
            f"inputPath={src}",
            "--param",
            f"outFile={out}",
        ]

        try:

            proc = subprocess.run(
                cmd,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(tmp),
            )

        except subprocess.TimeoutExpired:

            return {
                "_error": "timeout",
            }

        if not out.exists():

            return {
                "_error": (
                    proc.stderr[-2000:]
                    or proc.stdout[-2000:]
                ),
            }

        return (
            self._parse_dump(
                out,
                name_of,
            ),
            tmp,
        )

    # --------------------------------------------------------

    @staticmethod
    def _parse_dump(
        path,
        name_of,
    ):
        """
        Mỗi dòng JSONL: {"file":..., "nodes":[[id,line]],
                         "edges":[[src,dst,type]]}

        -> dict key -> LineGraph  (mức DÒNG, vô hướng,
           chỉ giữ CDG và REACHING_DEF, giống LineVD)
        """

        result = {}

        with open(
            path,
            encoding="utf-8",
        ) as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                try:
                    rec = json.loads(line)
                except Exception:
                    continue

                fname = os.path.basename(
                    rec.get("file", "")
                )

                key = name_of.get(
                    fname
                )

                if key is None:
                    continue

                line_of = {
                    int(nid): int(ln)
                    for nid, ln in rec.get(
                        "nodes",
                        [],
                    )
                    if ln is not None
                }

                g = LineGraph()

                for ln in line_of.values():
                    g.touch(ln)

                for a, b, etype in rec.get(
                    "edges",
                    [],
                ):

                    la = line_of.get(int(a))
                    lb = line_of.get(int(b))

                    if la is None or lb is None:
                        continue

                    g.add(
                        la,
                        lb,
                        (
                            "cdg"
                            if etype == "CDG"
                            else "ddg"
                        ),
                    )

                result[key] = g

        return result
