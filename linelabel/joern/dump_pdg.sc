// Dump PDG MỨC DÒNG cho từng file trong thư mục.
//
// Chỉ giữ CDG và REACHING_DEF — đúng bộ lọc LineVD dùng
// (sastvd/helpers/joern.py::rdg với gtype="pdg").
//
// Joern v4 dùng flatgraph: truy cập qua accessor sinh tự động
// _cdgOut / _reachingDefOut, KHÔNG phải outNode/inNode.
//
// Ra JSONL, mỗi dòng một file:
//   {"file":"s000001.c","lines":[1,2,3],
//    "cdg":[[5,6],[5,7]],"rd":[[3,5],[3,7]]}
//
// Chạy:
//   joern --script dump_pdg.sc --param inputPath=DIR --param outFile=OUT

import java.io.PrintWriter

@main def exec(inputPath: String, outFile: String): Unit = {

  importCode(inputPath)

  val pw = new PrintWriter(outFile)

  def lineOf(n: Any): Option[Int] = n match {
    case a: nodes.AstNode => a.lineNumber.map(_.toInt)
    case _                => None
  }

  // gom method theo file
  val byFile = cpg.method.internal.l.groupBy(_.filename)

  byFile.foreach { case (fname, methods) =>

    val ns = methods.flatMap(_.ast.l)

    val lines = ns.flatMap(n => lineOf(n)).distinct.sorted

    val cdg = ns.flatMap { n =>
      lineOf(n).toList.flatMap { a =>
        n._cdgOut.l.flatMap(x => lineOf(x)).map(b => (a, b))
      }
    }.filter { case (a, b) => a != b }.distinct

    val rd = ns.flatMap { n =>
      lineOf(n).toList.flatMap { a =>
        n._reachingDefOut.l.flatMap(x => lineOf(x)).map(b => (a, b))
      }
    }.filter { case (a, b) => a != b }.distinct

    def pairs(ps: List[(Int, Int)]): String =
      ps.map { case (a, b) => s"[$a,$b]" }.mkString(",")

    val esc = fname.replace("\\", "\\\\").replace("\"", "\\\"")

    pw.println(
      s"""{"file":"$esc","lines":[${lines.mkString(",")}],""" +
      s""""cdg":[${pairs(cdg)}],"rd":[${pairs(rd)}]}"""
    )
  }

  pw.close()
  println(s"WROTE ${byFile.size} files -> $outFile")
}
