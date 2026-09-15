"""REPORT.md -> report.pdf (Chromium 헤드리스 인쇄, 한글 Noto CJK 사용)"""
import subprocess, sys, pathlib, markdown

SRC = pathlib.Path(sys.argv[1])
OUT = pathlib.Path(sys.argv[2])
TMP_HTML = pathlib.Path(sys.argv[3])

body = markdown.markdown(
    SRC.read_text(encoding="utf-8"),
    extensions=["tables", "fenced_code", "toc", "sane_lists"],
)

HTML = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><title>PE 정적 특징 추출기 보고서</title>
<style>
  @page { size: A4; margin: 18mm 16mm 20mm 16mm; }
  body {
    font-family: "Noto Sans CJK KR", "Noto Sans KR", sans-serif;
    font-size: 10pt; line-height: 1.65; color: #1a1a1a; margin: 0;
    word-break: keep-all; overflow-wrap: anywhere;
  }
  h1 { font-size: 17pt; border-bottom: 2.5px solid #2d3748; padding-bottom: 8px;
       margin: 0 0 20px; letter-spacing: -0.3px; }
  h2 { font-size: 13pt; margin: 22px 0 10px; padding-left: 9px;
       border-left: 4px solid #2d3748; page-break-after: avoid; }
  h3 { font-size: 11pt; margin: 16px 0 7px; color: #2d3748; page-break-after: avoid; }
  p, li { margin: 6px 0; }
  ul, ol { padding-left: 20px; margin: 7px 0; }
  li { page-break-inside: avoid; }
  strong { font-weight: 700; }
  code {
    font-family: "DejaVu Sans Mono", "Noto Sans Mono CJK KR", monospace;
    font-size: 8.7pt; background: #f1f3f5; padding: 1px 4px;
    border-radius: 3px; border: 1px solid #e3e6ea; white-space: nowrap;
  }
  pre { background: #f7f8fa; border: 1px solid #e3e6ea; border-radius: 5px;
        padding: 10px 12px; overflow-x: auto; page-break-inside: avoid; }
  pre code { background: none; border: none; padding: 0; white-space: pre; font-size: 8.5pt; }
  table { border-collapse: collapse; width: 100%; margin: 11px 0;
          font-size: 8.4pt; table-layout: fixed; }
  th, td { border: 1px solid #ccd1d7; padding: 5px 7px;
           text-align: left; vertical-align: top; word-break: break-word; }
  th { background: #eceff3; font-weight: 700; }
  thead { display: table-header-group; }
  td code, th code { font-size: 7.8pt; white-space: normal; }
  hr { border: none; border-top: 1px solid #d5d9de; margin: 20px 0; }
</style></head><body>
""" + body + "\n</body></html>\n"

TMP_HTML.write_text(HTML, encoding="utf-8")

subprocess.run([
    "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
    "--headless", "--no-sandbox", "--disable-gpu",
    "--no-pdf-header-footer",
    f"--print-to-pdf={OUT}",
    TMP_HTML.resolve().as_uri(),
], check=True, capture_output=True)

print(f"생성 완료: {OUT} ({OUT.stat().st_size:,} bytes)")
