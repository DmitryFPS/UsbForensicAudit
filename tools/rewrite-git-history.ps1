$ErrorActionPreference = "Stop"
Set-Location "C:\Users\adm\UsbForensicAudit"

$map = [ordered]@{
    "chore: add gitignore, README, and solution scaffold" = "chore: gitignore, README и каркас решения"
    "feat: core WPF shell and USB forensic collectors" = "feat: основная оболочка WPF и сборщики USB-арtefактов"
    "feat: PDF/HTML reports, branding, and executive brief" = "feat: PDF/HTML отчёты, брендинг и краткое резюме"
    "feat: live USB monitoring and active devices window" = "feat: live-мониторинг USB и окно активных устройств"
    "feat: cleanup traces, endpoint protection, and USB Oblivion attribution" = "feat: следы очистки, endpoint protection и USB Oblivion"
    "feat: external utilities capture from USBDeview and USBDetector" = "feat: захват данных из USBDeview и USBDetector"
    "feat: external utility analysis UI, verdicts, and column normalization" = "feat: UI анализа сторонних утилит, вердикты и нормализация столбцов"
    "feat: embed merged USB VID/PID database (usb.ids format)" = "feat: встроенная база USB VID/PID (формат usb.ids)"
    "test: unit tests and external utility integration harness" = "test: unit-тесты и интеграционный harness внешних утилит"
    "chore: include remaining project files" = "chore: добавлены оставшиеся файлы проекта"
    "chore: ignore local build marker files" = "chore: игнор локальных маркеров сборки"
}

$msgFilter = @'
import sys, re
text = sys.stdin.read()
text = re.sub(r"(?m)^Co-authored-by: Cursor.*\n", "", text)
first = text.splitlines()[0].strip() if text else ""
mapping = {
'@ + ($map.GetEnumerator() | ForEach-Object { "    '$($_.Key)': '$($_.Value)'," } | Out-String) + @'
}
sys.stdout.write(mapping.get(first, text))
'@

$filterPath = Join-Path $env:TEMP "usb-audit-msg-filter.py"
Set-Content -Path $filterPath -Value $msgFilter -Encoding UTF8

git filter-branch -f --msg-filter "python `"$filterPath`"" -- --all

Write-Host "Done. Verify with: git log --oneline -15"
