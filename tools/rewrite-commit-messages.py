import re
import sys

MAPPING = {
    "chore: add gitignore, README, and solution scaffold": "chore: gitignore, README и каркас решения",
    "feat: core WPF shell and USB forensic collectors": "feat: основная оболочка WPF и сборщики USB-артефактов",
    "feat: PDF/HTML reports, branding, and executive brief": "feat: PDF/HTML отчёты, брендинг и краткое резюме",
    "feat: live USB monitoring and active devices window": "feat: live-мониторинг USB и окно активных устройств",
    "feat: cleanup traces, endpoint protection, and USB Oblivion attribution": "feat: следы очистки, endpoint protection и USB Oblivion",
    "feat: external utilities capture from USBDeview and USBDetector": "feat: захват данных из USBDeview и USBDetector",
    "feat: external utility analysis UI, verdicts, and column normalization": "feat: UI анализа сторонних утилит, вердикты и нормализация столбцов",
    "feat: embed merged USB VID/PID database (usb.ids format)": "feat: встроенная база USB VID/PID (формат usb.ids)",
    "test: unit tests and external utility integration harness": "test: unit-тесты и интеграционный harness внешних утилит",
    "chore: include remaining project files": "chore: добавлены оставшиеся файлы проекта",
    "chore: ignore local build marker files": "chore: игнор локальных маркеров сборки",
}

text = sys.stdin.read()
text = re.sub(r"(?m)^Co-authored-by: Cursor.*\n", "", text)
first = text.splitlines()[0].strip() if text else ""
sys.stdout.write(MAPPING.get(first, text))
