# Changelog

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версионирование — [SemVer](https://semver.org/lang/ru/).

## [Unreleased]

### Added
- Release-workflow (`.github/workflows/release.yml`): по тегу `vX.Y.Z` —
  сборка, тесты, аудит уязвимостей, публикация self-contained `win-x64`,
  zip-архив, `SHA256SUMS.txt` и GitHub Release с автогенерацией release notes.
- `LICENSE` — проприетарная source-available лицензия.
- `.editorconfig` — единый стиль кода C# для всего репозитория.
- `SECURITY.md` — политика сообщений об уязвимостях.
- `CONTRIBUTING.md` — правила участия в проекте.
- `CHANGELOG.md` — этот файл.

## [1.0.0] — не выпущено (текущая версия в csproj)

### Added
- GUI-first forensic-аудит USB/Type-C устройств для Windows 10/11 (WPF + MVVM).
- Конвейер сканирования из 20 шагов: реестр (USBSTOR, USB, SetupAPI и др.),
  журналы событий Windows, профили пользователей, USN Journal,
  артефакты запуска, браузеры, сети.
- Корреляция артефактов с устройствами и выявление признаков очистки следов.
- Отчёты HTML / PDF / Excel.
- Хранение сессий в SQLite (`audit.sqlite`) и доказательной цепочки
  с hash-chain SHA-256 в `evidence.jsonl`.
- Живой монитор подключённых устройств.
- Интеграция с Procmon.
- Portable-сборка (self-contained, single-file, win-x64).
- CI: сборка, 600+ тестов, coverage gate ≥90%, аудит уязвимостей,
  CodeQL, Dependabot, locked restore.

[Unreleased]: https://github.com/DmitryFPS/UsbForensicAudit/compare/main...HEAD
