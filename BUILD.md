# Сборка UsbForensicAudit.exe

Скопируйте команды по порядку в PowerShell (из корня репозитория).

```powershell
cd <путь-к-репозиторию>
```

```powershell
dotnet test tests\UsbForensicAudit.Tests\UsbForensicAudit.Tests.csproj -c Release
```

```powershell
.\build-exe.ps1
```

Готовые файлы:

```text
bin\publish\UsbForensicAudit.exe
bin\publish\UsbForensicAudit_Инженерное_руководство.pdf   # если HTML→PDF удалось сгенерировать
```

`UsbForensicAudit-Instrukciya.pdf` и `PORTABLE.txt` не создаются: вся необходимая
информация включена в инженерное PDF-руководство.

PDF генерируется из `docs\UsbForensicAudit_Инженерное_руководство.html` через Edge/Chrome
(headless). Чтобы пропустить PDF: `.\build-exe.ps1 -SkipEngineeringGuide`.

Опционально — скопировать комплект в другую папку:

```powershell
Copy-Item bin\publish\UsbForensicAudit.exe, bin\publish\*.pdf -Destination "C:\путь\к\папке\" -Force
```

Требования: .NET 10 SDK (версия зафиксирована в `global.json`), Windows 10/11 x64, Edge или Chrome для PDF. Перед сборкой требуется успешный `dotnet test` (**1244** тестовых кейса, line coverage ≥ 90%). Зависимости фиксируются `packages.lock.json`. Для portable-сборки нужен интернет при первом запуске (Procmon); загруженный Procmon принимается только при действительной подписи Microsoft.

CI использует тот же скрипт: `scripts\publish-app.ps1`.
