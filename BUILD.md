# Сборка UsbForensicAudit.exe

Скопируйте команды по порядку в PowerShell (из корня репозитория).

```powershell
cd C:\Users\adm\IdeaProjects\UsbForensicAudit
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
bin\publish\UsbForensicAudit_Инженерное_руководство.pdf
```

`UsbForensicAudit-Instrukciya.pdf` и `PORTABLE.txt` не создаются: вся необходимая
информация включена в инженерное PDF-руководство.

Опционально — скопировать комплект в другую папку:

```powershell
Copy-Item bin\publish\UsbForensicAudit.exe, bin\publish\*.pdf -Destination "C:\путь\к\папке\" -Force
```

Требования: .NET 8 SDK (версия зафиксирована в `global.json`), Windows 10/11 x64. Перед сборкой требуется успешный `dotnet test` (621 тест, line coverage ≥ 90%). Зависимости фиксируются `packages.lock.json`. Для portable-сборки нужен интернет при первом запуске `build-exe.ps1`; загруженный Procmon принимается только при действительной подписи Microsoft.
