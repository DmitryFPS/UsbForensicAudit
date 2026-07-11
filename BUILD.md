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

Требования: .NET 8 SDK, Windows 10/11 x64. Перед сборкой рекомендуется `dotnet test` (322 теста). Для portable-сборки нужен интернет при первом запуске `build-exe.ps1` (скачивание Procmon).
