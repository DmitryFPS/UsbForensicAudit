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

Готовый файл:

```text
bin\publish\UsbForensicAudit.exe
```

Опционально — скопировать в другую папку:

```powershell
Copy-Item bin\publish\UsbForensicAudit.exe -Destination "C:\путь\к\папке\" -Force
```

Требования: .NET 8 SDK, Windows 10/11 x64. Перед сборкой рекомендуется `dotnet test` (297+ тестов). Для portable-сборки нужен интернет при первом запуске `build-exe.ps1` (скачивание Procmon).
