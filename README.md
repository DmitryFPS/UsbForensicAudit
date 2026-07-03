# UsbForensicAudit

GUI-first forensic-аудитор USB/Type-C устройств для **Windows 10/11**. Собирает артефакты из реестра, журналов событий и профилей пользователей, коррелирует их с устройствами, выявляет признаки очистки следов и формирует отчёты HTML/PDF.

Приложение ориентировано на аналитика/администратора: русский интерфейс, пояснения к каждой записи, portable-сборка для работы с флешки без следов в `%LOCALAPPDATA%`.

---

## Содержание

- [Возможности](#возможности)
- [Требования](#требования)
- [Быстрый старт](#быстрый-старт)
- [Архитектура](#архитектура)
- [Структура решения](#структура-решения)
- [Конвейер сканирования](#конвейер-сканирования)
- [Presentation-слой (WPF + MVVM)](#presentation-слой-wpf--mvvm)
- [Хранение данных](#хранение-данных)
- [Сборка](#сборка)
- [Тестирование](#тестирование)
- [Вспомогательные утилиты (`tools/`)](#вспомогательные-утилиты-tools)
- [Расширение системы](#расширение-системы)
- [Ограничения и интерпретация](#ограничения-и-интерпретация)

---

## Возможности

### Сбор артефактов

| Источник | Что извлекается |
|---|---|
| Реестр `HKLM\SYSTEM\CurrentControlSet\Enum` | `USB`, `USBSTOR`, `SCSI`, `SWD\WPDBUSENUM` |
| Реестр `HKLM\SYSTEM\MountedDevices` | точки монтирования томов |
| `C:\Windows\inf\setupapi.dev.log` | история PnP/USB из SetupAPI |
| Event Log | `System`, `Security`, `DeviceSetupManager`, `DriverFrameworks-UserMode` |
| Endpoint Protection (если установлен) | корпоративные журналы контроля USB |
| Профили пользователей (`HKU`, offline hive) | `MountPoints2`, Recent, LNK, Jump Lists, Shellbags |
| Execution artifacts | Prefetch, Amcache, Shimcache |
| Security 4688 | атрибуция процессов очистки (при включённом аудите) |

### Аналитика

- Корреляция **устройство → доказательство → пользовательский артефакт** с уровнем уверенности.
- Классификация записей: `RealUsb`, `RelatedStorage`, `SupportArtifact`.
- Расчёт дат подключения/отключения по SetupAPI, Event Log и user artifacts; все даты в GUI/отчётах — **МСК** (`дд.ММ.гггг ЧЧ:мм:сс МСК`).
- Поиск признаков очистки с атрибуцией: инициатор, возможный инструмент, уверенность, severity.
- Учёт даты установки Windows и **grace period 3 часа** после установки (события «Норма: ОС после установки»).
- Live-мониторинг USB/Type-C по **событиям PnP Windows** (без постоянного опроса каждые 2 секунды).
- Вкладка **«Сторонние утилиты»**: захват таблиц USBDetector/USBDeview, разбор строк, Procmon-трассировка реестра.
- Отчёты **HTML** и **PDF** (полный и сводный) на русском языке с корректной кириллицей.

### Portable-режим

При запуске из записываемой папки (флешка, `bin\publish\`) все данные пишутся в `data\` рядом с exe. Procmon64 встроен в сборку и распаковывается при первом использовании.

---

## Требования

| Компонент | Версия |
|---|---|
| ОС | Windows 10 / 11 x64 |
| .NET SDK | 8.0+ |
| IDE (опционально) | Visual Studio 2022 (workload *Desktop development with .NET*) или JetBrains Rider |

Для полного сканирования, Procmon-трассировки и захвата сторонних утилит нужны **права администратора**. Окно приложения открывается и без UAC; ограничения отображаются в статусе шапки.

---

## Быстрый старт

### Разработческая сборка

```powershell
git clone https://github.com/DmitryFPS/UsbForensicAudit.git
cd UsbForensicAudit
dotnet build UsbForensicAudit.sln -c Release
```

Запуск:

```text
bin\Release\net8.0-windows\UsbForensicAudit.exe
```

### Portable single-file exe

```powershell
.\build-exe.ps1
```

Результат:

```text
bin\publish\UsbForensicAudit.exe
bin\publish\UsbForensicAudit-Instrukciya.pdf
bin\publish\PORTABLE.txt
```

### Типовой сценарий работы

1. Запустить exe **от имени администратора** (ПКМ или кнопка «Запуск от администратора»).
2. Нажать **«Полное сканирование»**.
3. Изучить вкладки **USB устройства**, **Доказательства**, **Следы очистки**.
4. При необходимости — **«Старт мониторинга»** и окно **«Окно USB»**.
5. На вкладке **Отчёт** — создать HTML или PDF.

**Цвета строк USB:**

| Цвет | Категория | Смысл |
|---|---|---|
| Зелёный | `RealUsb` | реальное USB/Type-C устройство |
| Жёлтый | `RelatedStorage` | связанная storage-запись (диск/том) |
| Серый | `SupportArtifact` | служебная запись Windows |

---

## Архитектура

Проект следует **Clean Architecture** (слои + порты/адаптеры + DI). Зависимости направлены внутрь: Presentation → Application → Domain; Infrastructure реализует порты Application.

```mermaid
flowchart TB
    subgraph Presentation["Presentation (WPF)"]
        MW[MainWindow]
        VM[MainViewModel]
        ADW[ActiveDevicesWindow]
    end

    subgraph Application["Application — use cases"]
        AO[AuditOrchestrator]
        CS[CorrelationService]
        TE[TimelineEnricher]
        CD[CleanupDetector]
        Ports["Порты: IAuditStorage, IEvidenceCollector, IReportService, …"]
    end

    subgraph Domain["Domain — модели и правила"]
        Models[UsbDeviceRecord, EvidenceRecord, …]
        Catalogs[Справочники, форматтеры, VID/PID]
    end

    subgraph Infrastructure["Infrastructure — ОС и I/O"]
        Collectors[Коллекторы реестра/Event Log/WMI]
        Storage[AuditStorage SQLite/JSONL]
        Reports[QuestPDF, HTML builder]
        Win32[Win32 UI Automation, Procmon]
    end

    MW --> VM
    VM --> AO
    VM --> Ports
    AO --> Ports
    AO --> CS
    AO --> TE
    AO --> CD
    CS --> Models
    TE --> Models
    CD --> Models
    Ports -.->|реализация| Collectors
    Ports -.->|реализация| Storage
    Ports -.->|реализация| Reports
```

### Правила зависимостей

| Слой | Может ссылаться на | Не должен |
|---|---|---|
| **Domain** | только BCL / CodePages | Application, Infrastructure, WPF |
| **Application** | Domain | Infrastructure (только интерфейсы-порты) |
| **Infrastructure** | Application, Domain | Presentation |
| **Presentation** | все слои через DI | — |

Корневой namespace везде `UsbForensicAudit` — осознанное решение для минимизации churn при рефакторинге. Границы слоёв обеспечиваются `.csproj`-ссылками и `InternalsVisibleTo` для тестов.

### DI и точка входа

`App.xaml.cs` поднимает `Microsoft.Extensions.Hosting`:

```csharp
services.AddApplicationServices();      // CorrelationService, CleanupDetector, TimelineEnricher, AuditOrchestrator
services.AddInfrastructureServices();   // коллекторы, хранилище, отчёты, WMI
services.AddSingleton<MainViewModel>();
services.AddSingleton<MainWindow>();
```

`MainWindow` получает `MainViewModel` и платформенные сервисы через конструктор; `DataContext = MainViewModel`.

---

## Структура решения

```text
UsbForensicAudit/
├── UsbForensicAudit.sln          # Domain, Application, Infrastructure, Presentation
├── UsbForensicAudit.csproj       # WPF-приложение (Presentation)
├── MainWindow.xaml(.cs)          # View: разметка + тонкий code-behind (Win32, clipboard, Procmon UI)
├── MainViewModel.cs              # ViewModel: коллекции, состояние сканирования, порядок сортировки
├── ActiveDevicesWindow.xaml(.cs)  # Окно live-мониторинга
├── App.xaml(.cs)                 # Generic Host, DI, глобальные обработчики ошибок
├── build-exe.ps1                 # Portable publish + PDF-инструкция + проверка Procmon
├── Assets/                       # Иконки, логотип, USBVendors.txt (embedded в Domain)
├── src/
│   ├── UsbForensicAudit.Domain/           # Модели, справочники, форматтеры, парсеры
│   ├── UsbForensicAudit.Application/      # Use cases, оркестратор, порты, аналитика
│   └── UsbForensicAudit.Infrastructure/   # Коллекторы, SQLite, PDF, WMI, Win32, Procmon
├── tests/
│   └── UsbForensicAudit.Tests/            # xUnit, coverlet (209+ тестов)
└── tools/
    ├── GenerateIcon/                      # PNG → ICO для сборки
    ├── GenerateManual/                  # PDF-инструкция пользователя
    ├── MergeUsbVendorDatabase/            # Слияние usb.ids с локальной базой VID/PID
    └── ExternalUtilityHarness/            # Интеграционный harness захвата утилит
```

**Папки, которых нет в git** (создаются при сборке/работе): `bin/`, `obj/`, `obj/rid-out/`, `TestResults/`, `.idea/`.

---

## Конвейер сканирования

Центральный use case — `AuditOrchestrator.RunFullScanAsync`. Выполняется в фоне (`Task.Run`), прогресс отдаётся в UI через `IProgress<string>`.

```text
1. UsbRegistryCollector          → Devices
2. SetupApiLogCollector          → Evidence
3. EventLogCollector             → Evidence
4. EndpointProtectionCollector   → Evidence (если ShouldRun)
5. UserArtifactCollector         → Evidence
6. OfflineHiveCollector          → Evidence
7. ExecutionArtifactCollector    → Evidence
8. ProcessAttributionCollector   → Evidence
9. CorrelationService            → доп. Evidence (корреляции)
10. LiveDeviceMerger             → обогащение Devices
11. TimelineEnricher             → даты, пояснения, WMI «подключено сейчас»
12. CleanupDetector              → CleanupFindings
13. AuditStorage.Save            → SQLite + JSONL
```

Порядок шагов 2–8 задаётся регистрацией `IEvidenceCollector` в `InfrastructureServiceCollectionExtensions` (порядок `AddSingleton` = порядок выполнения).

Ключевые порты Application (`Abstractions.cs`):

| Порт | Назначение |
|---|---|
| `IUsbDeviceCollector` | первый шаг — устройства из реестра |
| `IEvidenceCollector` | один источник доказательств; `ShouldRun` для условных сборщиков |
| `IAuditStorage` | персистентность результатов |
| `ILiveDeviceMerger` | слияние с live-устройствами |
| `IConnectedDeviceProbe` | WMI-проба «подключено сейчас» для TimelineEnricher |
| `IReportService` | HTML/PDF отчёты |
| `IPrivilegeChecker` | проверка прав администратора |
| `IExternalUtilityRegistryTracer` | live-трассировка реестра для сторонних утилит |

---

## Presentation-слой (WPF + MVVM)

| Компонент | Ответственность |
|---|---|
| `MainViewModel` | `ObservableCollection` для таблиц, `IsScanning` / `IsProcmonTracing`, `LastResult`, вызов `AuditOrchestrator`, сортировка результатов (`OrderDevices`, `OrderEvidence`, `OrderCleanupFindings`) |
| `MainWindow` | XAML-привязки `{Binding Devices}`, `{Binding Evidence}`, обработчики кнопок, Win32/clipboard, Procmon UI, обновление счётчиков и `DataGrid` |
| `ActiveDevicesWindow` | отдельное окно live-списка подключённых устройств |

Платформенный код (UI Automation, захват ListView, Procmon session folder) **намеренно** остаётся во View — это допустимый компромисс: бизнес-логика в нижних слоях, View — адаптер ОС.

---

## Хранение данных

### Portable (приоритет)

```text
{папка с UsbForensicAudit.exe}\data\
```

### Fallback (если рядом с exe нельзя писать)

```text
%LOCALAPPDATA%\UsbForensicAudit\
```

### Содержимое `data\`

| Файл / папка | Назначение |
|---|---|
| `audit.sqlite` | структурированное хранилище для поиска |
| `evidence.jsonl` | append-only журнал с SHA-256 hash-chain |
| `app.log` | технический лог приложения |
| `external_utility_snapshot.json` | снимок сторонней утилиты |
| `tools\Procmon64.exe` | распакованный Procmon (из embedded resource) |
| `procmon\{session}\` | CSV-трассировки Procmon |
| `UsbForensicAudit_*.html/pdf` | сгенерированные отчёты |

Логика выбора каталога — `AppPaths` (Infrastructure).

---

## Сборка

### Dev-сборка (Rider / Visual Studio / CLI)

```powershell
dotnet build UsbForensicAudit.sln -c Release
```

Выход:

```text
bin\Release\net8.0-windows\UsbForensicAudit.exe
```

### Portable publish

```powershell
.\build-exe.ps1
```

Скрипт:

1. Проверяет/скачивает `tools\Procmon64.exe` (нужен интернет **только при сборке**).
2. Генерирует `Assets\app.ico` через `tools\GenerateIcon`.
3. Выполняет `dotnet publish` (single-file, self-contained, `win-x64`).
4. Создаёт PDF-инструкцию через `tools\GenerateManual`.
5. Проверяет, что Procmon встроен в `UsbForensicAudit.Infrastructure.dll`.

RID-сборка (`publish -r win-x64`) пишет промежуточные артефакты в `obj\rid-out\`, не затрагивая `bin\Release\` — это исключает конфликты блокировки DLL при параллельной работе IDE и скрипта.

**Если publish падает с «файл заблокирован»:** закройте запущенный `UsbForensicAudit.exe`, остановите Debug в Rider/VS, выполните `dotnet build-server shutdown`, повторите скрипт.

---

## Тестирование

```powershell
dotnet test tests\UsbForensicAudit.Tests\UsbForensicAudit.Tests.csproj -c Release
```

С покрытием:

```powershell
dotnet test tests\UsbForensicAudit.Tests\UsbForensicAudit.Tests.csproj --collect:"XPlat Code Coverage"
```

Конфигурация coverlet: `tests/UsbForensicAudit.Tests/coverlet.runsettings`.

**Стратегия покрытия:** unit-тесты на измеряемое ядро (парсеры, корреляции, Procmon CSV, ViewModel-сортировка, DI-регистрация) с порогом **≥ 90% line coverage** по включённым файлам. Исключены из метрики: WPF code-behind, коллекторы ОС, PDF-генераторы, WMI — они требуют интерактивной Windows-среды.

Примеры тестовых классов:

| Класс | Что проверяет |
|---|---|
| `CoreLogicTests`, `CorrelationServiceTests` | корреляция и ключевая логика |
| `ProcmonCsvParserTests`, `ProcmonCompletenessTests` | разбор Procmon |
| `ExternalUtilityTests`, `ExternalUtilityReportConclusionTests` | сторонние утилиты |
| `MainViewModelTests` | порядок сортировки результатов в VM |
| `ServiceRegistrationTests` | порядок сборщиков и WMI-probe в DI |
| `TimelineEnricherTests`, `TextSanitizerTests` | обогащение и нормализация текста |

---

## Вспомогательные утилиты (`tools/`)

| Проект | Назначение |
|---|---|
| `GenerateIcon` | конвертация `Assets/app-icon.png` → `Assets/app.ico` |
| `GenerateManual` | генерация `UsbForensicAudit-Instrukciya.pdf` (использует `ManualPdfGenerator` из Infrastructure) |
| `MergeUsbVendorDatabase` | слияние `Assets/USBVendors.txt` с загруженным `usb.ids` |
| `ExternalUtilityHarness` | headless-тест захвата окон USBDeview/USBDetector |

Procmon на этапе сборки: `tools\Procmon64.exe` (в `.gitignore`; скачивается `build-exe.ps1` или кладётся вручную).

---

## Расширение системы

### Добавить новый источник доказательств

1. Реализовать `IEvidenceCollector` в `UsbForensicAudit.Infrastructure`.
2. Зарегистрировать в `InfrastructureServiceCollectionExtensions` **в нужном порядке**:
   ```csharp
   services.AddSingleton<IEvidenceCollector, MyNewCollector>();
   ```
3. Добавить unit-тесты на парсинг/нормализацию (без обращения к ОС, если возможно).

Оркестратор менять не нужно — он итерирует все зарегистрированные `IEvidenceCollector`.

### Добавить порт / адаптер

1. Интерфейс — в `UsbForensicAudit.Application`.
2. Реализация — в `UsbForensicAudit.Infrastructure`.
3. Регистрация — в `AddInfrastructureServices()` или `AddApplicationServices()`.

---

## Ограничения и интерпреация

- Приложение **не блокирует** USB — только анализирует и мониторит.
- Корпоративные политики DLP/Endpoint Protection могут скрывать стандартные следы Windows; программа использует дополнительные источники и помечает даты как ориентир.
- Windows **не всегда** сохраняет физический номер порта; показываются `LocationInformation` / `LocationPaths`, если ОС их отдала.
- Отсутствие артефакта ≠ факт очистки. Оценивайте findings в совокупности и смотрите колонку «Уверенность».
- **Grace period 3 часа** после установки Windows: очистка журналов ОС — норма, статус «Норма: ОС после установки».
- Security **4688** доступен только при включённом аудите создания процессов.
- Prefetch/Amcache фиксируют **запуск** утилиты, но не доказывают очистку в конкретную секунду.
- Offline-загрузка hive может не сработать для активного профиля; активные профили анализируются через загруженный `HKU`, ошибка попадает в warnings.
- Разные сборки Windows 10/11 дают разную детализацию Event Log; каждый collector изолирован — сбой одного не останавливает весь аудит.

---

## Автор

**Орлов Дмитрий Владимирович**
