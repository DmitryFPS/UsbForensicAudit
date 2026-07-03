namespace UsbForensicAudit;

public sealed class ExternalUtilitySectionInfo
{
    public required string Title { get; init; }
    public required string ShortTitle { get; init; }
    public required string Summary { get; init; }
    public required string Reliability { get; init; }
    public required string TypicalSources { get; init; }
    public required string InvestigationHint { get; init; }
}

public static class ExternalUtilitySectionCatalog
{
    public const string MainRegistrySection = "Основной список (реестр)";
    public const string OtherTracesSection = "Другие следы подключения устройств";
    public const string DeviceListSection = "Список устройств";

    public static ExternalUtilitySectionInfo GetInfo(string sectionTitle)
    {
        if (sectionTitle.Contains("Другие следы", StringComparison.OrdinalIgnoreCase))
        {
            return OtherTraces;
        }

        if (sectionTitle.Contains("Основной список", StringComparison.OrdinalIgnoreCase)
            || sectionTitle.Contains("реестр", StringComparison.OrdinalIgnoreCase))
        {
            return MainRegistry;
        }

        if (sectionTitle.Contains("Список устройств", StringComparison.OrdinalIgnoreCase))
        {
            return UsbDeviewList;
        }

        return Generic(sectionTitle);
    }

    public static bool IsOtherTracesSection(string sectionTitle) =>
        sectionTitle.Contains("Другие следы", StringComparison.OrdinalIgnoreCase);

    private static readonly ExternalUtilitySectionInfo MainRegistry = new()
    {
        Title = MainRegistrySection,
        ShortTitle = "Основной список",
        Summary = "Записи из веток реестра Enum\\USB и USBSTOR — это прямой след того, что Windows когда-либо видела USB-устройство.",
        Reliability = "Обычно надёжнее раздела «Другие следы».",
        TypicalSources = "Реестр: HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB, USBSTOR.",
        InvestigationHint = "Сравнивайте с нашей вкладкой «USB устройства» и setupapi.dev.log."
    };

    public static readonly ExternalUtilitySectionInfo OtherTraces = new()
    {
        Title = OtherTracesSection,
        ShortTitle = "Другие следы",
        Summary =
            "USBDetector показывает здесь косвенные записи: не только флешки из реестра, " +
            "но и следы из MRU, MountedDevices, профиля пользователя, виртуальных машин и старых ключей.",
        Reliability =
            "Строка в этом разделе не означает автоматически, что устройство реально подключали к этому ПК. " +
            "Часть записей — артефакты интерпретации USBDetector, а не доказательство подключения.",
        TypicalSources =
            "MountedDevices, MountPoints2, MRU пользователя, VMware (VID 0E0F), перенос профиля, " +
            "устаревшие ключи после переустановки Windows, FILETIME=0 (дата 01.01.1970).",
        InvestigationHint =
            "Смотрите вердикт по каждой строке: подтверждено нашим аудитом, косвенный след, виртуальное устройство или артефакт даты."
    };

    private static readonly ExternalUtilitySectionInfo UsbDeviewList = new()
    {
        Title = DeviceListSection,
        ShortTitle = "USBDeview",
        Summary = "Список устройств из NirSoft USBDeview — обычно собран из реестра и журналов установки.",
        Reliability = "Как правило, ближе к фактическим USB-записям Windows.",
        TypicalSources = "Реестр, setupapi, история подключений USBDeview.",
        InvestigationHint = "Сверяйте даты с нашим аудитом и журналом доказательств."
    };

    private static ExternalUtilitySectionInfo Generic(string title) => new()
    {
        Title = title,
        ShortTitle = title,
        Summary = "Дополнительная таблица, считанная из окна утилиты.",
        Reliability = "Оценивайте каждую строку отдельно и сверяйте с нашим полным сканированием.",
        TypicalSources = "Зависит от утилиты.",
        InvestigationHint = "Выберите строку и откройте вкладку «Разбор»."
    };
}
