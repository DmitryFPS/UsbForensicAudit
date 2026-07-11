using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace UsbForensicAudit;

public sealed class CellExplanationToolTipConverter : IMultiValueConverter
{
    public object? Convert(
        object[] values,
        Type targetType,
        object parameter,
        CultureInfo culture)
    {
        if (values.Length < 2
            || values[0] is null
            || values[0] == DependencyProperty.UnsetValue
            || values[1] is not string header)
        {
            return null;
        }

        return CellExplanationText.Explain(values[0], header);
    }

    public object[] ConvertBack(
        object value,
        Type[] targetTypes,
        object parameter,
        CultureInfo culture) =>
        throw new NotSupportedException();
}

internal static class CellExplanationText
{
    public static string? Explain(object row, string header) =>
        row switch
        {
            UsbDeviceRecord device => ExplainDevice(device, header),
            EvidenceRecord evidence => ExplainEvidence(evidence, header),
            CleanupFinding finding => ExplainCleanup(finding, header),
            _ => null
        };

    private static string? ExplainDevice(UsbDeviceRecord device, string header) =>
        header switch
        {
            "Что это за запись" => Build(
                header,
                device.UserMeaning,
                "Краткое описание роли этой строки. Оно помогает отличить физическое устройство от диска, интерфейса, хаба или служебного следа Windows.",
                "Служебная запись или остаточный след не всегда означает отдельное физическое устройство."),
            "Имя устройства" => Build(
                header,
                device.DisplayName,
                "Название, которое удалось получить из Windows, данных производителя или системного идентификатора.",
                "Название может быть общим и само по себе не доказывает, что две записи относятся к одному экземпляру."),
            "Тип" => Build(
                header,
                device.CategoryText,
                ExplainDeviceCategory(device.VisualCategory)),
            "Transport" => Build(
                header,
                device.Transport,
                ExplainTransport(device.Transport)),
            "Connection" => Build(
                header,
                device.Connection,
                ExplainConnection(device.Connection)),
            "Classification" => Build(
                header,
                device.Classification,
                ExplainClassification(device.Classification)),
            "Confidence / evidence" => Build(
                header,
                device.ClassificationEvidenceText,
                "Признаки, по которым программа определила транспорт, способ подключения и роль устройства.",
                "Это объяснение автоматической классификации. Если признаков мало или они противоречат друг другу, результат нужно проверить вручную."),
            "Когда подключали" => Build(
                header,
                device.FirstConnectedText,
                "Наиболее ранний доступный ориентир для этой записи. Это может быть событие подключения или установки, время изменения реестра либо момент обнаружения при сканировании.",
                ExplainConnectionDateCaution(device.ConnectionDisplayKind)),
            "Когда отключали" => Build(
                header,
                device.LastDisconnectedText,
                "Время отключения, если Windows сохранила точное событие. Иначе здесь может быть оценка по последней активности или текущий статус.",
                "Оценочная дата не равна точному событию физического отключения."),
            "Последняя активность" => Build(
                header,
                device.LastSeenText,
                "Последнее время, когда устройство или связанная запись проявились в доступных источниках Windows.",
                "Это может быть установка драйвера, запись журнала или изменение реестра, а не физическое отключение."),
            "Пояснение по датам" => Build(
                header,
                device.DateConfidenceText,
                "Объясняет, откуда взялись показанные даты и насколько точно их можно трактовать."),
            "Производитель" => Build(
                header,
                device.ManufacturerText,
                "Название производителя из свойств Windows или справочника VID.",
                "Значение может быть общим, отсутствовать или относиться к USB-контроллеру, а не к бренду готового устройства."),
            "Модель" => Build(
                header,
                device.ModelText,
                "Название модели или продукта, которое сохранила Windows.",
                "Одинаковая модель не означает один и тот же физический экземпляр."),
            "VID / PID" => Build(
                header,
                device.VidPidText,
                "VID — идентификатор поставщика USB, PID — назначенный им идентификатор продукта.",
                "PID не гарантирует точного определения модели или ревизии. VID/PID не определяют уникальный экземпляр; для точной связи нужен проверенный серийный номер или другой сильный идентификатор."),
            "Серийный номер" => Build(
                header,
                device.SerialText,
                "Серийная или экземплярная часть идентификатора Plug and Play.",
                "Она может быть аппаратным серийным номером либо значением, сформированным Windows. Уникальность и стабильность нужно проверять."),
            "Расположение в USB" => Build(
                header,
                device.LocationDisplayText,
                "Положение устройства в дереве USB: контроллер, хаб и порт. Оно помогает связать несколько интерфейсов одного устройства.",
                "Путь может измениться после подключения к другому порту."),
            "Откуда взята информация" => Build(
                header,
                device.SourceText,
                "Источник Windows, из которого получена эта запись: реестр, журнал установки, системное событие или другой артефакт."),
            "Системный ID" => Build(
                header,
                device.DeviceInstanceId,
                "Технический идентификатор экземпляра устройства в Plug and Play Windows. В нём часто видны шина, VID/PID, интерфейс и серийная часть.",
                "Не редактируйте значение при ручной проверке: даже разделители и суффиксы могут быть важны."),
            _ => null
        };

    private static string? ExplainEvidence(EvidenceRecord evidence, string header) =>
        header switch
        {
            "Дата и время" => Build(
                header,
                evidence.TimestampText,
                "Время записи или события, приведённое к московскому времени.",
                "Время показывает момент данного артефакта. Оно устанавливает дату подключения только для источников, которым это явно разрешено."),
            "Что произошло" => Build(
                header,
                evidence.EvidenceCategoryText,
                "Категория события, которую программа определила по источнику и содержимому записи."),
            "Откуда взято" => Build(
                header,
                evidence.SourceText,
                "Источник доказательства: журнал Windows, SetupAPI, реестр, профиль пользователя или другой системный артефакт."),
            "Сила доказательства" => Build(
                header,
                evidence.EvidenceStrength,
                ExplainEvidenceStrength(evidence.EvidenceStrength)),
            "Уверенность" => Build(
                header,
                evidence.Confidence,
                ExplainEvidenceConfidence(evidence.Confidence),
                "Уверенность относится к трактовке этой записи, а не ко всему расследованию."),
            "ID события/записи" => Build(
                header,
                evidence.EventId,
                "Числовой Event ID либо внутренний код типа записи.",
                "Его смысл определяется источником и провайдером; это не номер записи журнала. Одинаковый ID в разных источниках может означать разные вещи."),
            "Связанное устройство" => Build(
                header,
                evidence.DeviceHintText,
                "Идентификатор, путь или другой признак устройства, найденный в исходной записи.",
                "Это подсказка для сопоставления. Слабое или частичное совпадение не всегда означает точную связь."),
            "Простыми словами" => Build(
                header,
                evidence.UserExplanationText,
                "Краткое объяснение того, что эта запись означает для пользователя."),
            "Подробности" => Build(
                header,
                evidence.SummaryText,
                "Сжатое техническое содержание исходной записи. Оно нужно для ручной проверки вывода."),
            "Provenance" => Build(
                header,
                evidence.Provenance,
                "Происхождение данных: файл, журнал, канал, провайдер, номер записи или правило, по которому получено доказательство.",
                "Это поле помогает повторно найти первоисточник и проверить вывод программы."),
            _ => null
        };

    private static string? ExplainCleanup(CleanupFinding finding, string header) =>
        header switch
        {
            "Дата и время" => Build(
                header,
                finding.TimestampText,
                "Время найденного события или артефакта, приведённое к московскому времени.",
                "Оно не всегда равно времени фактического удаления следов: для косвенных признаков это время исходной записи."),
            "Тип действия" => Build(
                header,
                finding.ActionKindText,
                ExplainCleanupAction(finding.ActionKind)),
            "Статус" => Build(
                header,
                finding.AssessmentText,
                ExplainAssessment(finding.Assessment)),
            "Инициатор" => Build(
                header,
                finding.InitiatorText,
                "Учётная запись или системный компонент, который удалось связать с событием.",
                "«Не определено» означает, что доступные источники не содержат надёжной атрибуции."),
            "Инструмент" => Build(
                header,
                finding.PossibleToolText,
                "Программа или компонент Windows, который мог быть связан с найденным действием.",
                "Сам факт запуска утилиты ещё не доказывает, что она выполнила очистку."),
            "Уверенность" => Build(
                header,
                finding.ConfidenceText,
                ExplainCleanupConfidence(finding.Confidence),
                "Чем ниже уверенность, тем важнее ручная проверка первоисточника и соседних событий."),
            "Риск" => Build(
                header,
                finding.SeverityText,
                ExplainSeverity(finding.Severity),
                "Уровень риска помогает расставить приоритеты, но не является готовым обвинительным выводом."),
            "Где искали" => Build(
                header,
                finding.AreaText,
                "Область проверки, где найден признак: журналы Windows, SetupAPI, программы очистки или противоречие между источниками.",
                "Это место поиска, а не название USB-устройства."),
            "Что найдено" => Build(
                header,
                finding.Finding,
                "Краткое описание обнаруженного признака или противоречия."),
            "Подробности" => Build(
                header,
                finding.Details,
                "Факты и контекст, на которых основана находка. Используйте их для ручной проверки.",
                "Подозрительный признак нужно оценивать вместе с инициатором, временем, источником и другими независимыми записями."),
            _ => null
        };

    private static string Build(
        string title,
        string? value,
        string meaning,
        string? caution = null)
    {
        var displayValue = ReportText.ForDisplayOrClean(value, 420);
        if (string.IsNullOrWhiteSpace(displayValue))
        {
            displayValue = "не указано";
        }

        var result =
            $"{title}\n\nЗначение: {displayValue}\n\nЧто это значит: {meaning}";
        if (!string.IsNullOrWhiteSpace(caution))
        {
            result += $"\n\nВажно: {caution}";
        }

        return result;
    }

    private static string ExplainDeviceCategory(string? value) =>
        value switch
        {
            "RealUsb" => "Реальное USB/Type‑C устройство или инфраструктура USB, подтверждённая сильными системными признаками.",
            "RelatedStorage" => "Запись диска или тома, которую программа связала с USB‑устройством.",
            "UsbFlagsTrace" => "Остаточная запись usbflags. Она показывает, что Windows знает VID/PID, но не подтверждает конкретное подключение.",
            "SupportArtifact" => "Служебная запись Windows, которая помогает анализу, но не считается отдельным пользовательским устройством.",
            _ => "Категория не определена: доступных признаков недостаточно."
        };

    private static string ExplainTransport(string? value) =>
        value switch
        {
            "USB" => "Устройство работает через обычный USB‑стек Windows.",
            "UASP/SCSI" => "USB‑накопитель использует быстрый протокол UASP и поэтому может отображаться как SCSI‑устройство.",
            "MTP/PTP/WPD" => "Телефон, камера или другое переносное устройство работает через MTP, PTP или Windows Portable Devices.",
            "MSC/USBSTOR" => "USB‑накопитель работает через стандартный класс Mass Storage и драйвер USBSTOR.",
            "USB4/Thunderbolt" => "Устройство связано с USB4 или Thunderbolt. Часть трафика может проходить не как обычный USB.",
            "USB4/Thunderbolt/PCIe-tunneled candidate" => "Найдены признаки USB4, Thunderbolt или туннелирования PCIe. Конкретный транспорт окончательно не подтверждён.",
            _ => "Транспорт не удалось надёжно определить по доступным данным."
        };

    private static string ExplainConnection(string? value) =>
        value switch
        {
            "USB" => "Системные признаки указывают на подключение через USB.",
            "USB4/Thunderbolt" => "Подключение относится к инфраструктуре USB4 или Thunderbolt.",
            "PCIe-tunneled candidate" => "Возможное внешнее устройство передаёт PCIe через Thunderbolt/USB4. Это вероятностная классификация.",
            "HistoricalResidual" => "Найдена только историческая или остаточная запись; текущее подключение не подтверждено.",
            _ => "Способ подключения не удалось определить."
        };

    private static string ExplainClassification(string? value) =>
        value switch
        {
            "External" => "Внешнее устройство, подключаемое пользователем.",
            "BuiltIn" => "Встроенное устройство внутренней USB‑шины, например камера или считыватель.",
            "Hub" => "USB‑хаб, корневой хаб, контроллер или другая инфраструктура шины.",
            "Composite" => "Отдельный интерфейс составного устройства, которое выполняет несколько функций.",
            "Virtual" => "Виртуальное USB‑устройство или шина программной среды.",
            _ => "Роль устройства не удалось надёжно определить."
        };

    private static string ExplainConnectionDateCaution(string? displayKind) =>
        displayKind switch
        {
            "ExactEvent" => "Дата основана на разрешённом системном событии или другом прямом источнике.",
            "PnpDevProperty" => "Дата взята из свойства PnP этой установки Windows; это не обязательно первое подключение устройства за всю его жизнь.",
            "RegistryActivity" => "Дата получена по активности реестра и менее точна, чем системное событие.",
            "LiveAtScan" => "Устройство было видно во время сканирования, но точное более раннее время подключения неизвестно.",
            _ => "Если указано «точное время неизвестно», Windows не сохранила подходящее прямое событие."
        };

    private static string ExplainEvidenceStrength(string? value) =>
        value?.ToUpperInvariant() switch
        {
            "DIRECT" => "Прямое для указанного факта: источник непосредственно зафиксировал событие из категории этой строки. Это не подтверждает намерение или последствия действия.",
            "CORROBORATING" => "Подтверждающее доказательство: запись усиливает вывод вместе с другими источниками, но обычно недостаточна одна.",
            "INDIRECT" => "Косвенное доказательство: запись показывает связанный контекст, но не доказывает само событие.",
            _ => "Сила доказательства не определена."
        };

    private static string ExplainEvidenceConfidence(string? value) =>
        value?.ToUpperInvariant() switch
        {
            "HIGH" => "Высокая уверенность в извлечении и сопоставлении этой записи. Она не превращает косвенное доказательство в прямое.",
            "MEDIUM" => "Средняя уверенность: связь правдоподобна, но требует проверки дополнительными источниками.",
            "LOW" => "Низкая уверенность: вывод основан на слабом или неполном признаке.",
            _ => "Уровень уверенности не определён."
        };

    private static string ExplainCleanupAction(string? value) =>
        value switch
        {
            "ToolLaunch" => "Зафиксирован запуск утилиты. Это ещё не доказательство очистки.",
            "ProbableCleanup" => "Эвристика обнаружила запуск утилиты и как минимум один дополнительный признак состояния системы. Причинная и временная связь с очисткой не доказана.",
            "LogClearing" => "Источник зафиксировал очистку или пересоздание журнала Windows.",
            "RegistryArtifact" => "Найдено изменение или состояние реестра/файла, связанное с очисткой.",
            "Correlation" => "Обнаружено противоречие между независимыми источниками.",
            "OsInstall" or "NormalMigrationContext" => "Событие совпадает по времени с установкой, миграцией или штатным обновлением Windows. Причину всё равно нужно подтверждать источниками.",
            _ => "Тип действия не удалось определить."
        };

    private static string ExplainAssessment(string? value) =>
        value switch
        {
            "Suspicious" => "Запись требует внимания и ручной проверки. Это не автоматическое доказательство умышленной очистки.",
            "OsInstall" => "Событие произошло в первые три часа после указанной даты установки Windows. Это снижает подозрительность, но само по себе не устанавливает причину и инициатора.",
            "Informational" => "Информационная запись: она сохранена для полноты, но сама по себе не подозрительна.",
            _ => "Статус не определён."
        };

    private static string ExplainCleanupConfidence(string? value) =>
        value switch
        {
            "Confirmed" => "Действие подтверждено прямой записью источника.",
            "Probable" => "Действие вероятно: совпали несколько связанных признаков.",
            "Indirect" => "Есть только косвенный признак; действие не подтверждено.",
            "Normal" => "Событие попало в первые три часа после указанной даты установки Windows. Это контекст, а не доказанная причина события.",
            _ => "Доступных данных недостаточно для оценки."
        };

    private static string ExplainSeverity(string? value) =>
        value?.ToUpperInvariant() switch
        {
            "HIGH" => "Высокий приоритет: есть серьёзный признак, который нужно проверить первым.",
            "MEDIUM" => "Средний приоритет: событие подозрительно, но возможны штатные причины.",
            "LOW" => "Низкий приоритет: слабый или одиночный сигнал.",
            "INFO" => "Информационная запись без самостоятельного признака нарушения.",
            _ => "Уровень риска не определён."
        };
}
