using System.IO;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace UsbForensicAudit;

public static class ManualPdfGenerator
{
    private const string FontName = PdfFontHelper.DefaultFamily;

    public static void Generate(string outputPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
        PdfFontHelper.EnsureRegistered();

        Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.MarginHorizontal(36);
                page.MarginVertical(32);
                page.DefaultTextStyle(x => x.FontSize(10).FontFamily(FontName).LineHeight(1.35f));

                page.Header().Column(header =>
                {
                    header.Item().Text("UsbForensicAudit").SemiBold().FontSize(20).FontColor(Colors.Blue.Darken3);
                    header.Item().Text("Полная инструкция пользователя").FontSize(11).FontColor(Colors.Grey.Darken2);
                    header.Item().PaddingTop(6).LineHorizontal(1).LineColor(Colors.Grey.Lighten2);
                });

                page.Content().Column(column =>
                {
                    column.Spacing(10);
                    AddIntro(column);
                    AddRequirements(column);
                    AddMainWindow(column);
                    AddOverviewTab(column);
                    AddDevicesTab(column);
                    AddEvidenceTab(column);
                    AddCleanupTab(column);
                    AddExternalUtilitiesTab(column);
                    AddReportTab(column);
                    AddLiveWindow(column);
                    AddDataStorage(column);
                    AddSources(column);
                    AddLimitations(column);
                    AddScenarios(column);
                    AddTroubleshooting(column);
                    AddDonation(column);
                });

                page.Footer().AlignCenter().Text(text =>
                {
                    text.DefaultTextStyle(x => x.FontSize(9).FontColor(Colors.Grey.Darken1));
                    text.Span("UsbForensicAudit v1.0 | ");
                    text.Span("Страница ");
                    text.CurrentPageNumber();
                    text.Span(" / ");
                    text.TotalPages();
                });
            });
        }).GeneratePdf(outputPath);
    }

    private static void AddIntro(ColumnDescriptor column)
    {
        SectionTitle(column, "1. О программе");
        Paragraph(column,
            "UsbForensicAudit — программа для проверки USB и Type-C устройств в Windows 10 и Windows 11. " +
            "Она показывает, какие флешки, телефоны и другие устройства подключались к компьютеру, " +
            "ищет признаки удаления следов, следит за новыми подключениями и создаёт PDF-отчёты (полный и сводный).");
        Bullet(column, "Программа не блокирует USB — только показывает информацию и ведёт журнал.");
        Bullet(column, "Интерфейс и отчёты написаны простым языком, без лишних технических терминов.");
        Bullet(column, "Ширина столбцов в таблицах подстраивается под содержимое после каждого сканирования.");
        Bullet(column, "Текст в таблицах и PDF проходит нормализацию кодировки — кириллица отображается корректно.");
        Bullet(column, "Все даты показываются по московскому времени: дд.ММ.гггг ЧЧ:мм:сс МСК.");
        Bullet(column, "На вкладке «Следы очистки» для каждой записи указываются инициатор, возможный инструмент и уверенность вывода.");
        Bullet(column, "Рядом с программой лежит файл UsbForensicAudit-Instrukciya.pdf — эта инструкция.");
    }

    private static void AddRequirements(ColumnDescriptor column)
    {
        SectionTitle(column, "2. Требования и запуск");
        AddTable(column,
            ("Требование", "Описание"),
            ("ОС", "Windows 10 или Windows 11"),
            ("Права", "Обязательно администратор (UAC при запуске)"),
            ("Установка", "Не нужна — один exe-файл"),
            ("Интернет", "Не требуется"));

        Numbered(column, 1, "Запустите UsbForensicAudit.exe (можно без администратора — окно откроется).");
        Numbered(column, 2, "Для полного сканирования: ПКМ → «Запуск от имени администратора» или кнопка «Запуск от администратора» в программе.");
        Numbered(column, 3, "Подтвердите UAC («Да»), если появится запрос.");
        Numbered(column, 4, "В карточке «Статус» на вкладке «Обзор» должно быть: Администратор.");
        Numbered(column, 5, "Проверьте строку «Установка Windows» — дата берётся из реестра Windows (InstallDate).");
        Numbered(column, 6, "Нажмите «Полное сканирование» — это основной первый шаг.");
        Paragraph(column, "Без прав администратора часть источников (Security Event Log, offline hive профилей) будет недоступна. Программа не должна «мигать» и закрываться — если так, обновите exe до последней сборки.");
    }

    private static void AddMainWindow(ColumnDescriptor column)
    {
        SectionTitle(column, "3. Главное окно");
        SubTitle(column, "Кнопки в шапке");
        AddTable(column,
            ("Кнопка", "Назначение"),
            ("Полное сканирование", "Однократный полный сбор всех forensic-артефактов с ПК"),
            ("Старт мониторинга", "Фоновое отслеживание подключений USB/Type-C и окно «Сейчас подключено»"),
            ("Окно USB", "Снова открыть окно текущих устройств, если его закрыли (мониторинг продолжается)"),
            ("Стоп", "Остановка live-мониторинга"));

        SubTitle(column, "Рекомендуемый порядок работы");
        Numbered(column, 1, "Полное сканирование.");
        Numbered(column, 2, "Изучение вкладок: USB устройства → Доказательства → Следы очистки → Сторонние утилиты (при необходимости).");
        Numbered(column, 3, "Создание полного или сводного отчёта в PDF либо Excel на вкладке «Отчёт».");
        Numbered(column, 4, "При необходимости — «Старт мониторинга» для фиксации новых подключений.");

        SubTitle(column, "Иконка программы");
        Paragraph(column,
            "У exe-файла и окна программы есть иконка (USB и лупа). Ярлык на рабочем столе можно создать вручную: " +
            "ПКМ по UsbForensicAudit.exe → «Отправить» → «Рабочий стол (создать ярлык)».");
    }

    private static void AddOverviewTab(ColumnDescriptor column)
    {
        column.Item().PageBreak();
        SectionTitle(column, "4. Вкладка «Обзор»");
        SubTitle(column, "Карточки статистики");
        AddTable(column,
            ("Карточка", "Что означает"),
            ("Устройства", "Все USB/Type-C, которые Windows когда-либо видела на этом ПК"),
            ("Доказательства", "События и записи, по которым строится история подключений"),
            ("Признаки очистки", "Число подозрительных записей; все находки (включая норму после установки) — на вкладке «Следы очистки»"),
            ("Статус", "Запущена ли программа с правами администратора"));

        SubTitle(column, "Дата установки Windows");
        Paragraph(column,
            "Над карточками показана дата установки Windows из реестра (InstallDate) в московском времени. " +
            "Она нужна, чтобы отличать свежую переустановку от ручной зачистки следов.");
        Bullet(column, "Если Windows установлена менее 3 часов назад, события очистки получают статус «Норма: ОС после установки» и инициатора «Система».");
        Bullet(column, "Та же дата показывается на вкладке «Следы очистки» и в PDF-отчётах.");
        Bullet(column, "В журнале активности после сканирования пишется: всего записей об очистке и сколько из них подозрительных.");

        SubTitle(column, "Журнал активности");
        Paragraph(column,
            "Текстовое поле внизу вкладки показывает этапы сканирования, предупреждения и итоговую статистику. " +
            "Технический лог ошибок также пишется в файл app.log в папке данных.");
    }

    private static void AddDevicesTab(ColumnDescriptor column)
    {
        SectionTitle(column, "5. Вкладка «USB устройства»");
        Paragraph(column,
            "Главный список устройств. Здесь видно, что подключалось, когда (если Windows это записала) " +
            "и откуда программа получила информацию.");
        SubTitle(column, "Цвет строк");
        AddTable(column,
            ("Цвет", "Что это"),
            ("Зелёный", "Реальное USB/Type-C устройство: флешка, диск, телефон, мышь и т.д."),
            ("Жёлтый", "Связанный диск или память USB — часто появляется вместе с флешкой"),
            ("Серый", "Служебная запись Windows — это не отдельное устройство"));

        SubTitle(column, "Столбцы таблицы");
        AddTable(column,
            ("Столбец", "Что означает"),
            ("Что это за запись", "Краткое описание простым языком"),
            ("Имя устройства", "Как Windows называет устройство"),
            ("Тип", "Реальное устройство, диск USB или служебная запись"),
            ("Когда подключали", "Первое известное подключение. Если пусто — «точное время неизвестно»"),
            ("Когда отключали", "Точная дата, оценка по последней активности, «Подключено сейчас» или «Сейчас не подключено»"),
            ("Последняя активность", "Когда устройство последний раз «мелькало» в системе"),
            ("Пояснение по датам", "Почему дата есть или почему её нет"),
            ("Производитель", "Название производителя из Windows, не код VID"),
            ("Модель", "Название модели из Windows, не код PID"),
            ("VID / PID", "Технические коды производителя и модели"),
            ("Серийный номер", "Уникальный номер экземпляра устройства, если Windows его знает"),
            ("Расположение в USB", "Где устройство сидит в USB-дереве. Если пусто: «Windows не сохранила расположение порта»"),
            ("Откуда взята информация", "Источник: реестр, журнал Windows, профиль пользователя и т.д."),
            ("Системный ID", "Технический номер для специалистов — обычному пользователю можно не смотреть"));

        SubTitle(column, "Важно про «Когда подключали»");
        Bullet(column, "Если Windows записала подключение — показывается точная дата.");
        Bullet(column, "Если точной даты нет, но устройство подключено сейчас — может быть ориентир по записи в реестре или по времени сканирования (с пояснением в столбце «Пояснение по датам»).");
        Bullet(column, "При активной корпоративной защите USB стандартные журналы Windows иногда пусты — программа использует дополнительные источники и оценки.");

        SubTitle(column, "Важно про «Когда отключали»");
        Bullet(column, "Если Windows записала отключение — показывается точная дата.");
        Bullet(column, "Если устройство не подключено, но события нет — дата последней активности с пометкой «ориентир».");
        Bullet(column, "Если подключено сейчас — «Подключено сейчас».");
        Bullet(column, "VID и PID — технические коды. Названия — в столбцах «Производитель» и «Модель».");
    }

    private static void AddEvidenceTab(ColumnDescriptor column)
    {
        column.Item().PageBreak();
        SectionTitle(column, "6. Вкладка «Доказательства»");
        Paragraph(column,
            "Здесь все найденные следы: записи Windows, события подключения, ярлыки пользователя, " +
            "запуск программ. Это «сырые данные», по которым программа строит историю на вкладке «USB устройства».");
        SubTitle(column, "Столбцы таблицы");
        AddTable(column,
            ("Столбец", "Что означает"),
            ("Дата и время", "Когда произошло событие (Москва)"),
            ("Что произошло", "Тип события: подключение, отключение, установка, очистка и т.д."),
            ("Откуда взято", "Источник простым языком: журнал Windows, реестр, ярлыки…"),
            ("Номер события", "Технический номер записи в журнале Windows"),
            ("Связанное устройство", "Подсказка, к какому USB это относится"),
            ("Простыми словами", "Краткое объяснение без технического жаргона"),
            ("Подробности", "Полный текст события (без «кракозябр» — программа очищает бинарный мусор из путей)"));

        Bullet(column, "Столбцы «Связанное устройство» и «Подробности» показывают только читаемый текст: пути, VID/PID, названия.");
        Bullet(column, "События «Контроль USB: …» — записи из журнала корпоративной защиты (DLP), если она установлена на ПК.");
    }

    private static void AddCleanupTab(ColumnDescriptor column)
    {
        SectionTitle(column, "7. Вкладка «Следы очистки»");
        Paragraph(column,
            "Признаки того, что следы USB могли намеренно удалять: очистка журналов Windows, " +
            "пересоздание setupapi.dev.log, запуск утилит (USBDeview, USBDetector, wevtutil и др.). " +
            "Все записи остаются в отчёте для полного аудита.");
        Paragraph(column,
            "Вверху вкладки показана дата установки Windows. Первые 3 часа после установки Windows сама очищает и пересоздаёт журналы — " +
            "такие события остаются в таблице для полного аудита, но получают статус «Норма: ОС после установки».");
        SubTitle(column, "Столбцы таблицы");
        AddTable(column,
            ("Столбец", "Что означает"),
            ("Дата и время", "Когда найден признак"),
            ("Тип действия", "Запуск утилиты, вероятная очистка, очистка журналов, норма после установки ОС"),
            ("Статус", "«Подозрительно» или «Норма: ОС после установки»"),
            ("Инициатор", "Система, администратор, пользователь или «не определено» — из Event Log 104/1102"),
            ("Инструмент", "Возможная программа: USBDeview, USBDetector, wevtutil, PowerShell и др."),
            ("Уверенность", "Норма / Вероятно / Косвенный след / Не определено"),
            ("Риск", "Высокий, Средний, Низкий или Информация"),
            ("Где искали", "В какой части системы нашли след"),
            ("Что найдено", "Краткое описание"),
            ("Подробности", "Технические детали и пояснение атрибуции"));

        SubTitle(column, "«Где искали» — расшифровка");
        AddTable(column,
            ("Значение", "Что это"),
            ("Журналы Windows", "Очистка системных журналов (Event ID 104, 1102). В первые 3 ч. после установки — статус «Норма: ОС после установки»"),
            ("Журнал установки устройств", "Файл setupapi.dev.log удалён, маленький или пересоздан. Создание при установке — норма, остаётся в отчёте"),
            ("Программы очистки следов", "На ПК запускали утилиты для удаления USB-следов"),
            ("Противоречия между источниками", "В одном месте устройство есть, в другом — следы пропали"));

        SubTitle(column, "Уровни риска");
        AddTable(column,
            ("Риск", "Значение"),
            ("Высокий", "Серьёзный повод насторожиться — например, очищен Security log"),
            ("Средний", "Подозрительно, но нужно смотреть вместе с другими находками"),
            ("Низкий", "Слабый сигнал — может оказаться обычной ситуацией"),
            ("Информация", "Событие зафиксировано для аудита, но относится к норме после установки Windows"));

        SubTitle(column, "Уровни уверенности");
        AddTable(column,
            ("Уверенность", "Значение"),
            ("Норма (после установки)", "Windows сама очистила журналы в первые 3 ч. после InstallDate"),
            ("Вероятно", "Инициатор пользователь/админ и рядом по времени найден инструмент (Prefetch, 4688)"),
            ("Косвенный след", "Утилита запускалась или очистка от SYSTEM — связь с USB не доказана напрямую"),
            ("Не определено", "Windows не сохранила достаточно данных для вывода"));

        SubTitle(column, "Инициатор и инструмент");
        Bullet(column, "Инициатор для Event ID 104/1102 берётся из XML журнала (SubjectUserName, SID): Система, Администратор или Пользователь.");
        Bullet(column, "Инструмент определяется по Prefetch, Amcache и Security Event ID 4688 (если аудит процессов включён).");
        Bullet(column, "Тип действия на вкладке «Следы очистки»: «Запуск утилиты» — только факт запуска USBDeview/USBDetector; «Вероятная очистка» — рядом очистка журналов или противоречия в реестре; для USB Oblivion — отдельный анализ удаления следов.");
        Bullet(column, "Prefetch USBDeview/USBDetector доказывает запуск программы, но не факт очистки в ту же секунду — смотрите «Тип действия» и «Уверенность».");
        Bullet(column, "Корреляция по времени: инструмент ищется в окне до 60 минут до события очистки и 5 минут после.");

        Paragraph(column, "Одна строка сама по себе не доказывает, что кто-то что-то скрывал. Смотрите на картину целиком: тип действия, статус, инициатор, инструмент, уверенность и дату установки Windows.");
        Paragraph(column, "Фильтр на вкладке: все записи / только USB-утилиты / только запуск / вероятная очистка / только подозрительные.");
    }

    private static void AddExternalUtilitiesTab(ColumnDescriptor column)
    {
        column.Item().PageBreak();
        SectionTitle(column, "8a. Вкладка «Сторонние утилиты»");
        Paragraph(column,
            "Позволяет считать результат из окна запущенной USBDetector, USBDeview или USB Oblivion и разобрать каждую строку: " +
            "почему утилита показала такую дату, совпадает ли это с нашим аудитом, не является ли это артефактом или багом утилиты.");
        AddTable(column,
            ("Кнопка", "Действие"),
            ("Найти запущенные утилиты", "Ищет USBDetector.exe, USBDeview.exe, USBOblivion64.exe в процессах"),
            ("Считать результат из окна", "Читает таблицы из окна утилиты (верхний список и «Другие следы»)"),
            ("Разобрать вставку", "Если окно не считалось — вставьте строку вручную и получите разбор"),
            ("Ранее запускались", "Исторические запуски из Prefetch/Amcache/4688 после полного сканирования"));

        Bullet(column, "Доступно только при запуске UsbForensicAudit от администратора.");
        Bullet(column, "Дата 01.01.1970 в USBDetector — это технический ноль, а не реальное подключение в 1970 году.");
        Bullet(column, "Раздел «Другие следы подключения устройств» часто показывает косвенные записи (VMware, MRU) — сравнивайте с нашим аудитом.");
        Bullet(column, "Результат считывания сохраняется и попадает в полный PDF-отчёт.");

        SubTitle(column, "Жёсткая трассировка (Procmon)");
        Paragraph(column,
            "Procmon64 встроен в exe и распаковывается в папку data\\tools\\ при первом запуске. " +
            "Трассировка фиксирует, какие ключи реестра читала утилита во время сканирования — это жёсткое доказательство источника строки, " +
            "но не доказательство физического подключения флешки.");
        AddTable(column,
            ("Кнопка", "Действие"),
            ("Жёсткая трассировка (Procmon)", "Запускает Procmon, автоматически нажимает «Поиск» в USBDetector и сохраняет CSV"),
            ("Папка сессии Procmon", "Открывает data\\procmon\\yyyyMMdd-HHmmss\\ с capture.csv и README"));

        Bullet(column, "USBDetector должен быть запущен и виден на экране — иначе трассировка не поймает чтение реестра.");
        Bullet(column, "Строки из «Другие следы» с датой 01.01.1970 и косвенным ключом MountedDevices/MRU — часто артефакт, а не флешка.");
        Bullet(column, "Procmon доказывает «утилита прочитала ключ X в момент T», аудит показывает «ключ X существует в системе».");
    }

    private static void AddReportTab(ColumnDescriptor column)
    {
        SectionTitle(column, "9. Вкладка «Отчёт»");
        AddTable(column,
            ("Кнопка", "Результат"),
            ("Полный PDF", "Детальный альбомный отчёт для расследования"),
            ("Сводный PDF", "Краткое резюме на 2–3 страницы"),
            ("Полный Excel", "Все данные по отдельным листам с фильтрами и закреплёнными заголовками"),
            ("Сводный Excel", "Ключевые показатели, инциденты и значимые USB-устройства"),
            ("Открыть папку данных", "Открывает папку, где лежат база, журнал и все отчёты"));

        Paragraph(column, "Кнопки PDF и Excel активны только после успешного полного сканирования.");
        Paragraph(column,
            "Отчёты содержат только USB/Type-C: внешние и встроенные устройства внутренней USB-шины, " +
            "подтверждённые связанные USB-диски, usbflags и непосредственно связанные forensic-артефакты. " +
            "ОЗУ и внутренние SATA/NVMe-накопители не относятся к USB и исключаются. " +
            "PDF используют шрифты с кириллицей; Excel — отдельные читаемые листы, фильтры и закреплённые заголовки.");
    }

    private static void AddLiveWindow(ColumnDescriptor column)
    {
        column.Item().PageBreak();
        SectionTitle(column, "10. Окно «Сейчас подключено USB/Type-C»");
        Paragraph(column,
            "Открывается автоматически при нажатии «Старт мониторинга». Показывает только активные (физически подключённые) устройства. " +
            "Список обновляется при подключении и отключении USB — не нужно перезапускать мониторинг при каждом изменении.");
        AddTable(column,
            ("Столбец", "Описание"),
            ("Когда заметили", "Когда программа впервые увидела устройство в этой сессии"),
            ("Что подключено", "Имя устройства"),
            ("Расположение", "Где в USB-дереве или «Windows не сохранила расположение порта»"),
            ("Производитель", "Название производителя из Windows, не код VID"),
            ("Модель", "Название модели из Windows, не код PID"),
            ("VID / PID", "Технические коды производителя и модели"),
            ("Статус", "Состояние по данным Windows. При корпоративном контроле USB может показываться «Error» — это не всегда означает поломку флешки"),
            ("Системный ID", "Технический номер — для специалистов"));

        Bullet(column, "Новое устройство появляется в таблице в течение нескольких секунд после подключения.");
        Bullet(column, "После отключения устройство исчезает из окна, но история остаётся в основных вкладках.");
        Bullet(column, "Если устройство было подключено до старта мониторинга — будет пометка «уже было подключено».");
        Bullet(column, "Закрыли окно случайно — нажмите «Окно USB» в главном окне. Останавливать мониторинг не нужно.");
    }

    private static void AddDataStorage(ColumnDescriptor column)
    {
        SectionTitle(column, "11. Где хранятся данные");
        Paragraph(column,
            "Portable-сборка (exe с флешки или из bin\\publish\\): все данные рядом с программой в папке data\\ — " +
            "после удаления папки на ПК не остаётся следов в %LOCALAPPDATA%.");
        Paragraph(column,
            "Если папка data\\ рядом с exe недоступна для записи (например, exe лежит в Program Files), " +
            "данные сохраняются в %LOCALAPPDATA%\\UsbForensicAudit\\.");
        AddTable(column,
            ("Файл / папка", "Назначение"),
            ("data\\audit.sqlite", "База SQLite — устройства, доказательства, находки"),
            ("data\\evidence.jsonl", "Forensic-журнал с SHA-256 hash-chain"),
            ("data\\app.log", "Технический лог ошибок приложения"),
            ("data\\external_utility_snapshot.json", "Снимок сторонней утилиты и исторические запуски"),
            ("data\\tools\\Procmon64.exe", "Распакованный Procmon (встроен в exe)"),
            ("data\\procmon\\*", "Сессии жёсткой трассировки: capture.csv, README"),
            ("UsbForensicAudit_*.pdf", "Полные PDF-отчёты"),
            ("UsbForensicAudit_Svodnyj_*.pdf", "Сводные PDF-отчёты"));
    }

    private static void AddSources(ColumnDescriptor column)
    {
        SectionTitle(column, "12. Что сканирует программа");
        SubTitle(column, "Системные источники");
        Bullet(column, "Реестр: USB, USBSTOR, SCSI, SWD\\WPDBUSENUM, MountedDevices.");
        Bullet(column, "C:\\Windows\\inf\\setupapi.dev.log.");
        Bullet(column, "Event Logs: System, Security, DeviceSetupManager, DriverFrameworks-UserMode.");

        SubTitle(column, "Пользовательские источники");
        Bullet(column, "MountPoints2, RecentDocs, OpenSavePidlMRU, LastVisitedPidlMRU.");
        Bullet(column, "LNK-файлы, Jump Lists, offline NTUSER.DAT и UsrClass.dat.");

        SubTitle(column, "Исполнение и очистка");
        Bullet(column, "Prefetch, Amcache, Shimcache — индикаторы запуска программ.");
        Bullet(column, "Security Event ID 4688 — создание процессов wevtutil, PowerShell, USBDeview, USBDetector и др.");
        Bullet(column, "Атрибуция очистки: инициатор из 104/1102, инструмент из Prefetch/4688, уверенность по правилам корреляции.");
        Bullet(column, "Противоречия между источниками (реестр vs setupapi).");

        SubTitle(column, "Live-мониторинг");
        Bullet(column, "События PnP Windows (Win32_DeviceChangeEvent), если система их отдаёт.");
        Bullet(column, "Live-мониторинг обновляет окно «Сейчас подключено» по событиям Windows (PnP и USB), без опроса каждые 2 секунды.");
        Bullet(column, "Учёт съёмных томов (буквы дисков) и USB-накопителей, даже если стандартный PnP-след не появился.");
        Bullet(column, "Сопоставление устройств по VID/PID и серийному номеру, если системный ID меняется между подключениями.");

        SubTitle(column, "Корпоративный контроль USB (DLP)");
        Bullet(column, "Если на ПК включена политика контроля съёмных носителей, Windows может не писать обычные следы в setupapi.dev.log и Event Log.");
        Bullet(column, "Программа дополнительно читает журнал корпоративной защиты USB (Application log) и сверяет устройства с тем, что видно «прямо сейчас».");
        Bullet(column, "В таблице «Доказательства» такие записи помечены как «Контроль USB: …»; источник — «Журнал корпоративной защиты USB (DLP)».");
        Bullet(column, "В окне мониторинга статус WMI «Error» при работающей флешке часто означает фильтрацию на уровне ОС, а не неисправность накопителя.");
    }

    private static void AddLimitations(ColumnDescriptor column)
    {
        column.Item().PageBreak();
        SectionTitle(column, "13. Ограничения");
        Bullet(column, "Windows часто не сохраняет номер физического USB-порта — поэтому «Расположение в USB» может быть пустым.");
        Bullet(column, "Корпоративные политики контроля USB могут скрывать или подменять стандартные следы Windows — даты тогда помечаются как ориентир.");
        Bullet(column, "Отсутствие следов не всегда означает очистку.");
        Bullet(column, "Сразу после переустановки Windows (первые 3 часа) журналы часто очищаются самой системой — это не признак ручной зачистки USB.");
        Bullet(column, "Инициатор «Система» при очистке журналов не всегда означает злоумышленника — Windows Update, службы и политики тоже работают от SYSTEM.");
        Bullet(column, "Prefetch утилиты очистки не доказывает, что именно она очистила журнал в момент события 104/1102.");
        Bullet(column, "Security Event ID 4688 доступен только при включённом аудите создания процессов.");
        Bullet(column, "Security Event ID 6416 доступен только при включённом аудите PnP.");
        Bullet(column, "Offline hive активного пользователя может быть заблокирован.");
        Bullet(column, "Программа не заменяет экспертизу высокого уровня — результаты нужно интерпретировать специалисту.");
        Bullet(column, "Разные сборки Windows дают разные Event ID — ошибка одного источника не останавливает весь анализ.");
    }

    private static void AddScenarios(ColumnDescriptor column)
    {
        SectionTitle(column, "14. Типичные сценарии");
        SubTitle(column, "Домашняя защита");
        Numbered(column, 1, "Запустить от администратора и выполнить полное сканирование.");
        Numbered(column, 2, "Проверить вкладку «USB устройства».");
        Numbered(column, 3, "Включить мониторинг для контроля новых подключений.");

        SubTitle(column, "Сразу после переустановки Windows");
        Numbered(column, 1, "Запустить полное сканирование и посмотреть дату «Установка Windows» на вкладке «Обзор».");
        Numbered(column, 2, "Если прошло менее 3 часов с установки, на вкладке «Следы очистки» будут записи со статусом «Норма: ОС после установки» — это не ручная зачистка.");
        Numbered(column, 3, "Повторить проверку позже, если нужна оценка уже «устоявшейся» системы.");

        SubTitle(column, "Расследование после инцидента");
        Numbered(column, 1, "Сканирование до любых действий на ПК.");
        Numbered(column, 2, "Сначала вкладка «Следы очистки» — подозрительные строки (статус «Подозрительно»), смотрите инициатор, инструмент и уверенность.");
        Numbered(column, 3, "Сопоставить устройства с вкладкой «Доказательства».");
        Numbered(column, 4, "Создать PDF-отчёт и не удалять папку данных.");
    }

    private static void AddTroubleshooting(ColumnDescriptor column)
    {
        SectionTitle(column, "15. Устранение проблем");
        AddTable(column,
            ("Проблема", "Решение"),
            ("UAC не подтверждён", "Запустите exe снова и нажмите «Да», либо используйте кнопку «Запуск от администратора»"),
            ("Программа мигает и не открывается", "Обновите exe: старые сборки перезапускали себя в цикле. Новая версия открывается сразу"),
            ("Нет прав администратора", "ПКМ по exe → «Запуск от имени администратора»"),
            ("«Точное время неизвестно»", "Нормально — Windows не всегда пишет дату подключения"),
            ("«Подключено сейчас»", "Устройство физически подключено в момент сканирования"),
            ("«ориентир — запись в реестре»", "Точной даты в журналах нет; показано время изменения записи Windows об устройстве"),
            ("«обнаружено при сканировании»", "Устройство подключено сейчас; точное время первого подключения не найдено"),
            ("«ориентир — последняя активность»", "Точного отключения нет; показана последняя известная активность"),
            ("В статусе «Error», но флешка работает", "Часто бывает при корпоративном контроле USB — смотрите пояснение в столбце «Статус»"),
            ("Закрыл окно «Сейчас подключено»", "Нажмите «Окно USB» — мониторинг не нужно останавливать"),
            ("Устройство не появляется в окне мониторинга", "Подождите 2–3 секунды; если не помогло — «Стоп» и снова «Старт мониторинга»"),
            ("«Сейчас не подключено, время неизвестно»", "Флешка/устройство не подключено, но когда отключили — неизвестно"),
            ("«Windows не сохранила расположение порта»", "Нормально — Windows редко сохраняет этот путь"),
            ("Кнопки отчёта неактивны", "Сначала выполните «Полное сканирование»"),
            ("Procmon: 0 чтений реестра", "Запустите USBDetector, откройте вкладку «Поиск» и повторите трассировку"),
            ("Procmon: кнопка неактивна", "Выберите строку в таблице сторонней утилиты — кнопка привязана к выбранной записи"),
            ("Кракозябры в PDF или колонках", "Обновите программу — текст проходит через нормализацию кодировки и шрифты с поддержкой кириллицы"),
            ("Ошибка в работе", "Откройте app.log в папке данных"));
    }

    private static void AddDonation(ColumnDescriptor column)
    {
        column.Item().PageBreak();
        SectionTitle(column, "16. А можно печеньку?");
        Paragraph(column,
            "Если UsbForensicAudit помог вам разобраться, кто подключал флешки, " +
            "найти следы очистки или просто спасти нервные клетки при разборе «кто это подключил» — " +
            "разработчик не против маленькой благодарности.");
        Paragraph(column,
            "Шуточная, но абсолютно серьёзная просьба: угостите печеньками " +
            "разработчика Орлова Дмитрия Владимировича. Не Bitcoin, не NFT, не «подписку на курс» — " +
            "а обычные, человеческие печеньки. Желательно с шоколадом. Или без. Главное — с добрыми намерениями.");
        Bullet(column, "Один USB-разбор = одна печенька (минимальная ставка).");
        Bullet(column, "Нашли очистку журналов с инициатором-пользователем и инструментом USBDeview/USBDetector = печенька и чай (повышенная ставка).");
        Bullet(column, "Программа реально помогла в расследовании = целая коробка (вы знаете, что делали).");
        Paragraph(column,
            "Печеньки принимаются в любой форме: реальной, домашней, сдобной и моральной. " +
            "Спасибо, что пользуетесь UsbForensicAudit!");
        column.Item().PaddingTop(8).Text("С уважением, команда UsbForensicAudit (то есть в основном Орлов Д.В.)")
            .Italic().FontColor(Colors.Grey.Darken1);
    }

    private static void SectionTitle(ColumnDescriptor column, string title)
    {
        column.Item().PaddingTop(4).Text(title).SemiBold().FontSize(13).FontColor(Colors.Blue.Darken3);
    }

    private static void SubTitle(ColumnDescriptor column, string title)
    {
        column.Item().PaddingTop(2).Text(title).SemiBold().FontSize(11);
    }

    private static void Paragraph(ColumnDescriptor column, string text)
    {
        column.Item().Text(text);
    }

    private static void Bullet(ColumnDescriptor column, string text)
    {
        column.Item().Row(row =>
        {
            row.ConstantItem(12).Text("•");
            row.RelativeItem().Text(text);
        });
    }

    private static void Numbered(ColumnDescriptor column, int number, string text)
    {
        column.Item().Row(row =>
        {
            row.ConstantItem(18).Text($"{number}.");
            row.RelativeItem().Text(text);
        });
    }

    private static void AddTable(ColumnDescriptor column, params (string Col1, string Col2)[] rows)
    {
        AddTable(column, rows.Select(r => (r.Col1, r.Col2, (string?)null)).ToArray());
    }

    private static void AddTable(ColumnDescriptor column, params (string Col1, string Col2, string? Col3)[] rows)
    {
        if (rows.Length == 0)
        {
            return;
        }

        column.Item().Table(table =>
        {
            table.ColumnsDefinition(columns =>
            {
                columns.RelativeColumn(1.1f);
                if (rows[0].Col3 is not null)
                {
                    columns.RelativeColumn(0.8f);
                }

                columns.RelativeColumn(2f);
            });

            for (var i = 0; i < rows.Length; i++)
            {
                var row = rows[i];
                var isHeader = i == 0;
                TableCell(table, row.Col1, isHeader);
                if (row.Col3 is not null)
                {
                    TableCell(table, row.Col2, isHeader);
                    TableCell(table, row.Col3, isHeader);
                }
                else
                {
                    TableCell(table, row.Col2, isHeader);
                }
            }
        });
    }

    private static void TableCell(TableDescriptor table, string text, bool header)
    {
        table.Cell().Border(0.5f).BorderColor(Colors.Grey.Lighten2).Padding(4).Element(cell =>
        {
            if (header)
            {
                cell.Text(text).FontFamily(FontName).SemiBold().FontSize(9);
            }
            else
            {
                cell.Text(text).FontFamily(FontName).FontSize(9);
            }
        });
    }
}
