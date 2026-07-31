using System.Globalization;

namespace UsbForensicAudit;

/// <summary>
/// Услуги Bluetooth, о которых устройство сообщило машине.
///
/// Это самое важное в записи о сопряжении: сам факт, что телефон был сопряжён,
/// говорит мало, а вот перечень услуг говорит, что через это соединение было
/// можно. Передача файлов, доступ в интернет через телефон, чтение книги
/// контактов и сообщений — разные вещи, и в отчёте их надо называть.
/// </summary>
internal static class BluetoothServiceCatalog
{
    private sealed record Service(string Name, bool Notable);

    private static readonly Dictionary<int, Service> Known = new()
    {
        [0x1101] = new("последовательный порт", false),
        [0x1103] = new("выход в интернет по телефонной линии", true),
        [0x1105] = new("передача файлов на устройство и с него (OBEX Object Push)", true),
        [0x1106] = new("доступ к файловой системе устройства (OBEX File Transfer)", true),
        [0x1108] = new("гарнитура", false),
        [0x110A] = new("устройство передаёт звук", false),
        [0x110B] = new("устройство принимает звук", false),
        [0x110C] = new("управление воспроизведением", false),
        [0x110D] = new("передача звука", false),
        [0x110E] = new("пульт управления", false),
        [0x110F] = new("пульт управления", false),
        [0x1112] = new("шлюз гарнитуры", false),
        [0x1115] = new("выход в сеть через это устройство (PANU)", true),
        [0x1116] = new("устройство раздаёт сеть (точка доступа NAP)", true),
        [0x1117] = new("объединение в сеть по Bluetooth (GN)", true),
        [0x111E] = new("громкая связь", false),
        [0x111F] = new("шлюз громкой связи", false),
        [0x1124] = new("клавиатура, мышь или иной ввод (HID)", false),
        [0x112D] = new("доступ к SIM-карте", true),
        [0x112F] = new("доступ к книге контактов (PBAP)", true),
        [0x1130] = new("доступ к книге контактов", true),
        [0x1132] = new("доступ к сообщениям (MAP)", true),
        [0x1133] = new("доступ к сообщениям", true),
        [0x1134] = new("уведомления о сообщениях", true),
        [0x1200] = new("сведения об устройстве (PnP)", false),
        [0x1800] = new("общие сведения об устройстве", false),
        [0x1801] = new("общие сведения об устройстве", false),
        [0x180A] = new("сведения о производителе", false),
        [0x180F] = new("уровень заряда", false)
    };

    /// <summary>
    /// Услуга по её опознавателю. Опознаватели Bluetooth записаны в реестре
    /// полным видом: «{00001105-0000-1000-8000-00805f9b34fb}», где значение
    /// несут первые четыре байта. Опознаватель вне списка остаётся числом:
    /// придумывать ему назначение нельзя.
    /// </summary>
    internal static bool TryDescribe(string? uuid, out string description, out bool notable)
    {
        description = "";
        notable = false;

        var text = (uuid ?? "").Trim().Trim('{', '}');
        if (text.Length < 8 || !int.TryParse(
                text[..8], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code))
        {
            return false;
        }

        // Услуги Bluetooth занимают младшие два байта; старшие два у стандартных
        // услуг всегда нулевые, а иное значение означает услугу производителя.
        if ((code & 0xFFFF0000) != 0)
        {
            return false;
        }

        if (Known.TryGetValue(code, out var service))
        {
            description = service.Name;
            notable = service.Notable;
            return true;
        }

        description = $"услуга с опознавателем 0x{code:X4}, назначение которой не определено";
        return true;
    }

    /// <summary>
    /// Класс устройства, который оно само о себе сообщает. Число вроде 5898764
    /// в отчёте бесполезно, а «телефон, смартфон» отвечает на вопрос, что
    /// подключали.
    /// </summary>
    internal static string DescribeDeviceClass(int? classOfDevice)
    {
        if (classOfDevice is null or 0)
        {
            return "";
        }

        var value = classOfDevice.Value;
        var major = (value >> 8) & 0x1F;
        var minor = (value >> 2) & 0x3F;

        var majorText = major switch
        {
            0 => "устройство неизвестного вида",
            1 => "компьютер",
            2 => "телефон",
            3 => "точка доступа в сеть",
            4 => "звуковое устройство",
            5 => "клавиатура, мышь или игровой пульт",
            6 => "камера или сканер",
            7 => "часы или иное носимое устройство",
            8 => "игрушка",
            9 => "медицинское устройство",
            _ => "устройство неизвестного вида"
        };

        var minorText = (major, minor) switch
        {
            (1, 1) => "настольный",
            (1, 2) => "сервер",
            (1, 3) => "ноутбук",
            (1, 4) => "карманный компьютер",
            (1, 5) => "карманный компьютер",
            (1, 6) => "планшет",
            (2, 1) => "мобильный телефон",
            (2, 2) => "беспроводная трубка",
            (2, 3) => "смартфон",
            (2, 4) => "модем",
            (4, 1) => "гарнитура",
            (4, 2) => "громкая связь",
            (4, 4) => "микрофон",
            (4, 5) => "динамик",
            (4, 6) => "наушники",
            (4, 8) => "автомобильная система",
            (5, 16) => "клавиатура",
            (5, 32) => "мышь",
            _ => ""
        };

        return minorText.Length > 0 ? $"{majorText}, {minorText}" : majorText;
    }

    /// <summary>
    /// Возможности, которые устройство объявило вместе со своим классом. Здесь
    /// важны две: передача файлов и выход в сеть — через них с машины уходят
    /// данные.
    /// </summary>
    internal static List<string> DescribeServiceClasses(int? classOfDevice)
    {
        var result = new List<string>();
        if (classOfDevice is null or 0)
        {
            return result;
        }

        var value = classOfDevice.Value;
        foreach (var (bit, text) in new (int Bit, string Text)[]
                 {
                     (16, "определение местоположения"),
                     (17, "выход в сеть"),
                     (18, "вывод изображения или звука"),
                     (19, "съёмка изображения или звука"),
                     (20, "передача файлов"),
                     (21, "звук"),
                     (22, "телефония"),
                     (23, "выдача сведений о себе")
                 })
        {
            if (((value >> bit) & 1) == 1)
            {
                result.Add(text);
            }
        }

        return result;
    }
}
