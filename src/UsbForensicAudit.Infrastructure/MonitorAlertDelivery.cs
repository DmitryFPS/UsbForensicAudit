using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace UsbForensicAudit;

/// <summary>Настройки доставки алертов мониторинга из monitor-config.json рядом с программой.</summary>
public sealed class MonitorAlertOptions
{
    /// <summary>URL для POST JSON-алерта; null — вебхук выключен.</summary>
    public string? WebhookUrl { get; init; }

    /// <summary>Писать ли алерты в журнал приложений Windows (через eventcreate).</summary>
    public bool WriteWindowsEventLog { get; init; } = true;

    public const string DefaultFileName = "monitor-config.json";

    public static MonitorAlertOptions LoadDefault()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, DefaultFileName);
            if (!File.Exists(path))
            {
                return new MonitorAlertOptions();
            }

            var dto = JsonSerializer.Deserialize<Dto>(File.ReadAllText(path), JsonOptions);
            return dto is null
                ? new MonitorAlertOptions()
                : new MonitorAlertOptions
                {
                    WebhookUrl = string.IsNullOrWhiteSpace(dto.WebhookUrl) ? null : dto.WebhookUrl.Trim(),
                    WriteWindowsEventLog = dto.WriteWindowsEventLog ?? true
                };
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, "monitor-config.json read failed");
            return new MonitorAlertOptions();
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private sealed class Dto
    {
        public string? WebhookUrl { get; set; }
        public bool? WriteWindowsEventLog { get; set; }
    }
}

/// <summary>
/// Доставка алертов фонового мониторинга: журнал alerts.jsonl в каталоге данных
/// (всегда), журнал приложений Windows (eventcreate — без новых зависимостей)
/// и опциональный вебхук. Сбой одного канала не мешает остальным: алерт о
/// чужой флешке важнее, чем недоступный вебхук.
/// </summary>
public static class MonitorAlertDelivery
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

    // Сериализует запись в alerts.jsonl: два одновременно подключённых устройства
    // иначе конкурировали бы за файл, и один алерт терялся бы с IOException.
    private static readonly object FileLock = new();

    public static void Deliver(MonitorAlert alert, MonitorAlertOptions options, string dataDirectory, Action<string>? log = null)
    {
        ArgumentNullException.ThrowIfNull(alert);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);

        AppendToFile(alert, dataDirectory, log);

        if (options.WriteWindowsEventLog)
        {
            WriteWindowsEventLog(alert, log);
        }

        if (options.WebhookUrl is not null)
        {
            // Вебхук отправляется в фоне: сетевой таймаут до 10 с не должен
            // блокировать поток мониторинга (иначе — истощение пула потоков
            // при недоступном вебхуке и потоке подключений).
            var url = options.WebhookUrl;
            _ = Task.Run(() => PostWebhookAsync(alert, url, log));
        }
    }

    private static void AppendToFile(MonitorAlert alert, string dataDirectory, Action<string>? log)
    {
        try
        {
            Directory.CreateDirectory(dataDirectory);
            var line = JsonSerializer.Serialize(new
            {
                whenUtc = alert.WhenUtc,
                kind = alert.Kind.ToString(),
                title = alert.Title,
                details = alert.Details,
                deviceKey = alert.DeviceKey
            });
            lock (FileLock)
            {
                File.AppendAllText(
                    Path.Combine(dataDirectory, "alerts.jsonl"),
                    line + Environment.NewLine,
                    new UTF8Encoding(false));
            }
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, "Alert file append failed");
            log?.Invoke($"Не удалось записать алерт в alerts.jsonl: {exception.Message}");
        }
    }

    /// <summary>
    /// Запись в журнал приложений Windows штатной утилитой eventcreate: не
    /// требует новых NuGet-зависимостей. ID 776 — «событие мониторинга USB».
    /// </summary>
    private static void WriteWindowsEventLog(MonitorAlert alert, Action<string>? log)
    {
        try
        {
            var description = $"{alert.Title}. {alert.Details}";
            if (description.Length > 800)
            {
                description = description[..800];
            }

            // ArgumentList вместо строки Arguments: каждый аргумент передаётся
            // отдельно, .NET сам корректно квотирует. Имя устройства с кавычками,
            // скобками, & или | больше не может «сломать» или подменить аргумент
            // eventcreate — закрыта инъекция аргументов от вредоносного USB.
            var info = new ProcessStartInfo
            {
                FileName = "eventcreate",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            info.ArgumentList.Add("/T"); info.ArgumentList.Add("WARNING");
            info.ArgumentList.Add("/ID"); info.ArgumentList.Add("776");
            info.ArgumentList.Add("/L"); info.ArgumentList.Add("APPLICATION");
            info.ArgumentList.Add("/SO"); info.ArgumentList.Add("UsbForensicAudit");
            info.ArgumentList.Add("/D"); info.ArgumentList.Add(description);

            using var process = Process.Start(info);
            process?.WaitForExit(5000);
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, "Event log alert failed");
            log?.Invoke($"Не удалось записать алерт в журнал Windows: {exception.Message}");
        }
    }

    private static async Task PostWebhookAsync(MonitorAlert alert, string url, Action<string>? log)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                tool = "UsbForensicAudit",
                whenUtc = alert.WhenUtc,
                kind = alert.Kind.ToString(),
                title = alert.Title,
                details = alert.Details
            });
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var response = await Http.PostAsync(url, content).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                log?.Invoke($"Вебхук ответил {(int)response.StatusCode} на алерт «{alert.Title}».");
            }
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, "Webhook alert failed");
            log?.Invoke($"Не удалось отправить алерт на вебхук: {exception.Message}");
        }
    }
}
