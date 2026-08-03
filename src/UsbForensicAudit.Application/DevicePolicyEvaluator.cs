using System.Text.Json;
using System.Text.Json.Serialization;

namespace UsbForensicAudit;

/// <summary>
/// Оценивает устройства аудита политикой «свой/чужой» и разбирает файл политики.
/// Оценка чистая (детерминированная, без ФС); разбор JSON тоже чистый — файловая
/// обёртка вынесена отдельно, чтобы логика тестировалась без диска.
/// </summary>
public static class DevicePolicyEvaluator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    /// <summary>Стандартное имя файла политики рядом с программой.</summary>
    public const string DefaultFileName = "device-policy.json";

    public static DevicePolicySummary Evaluate(AuditResult result, DevicePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(policy);

        if (policy.IsEmpty)
        {
            return DevicePolicySummary.NotDefined;
        }

        // Оцениваются только принесённые с собой устройства: у записи внутреннего
        // диска и частей шины «политика подключения» смысла не имеет.
        var items = result.Devices
            .Where(device => device.IsExternalDevice || device.Externality == DeviceExternality.PossiblyExternal)
            .Select(device => new DevicePolicyResultItem
            {
                DeviceDisplayName = device.DisplayName,
                VidPidText = device.VidPidText,
                SerialText = device.SerialText,
                Decision = policy.Decide(device)
            })
            .OrderByDescending(x => x.IsViolation)
            .ThenBy(x => x.DeviceDisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new DevicePolicySummary { Items = items, PolicyDefined = true };
    }

    /// <summary>Разбирает JSON политики. Пустая или пробельная строка даёт пустую политику.</summary>
    public static DevicePolicy Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return DevicePolicy.None;
        }

        var dto = JsonSerializer.Deserialize<PolicyDto>(json, JsonOptions) ?? new PolicyDto();
        return new DevicePolicy
        {
            Allowed = (dto.Allowed ?? []).Select(ToRule).ToArray(),
            Blocked = (dto.Blocked ?? []).Select(ToRule).ToArray(),
            AllowlistEnforced = dto.AllowlistEnforced
        };
    }

    private static DevicePolicyRule ToRule(RuleDto dto) => new()
    {
        Vid = dto.Vid,
        Pid = dto.Pid,
        Serial = dto.Serial,
        Note = dto.Note
    };

    private sealed class PolicyDto
    {
        [JsonPropertyName("allowlistEnforced")]
        public bool AllowlistEnforced { get; set; }

        [JsonPropertyName("allowed")]
        public List<RuleDto>? Allowed { get; set; }

        [JsonPropertyName("blocked")]
        public List<RuleDto>? Blocked { get; set; }
    }

    private sealed class RuleDto
    {
        public string? Vid { get; set; }
        public string? Pid { get; set; }
        public string? Serial { get; set; }
        public string? Note { get; set; }
    }
}
