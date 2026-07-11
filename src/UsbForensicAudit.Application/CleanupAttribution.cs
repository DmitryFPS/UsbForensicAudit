using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace UsbForensicAudit;

public static class CleanupAttribution
{
    private static readonly TimeSpan ToolCorrelationBefore = TimeSpan.FromMinutes(60);
    private static readonly TimeSpan ToolCorrelationAfter = TimeSpan.FromMinutes(5);

    private static readonly Regex XmlFieldRegex = new(
        @"<(SubjectUserName|SubjectDomainName|SubjectUserSid|UserID|Channel)>([^<]*)</\1>",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static InitiatorInfo ParseEventLogInitiator(string rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText))
        {
            return InitiatorInfo.Unknown;
        }

        string? userName = null;
        string? domain = null;
        string? sid = null;

        try
        {
            if (rawText.TrimStart().StartsWith("<", StringComparison.Ordinal))
            {
                var doc = XDocument.Parse(rawText);
                var eventData = doc.Descendants().Where(x => x.Name.LocalName is "Data" or "SubjectUserName" or "SubjectDomainName" or "SubjectUserSid" or "UserID").ToList();
                userName = FindXmlValue(doc, "SubjectUserName") ?? FindDataValue(doc, "SubjectUserName");
                domain = FindXmlValue(doc, "SubjectDomainName") ?? FindDataValue(doc, "SubjectDomainName");
                sid = FindXmlValue(doc, "SubjectUserSid") ?? FindDataValue(doc, "SubjectUserSid") ?? FindDataValue(doc, "UserID");
            }
        }
        catch
        {
            // Ниже — запасной вариант через регулярное выражение.
        }

        if (string.IsNullOrWhiteSpace(userName) && string.IsNullOrWhiteSpace(sid))
        {
            foreach (Match match in XmlFieldRegex.Matches(rawText))
            {
                var name = match.Groups[1].Value;
                var value = match.Groups[2].Value.Trim();
                switch (name.ToUpperInvariant())
                {
                    case "SUBJECTUSERNAME":
                        userName = value;
                        break;
                    case "SUBJECTDOMAINNAME":
                        domain = value;
                        break;
                    case "SUBJECTUSERSID":
                    case "USERID":
                        sid = value;
                        break;
                }
            }
        }

        var account = FormatAccount(domain, userName);
        var kind = ClassifyInitiatorKind(account, sid);
        return new InitiatorInfo(kind, account, sid);
    }

    public static string? FindCorrelatedTool(DateTimeOffset eventAtUtc, IReadOnlyList<EvidenceRecord> evidence)
    {
        var windowStart = eventAtUtc.Subtract(ToolCorrelationBefore);
        var windowEnd = eventAtUtc.Add(ToolCorrelationAfter);

        var candidates = evidence
            .Where(x => x.TimestampUtc >= windowStart && x.TimestampUtc <= windowEnd)
            .Select(x => new
            {
                Tool = DetectToolFromEvidence(x),
                x.TimestampUtc,
                x.Source
            })
            .Where(x => x.Tool is not null)
            .OrderBy(x => Math.Abs((x.TimestampUtc - eventAtUtc).TotalSeconds))
            .ToList();

        return candidates.FirstOrDefault()?.Tool;
    }

    public static string? DetectToolFromEvidence(EvidenceRecord evidence)
    {
        return CleanerEvidenceClassifier.Analyze(evidence)?.Tool;
    }

    public static string DetermineConfidence(
        string assessment,
        InitiatorInfo initiator,
        string? correlatedTool,
        string area)
    {
        if (assessment.Equals("OsInstall", StringComparison.OrdinalIgnoreCase))
        {
            return "Normal";
        }

        if (area.Equals("Cleaner Artifacts", StringComparison.OrdinalIgnoreCase))
        {
            return "Indirect";
        }

        if (!string.IsNullOrWhiteSpace(correlatedTool)
            && initiator.Kind is "Administrator" or "User")
        {
            return "Probable";
        }

        if (!string.IsNullOrWhiteSpace(correlatedTool)
            && initiator.Kind == "System")
        {
            return "Indirect";
        }

        if (initiator.Kind == "System")
        {
            return "Indirect";
        }

        if (initiator.Kind is "Administrator" or "User")
        {
            return "Indirect";
        }

        return "Unknown";
    }

    public static InitiatorInfo InitiatorForSetupApi(bool fromInitialSetup, DateTimeOffset? installAtUtc)
    {
        if (fromInitialSetup)
        {
            return new InitiatorInfo("System", "SYSTEM (Windows Setup)", "S-1-5-18");
        }

        return InitiatorInfo.Unknown;
    }

    public static string ToolForSetupApi(bool fromInitialSetup, string? correlatedTool)
    {
        if (!string.IsNullOrWhiteSpace(correlatedTool))
        {
            return correlatedTool;
        }

        return fromInitialSetup ? "Windows Setup / PnP" : "не определено";
    }

    public static string BuildAttributionDetails(InitiatorInfo initiator, string? tool, string confidence)
    {
        var toolText = string.IsNullOrWhiteSpace(tool) ? "не определено" : tool;
        return $"Инициатор: {initiator.DisplayText}. Возможный инструмент: {toolText}. Уверенность: {UserDisplayText.Confidence(confidence)}.";
    }

    private static string ClassifyInitiatorKind(string account, string? sid)
    {
        var sidUpper = sid?.Trim().ToUpperInvariant() ?? "";
        var accountUpper = account.ToUpperInvariant();

        if (IsSystemSid(sidUpper)
            || accountUpper.Contains(@"NT AUTHORITY\SYSTEM", StringComparison.Ordinal)
            || accountUpper.Equals("SYSTEM", StringComparison.Ordinal)
            || accountUpper.Contains("LOCAL SERVICE", StringComparison.Ordinal)
            || accountUpper.Contains("NETWORK SERVICE", StringComparison.Ordinal)
            || accountUpper.Contains("NT AUTHORITY\\LOCAL SERVICE", StringComparison.Ordinal)
            || accountUpper.Contains("NT AUTHORITY\\NETWORK SERVICE", StringComparison.Ordinal)
            || accountUpper.EndsWith('$'))
        {
            return "System";
        }

        if (sidUpper.EndsWith("-500", StringComparison.Ordinal)
            || accountUpper.Contains("ADMIN", StringComparison.Ordinal)
            || accountUpper.Contains("АДМИН", StringComparison.Ordinal))
        {
            return "Administrator";
        }

        if (string.IsNullOrWhiteSpace(account) || account.Equals("не определено", StringComparison.OrdinalIgnoreCase))
        {
            return "Unknown";
        }

        return "User";
    }

    private static bool IsSystemSid(string sid)
    {
        return sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20" or "S-1-5-6";
    }

    private static string FormatAccount(string? domain, string? userName)
    {
        if (string.IsNullOrWhiteSpace(userName))
        {
            return "не определено";
        }

        if (string.IsNullOrWhiteSpace(domain) || userName.Contains('\\', StringComparison.Ordinal))
        {
            return userName;
        }

        return $"{domain}\\{userName}";
    }

    private static string? FindXmlValue(XDocument doc, string localName)
    {
        return doc.Descendants().FirstOrDefault(x => x.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase))?.Value?.Trim();
    }

    public static string ExtractProcessPath(string rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText))
        {
            return "";
        }

        try
        {
            if (rawText.TrimStart().StartsWith("<", StringComparison.Ordinal))
            {
                var doc = XDocument.Parse(rawText);
                return FindDataValue(doc, "NewProcessName")
                       ?? FindXmlValue(doc, "NewProcessName")
                       ?? "";
            }
        }
        catch
        {
            // Ниже — запасной вариант через регулярное выражение.
        }

        var match = Regex.Match(rawText, @"New Process Name:\s*(.+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value.Trim() : "";
    }

    private static string? FindDataValue(XDocument doc, string nameAttribute)
    {
        return doc.Descendants()
            .Where(x => x.Name.LocalName == "Data")
            .FirstOrDefault(x => (string?)x.Attribute("Name") == nameAttribute)
            ?.Value?.Trim();
    }
}
