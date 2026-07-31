namespace UsbForensicAudit;

/// <summary>
/// Поиск признаков устройства в свободном тексте. Короткие аббревиатуры (MTP, PTP,
/// WPD, SD) ищутся как отдельные слова: подстрочное совпадение даёт ложные
/// срабатывания — например PTP находится внутри PPTP у сетевого адаптера
/// "WAN Miniport (PPTP)", и адаптер попадает в отчёт как переносное устройство.
/// </summary>
public static class DeviceMarkerText
{
    public static bool ContainsWord(string? value, string marker)
    {
        if (string.IsNullOrEmpty(value) || string.IsNullOrEmpty(marker))
        {
            return false;
        }

        var index = 0;
        while (index <= value.Length - marker.Length)
        {
            var found = value.IndexOf(marker, index, StringComparison.OrdinalIgnoreCase);
            if (found < 0)
            {
                return false;
            }

            var end = found + marker.Length;
            var boundedLeft = found == 0 || !char.IsLetterOrDigit(value[found - 1]);
            var boundedRight = end >= value.Length || !char.IsLetterOrDigit(value[end]);
            if (boundedLeft && boundedRight)
            {
                return true;
            }

            index = found + 1;
        }

        return false;
    }

    public static bool ContainsAnyWord(string? value, params string[] markers) =>
        markers.Any(marker => ContainsWord(value, marker));

    /// <summary>
    /// Однозначный признак ищется как подстрока, короткая аббревиатура — как слово.
    /// </summary>
    public static bool ContainsMarker(string? value, string marker)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        return RequiresWordBoundary(marker)
            ? ContainsWord(value, marker)
            : value.Contains(marker, StringComparison.OrdinalIgnoreCase);
    }

    public static bool ContainsAnyMarker(string? value, params string[] markers) =>
        markers.Any(marker => ContainsMarker(value, marker));

    /// <summary>
    /// Признак короткий и состоит только из букв и цифр, поэтому легко оказывается
    /// частью другого слова.
    /// </summary>
    public static bool RequiresWordBoundary(string marker) =>
        marker.Length <= 4 && marker.All(char.IsLetterOrDigit);
}
