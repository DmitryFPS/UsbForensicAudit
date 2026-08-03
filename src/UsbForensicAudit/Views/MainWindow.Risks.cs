using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace UsbForensicAudit;

/// <summary>
/// Вкладка «Риски»: вынос данных, соответствие политике устройств и
/// MITRE ATT&CK поверх готовых анализаторов Application-слоя. Работает без
/// настройки: после сканирования всегда показываются три вердикта, а таблицы
/// появляются только когда по блоку что-то найдено. Политика — необязательная
/// возможность: без device-policy.json её блок и колонка в устройствах скрыты.
/// Оценка политики дополнительно штампует решение на записи устройств,
/// поэтому вызывается до обновления таблицы устройств.
/// </summary>
public partial class MainWindow
{
    private void RefreshRisks(AuditResult result)
    {
        var exfiltration = ExfiltrationAnalyzer.Analyze(result);
        var policy = DevicePolicyEvaluator.Evaluate(result, DevicePolicyProvider.LoadDefault());
        var mitre = MitreMapper.Map(result);

        RiskExfiltrationVerdictText.Text = exfiltration.Verdict();
        RiskMitreVerdictText.Text = mitre.Verdict();
        RiskPolicyVerdictText.Text = policy.PolicyDefined
            ? policy.Verdict()
            : "Политика устройств: проверка «свой/чужой» не выполнялась — это необязательная "
              + "настройка для корпоративного контроля. Включается файлом device-policy.json "
              + "рядом с программой (пример: docs\\device-policy.example.json).";

        ExfiltrationGrid.ItemsSource = exfiltration.OutboundFiles;
        PolicyGrid.ItemsSource = policy.Items;
        MitreGrid.ItemsSource = mitre.Findings;

        ShowSection(ExfiltrationSectionHeader, ExfiltrationGrid, ExfiltrationRow, exfiltration.HasFindings);
        ShowSection(PolicySectionHeader, PolicyGrid, PolicyRow, policy.PolicyDefined && policy.Items.Count > 0);
        ShowSection(MitreSectionHeader, MitreGrid, MitreRow, mitre.HasFindings);

        // Колонка «Политика» в таблице устройств имеет смысл, только когда
        // политика задана: пустой столбец лишь занимал бы место.
        PolicyColumn.Visibility = policy.PolicyDefined ? Visibility.Visible : Visibility.Collapsed;

        UpdateOverviewAnswers(result, exfiltration, policy);

        if (exfiltration.HasFindings)
        {
            DataGridAutoSize.FitColumns(ExfiltrationGrid);
        }

        if (policy.Items.Count > 0)
        {
            DataGridAutoSize.FitColumns(PolicyGrid);
        }

        if (mitre.HasFindings)
        {
            DataGridAutoSize.FitColumns(MitreGrid);
        }
    }

    /// <summary>
    /// Карточки-ответы на вкладке «Обзор»: те же три вопроса расследования,
    /// что и в отчётах, с цветной кромкой-светофором. Пользователь видит
    /// положение дел сразу после сканирования, не открывая другие вкладки.
    /// </summary>
    private void UpdateOverviewAnswers(AuditResult result, ExfiltrationSummary exfiltration, DevicePolicySummary policy)
    {
        var ok = (Brush)FindResource("Ok");
        var warn = (Brush)FindResource("Warn");
        var danger = (Brush)FindResource("Danger");
        var accent = (Brush)FindResource("Accent2");
        var textMain = (Brush)FindResource("TextMain");

        // Вопрос 1: что подключали. Единый источник с отчётами
        // (ForensicReportContext.ExternalListedDevices) — иначе число внешних
        // устройств в «Обзоре» и в отчёте руководителю расходилось (8 против 7).
        var external = ForensicReportContext.ExternalListedDevices(result.Devices);
        var lastSeen = external
            .Select(x => x.LastSeenUtc)
            .Where(x => x is not null)
            .OrderByDescending(x => x)
            .FirstOrDefault();
        AnswerDevicesBar.Background = policy.HasViolations ? danger : accent;
        AnswerDevicesVerdict.Foreground = policy.HasViolations ? danger : textMain;
        AnswerDevicesVerdict.Text = external.Count == 0
            ? "Следов внешних носителей не найдено"
            : $"Да — внешних устройств: {external.Count}";
        AnswerDevicesNote.Text = external.Count == 0
            ? "Отсутствие следов не доказывает отсутствие подключений."
            : (lastSeen is not null ? $"Последняя активность: {DateDisplay.FormatMoscow(lastSeen.Value)}. " : "")
              + (policy.HasViolations
                  ? $"Нарушений политики: {policy.Violations.Count} — вкладка «Риски»."
                  : "Подробности — на вкладке «USB устройства».");

        // Вопрос 2: уходили ли данные.
        AnswerExfilBar.Background = exfiltration.ConfirmedCount > 0 ? danger : exfiltration.HasFindings ? warn : ok;
        AnswerExfilVerdict.Foreground = exfiltration.ConfirmedCount > 0 ? danger : exfiltration.HasFindings ? warn : textMain;
        AnswerExfilVerdict.Text = exfiltration.ConfirmedCount > 0
            ? $"Да — подтверждено файлов: {exfiltration.ConfirmedCount}"
            : exfiltration.HasFindings
                ? $"Возможно — признаков: {exfiltration.OutboundCount}"
                : "Признаков выноса данных не найдено";
        AnswerExfilNote.Text = exfiltration.HasFindings
            ? "Список файлов — вкладка «Риски» и отчёты."
            : "Проверены следы копирования на съёмные носители.";

        // Вопрос 3: чистили ли следы.
        var suspicious = result.CleanupFindings.Count(x => x.IsSuspicious);
        var highRisk = result.CleanupFindings.Count(x =>
            x.IsSuspicious && x.Severity.Equals("High", StringComparison.OrdinalIgnoreCase));
        var attention = result.CleanupFindings.Count(x => x.NeedsAttention);
        AnswerCleanupBar.Background = highRisk > 0 ? danger : suspicious > 0 || attention > 0 ? warn : ok;
        AnswerCleanupVerdict.Foreground = highRisk > 0 ? danger : suspicious > 0 || attention > 0 ? warn : textMain;
        AnswerCleanupVerdict.Text = highRisk > 0
            ? $"Да, вероятно — высокого риска: {highRisk}"
            : suspicious > 0
                ? $"Возможно — подозрительных: {suspicious}"
                : attention > 0
                    ? $"Явной очистки нет, требуют внимания: {attention}"
                    : "Признаков очистки не найдено";
        AnswerCleanupNote.Text = suspicious > 0 || attention > 0
            ? "Разбор — вкладка «Следы очистки», там же заметки эксперта."
            : "Проверены журналы, реестр и следы утилит очистки.";
    }

    /// <summary>
    /// Показывает или полностью убирает секцию (заголовок, таблицу и её строку
    /// сетки): скрытая секция не должна оставлять пустой полосы на вкладке.
    /// </summary>
    private static void ShowSection(UIElement header, UIElement grid, RowDefinition row, bool visible)
    {
        header.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        grid.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        row.Height = visible ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
    }
}
