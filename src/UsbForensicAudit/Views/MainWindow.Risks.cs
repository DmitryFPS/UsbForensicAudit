using System.Windows;
using System.Windows.Controls;

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
