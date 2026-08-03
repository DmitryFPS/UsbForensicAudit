namespace UsbForensicAudit;

/// <summary>
/// Вкладка «Риски»: вынос данных, соответствие политике устройств и
/// MITRE ATT&CK поверх готовых анализаторов Application-слоя. Логики здесь
/// нет — только привязка результатов к таблицам и строкам вердиктов.
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

        ExfiltrationGrid.ItemsSource = exfiltration.OutboundFiles;
        PolicyGrid.ItemsSource = policy.Items;
        MitreGrid.ItemsSource = mitre.Findings;

        RiskExfiltrationVerdictText.Text = exfiltration.Verdict();
        RiskPolicyVerdictText.Text = policy.Verdict();
        RiskMitreVerdictText.Text = mitre.Verdict();

        DataGridAutoSize.FitColumns(ExfiltrationGrid);
        DataGridAutoSize.FitColumns(PolicyGrid);
        DataGridAutoSize.FitColumns(MitreGrid);
    }
}
