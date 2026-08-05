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
        var policyDefinition = DevicePolicyProvider.LoadDefault();
        var policy = DevicePolicyEvaluator.Evaluate(result, policyDefinition);
        var mitre = MitreMapper.Map(result);

        RiskExfiltrationVerdictText.Text = exfiltration.Verdict();
        RiskMitreVerdictText.Text = mitre.Verdict();
        RiskPolicyVerdictText.Text = policy.PolicyDefined
            ? policy.Verdict()
            : "Политика устройств: проверка «свой/чужой» не выполнялась — это необязательная "
              + "настройка для корпоративного контроля. Включается файлом device-policy.json "
              + "рядом с программой (пример: docs\\device-policy.example.json).";

        // DisplayFiles включает и переносы с неопределённым направлением: это самые
        // уверенные совпадения (разница < 10 минут), раньше они не показывались вовсе.
        ExfiltrationGrid.ItemsSource = exfiltration.DisplayFiles;
        PolicyGrid.ItemsSource = policy.Items;
        MitreGrid.ItemsSource = mitre.Findings;

        ShowSection(ExfiltrationSectionHeader, ExfiltrationGrid, ExfiltrationRow, exfiltration.HasAnyIndication);
        ShowSection(PolicySectionHeader, PolicyGrid, PolicyRow, policy.PolicyDefined && policy.Items.Count > 0);
        ShowSection(MitreSectionHeader, MitreGrid, MitreRow, mitre.HasFindings);

        // Колонка «Политика» в таблице устройств имеет смысл, только когда
        // политика задана: пустой столбец лишь занимал бы место.
        PolicyColumn.Visibility = policy.PolicyDefined ? Visibility.Visible : Visibility.Collapsed;

        UpdateOverviewAnswers(result, policyDefinition);

        if (exfiltration.HasAnyIndication)
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
    /// что и в отчётах, с цветной кромкой-светофором. Вердикты даёт общий
    /// KeyAnswersContent — тот же, что в HTML, PDF и Excel: три копии логики
    /// уже расходились между собой (Обзор показывал 8 устройств, отчёт — 7).
    /// Здесь остаётся только окраска и подсказки, на какой вкладке подробности.
    /// </summary>
    private void UpdateOverviewAnswers(AuditResult result, DevicePolicy? policy)
    {
        var ok = (Brush)FindResource("Ok");
        var warn = (Brush)FindResource("Warn");
        var danger = (Brush)FindResource("Danger");
        var accent = (Brush)FindResource("Accent2");
        var textMain = (Brush)FindResource("TextMain");

        var ctx = ForensicReportContext.Create(result, policy: policy);
        var answers = KeyAnswersContent.Build(ctx);

        (Brush Bar, Brush Fore) Paint(KeyAnswersContent.Tone tone) => tone switch
        {
            KeyAnswersContent.Tone.Bad => (danger, danger),
            KeyAnswersContent.Tone.Attention => (warn, warn),
            KeyAnswersContent.Tone.Plain => (accent, textMain),
            _ => (ok, textMain)
        };

        var hints = new[]
        {
            "Подробности — на вкладке «USB устройства».",
            "Разбор — вкладки «Доказательства» и «Риски».",
            "Разбор — вкладка «Следы очистки», там же заметки эксперта."
        };

        var targets = new[]
        {
            (Bar: AnswerDevicesBar, Verdict: AnswerDevicesVerdict, Note: AnswerDevicesNote, Question: AnswerDevicesQuestion),
            (Bar: AnswerExfilBar, Verdict: AnswerExfilVerdict, Note: AnswerExfilNote, Question: AnswerExfilQuestion),
            (Bar: AnswerCleanupBar, Verdict: AnswerCleanupVerdict, Note: AnswerCleanupNote, Question: AnswerCleanupQuestion)
        };

        for (var i = 0; i < targets.Length; i++)
        {
            var answer = answers[i];
            var (bar, fore) = Paint(answer.Tone);
            targets[i].Bar.Background = bar;
            targets[i].Verdict.Foreground = fore;
            targets[i].Verdict.Text = answer.Verdict;
            targets[i].Question.Text = answer.Question.ToUpperInvariant();
            targets[i].Note.Text = $"{answer.Note} {hints[i]}";
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
