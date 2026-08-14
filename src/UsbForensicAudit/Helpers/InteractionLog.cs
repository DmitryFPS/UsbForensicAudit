using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace UsbForensicAudit;

/// <summary>
/// Записывает действия оператора в app.log. Обработчики регистрируются на уровне классов,
/// поэтому охватывают все окна и все элементы сразу — отдельные обработчики трогать не нужно
/// и новые кнопки попадают в журнал автоматически.
/// </summary>
public static class InteractionLog
{
    private static bool _attached;
    private static bool _ready;

    /// <summary>
    /// Вызывается после первой отрисовки. До неё списки и вкладки сами выставляют
    /// значения по умолчанию, и без этой отметки инициализация выглядела бы в журнале
    /// как действия оператора.
    /// </summary>
    public static void MarkReady()
    {
        _ready = true;
    }

    public static void Attach()
    {
        if (_attached)
        {
            return;
        }

        _attached = true;

        EventManager.RegisterClassHandler(
            typeof(ButtonBase),
            ButtonBase.ClickEvent,
            new RoutedEventHandler(OnClick),
            handledEventsToo: true);

        EventManager.RegisterClassHandler(
            typeof(TabControl),
            Selector.SelectionChangedEvent,
            new SelectionChangedEventHandler(OnTabChanged),
            handledEventsToo: true);

        EventManager.RegisterClassHandler(
            typeof(ComboBox),
            Selector.SelectionChangedEvent,
            new SelectionChangedEventHandler(OnComboChanged),
            handledEventsToo: true);

        EventManager.RegisterClassHandler(
            typeof(Window),
            FrameworkElement.LoadedEvent,
            new RoutedEventHandler(OnWindowLoaded));
    }

    private static void OnClick(object sender, RoutedEventArgs e)
    {
        // Нажатия внутри выпадающих списков и прокрутки — шум, а не действия оператора.
        if (sender is ComboBoxItem or RepeatButton or Thumb)
        {
            return;
        }

        AppLog.Action($"Нажато: {Describe(sender)}");
    }

    private static void OnTabChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || !ReferenceEquals(sender, e.OriginalSource) || e.AddedItems.Count == 0)
        {
            return;
        }

        var header = (e.AddedItems[0] as HeaderedContentControl)?.Header as string;
        AppLog.Action($"Открыт раздел: {header ?? Describe(e.AddedItems[0])}");
    }

    private static void OnComboChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || !ReferenceEquals(sender, e.OriginalSource) || e.AddedItems.Count == 0)
        {
            return;
        }

        AppLog.Action($"Выбрано в «{Describe(sender)}»: {AsText(e.AddedItems[0])}");
    }

    private static void OnWindowLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is Window window)
        {
            AppLog.Action($"Открыто окно: {window.GetType().Name} «{window.Title}»");
        }
    }

    private static string Describe(object? source)
    {
        if (source is not FrameworkElement element)
        {
            return AsText(source);
        }

        var caption = AsText((element as ContentControl)?.Content);
        var name = element.Name;

        if (!string.IsNullOrWhiteSpace(caption) && !string.IsNullOrWhiteSpace(name))
        {
            return $"{caption} ({name})";
        }

        if (!string.IsNullOrWhiteSpace(caption))
        {
            return caption;
        }

        return string.IsNullOrWhiteSpace(name) ? element.GetType().Name : name;
    }

    private static string AsText(object? value)
    {
        return value switch
        {
            null => "",
            string text => text.Replace(Environment.NewLine, " ").Trim(),
            ContentControl content => AsText(content.Content),
            _ => value.GetType().Name
        };
    }
}
