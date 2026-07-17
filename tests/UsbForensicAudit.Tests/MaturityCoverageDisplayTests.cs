using UsbForensicAudit;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace UsbForensicAudit.Tests;

public sealed class MaturityUserDisplayTextTests
{
    [Theory]
    [InlineData("RealUsb", "Реальное USB-устройство")]
    [InlineData("RelatedStorage", "Память или диск USB")]
    [InlineData("UsbFlagsTrace", "Остаточный след USB (usbflags)")]
    [InlineData("SupportArtifact", "Служебная запись Windows")]
    [InlineData(null, "Не определено")]
    [InlineData("Other", "Не определено")]
    public void Category_maps_every_category_and_fallback(string? value, string expected) =>
        Assert.Equal(expected, UserDisplayText.Category(value));

    [Theory]
    [InlineData("high", "Высокий")]
    [InlineData("Medium", "Средний")]
    [InlineData("LOW", "Низкий")]
    [InlineData("info", "Информация")]
    [InlineData("Critical", "Critical")]
    [InlineData(null, "")]
    public void Severity_maps_case_insensitively_and_preserves_unknown(string? value, string expected) =>
        Assert.Equal(expected, UserDisplayText.Severity(value));

    [Theory]
    [InlineData("OsInstall", "Контекст установки ОС")]
    [InlineData("Suspicious", "Подозрительно")]
    [InlineData("Informational", "Информационно")]
    [InlineData("Custom", "Custom")]
    [InlineData(null, "Подозрительно")]
    public void Assessment_maps_known_values_and_fallback(string? value, string expected) =>
        Assert.Equal(expected, UserDisplayText.Assessment(value));

    [Theory]
    [InlineData("Normal", "Контекст установки ОС")]
    [InlineData("Confirmed", "Подтверждено")]
    [InlineData("Probable", "Вероятно")]
    [InlineData("Indirect", "Косвенный след")]
    [InlineData("ContextRequired", "Требуется контекст")]
    [InlineData("Unknown", "Не определено")]
    [InlineData("Custom", "Custom")]
    [InlineData(null, "Не определено")]
    public void Confidence_maps_every_value_and_fallback(string? value, string expected) =>
        Assert.Equal(expected, UserDisplayText.Confidence(value));

    [Theory]
    [InlineData("ToolLaunch", "Запуск утилиты")]
    [InlineData("ToolPresence", "След наличия утилиты")]
    [InlineData("ExecutionGap", "Запуск без Prefetch")]
    [InlineData("ProbableCleanup", "Вероятная очистка")]
    [InlineData("LogClearing", "Очистка журналов")]
    [InlineData("RegistryArtifact", "Изменение реестра/файлов")]
    [InlineData("Correlation", "Противоречие источников")]
    [InlineData("ControlSetDifference", "Различие ControlSet")]
    [InlineData("NormalMigrationContext", "Штатная миграция/ротация Windows")]
    [InlineData("OsInstall", "Контекст установки ОС")]
    [InlineData(null, "Не определено")]
    public void ActionKind_maps_every_action_and_fallback(string? value, string expected) =>
        Assert.Equal(expected, UserDisplayText.ActionKind(value));

    [Theory]
    [InlineData(null, "")]
    [InlineData(" ", "")]
    [InlineData("registry: usb", "Реестр Windows — USB-устройства")]
    [InlineData("Registry usbflags", "Реестр Windows — кэш USB-дескрипторов (usbflags)")]
    [InlineData("Registry: USBSTOR", "Реестр Windows — USB-накопители")]
    [InlineData("Registry: SCSI", "Реестр Windows — диски")]
    [InlineData("MountedDevices", "Реестр Windows — буквы дисков")]
    [InlineData("setupapi.dev.log", "Журнал установки Windows (setupapi.dev.log)")]
    [InlineData("EventLog:System", "Журнал Windows — System")]
    [InlineData("Prefetch files", "Prefetch — следы запуска программ")]
    [InlineData("Amcache hive", "Amcache — следы установленных программ")]
    [InlineData("Recent LNK", "Ярлыки пользователя (.lnk)")]
    [InlineData("Automatic JumpList", "Jump Lists — недавние файлы")]
    [InlineData("NTUSER Hive", "Профиль пользователя Windows")]
    [InlineData("correlation", "Автоматическая связь данных")]
    [InlineData("Журнал контроля USB: test", "Журнал корпоративной защиты USB (DLP)")]
    [InlineData("Custom source", "Custom source")]
    public void Source_maps_each_recognized_source_in_priority_order(string? value, string expected) =>
        Assert.Equal(expected, UserDisplayText.Source(value));

    [Theory]
    [InlineData(null, "")]
    [InlineData("Служебный артефакт usbflags", "Это не само устройство, а служебная запись Windows — даты здесь не показываются.")]
    [InlineData("Даты взяты из журнала Windows", "Даты взяты из журналов Windows — это наиболее надёжные значения.")]
    [InlineData("Время оценено по последней активности", "Точное отключение не найдено. Показана дата последней активности — устройство сейчас не подключено.")]
    [InlineData("Показана дата последней активности", "Точное отключение не найдено. Показана дата последней активности — устройство сейчас не подключено.")]
    [InlineData("Сейчас не подключено", "Устройство сейчас не подключено, но точное время отключения Windows не записала.")]
    [InlineData("Сейчас устройство снова подключено: точное событие", "Сейчас устройство снова подключено: точное событие")]
    [InlineData("Точного события подключения не найдено", "Устройство видно в системе, но точное время первого подключения не найдено.")]
    [InlineData("Есть запись в Registry", "Windows помнит устройство, но когда его подключали или отключали — неизвестно.")]
    [InlineData("Исходное пояснение", "Исходное пояснение")]
    public void DateConfidence_rewrites_each_supported_explanation(string? value, string expected) =>
        Assert.Equal(expected, UserDisplayText.DateConfidence(value));

    [Theory]
    [InlineData("", "", "не указаны")]
    [InlineData("", "1666", "PID 1666")]
    [InlineData("0951", "", "VID 0951")]
    [InlineData("0951", "1666", "VID 0951 / PID 1666")]
    public void VidPidCodes_formats_all_partial_combinations(string vid, string pid, string expected)
    {
        Assert.Equal(expected, UserDisplayText.VidPidCodes(vid, pid));
        Assert.Equal(expected, UserDisplayText.VidPid(vid, pid));
    }

    [Theory]
    [InlineData("Kingston DataTraveler", "", "", "id", "Kingston DataTraveler")]
    [InlineData(@"USB\VID_0951", "Kingston", "DataTraveler", "id", "Kingston DataTraveler")]
    [InlineData(@"USBSTOR\Disk", "", "DataTraveler", "id", "DataTraveler")]
    [InlineData("", "Kingston", "", "id", "Kingston")]
    [InlineData("", "", "", @"USB\VID_0951", @"USB\VID_0951")]
    public void DeviceDisplayName_uses_each_fallback_level(
        string friendlyName, string manufacturer, string product, string id, string expected) =>
        Assert.Equal(expected, UserDisplayText.DeviceDisplayName(friendlyName, manufacturer, product, id));

    [Theory]
    [InlineData("DataTraveler", "", "1.00", "", "DataTraveler 1.00")]
    [InlineData("DataTraveler", "", "", "", "DataTraveler")]
    [InlineData("", "Kingston USB Device", "", "", "Kingston")]
    [InlineData("", "Kingston DataTraveler Max", "", "", "DataTraveler Max")]
    [InlineData("", "Solo", "", "", "Solo")]
    [InlineData("", "", "", "1666", "неизвестна (PID 1666)")]
    [InlineData("", "", "", "", "не определена")]
    public void ModelName_uses_each_source_and_fallback(
        string product, string friendlyName, string revision, string pid, string expected) =>
        Assert.Equal(expected, UserDisplayText.ModelName(product, friendlyName, revision, pid));

    [Theory]
    [InlineData("ExactEvent", true, "01.06.2024 12:00:00 МСК")]
    [InlineData("RegistryActivity", true, "01.06.2024 12:00:00 МСК (ориентир — запись в реестре)")]
    [InlineData("LiveAtScan", true, "01.06.2024 12:00:00 МСК (обнаружено при сканировании)")]
    [InlineData("ExactEvent", false, UserDisplayText.NoFirstConnectEvent)]
    [InlineData("Other", true, UserDisplayText.NoFirstConnectEvent)]
    public void ConnectionText_handles_all_kinds_and_missing_dates(string kind, bool hasDate, string expected)
    {
        DateTimeOffset? timestamp = hasDate ? DateTimeOffset.Parse("2024-06-01T09:00:00Z") : null;
        Assert.Equal(expected, UserDisplayText.ConnectionText(kind, timestamp));
    }

    [Theory]
    [InlineData("OK", "PCI\\DEVICE", "Работает")]
    [InlineData("Error", "PCI\\DEVICE", "Ошибка WMI")]
    [InlineData("Degraded", "PCI\\DEVICE", "Ограничено")]
    [InlineData("Unknown", "PCI\\DEVICE", "Неизвестно")]
    [InlineData(null, "PCI\\DEVICE", "Неизвестно")]
    [InlineData("Starting", "PCI\\DEVICE", "Starting")]
    public void DeviceStatus_maps_non_usb_statuses(string? status, string id, string expected) =>
        Assert.Equal(expected, UserDisplayText.DeviceStatus(status, id));

    [Theory]
    [InlineData(@"USB\VID_0951")]
    [InlineData(@"USBSTOR\DISK&VEN_TEST")]
    [InlineData(@"REMOVABLE\DISK")]
    public void DeviceStatus_explains_usb_errors_without_active_protection(string id)
    {
        var previous = EndpointProtectionState.IsProtectionActive;
        try
        {
            EndpointProtectionState.IsProtectionActive = false;
            Assert.Equal(
                "Подключено (WMI: Error — часто при активной DLP-защите)",
                UserDisplayText.DeviceStatus("Error", id));
        }
        finally
        {
            EndpointProtectionState.IsProtectionActive = previous;
        }
    }

    [Fact]
    public void DeviceStatus_explains_usb_filter_when_protection_is_active()
    {
        var previous = EndpointProtectionState.IsProtectionActive;
        try
        {
            EndpointProtectionState.IsProtectionActive = true;
            Assert.Equal(
                "Подключено через корпоративную защиту USB (WMI показывает Error — это нормально для фильтра дисков)",
                UserDisplayText.DeviceStatus("Error", @"USB\VID_0951"));
        }
        finally
        {
            EndpointProtectionState.IsProtectionActive = previous;
        }
    }

    [Theory]
    [InlineData("ExactEvent", true, true, "01.06.2024 12:00:00 МСК (сейчас снова подключено)")]
    [InlineData("ExactEvent", true, false, "01.06.2024 12:00:00 МСК")]
    [InlineData("LastActivityEstimate", true, false, "01.06.2024 12:00:00 МСК (ориентир — последняя активность)")]
    [InlineData("ConnectedNow", false, true, UserDisplayText.ConnectedNow)]
    [InlineData("NotConnectedUnknown", false, false, UserDisplayText.NotConnectedUnknown)]
    [InlineData("NotApplicable", false, false, UserDisplayText.NotApplicableDisconnect)]
    [InlineData("ExactEvent", false, false, UserDisplayText.NoDisconnectEvent)]
    [InlineData("Other", true, false, UserDisplayText.NoDisconnectEvent)]
    public void DisconnectText_handles_every_display_kind(
        string kind, bool hasDate, bool connected, string expected)
    {
        DateTimeOffset? timestamp = hasDate ? DateTimeOffset.Parse("2024-06-01T09:00:00Z") : null;
        Assert.Equal(expected, UserDisplayText.DisconnectText(kind, timestamp, connected));
    }

    [Theory]
    [InlineData("Port_#0001", "PCIROOT(0)", "Port_#0001")]
    [InlineData("", "PCIROOT(0)", "PCIROOT(0)")]
    [InlineData("", "", UserDisplayText.NoLocationData)]
    public void Location_prefers_information_then_path_then_fallback(
        string information, string paths, string expected) =>
        Assert.Equal(expected, UserDisplayText.Location(information, paths));

    [Theory]
    [InlineData("USBSTOR", "USB-накопитель")]
    [InlineData("USB", "USB-устройство")]
    [InlineData("HID", "Мышь, клавиатура и т.п.")]
    [InlineData("WPD", "Телефон / камера (MTP)")]
    [InlineData("SCSI", "Диск")]
    [InlineData("USBFlags", "Остаточный след usbflags")]
    [InlineData("VolumeMapping", "Буква диска")]
    [InlineData("Custom", "Custom")]
    [InlineData(null, "не определено")]
    [InlineData(" ", "не определено")]
    public void DeviceType_maps_every_type_and_fallback(string? value, string expected) =>
        Assert.Equal(expected, UserDisplayText.DeviceType(value));
}

public sealed class MaturityDeviceLiveMatcherTests
{
    [Fact]
    public void AreLikelySameDevice_matches_exact_normalized_pnp_id()
    {
        var left = Device(@"USB#VID_0951&PID_1666#SERIAL");
        var right = Device(@"usb\vid_0951&pid_1666\serial");

        Assert.True(DeviceLiveMatcher.AreLikelySameDevice(left, right));
    }

    [Fact]
    public void AreLikelySameDevice_matches_shared_non_placeholder_container()
    {
        var left = Device(@"USB\LEFT", container: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}");
        var right = Device(@"USB\RIGHT", container: "{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}");

        Assert.True(DeviceLiveMatcher.AreLikelySameDevice(left, right));
    }

    [Theory]
    [InlineData("", "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}")]
    [InlineData("{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", "")]
    [InlineData("{00000000-0000-0000-ffff-ffffffffffff}", "{00000000-0000-0000-ffff-ffffffffffff}")]
    [InlineData("{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", "{00000000-0000-0000-ffff-ffffffffffff}")]
    public void AreLikelySameDevice_does_not_use_missing_or_placeholder_container(string leftContainer, string rightContainer)
    {
        var left = Device(@"USB\LEFT", container: leftContainer);
        var right = Device(@"USB\RIGHT", container: rightContainer);

        Assert.False(DeviceLiveMatcher.AreLikelySameDevice(left, right));
    }

    [Theory]
    [InlineData("0951", "1666", "0951", "1666")]
    [InlineData("", "1666", "0951", "1666")]
    [InlineData("0951", "", "0951", "1666")]
    [InlineData("0951", "1666", "", "1666")]
    [InlineData("0951", "1666", "0951", "")]
    public void AreLikelySameDevice_matches_hardware_serial_with_compatible_vid_pid(
        string leftVid, string leftPid, string rightVid, string rightPid)
    {
        var left = Device(@"USB\LEFT", vid: leftVid, pid: leftPid, serial: " abcd1234&0");
        var right = Device(@"USB\RIGHT", vid: rightVid, pid: rightPid, serial: "ABCD1234");

        Assert.True(DeviceLiveMatcher.AreLikelySameDevice(left, right));
    }

    [Theory]
    [InlineData("0951", "1666", "1234", "1666", "ABCD1234", "ABCD1234")]
    [InlineData("0951", "1666", "0951", "9999", "ABCD1234", "ABCD1234")]
    [InlineData("0951", "1666", "0951", "1666", "ABC", "ABC")]
    [InlineData("0951", "1666", "0951", "1666", "ABCD1234", "ABC")]
    [InlineData("0951", "1666", "0951", "1666", "ABCD1234", "DIFFERENT")]
    public void AreLikelySameDevice_rejects_incompatible_or_nonmatching_serials(
        string leftVid, string leftPid, string rightVid, string rightPid, string leftSerial, string rightSerial)
    {
        var left = Device(@"USB\LEFT", vid: leftVid, pid: leftPid, serial: leftSerial);
        var right = Device(@"USB\RIGHT", vid: rightVid, pid: rightPid, serial: rightSerial);

        Assert.False(DeviceLiveMatcher.AreLikelySameDevice(left, right));
    }

    [Fact]
    public void ScsiInstancesMatch_matches_signature_case_insensitively()
    {
        var left = Device(@"SCSI\Disk&Ven_JMicron&Prod_Generic\7&456&0&000000\PATH_A");
        var right = Device(@"scsi\disk&ven_jmicron&prod_generic\7&456&0&000000\PATH_B");

        Assert.False(DeviceLiveMatcher.PnpIdsMatch(left.DeviceInstanceId, right.DeviceInstanceId));
        Assert.True(DeviceLiveMatcher.ScsiInstancesMatch(left, right));
        Assert.True(DeviceLiveMatcher.AreLikelySameDevice(left, right));
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData(@"USB\VID_0951\SERIAL", "")]
    [InlineData(@"SCSI\DiskOnly", "")]
    [InlineData(@"SCSI\CdRom&Ven_Test&Prod_Test\INSTANCE", "")]
    [InlineData(@"SCSI\Disk&Ven_Test&Prod_Model\INSTANCE", @"DISK&VEN_TEST&PROD_MODEL\INSTANCE")]
    public void ParseScsiSignature_validates_shape(string? id, string expected) =>
        Assert.Equal(expected, DeviceLiveMatcher.ParseScsiSignature(id));

    [Theory]
    [InlineData("External-Disk_Model", "", "External Disk Model", "")]
    [InlineData("short", "DataTraveler_Max", "tiny", "DataTraveler-Max")]
    public void SameDiskModel_normalizes_friendly_or_product_names(
        string leftFriendly, string leftProduct, string rightFriendly, string rightProduct)
    {
        var left = Device(@"SCSI\Disk&Ven_A&Prod_Left\ONE", friendly: leftFriendly, product: leftProduct);
        var right = Device(@"SCSI\Disk&Ven_B&Prod_Right\TWO", friendly: rightFriendly, product: rightProduct);

        Assert.True(DeviceLiveMatcher.SameDiskModel(left, right));
        Assert.True(DeviceLiveMatcher.AreLikelySameDevice(left, right));
    }

    [Fact]
    public void SameDiskModel_falls_back_to_product_parsed_from_scsi_id()
    {
        var left = Device(@"SCSI\Disk&Ven_Test&Prod_DataTraveler_Max\ONE");
        var right = Device(@"SCSI\Disk&Ven_Other&Prod_DataTraveler-Max\TWO");

        Assert.True(DeviceLiveMatcher.SameDiskModel(left, right));
    }

    [Theory]
    [InlineData(@"USB\VID_1\ONE", @"SCSI\Disk&Ven_Test&Prod_DataTraveler\TWO", "DataTraveler", "DataTraveler")]
    [InlineData(@"SCSI\Disk&Ven_Test&Prod_DataTraveler\ONE", @"USB\VID_1\TWO", "DataTraveler", "DataTraveler")]
    [InlineData(@"SCSI\Disk&Ven_A&Prod_Left\ONE", @"SCSI\Disk&Ven_B&Prod_Right\TWO", "Different Model A", "Different Model B")]
    [InlineData(@"SCSI\Disk&Ven_A&Prod_X\ONE", @"SCSI\Disk&Ven_B&Prod_X\TWO", "short", "short")]
    public void SameDiskModel_rejects_wrong_bus_different_or_short_models(
        string leftId, string rightId, string leftName, string rightName)
    {
        var left = Device(leftId, friendly: leftName);
        var right = Device(rightId, friendly: rightName);

        Assert.False(DeviceLiveMatcher.SameDiskModel(left, right));
    }

    [Fact]
    public void ParseScsiProduct_absence_results_in_no_model_match()
    {
        var left = Device(@"SCSI\Disk&Ven_Test&Rev_1\ONE");
        var right = Device(@"SCSI\Disk&Ven_Other&Rev_1\TWO");

        Assert.False(DeviceLiveMatcher.SameDiskModel(left, right));
        Assert.False(DeviceLiveMatcher.AreLikelySameDevice(left, right));
    }

    [Fact]
    public void PnpIdsMatch_requires_nonempty_left_id()
    {
        Assert.False(DeviceLiveMatcher.PnpIdsMatch(null, null));
        Assert.False(DeviceLiveMatcher.PnpIdsMatch("", @"USB\A"));
    }

    private static UsbDeviceRecord Device(
        string id,
        string container = "",
        string vid = "",
        string pid = "",
        string serial = "",
        string friendly = "",
        string product = "") =>
        new()
        {
            DeviceInstanceId = id,
            ContainerId = container,
            Vid = vid,
            Pid = pid,
            Serial = serial,
            FriendlyName = friendly,
            Product = product
        };
}

public sealed class MaturityCleanupAttributionTests
{
    [Fact]
    public void ParseEventLogInitiator_reads_direct_xml_fields_and_formats_domain()
    {
        const string xml = """
            <Event><System><Security UserID="ignored" /></System><EventData>
              <SubjectUserName>alice</SubjectUserName>
              <SubjectDomainName>CONTOSO</SubjectDomainName>
              <SubjectUserSid>S-1-5-21-1001</SubjectUserSid>
            </EventData></Event>
            """;

        var result = CleanupAttribution.ParseEventLogInitiator(xml);

        Assert.Equal(new InitiatorInfo("User", @"CONTOSO\alice", "S-1-5-21-1001"), result);
    }

    [Fact]
    public void ParseEventLogInitiator_reads_named_data_fields()
    {
        const string xml = """
            <Event><EventData>
              <Data Name="SubjectUserName">Administrator</Data>
              <Data Name="SubjectDomainName">WORKSTATION</Data>
              <Data Name="SubjectUserSid">S-1-5-21-500</Data>
            </EventData></Event>
            """;

        var result = CleanupAttribution.ParseEventLogInitiator(xml);

        Assert.Equal("Administrator", result.Kind);
        Assert.Equal(@"WORKSTATION\Administrator", result.Account);
        Assert.Equal("S-1-5-21-500", result.Sid);
    }

    [Fact]
    public void ParseEventLogInitiator_uses_user_id_named_data_as_sid()
    {
        const string xml = """
            <Event><EventData>
              <Data Name="SubjectUserName">service</Data>
              <Data Name="UserID">S-1-5-19</Data>
            </EventData></Event>
            """;

        var result = CleanupAttribution.ParseEventLogInitiator(xml);

        Assert.Equal("System", result.Kind);
        Assert.Equal("service", result.Account);
        Assert.Equal("S-1-5-19", result.Sid);
    }

    [Fact]
    public void ParseEventLogInitiator_falls_back_to_regex_for_malformed_xml()
    {
        const string malformed =
            "<Event><SubjectUserName>bob</SubjectUserName><SubjectDomainName>LAB</SubjectDomainName>" +
            "<SubjectUserSid>S-1-5-21-1002</SubjectUserSid>";

        var result = CleanupAttribution.ParseEventLogInitiator(malformed);

        Assert.Equal(new InitiatorInfo("User", @"LAB\bob", "S-1-5-21-1002"), result);
    }

    [Fact]
    public void ParseEventLogInitiator_regex_accepts_user_id_and_ignores_channel()
    {
        const string fragment = "<UserID>S-1-5-20</UserID><Channel>Security</Channel>";

        var result = CleanupAttribution.ParseEventLogInitiator(fragment);

        Assert.Equal(new InitiatorInfo("System", "не определено", "S-1-5-20"), result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ordinary event text without account fields")]
    public void ParseEventLogInitiator_returns_unknown_when_account_is_absent(string? rawText) =>
        Assert.Equal(InitiatorInfo.Unknown, CleanupAttribution.ParseEventLogInitiator(rawText!));

    [Theory]
    [InlineData("SYSTEM", "", "S-1-5-18", "System")]
    [InlineData("SYSTEM", "", "", "System")]
    [InlineData("svc", "", "S-1-5-20", "System")]
    [InlineData("svc", "", "S-1-5-6", "System")]
    [InlineData("SYSTEM", "NT AUTHORITY", "", "System")]
    [InlineData("LOCAL SERVICE", "NT AUTHORITY", "", "System")]
    [InlineData("NETWORK SERVICE", "NT AUTHORITY", "", "System")]
    [InlineData("MACHINE$", "DOMAIN", "", "System")]
    [InlineData("Администратор", "PC", "", "Administrator")]
    [InlineData("root", "PC", "S-1-5-21-500", "Administrator")]
    [InlineData("alice", "PC", "S-1-5-21-1001", "User")]
    public void ParseEventLogInitiator_classifies_account_kinds(
        string user, string domain, string sid, string expectedKind)
    {
        var raw = $"<SubjectUserName>{user}</SubjectUserName>" +
                  $"<SubjectDomainName>{domain}</SubjectDomainName>" +
                  $"<SubjectUserSid>{sid}</SubjectUserSid>";

        Assert.Equal(expectedKind, CleanupAttribution.ParseEventLogInitiator(raw).Kind);
    }

    [Theory]
    [InlineData("alice", "", "alice")]
    [InlineData(@"CONTOSO\alice", "IGNORED", @"CONTOSO\alice")]
    [InlineData("alice", "CONTOSO", @"CONTOSO\alice")]
    public void ParseEventLogInitiator_formats_accounts_without_duplicate_domains(
        string user, string domain, string expectedAccount)
    {
        var raw = $"<SubjectUserName>{user}</SubjectUserName><SubjectDomainName>{domain}</SubjectDomainName>";

        Assert.Equal(expectedAccount, CleanupAttribution.ParseEventLogInitiator(raw).Account);
    }

    [Theory]
    [InlineData("OsInstall", "Unknown", null, "Event Logs", "Normal")]
    [InlineData("Suspicious", "Unknown", null, "Cleaner Artifacts", "Indirect")]
    [InlineData("Suspicious", "Administrator", "USB Trace Cleaner", "Event Logs", "Probable")]
    [InlineData("Suspicious", "User", "USB Trace Cleaner", "Event Logs", "Probable")]
    [InlineData("Suspicious", "System", "USB Trace Cleaner", "Event Logs", "Indirect")]
    [InlineData("Suspicious", "System", null, "Event Logs", "Indirect")]
    [InlineData("Suspicious", "Administrator", null, "Event Logs", "Indirect")]
    [InlineData("Suspicious", "User", null, "Event Logs", "Indirect")]
    [InlineData("Suspicious", "Unknown", null, "Event Logs", "Unknown")]
    public void DetermineConfidence_covers_assessment_area_tool_and_initiator_rules(
        string assessment, string kind, string? tool, string area, string expected)
    {
        var initiator = new InitiatorInfo(kind, "account", null);
        Assert.Equal(expected, CleanupAttribution.DetermineConfidence(assessment, initiator, tool, area));
    }

    [Fact]
    public void InitiatorForSetupApi_identifies_initial_windows_setup()
    {
        var result = CleanupAttribution.InitiatorForSetupApi(true, DateTimeOffset.UtcNow);

        Assert.Equal(new InitiatorInfo("System", "SYSTEM (Windows Setup)", "S-1-5-18"), result);
    }

    [Fact]
    public void InitiatorForSetupApi_returns_unknown_for_later_activity() =>
        Assert.Equal(InitiatorInfo.Unknown, CleanupAttribution.InitiatorForSetupApi(false, null));

    [Theory]
    [InlineData(true, "USB Trace Cleaner", "USB Trace Cleaner")]
    [InlineData(false, "USB Trace Cleaner", "USB Trace Cleaner")]
    [InlineData(true, null, "Windows Setup / PnP")]
    [InlineData(false, null, "не определено")]
    public void ToolForSetupApi_prefers_correlation_then_context(
        bool initialSetup, string? correlated, string expected) =>
        Assert.Equal(expected, CleanupAttribution.ToolForSetupApi(initialSetup, correlated));

    [Fact]
    public void FindCorrelatedTool_selects_nearest_recognized_tool_inside_window()
    {
        var eventAt = DateTimeOffset.Parse("2026-01-01T12:00:00Z");
        var evidence = new[]
        {
            CleanerEvidence(eventAt.AddMinutes(-61), "USBOblivion.exe"),
            CleanerEvidence(eventAt.AddMinutes(-30), "USBTraceCleaner.exe"),
            CleanerEvidence(eventAt.AddMinutes(-2), "USBOblivion.exe"),
            CleanerEvidence(eventAt.AddMinutes(6), "USBTraceCleaner.exe")
        };

        Assert.Equal("USB Oblivion", CleanupAttribution.FindCorrelatedTool(eventAt, evidence));
    }

    [Fact]
    public void FindCorrelatedTool_returns_null_without_recognized_evidence()
    {
        var eventAt = DateTimeOffset.Parse("2026-01-01T12:00:00Z");
        var evidence = new[]
        {
            new EvidenceRecord { TimestampUtc = eventAt, Source = "EventLog", Summary = "normal event" }
        };

        Assert.Null(CleanupAttribution.FindCorrelatedTool(eventAt, evidence));
        Assert.Null(CleanupAttribution.DetectToolFromEvidence(evidence[0]));
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("<Event><EventData><Data Name=\"NewProcessName\">C:\\Tools\\cleaner.exe</Data></EventData></Event>", @"C:\Tools\cleaner.exe")]
    [InlineData("<Event><NewProcessName>C:\\Windows\\System32\\wevtutil.exe</NewProcessName></Event>", @"C:\Windows\System32\wevtutil.exe")]
    [InlineData("New Process Name:   C:\\Tools\\USBOblivion.exe  ", @"C:\Tools\USBOblivion.exe")]
    [InlineData("Process information unavailable", "")]
    public void ExtractProcessPath_handles_xml_plain_text_and_missing_values(string? rawText, string expected) =>
        Assert.Equal(expected, CleanupAttribution.ExtractProcessPath(rawText!));

    [Fact]
    public void ExtractProcessPath_uses_plain_fallback_after_malformed_xml()
    {
        const string raw = "<broken>\nNew Process Name: C:\\Tools\\USBTraceCleaner.exe";
        Assert.Equal(@"C:\Tools\USBTraceCleaner.exe", CleanupAttribution.ExtractProcessPath(raw));
    }

    [Theory]
    [InlineData("USB Oblivion", "USB Oblivion")]
    [InlineData(null, "не определено")]
    public void BuildAttributionDetails_formats_initiator_tool_and_confidence(string? tool, string expectedTool)
    {
        var result = CleanupAttribution.BuildAttributionDetails(
            new InitiatorInfo("Administrator", @"PC\Admin", "S-1-5-21-500"),
            tool,
            "Probable");

        Assert.Contains(@"Администратор (PC\Admin)", result, StringComparison.Ordinal);
        Assert.Contains($"Возможный инструмент: {expectedTool}", result, StringComparison.Ordinal);
        Assert.Contains("Уверенность: Вероятно", result, StringComparison.Ordinal);
    }

    private static EvidenceRecord CleanerEvidence(DateTimeOffset timestamp, string executable) =>
        new()
        {
            TimestampUtc = timestamp,
            Source = "Prefetch",
            EventId = "CLEANER_EXECUTION",
            Summary = $"Prefetch execution: {executable}",
            DeviceHint = $@"C:\Tools\{executable}",
            RawText = $"Executable={executable}"
        };
}
