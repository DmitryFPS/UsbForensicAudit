using System;
using System.Linq;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Разбор проверяется на настоящих значениях BagMRU, снятых с машины, где к
/// компьютеру подключали телефон POCO X3 NFC по MTP.
///
/// Синтетические примеры здесь бесполезны: сломанным оказался именно разбор
/// живых данных. Отчёт показывал путь «X3 NFC\17&amp;pid_ff40#8dde262e#{6ac27878-…}\
/// общий накопитель\10001,,48582488064}\структура\107D5-A52A-4243-…», и читалось
/// это как перечень вложенных папок, которых никогда не было. Причин было две:
/// поиск строк сдвигался на один байт и съедал начало имени, а путь склеивался
/// из всех строк одного элемента оболочки, включая свойства и обрубки GUID-ов.
/// </summary>
public class MtpShellBagPathTests
{
    /// <summary>Узел BagMRU\0, значение 5 — сам телефон.</summary>
    private const string PhoneItem =
        "agEuAEQBBiAxCAMAAAAAAAAAAwAAAHQAAAABAAAADAAAAEoAAAAAAFAATwBDAE8AIABYADMAIABOAEYAQwAAAFwAXAA/AFwA"
        + "dQBzAGIAIwB2AGkAZABfADIANwAxADcAJgBwAGkAZABfAGYAZgA0ADAAIwA4AGQAZABlADIANgAyAGUAIwB7ADYAYQBjADIA"
        + "NwA4ADcAOAAtAGEANgBmAGEALQA0ADEANQA1AC0AYgBhADgANQAtAGYAOQA4AGYANAA5ADEAZAA0AGYAMwAzAH0AAAANAAAA"
        + "A9UVDBfQzkeQFns/l4chzAIAAACal9QmQ+YmRp4rc23AyS/cDAAAAB8AAAAYAAAAUABPAEMATwAgAFgAMwAgAE4ARgBDAAAA"
        + "ky0Fj8qrxU+lrLAd9NvlmAIAAABIAAAAa0bqCKTjNkOh86RNK1xDjAAAdBpZXpbf00iNZxczvO4oujxteDV1sLlJiN0CmHbh"
        + "HAEAAA==";

    /// <summary>Узел BagMRU\0\5, значение 0 — внутренняя память телефона.</summary>
    private const string StorageItem =
        "wAUAALoFBSAxEAMAAAC6ACAAAPC9TwsAAAAAAAAAAAAAAMwCAAAcAAAAGQAAABgAAAAHAAAAEgQ9BEMEQgRABDUEPQQ9BDgE"
        + "OQQgAD4EMQRJBDgEOQQgAD0EMAQ6BD4EPwQ4BEIENQQ7BEwEAABTAEkARAAtAHsAMQAwADAAMAAxACwALAA0ADgANQA4ADIA"
        + "NAA4ADgAMAA2ADQAfQAAABgENQRABDAEQARFBDgERwQ1BEEEOgQwBE8EIABBBEIEQARDBDoEQgRDBEAEMAQAAHsARQBGADIA"
        + "MQAwADcARAA1AC0AQQA1ADIAQQAtADQAMgA0ADMALQBBADIANgBCAC0ANgAyAEQANAAxADcANgBEADcANgAwADMAfQAAAHsA"
        + "NABBAEQAMgBDADgANQBFAC0ANQBFADIARAAtADQANQBFADUALQA4ADgANgA0AC0ANABGADIAMgA5AEUAMwBDADYAQwBGADAA"
        + "fQAAAHsAMQBBADMAMwBGADcARQA0AC0AQQBGADEAMwAtADQAOABGADUALQA5ADkANABFAC0ANwA3ADMANgA5AEQARgBFADAA"
        + "NABBADMAfQAAAHsAOQAyADYAMQBCADAAMwBDAC0AMwBEADcAOAAtADQANQAxADkALQA4ADUARQAzAC0AMAAyAEMANQBFADEA"
        + "RgA1ADAAQgBCADkAfQAAAHsANgA4ADAAQQBEAEYANQAyAC0AOQA1ADAAQQAtADQAMAA0ADEALQA5AEIANAAxAC0ANgA1AEUA"
        + "MwA5ADMANgA0ADgAMQA1ADUAfQAAAHsAMgA4AEQAOABEADMAMQBFAC0AMgA0ADkAQwAtADQANQA0AEUALQBBAEEAQgBDAC0A"
        + "MwA0ADgAOAAzADEANgA4AEUANgAzADQAfQAAAHsAMgA3AEUAMgBFADMAOQAyAC0AQQAxADEAMQAtADQAOABFADAALQBBAEIA"
        + "MABDAC0ARQAxADcANwAwADUAQQAwADUARgA4ADUAfQAAAA0AAAAD1RUMF9DOR5AWez+XhyHMDwAAAHoFowHWdIBOvqfcTCEs"
        + "5QoCAAAAEwAAAAMAAAB6BaMB1nSATr6n3EwhLOUKAwAAAB8AAAAwAAAAGAQ1BEAEMARABEUEOARHBDUEQQQ6BDAETwQgAEEE"
        + "QgRABEMEOgRCBEMEQAQwBAAAegWjAdZ0gE6+p9xMISzlCgsAAAATAAAAAAAAAHoFowHWdIBOvqfcTCEs5QoEAAAAFQAAAADw"
        + "vU8LAAAAegWjAdZ0gE6+p9xMISzlCgUAAAAVAAAAAHCoDgEAAAB6BaMB1nSATr6n3EwhLOUKBgAAABUAAAAAAABAAAAAAHoF"
        + "owHWdIBOvqfcTCEs5QoHAAAAHwAAADgAAAASBD0EQwRCBEAENQQ9BD0EOAQ5BCAAPgQxBEkEOAQ5BCAAPQQwBDoEPgQ/BDgE"
        + "QgQ1BDsETAQAAA1Ja+/YXHpDr/zai2DuSjwFAAAAHwAAADIAAABTAEkARAAtAHsAMQAwADAAMAAxACwALAA0ADgANQA4ADIA"
        + "NAA4ADgAMAA2ADQAfQAAAA1Ja+/YXHpDr/zai2DuSjwEAAAAHwAAADgAAAASBD0EQwRCBEAENQQ9BD0EOAQ5BCAAPgQxBEkE"
        + "OAQ5BCAAPQQwBDoEPgQ/BDgEQgQ1BDsETAQAAHoFowHWdIBOvqfcTCEs5QoIAAAAHwAAAAIAAAAAAA1Ja+/YXHpDr/zai2Du"
        + "SjwGAAAASAAAAAAAATBsrgRImLrFe0aWX+cNSWvv2Fx6Q6/82otg7ko8GgAAAAsAAAAAAA1Ja+/YXHpDr/zai2DuSjwHAAAA"
        + "SAAAAGAB7Zn/F0RMnZgdem+UGSGTLQWPyqvFT6WssB302+WYAgAAAEgAAAC8W/Aj3hUqTKVbqa9c5BLvDUlr79hcekOv/NqL"
        + "YO5KPBcAAAAfAAAADgAAAHMAMQAwADAAMAAxAAAAAAAAAA==";

    /// <summary>Узел BagMRU\0\5\0, значение 1 — папка DCIM в памяти телефона.</summary>
    private const string DcimItem =
        "zgIAAMgCBiAZB/sAAAACACAAAAAAAAAAAAAAAAAAAAAAAICInAnPDN0BkuPiJxGh4EirDOF3BaBfhSACAAAFAAAABQAAACcA"
        + "AABEAEMASQBNAAAARABDAEkATQAAAHsAQQAyADUANgAyADYAQwBEAC0AMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0A"
        + "MAAwADAAMAAwADAAMAAwADAAMAAwADAAfQAAAA0AAAAD1RUMF9DOR5AWez+XhyHMDAAAAA1Ja+/YXHpDr/zai2DuSjwCAAAA"
        + "HwAAAAYAAABvADkAAACr/dT7fZh3R7P5cmGFqTErAgAAAB8AAAAKAAAARABDAEkATQAAAA1Ja+/YXHpDr/zai2DuSjwTAAAA"
        + "BwAAAHIcxzEikOZADUlr79hcekOv/NqLYO5KPAYAAABIAAAAAAABMGyuBEiYusV7RpZf5w1Ja+/YXHpDr/zai2DuSjwHAAAA"
        + "SAAAAJLj4icRoeBIqwzhdwWgX4UNSWvv2Fx6Q6/82otg7ko8BAAAAB8AAAAKAAAARABDAEkATQAAAA1Ja+/YXHpDr/zai2Du"
        + "SjwXAAAAHwAAAA4AAABzADEAMAAwADAAMQAAAA1Ja+/YXHpDr/zai2DuSjwFAAAAHwAAAE4AAAB7AEEAMgA1ADYAMgA2AEMA"
        + "RAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAAMAAwADAAMAAwADAAMAAwAH0AAAANSWvv2Fx6Q6/8"
        + "2otg7ko8GgAAAAsAAAD//1hQVE3OT3hFlciGmKm8D0kD3AAAEgAAAAAAWFBUTc5PeEWVyIaYqbwPSU7cAAAfAAAAIAAAADIA"
        + "MAAyADYAMAA3ADAANgBUADAAMQAzADgANAA1AAAADUlr79hcekOv/NqLYO5KPAwAAAAfAAAACgAAAEQAQwBJAE0AAAAAAAAA";

    [Fact]
    public void Phone_item_gives_the_name_a_person_sees_in_explorer()
    {
        var artifact = ForensicArtifactParsers.ParseShellBagNode(
            Convert.FromBase64String(PhoneItem), parentPath: "", slot: 49);

        Assert.Equal("POCO X3 NFC", artifact.Path);
    }

    /// <summary>
    /// Самая длинная строка в этом элементе — путь устройства
    /// «\\?\usb#vid_2717&amp;pid_ff40#…». Раньше именно он попадал в путь, потому
    /// что выбиралась длиннейшая строка со слешем.
    /// </summary>
    [Fact]
    public void Device_instance_path_does_not_replace_the_name()
    {
        var artifact = ForensicArtifactParsers.ParseShellBagNode(
            Convert.FromBase64String(PhoneItem), parentPath: "", slot: 49);

        Assert.DoesNotContain("vid_2717", artifact.Path, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("#", artifact.Path, StringComparison.Ordinal);
    }

    [Fact]
    public void Storage_item_gives_one_folder_name_not_a_chain_of_properties()
    {
        var artifact = ForensicArtifactParsers.ParseShellBagNode(
            Convert.FromBase64String(StorageItem), parentPath: "POCO X3 NFC", slot: 50);

        Assert.Equal(@"POCO X3 NFC\Внутренний общий накопитель", artifact.Path);
    }

    /// <summary>
    /// Свойства элемента MTP — идентификатор объекта «SID-{10001,,48582488064}»,
    /// «Иерархическая структура» и десяток GUID-ов. В пути их быть не должно:
    /// они выглядели как имена вложенных папок.
    /// </summary>
    [Theory]
    [InlineData("SID-")]
    [InlineData("48582488064")]
    [InlineData("Иерархическая")]
    [InlineData("EF2107D5")]
    [InlineData("107D5")]
    public void Item_properties_do_not_leak_into_the_path(string noise)
    {
        var artifact = ForensicArtifactParsers.ParseShellBagNode(
            Convert.FromBase64String(StorageItem), parentPath: "POCO X3 NFC", slot: 50);

        Assert.DoesNotContain(noise, artifact.Path, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Both_nodes_are_still_recognised_as_removable_device_activity()
    {
        var phone = ForensicArtifactParsers.ParseShellBagNode(
            Convert.FromBase64String(PhoneItem), parentPath: "", slot: 49);
        var storage = ForensicArtifactParsers.ParseShellBagNode(
            Convert.FromBase64String(StorageItem), parentPath: "POCO X3 NFC", slot: 50);

        Assert.True(phone.IsUsbRelevant, phone.RelevanceReason);
        Assert.True(storage.IsUsbRelevant, storage.RelevanceReason);
    }

    /// <summary>
    /// Имя устройства нужно и для привязки следов к устройству: по нему история
    /// действий связывает папки телефона с самим телефоном.
    /// </summary>
    [Fact]
    public void Phone_name_stays_available_as_a_correlation_token()
    {
        var pidl = ForensicArtifactParsers.ParsePidl(Convert.FromBase64String(PhoneItem));

        Assert.Contains("POCO X3 NFC", pidl.PathFragments);
    }

    /// <summary>
    /// Папка в памяти телефона — самый частый случай: именно так выглядит запись
    /// о том, что человек открыл на телефоне снимки камеры.
    /// </summary>
    [Fact]
    public void Folder_on_the_phone_reads_as_a_folder_path()
    {
        var artifact = ForensicArtifactParsers.ParseShellBagNode(
            Convert.FromBase64String(DcimItem),
            parentPath: @"POCO X3 NFC\Внутренний общий накопитель",
            slot: 51);

        Assert.Equal(@"POCO X3 NFC\Внутренний общий накопитель\DCIM", artifact.Path);
    }

    /// <summary>
    /// Имя, прочитанное со сдвигом в один байт, складывается в иероглифы. Такой
    /// мусор в отчёте выглядел как настоящее имя папки на устройстве.
    /// </summary>
    [Fact]
    public void Byte_shifted_gibberish_never_reaches_the_path()
    {
        var paths = new[] { PhoneItem, StorageItem, DcimItem }
            .Select(x => ForensicArtifactParsers.ParseShellBagNode(
                Convert.FromBase64String(x), parentPath: "", slot: 1).Path);

        Assert.All(paths, path => Assert.DoesNotContain(path, char.IsSurrogate));
        Assert.All(paths, path => Assert.All(path, character =>
            Assert.True(character < '\u0500', $"Непечатное для имени папки: {path}")));
    }
}
