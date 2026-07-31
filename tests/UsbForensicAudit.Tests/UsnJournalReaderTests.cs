using System;
using System.Buffers.Binary;
using System.Text;
using UsbForensicAudit;
using Xunit;

namespace UsbForensicAudit.Tests;

/// <summary>
/// Разбор записей журнала изменений NTFS проверяется на собранных вручную
/// буферах: живой журнал зависит от машины, а ошибка в смещении полей тихо
/// подменяет дату или имя файла — и в отчёт попадает неверный вывод о переносе.
/// </summary>
public class UsnJournalReaderTests
{
    private static readonly DateTimeOffset Moment = new(2026, 3, 14, 10, 30, 0, TimeSpan.Zero);

    [Fact]
    public void Version_two_record_is_parsed_with_name_time_and_reason()
    {
        var bytes = BuildVersionTwoRecord(
            "отчёт.xlsx", parent: 0x1234, usn: 0x5678, Moment,
            reason: UsnJournalEntry.ReasonFileCreate, attributes: 0x20);

        Assert.True(UsnJournalReader.TryParseRecord(bytes, out var entry));
        Assert.Equal("отчёт.xlsx", entry.FileName);
        Assert.Equal(0x1234ul, entry.ParentFileReferenceNumber);
        Assert.Equal(0x5678, entry.Usn);
        Assert.Equal(Moment, entry.TimestampUtc);
        Assert.True(entry.IsCreate);
        Assert.False(entry.IsDelete);
        Assert.False(entry.IsDirectory);
    }

    [Fact]
    public void Version_three_record_uses_wider_file_identifiers()
    {
        var bytes = BuildVersionThreeRecord("данные.docx", parent: 0x99, usn: 0x777, Moment,
            reason: UsnJournalEntry.ReasonFileDelete);

        Assert.True(UsnJournalReader.TryParseRecord(bytes, out var entry));
        Assert.Equal("данные.docx", entry.FileName);
        Assert.Equal(0x99ul, entry.ParentFileReferenceNumber);
        Assert.Equal(0x777, entry.Usn);
        Assert.Equal(Moment, entry.TimestampUtc);
        Assert.True(entry.IsDelete);
    }

    [Fact]
    public void Directory_attribute_is_recognised()
    {
        var bytes = BuildVersionTwoRecord(
            "Фото", parent: 1, usn: 2, Moment,
            reason: UsnJournalEntry.ReasonFileCreate, attributes: 0x10);

        Assert.True(UsnJournalReader.TryParseRecord(bytes, out var entry));
        Assert.True(entry.IsDirectory);
    }

    [Fact]
    public void Cumulative_reasons_are_all_visible()
    {
        var bytes = BuildVersionTwoRecord(
            "смета.pdf", parent: 1, usn: 2, Moment,
            reason: UsnJournalEntry.ReasonFileCreate | 0x80000000 | 0x00000002, attributes: 0x20);

        Assert.True(UsnJournalReader.TryParseRecord(bytes, out var entry));
        Assert.True(entry.IsCreate);
        Assert.False(entry.IsRename);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(40)]
    [InlineData(59)]
    public void Truncated_record_is_rejected_instead_of_read_past_its_end(int length)
    {
        Assert.False(UsnJournalReader.TryParseRecord(new byte[length], out _));
    }

    [Fact]
    public void Unknown_record_version_is_rejected()
    {
        var bytes = BuildVersionTwoRecord("файл.txt", 1, 2, Moment, UsnJournalEntry.ReasonFileCreate, 0x20);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(4), 9);

        Assert.False(UsnJournalReader.TryParseRecord(bytes, out _));
    }

    [Fact]
    public void Record_without_a_name_is_rejected()
    {
        var bytes = BuildVersionTwoRecord("файл.txt", 1, 2, Moment, UsnJournalEntry.ReasonFileCreate, 0x20);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(56), 0);

        Assert.False(UsnJournalReader.TryParseRecord(bytes, out _));
    }

    [Fact]
    public void Name_reaching_outside_the_record_is_rejected()
    {
        var bytes = BuildVersionTwoRecord("файл.txt", 1, 2, Moment, UsnJournalEntry.ReasonFileCreate, 0x20);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(56), 4096);

        Assert.False(UsnJournalReader.TryParseRecord(bytes, out _));
    }

    [Fact]
    public void Empty_timestamp_is_rejected_instead_of_reported_as_the_year_1601()
    {
        var bytes = BuildVersionTwoRecord("файл.txt", 1, 2, Moment, UsnJournalEntry.ReasonFileCreate, 0x20);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(32), 0);

        Assert.False(UsnJournalReader.TryParseRecord(bytes, out _));
    }

    private static byte[] BuildVersionTwoRecord(
        string name, ulong parent, long usn, DateTimeOffset timestamp, uint reason, uint attributes)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        var record = new byte[60 + nameBytes.Length];
        BinaryPrimitives.WriteInt32LittleEndian(record, record.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(4), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(6), 0);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(8), 0xAAAA);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(16), parent);
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(24), usn);
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(32), timestamp.ToFileTime());
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(40), reason);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(52), attributes);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(56), (ushort)nameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(58), 60);
        nameBytes.CopyTo(record, 60);
        return record;
    }

    private static byte[] BuildVersionThreeRecord(
        string name, ulong parent, long usn, DateTimeOffset timestamp, uint reason)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        var record = new byte[76 + nameBytes.Length];
        BinaryPrimitives.WriteInt32LittleEndian(record, record.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(4), 3);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(8), 0xBBBB);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(24), parent);
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(40), usn);
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(48), timestamp.ToFileTime());
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(56), reason);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(68), 0x20);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(72), (ushort)nameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(74), 76);
        nameBytes.CopyTo(record, 76);
        return record;
    }
}
