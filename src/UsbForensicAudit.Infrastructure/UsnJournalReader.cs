using System.Diagnostics.CodeAnalysis;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace UsbForensicAudit;

/// <summary>
/// Читает журнал изменений NTFS (USN change journal) на томе.
///
/// Журнал ведёт сама файловая система: каждое создание, переименование и
/// удаление файла попадает в него с отметкой времени. Это единственный штатный
/// источник, по которому видно появление файла на диске, — Windows нигде не
/// записывает «файл скопировали».
///
/// Чтение идёт через штатный интерфейс тома, а не разбором сырого диска: том не
/// изменяется, и не нужен разбор структур MFT. Требуются права администратора.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "чтение журнала USN через DeviceIoControl — требует прав администратора")]
public sealed class UsnJournalReader : IDisposable
{
    private const uint FsctlQueryUsnJournal = 0x000900f4;
    private const uint FsctlReadUsnJournal = 0x000900bb;

    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    private const int ErrorJournalNotActive = 1179;
    private const int ErrorJournalDeleteInProgress = 1178;
    private const int ErrorJournalEntryDeleted = 1181;
    private const int ErrorInvalidFunction = 1;
    private const int ErrorAccessDenied = 5;

    /// <summary>Размер порции чтения. Больше — меньше системных вызовов.</summary>
    private const int ReadBufferSize = 512 * 1024;

    private readonly SafeFileHandle _volume;
    private readonly string _volumeRoot;

    private UsnJournalReader(SafeFileHandle volume, string volumeRoot)
    {
        _volume = volume;
        _volumeRoot = volumeRoot;
    }

    /// <summary>
    /// Открывает журнал тома. Возвращает <c>null</c> и причину, если журнал
    /// недоступен: выключен, том не NTFS или не хватает прав. Молчаливый отказ
    /// здесь недопустим — иначе пустой результат прочитают как «переносов не было».
    /// </summary>
    public static UsnJournalReader? TryOpen(string driveLetter, out string reason)
    {
        var normalized = driveLetter.TrimEnd('\\', ':').ToUpperInvariant();
        var handle = CreateFileW(
            $@"\\.\{normalized}:",
            GenericRead,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            reason = error == ErrorAccessDenied
                ? "Нет прав на чтение тома: журнал изменений читается только от имени администратора."
                : $"Не удалось открыть том: {new Win32Exception(error).Message}";
            return null;
        }

        var reader = new UsnJournalReader(handle, $"{normalized}:");
        if (reader.TryQueryJournal(out _, out reason))
        {
            return reader;
        }

        reader.Dispose();
        return null;
    }

    /// <summary>
    /// Перебирает записи журнала от самой старой к самой новой.
    /// </summary>
    public IEnumerable<UsnJournalEntry> Read(int maxRecords, CancellationToken cancellationToken = default)
    {
        if (!TryQueryJournal(out var journal, out _))
        {
            yield break;
        }

        var buffer = new byte[ReadBufferSize];
        var nextUsn = journal.FirstUsn;
        var produced = 0;

        while (produced < maxRecords && !cancellationToken.IsCancellationRequested)
        {
            if (!TryReadChunk(journal.JournalId, nextUsn, buffer, out var bytesReturned))
            {
                yield break;
            }

            // Первые восемь байт ответа — номер, с которого продолжать чтение.
            // Если кроме него ничего не пришло, журнал дочитан до конца.
            if (bytesReturned <= sizeof(long))
            {
                yield break;
            }

            // Номер обязан расти. Если он не сдвинулся, журнал перестал отдавать
            // новые записи, и продолжение чтения превратилось бы в бесконечный цикл.
            var advanced = BinaryPrimitives.ReadInt64LittleEndian(buffer);
            if (advanced <= nextUsn)
            {
                yield break;
            }

            nextUsn = advanced;
            var offset = sizeof(long);
            while (offset < bytesReturned && produced < maxRecords)
            {
                var length = BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(offset));
                if (length <= 0 || offset + length > bytesReturned)
                {
                    break;
                }

                if (TryParseRecord(buffer.AsSpan(offset, length), out var entry))
                {
                    produced++;
                    yield return entry;
                }

                offset += length;
            }
        }
    }

    /// <summary>
    /// Восстанавливает путь каталога по его номеру в файловой таблице. Каталог,
    /// удалённый после события, восстановить нельзя — тогда возвращается пусто,
    /// и запись остаётся с одним именем файла.
    /// </summary>
    public string ResolveDirectory(ulong fileReferenceNumber)
    {
        if (fileReferenceNumber == 0)
        {
            return "";
        }

        var descriptor = new FileIdDescriptor
        {
            Size = (uint)Marshal.SizeOf<FileIdDescriptor>(),
            Type = 0,
            FileId = (long)fileReferenceNumber
        };

        using var handle = OpenFileById(
            _volume, ref descriptor, GenericRead, FileShareRead | FileShareWrite, IntPtr.Zero, FileFlagBackupSemantics);
        if (handle.IsInvalid)
        {
            return "";
        }

        var path = new StringBuilder(1024);
        var length = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, 0);
        if (length == 0 || length > path.Capacity)
        {
            return "";
        }

        // Windows возвращает путь в форме «\\?\C:\Папка»: приставка нужна ядру,
        // но в отчёте она только мешает читать.
        var text = path.ToString();
        return text.StartsWith(@"\\?\", StringComparison.Ordinal) ? text[4..] : text;
    }

    public string Volume => _volumeRoot;

    internal static bool TryParseRecord(ReadOnlySpan<byte> record, out UsnJournalEntry entry)
    {
        entry = default;

        // Общая часть заголовка версий 2 и 3 совпадает до номера файла; всё, что
        // короче, разобрать нельзя.
        if (record.Length < 60)
        {
            return false;
        }

        var majorVersion = BinaryPrimitives.ReadUInt16LittleEndian(record[4..]);
        int nameLengthOffset;
        int fileReferenceOffset;
        int referenceSize;
        switch (majorVersion)
        {
            case 2:
                fileReferenceOffset = 8;
                referenceSize = 8;
                nameLengthOffset = 56;
                break;
            case 3:
                fileReferenceOffset = 8;
                referenceSize = 16;
                nameLengthOffset = 72;
                break;
            default:
                return false;
        }

        if (record.Length < nameLengthOffset + 4)
        {
            return false;
        }

        var parentOffset = fileReferenceOffset + referenceSize;
        var timestampOffset = parentOffset + referenceSize + sizeof(long);
        var reasonOffset = timestampOffset + sizeof(long);
        var attributesOffset = reasonOffset + 12;
        if (record.Length < attributesOffset + 4)
        {
            return false;
        }

        var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(record[nameLengthOffset..]);
        var nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(record[(nameLengthOffset + 2)..]);
        if (nameOffset + nameLength > record.Length || nameLength == 0)
        {
            return false;
        }

        var fileTime = BinaryPrimitives.ReadInt64LittleEndian(record[timestampOffset..]);
        if (fileTime <= 0)
        {
            return false;
        }

        DateTimeOffset timestamp;
        try
        {
            timestamp = DateTimeOffset.FromFileTime(fileTime).ToUniversalTime();
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }

        entry = new UsnJournalEntry(
            BinaryPrimitives.ReadUInt64LittleEndian(record[parentOffset..]),
            BinaryPrimitives.ReadInt64LittleEndian(record[(parentOffset + referenceSize)..]),
            timestamp,
            BinaryPrimitives.ReadUInt32LittleEndian(record[reasonOffset..]),
            BinaryPrimitives.ReadUInt32LittleEndian(record[attributesOffset..]),
            Encoding.Unicode.GetString(record.Slice(nameOffset, nameLength)));
        return true;
    }

    private bool TryQueryJournal(out JournalData journal, out string reason)
    {
        journal = default;
        var buffer = new byte[80];
        var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            var success = DeviceIoControl(
                _volume, FsctlQueryUsnJournal, IntPtr.Zero, 0,
                handle.AddrOfPinnedObject(), (uint)buffer.Length, out var returned, IntPtr.Zero);
            if (!success || returned < 16)
            {
                reason = DescribeJournalError(Marshal.GetLastWin32Error());
                return false;
            }
        }
        finally
        {
            handle.Free();
        }

        // Первое поле — идентификатор журнала, второе — самая старая из
        // сохранившихся записей. Читать раньше неё нельзя: те записи затёрты.
        journal = new JournalData(
            BinaryPrimitives.ReadUInt64LittleEndian(buffer),
            BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(8)));
        reason = "";
        return true;
    }

    private static string DescribeJournalError(int error) => error switch
    {
        ErrorJournalNotActive =>
            "Журнал изменений на этом томе выключен. Появление файлов на диске в нём не записано.",
        ErrorJournalDeleteInProgress =>
            "Журнал изменений в процессе удаления: его содержимое сейчас недостоверно.",
        ErrorInvalidFunction =>
            "Файловая система тома не поддерживает журнал изменений (он есть только у NTFS и ReFS).",
        ErrorAccessDenied =>
            "Нет прав на чтение журнала изменений: он читается только от имени администратора.",
        _ => $"Журнал изменений недоступен: {new Win32Exception(error).Message}"
    };

    private bool TryReadChunk(ulong journalId, long startUsn, byte[] buffer, out uint bytesReturned)
    {
        var request = new byte[40];
        BinaryPrimitives.WriteInt64LittleEndian(request, startUsn);
        BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(8), uint.MaxValue);   // все причины изменений
        BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(12), 0);              // не ждать закрытия файла
        BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(16), 0);              // без ожидания
        BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(24), 0);              // не ждать накопления данных
        BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(32), journalId);

        var requestHandle = GCHandle.Alloc(request, GCHandleType.Pinned);
        var bufferHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            var success = DeviceIoControl(
                _volume, FsctlReadUsnJournal,
                requestHandle.AddrOfPinnedObject(), (uint)request.Length,
                bufferHandle.AddrOfPinnedObject(), (uint)buffer.Length,
                out bytesReturned, IntPtr.Zero);

            // Затёртая по кругу запись — обычное дело для старого журнала: она
            // означает конец доступной истории, а не ошибку чтения.
            return success || Marshal.GetLastWin32Error() != ErrorJournalEntryDeleted;
        }
        finally
        {
            requestHandle.Free();
            bufferHandle.Free();
        }
    }

    public void Dispose() => _volume.Dispose();

    private readonly record struct JournalData(ulong JournalId, long FirstUsn);

    /// <summary>
    /// FILE_ID_DESCRIPTOR: за номером типа идёт объединение, самый большой член
    /// которого — 16 байт. Поэтому за восьмибайтным номером файла нужен второй
    /// восьмибайтный член, иначе структура окажется короче ожидаемой ядром.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdDescriptor
    {
        public uint Size;
        public uint Type;
        public long FileId;
        public long FileIdHigh;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device, uint controlCode, IntPtr inBuffer, uint inBufferSize,
        IntPtr outBuffer, uint outBufferSize, out uint bytesReturned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle OpenFileById(
        SafeFileHandle volumeHint, ref FileIdDescriptor fileId, uint desiredAccess,
        uint shareMode, IntPtr securityAttributes, uint flagsAndAttributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file, StringBuilder path, uint pathSize, uint flags);
}

/// <summary>
/// Запись журнала изменений в разобранном виде.
/// </summary>
public readonly record struct UsnJournalEntry(
    ulong ParentFileReferenceNumber,
    long Usn,
    DateTimeOffset TimestampUtc,
    uint Reason,
    uint FileAttributes,
    string FileName)
{
    public const uint ReasonFileCreate = 0x00000100;
    public const uint ReasonFileDelete = 0x00000200;
    public const uint ReasonRenameNewName = 0x00002000;

    private const uint FileAttributeDirectory = 0x00000010;

    public bool IsDirectory => (FileAttributes & FileAttributeDirectory) != 0;

    public bool IsCreate => (Reason & ReasonFileCreate) != 0;

    public bool IsDelete => (Reason & ReasonFileDelete) != 0;

    public bool IsRename => (Reason & ReasonRenameNewName) != 0;
}
