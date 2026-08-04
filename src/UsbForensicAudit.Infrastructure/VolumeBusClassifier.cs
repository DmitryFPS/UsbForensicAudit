using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace UsbForensicAudit;

/// <summary>
/// Определяет, подключён ли том по шине USB.
///
/// Нужно это потому, что <see cref="System.IO.DriveType"/> отвечает на другой
/// вопрос: внешние USB-диски (HDD/SSD в коробке) почти всегда представляются
/// системе как <c>Fixed</c>, а не <c>Removable</c>. Отбор «внутренних» томов
/// только по DriveType.Fixed втягивал журнал внешнего USB-диска в анализ как
/// журнал внутреннего диска — активность на внешнем носителе засчитывалась как
/// появление файлов на этой машине, что инвертирует смысл проверки переноса.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "запрос свойств устройства через DeviceIoControl — требует реального тома")]
public static class VolumeBusClassifier
{
    private const uint IoctlStorageQueryProperty = 0x002D1400;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;

    /// <summary>BusTypeUsb из перечисления STORAGE_BUS_TYPE.</summary>
    private const uint BusTypeUsb = 7;

    /// <summary>Смещение поля BusType в структуре STORAGE_DEVICE_DESCRIPTOR.</summary>
    private const int BusTypeOffset = 28;

    /// <summary>
    /// Возвращает <c>true</c>, если том подключён по USB. При любой ошибке
    /// возвращает <c>false</c>: сомнение трактуется в пользу «внутренний диск»,
    /// чтобы сбой запроса не выключил чтение журнала настоящего внутреннего тома.
    /// </summary>
    public static bool IsUsbAttached(string driveLetter)
    {
        var normalized = driveLetter.TrimEnd('\\', ':').ToUpperInvariant();

        // Нулевой уровень доступа: для запроса свойств устройства права на
        // чтение данных не нужны, достаточно открыть устройство.
        using var handle = CreateFileW(
            $@"\\.\{normalized}:",
            0,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            return false;
        }

        // STORAGE_PROPERTY_QUERY: PropertyId = StorageDeviceProperty (0),
        // QueryType = PropertyStandardQuery (0), один байт дополнительных данных.
        var query = new byte[12];
        var descriptor = new byte[512];

        var queryHandle = GCHandle.Alloc(query, GCHandleType.Pinned);
        var descriptorHandle = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try
        {
            var success = DeviceIoControl(
                handle, IoctlStorageQueryProperty,
                queryHandle.AddrOfPinnedObject(), (uint)query.Length,
                descriptorHandle.AddrOfPinnedObject(), (uint)descriptor.Length,
                out var returned, IntPtr.Zero);

            if (!success || returned < BusTypeOffset + 4)
            {
                return false;
            }

            return BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(BusTypeOffset)) == BusTypeUsb;
        }
        finally
        {
            queryHandle.Free();
            descriptorHandle.Free();
        }
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
}
