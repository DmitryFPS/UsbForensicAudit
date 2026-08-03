using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace UsbForensicAudit;

/// <summary>
/// Копирование файлов, которые Windows держит открытыми или закрывает списком
/// доступа: загруженные кусты реестра, журналы, NTUSER.DAT активного сеанса.
/// Обычный File.Copy на них падает, и артефакт просто выпадает из анализа.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "копирование заблокированных файлов через VSS — требует прав администратора")]
public static class LockedFileCopier
{
    private const int GenericRead = unchecked((int)0x80000000);
    private const int FileShareRead = 0x00000001;
    private const int FileShareWrite = 0x00000002;
    private const int FileShareDelete = 0x00000004;
    private const int OpenExisting = 3;
    private const int FileFlagBackupSemantics = 0x02000000;

    public static CopyOutcome Copy(string sourcePath, string destinationPath)
    {
        if (TryDirectCopy(sourcePath, destinationPath, out var directError))
        {
            return new CopyOutcome(true, "File.Copy", "");
        }

        if (TryBackupSemanticsCopy(sourcePath, destinationPath, out var backupError))
        {
            return new CopyOutcome(true, "SeBackupPrivilege", "");
        }

        if (TryShadowCopy(sourcePath, destinationPath, out var shadowError))
        {
            return new CopyOutcome(true, "Теневая копия тома", "");
        }

        return new CopyOutcome(
            false,
            "",
            $"File.Copy: {directError}; backup-привилегия: {backupError}; теневая копия: {shadowError}");
    }

    private static bool TryDirectCopy(string sourcePath, string destinationPath, out string error)
    {
        error = "";
        try
        {
            File.Copy(sourcePath, destinationPath, true);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// FILE_FLAG_BACKUP_SEMANTICS вместе с включённой SeBackupPrivilege позволяет
    /// прочитать файл в обход списка доступа, а полный режим совместного доступа —
    /// прочитать файл, открытый системой.
    /// </summary>
    private static bool TryBackupSemanticsCopy(string sourcePath, string destinationPath, out string error)
    {
        error = "";
        try
        {
            using var handle = CreateFile(
                sourcePath,
                GenericRead,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                return false;
            }

            using var source = new FileStream(handle, FileAccess.Read);
            using var destination = File.Create(destinationPath);
            source.CopyTo(destination);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Теневая копия даёт согласованный снимок тома, из которого файл читается
    /// без блокировок. Копия удаляется сразу после чтения.
    /// </summary>
    private static bool TryShadowCopy(string sourcePath, string destinationPath, out string error)
    {
        error = "";
        var shadowId = "";
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(sourcePath));
            if (string.IsNullOrWhiteSpace(root))
            {
                error = "не удалось определить том";
                return false;
            }

            using var shadowClass = new ManagementClass("Win32_ShadowCopy");
            var parameters = shadowClass.GetMethodParameters("Create");
            parameters["Volume"] = root;
            parameters["Context"] = "ClientAccessible";
            using var createResult = shadowClass.InvokeMethod("Create", parameters, null);

            var returnValue = Convert.ToInt32(createResult?["ReturnValue"] ?? -1);
            if (returnValue != 0)
            {
                error = $"Win32_ShadowCopy.Create вернул {returnValue}";
                return false;
            }

            shadowId = createResult?["ShadowID"]?.ToString() ?? "";
            var deviceObject = ResolveDeviceObject(shadowId);
            if (string.IsNullOrWhiteSpace(deviceObject))
            {
                error = "теневая копия создана, но её устройство не найдено";
                return false;
            }

            var relativePath = Path.GetFullPath(sourcePath)[root.Length..];
            var shadowPath = $@"{deviceObject}\{relativePath}";
            return TryBackupSemanticsCopy(shadowPath, destinationPath, out error);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
        finally
        {
            DeleteShadowCopy(shadowId);
        }
    }

    private static string ResolveDeviceObject(string shadowId)
    {
        if (string.IsNullOrWhiteSpace(shadowId))
        {
            return "";
        }

        using var searcher = new ManagementObjectSearcher(
            $"SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID = '{shadowId}'");
        foreach (var item in searcher.Get())
        {
            using (item)
            {
                return item["DeviceObject"]?.ToString() ?? "";
            }
        }

        return "";
    }

    private static void DeleteShadowCopy(string shadowId)
    {
        if (string.IsNullOrWhiteSpace(shadowId))
        {
            return;
        }

        try
        {
            using var shadow = new ManagementObject($"Win32_ShadowCopy.ID='{shadowId}'");
            shadow.Delete();
        }
        catch (Exception ex)
        {
            AppLog.Error(ex, "Не удалось удалить теневую копию");
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        int desiredAccess,
        int shareMode,
        IntPtr securityAttributes,
        int creationDisposition,
        int flagsAndAttributes,
        IntPtr templateFile);
}

/// <summary>
/// Результат копирования вместе со способом, которым его удалось выполнить:
/// способ попадает в происхождение артефакта.
/// </summary>
public sealed record CopyOutcome(bool Success, string Method, string Error);
