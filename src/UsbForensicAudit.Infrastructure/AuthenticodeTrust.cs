using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace UsbForensicAudit;

internal static class AuthenticodeTrust
{
    private static readonly Guid GenericVerifyV2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public static bool IsTrustedMicrosoftBinary(string path)
    {
        if (!File.Exists(path) || !VerifyEmbeddedSignature(path))
        {
            return false;
        }

        try
        {
#pragma warning disable SYSLIB0057
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return certificate.Subject.Contains("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase)
                   || certificate.Subject.Contains("CN=Microsoft Corporation", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception)
        {
            AppLog.Error(exception, "Authenticode signer inspection failed: " + path);
            return false;
        }
    }

    private static bool VerifyEmbeddedSignature(string path)
    {
        var fileInfo = new WinTrustFileInfo(path);
        var fileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
            var trustData = new WinTrustData(fileInfoPointer);
            return WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref trustData) == 0;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
            Marshal.FreeCoTaskMem(fileInfoPointer);
            fileInfo.Dispose();
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(
        IntPtr windowHandle,
        [MarshalAs(UnmanagedType.LPStruct)] Guid actionId,
        ref WinTrustData trustData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustFileInfo : IDisposable
    {
        public uint StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>();
        public IntPtr FilePath;
        public IntPtr FileHandle = IntPtr.Zero;
        public IntPtr KnownSubject = IntPtr.Zero;

        public WinTrustFileInfo(string path)
        {
            FilePath = Marshal.StringToCoTaskMemUni(path);
        }

        public void Dispose()
        {
            if (FilePath != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(FilePath);
                FilePath = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;

        public WinTrustData(IntPtr fileInfo)
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustData>();
            PolicyCallbackData = IntPtr.Zero;
            SipClientData = IntPtr.Zero;
            UiChoice = 2; // WTD_UI_NONE
            RevocationChecks = 1; // WTD_REVOKE_WHOLECHAIN
            UnionChoice = 1; // WTD_CHOICE_FILE
            FileInfo = fileInfo;
            StateAction = 0;
            StateData = IntPtr.Zero;
            UrlReference = IntPtr.Zero;
            ProviderFlags = 0x00000080; // WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            UiContext = 0;
            SignatureSettings = IntPtr.Zero;
        }
    }
}
