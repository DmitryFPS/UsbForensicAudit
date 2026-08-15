<#
    UsbForensicAudit - diagnostics for "infinite loading spinner at startup".

    Run ON A PROBLEM LAPTOP, in an elevated PowerShell:
        powershell -ExecutionPolicy Bypass -File .\UsbForensicAudit-Diag.ps1

    Optionally point at the exe so the script can find data\app.log next to it:
        powershell -ExecutionPolicy Bypass -File .\UsbForensicAudit-Diag.ps1 -ExePath "D:\UsbForensicAudit.exe"

    The script is read-only: it does not stop services, change the registry or touch the app's data.
    A report is written next to the script as UsbForensicAudit-Diag-<HOSTNAME>-<timestamp>.txt
#>

[CmdletBinding()]
param(
    [string]$ExePath = "",
    [int]$WmiTimeoutSec = 30
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportPath = Join-Path $PSScriptRoot "UsbForensicAudit-Diag-$env:COMPUTERNAME-$stamp.txt"
$lines = New-Object System.Collections.Generic.List[string]

function Add-Line { param([string]$Text = "") $lines.Add($Text); Write-Host $Text }
function Add-Section {
    param([string]$Title)
    Add-Line ""
    Add-Line ("=" * 78)
    Add-Line "  $Title"
    Add-Line ("=" * 78)
}
function Add-KV { param([string]$Key, $Value) Add-Line ("  {0,-34}: {1}" -f $Key, $Value) }

Add-Line "UsbForensicAudit startup diagnostics"
Add-Line "Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
Add-Line "Computer  : $env:COMPUTERNAME"
Add-Line "User      : $env:USERDOMAIN\$env:USERNAME"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Line "Elevated  : $isAdmin"
if (-not $isAdmin) {
    Add-Line "  !! WARNING: not elevated. Some checks will be incomplete. Re-run as administrator."
}

# ---------------------------------------------------------------- 1. OS / hardware
Add-Section "1. Operating system and hardware"
try {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    Add-KV 'ProductName'        $cv.ProductName
    Add-KV 'EditionID'          $cv.EditionID
    Add-KV 'DisplayVersion'     $cv.DisplayVersion
    Add-KV 'ReleaseId'          $cv.ReleaseId
    Add-KV 'OS build'           ("{0}.{1}.{2}" -f $cv.CurrentMajorVersionNumber, $cv.CurrentBuildNumber, $cv.UBR)
    Add-KV 'CurrentBuild.UBR'   ("{0}.{1}" -f $cv.CurrentBuild, $cv.UBR)
    Add-KV 'InstallationType'   $cv.InstallationType
    if ($cv.InstallDate) {
        Add-KV 'OS InstallDate' ([DateTimeOffset]::FromUnixTimeSeconds([int64]$cv.InstallDate).LocalDateTime)
    }
} catch { Add-KV 'CurrentVersion read' "FAILED: $($_.Exception.Message)" }

try {
    $fep = Get-AppxPackage -Name 'MicrosoftWindows.Client.CBS' -ErrorAction SilentlyContinue |
           Select-Object -First 1 -ExpandProperty Version
    if ($fep) { Add-KV 'Feature Experience Pack' $fep }
} catch { }

try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Add-KV 'OS caption'         $os.Caption
    Add-KV 'OS architecture'    $os.OSArchitecture
    Add-KV 'Last boot'          $os.LastBootUpTime
    Add-KV 'Free physical MB'   ([math]::Round($os.FreePhysicalMemory / 1024))
    Add-KV 'Locale / CodeSet'   "$($os.Locale) / $($os.CodeSet)"
} catch { Add-KV 'Win32_OperatingSystem' "FAILED: $($_.Exception.Message)" }

try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    Add-KV 'Model'              "$($cs.Manufacturer) $($cs.Model)"
    Add-KV 'Total RAM GB'       ([math]::Round($cs.TotalPhysicalMemory / 1GB, 1))
    Add-KV 'Domain joined'      $cs.PartOfDomain
    Add-KV 'Domain / workgroup' $cs.Domain
} catch { }

try {
    $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
    Add-KV 'CPU' $cpu.Name
} catch { }

Add-KV 'PowerShell version' $PSVersionTable.PSVersion
Add-KV 'TEMP' $env:TEMP

Add-Line ""
Add-Line "  ntdll.dll - decides the .NET 9+ CET issue (dotnet/runtime#110920):"
try {
    $ntdll = Get-Item "$env:WINDIR\System32\ntdll.dll" -ErrorAction Stop
    Add-KV '    ntdll version'  $ntdll.VersionInfo.FileVersion
    Add-KV '    ntdll modified' $ntdll.LastWriteTime
    Add-Line "    Reference points: 10.0.19041.2788 LACKS the CET fix,"
    Add-Line "    10.0.19041.5007 HAS it (fix shipped in KB5044273, Oct 2024)."
} catch { Add-KV '    ntdll' "FAILED: $($_.Exception.Message)" }

# ---------------------------------------------------------------- 2. Secret Net / endpoint protection
Add-Section "2. Endpoint protection (Secret Net Studio) - probed by the app at startup"
Add-Line "  The app calls EndpointProtectionEnvironment before showing its window."
Add-Line "  If 'Installed' is True below, the app then runs WMI queries on the UI thread."
Add-Line ""

$snRegKey = 'HKLM:\SOFTWARE\Security Code'
$snRegPresent = Test-Path $snRegKey
Add-KV 'HKLM\SOFTWARE\Security Code' $snRegPresent
if ($snRegPresent) {
    try {
        Get-ChildItem $snRegKey -ErrorAction Stop | ForEach-Object { Add-Line "      subkey: $($_.PSChildName)" }
    } catch { Add-Line "      (cannot enumerate: $($_.Exception.Message))" }
}

$pf = [Environment]::GetFolderPath('ProgramFiles')
$pd = [Environment]::GetFolderPath('CommonApplicationData')
$dir1 = Join-Path $pf 'Secret Net Studio'
$dir2 = Join-Path $pd 'Security Code\Secret Net Studio'
Add-KV "$dir1" (Test-Path $dir1)
Add-KV "$dir2" (Test-Path $dir2)

$snInstalled = $snRegPresent -or (Test-Path $dir1) -or (Test-Path $dir2)
Add-Line ""
Add-KV '>>> App sees it as Installed' $snInstalled

Add-Line ""
Add-Line "  Services the app queries via WMI:"
foreach ($n in @('SnSrvService', 'SnHwSrv', 'SnPolicySrv', 'OmsAgentGate')) {
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    if ($s) { Add-KV "    service $n" "$($s.Status) / StartType=$($s.StartType)" }
    else    { Add-KV "    service $n" "not present" }
}

Add-Line ""
Add-Line "  Filter drivers the app queries via WMI:"
foreach ($n in @('SnDiskFilter', 'SnFileControl', 'SnSDD', 'SnEraser')) {
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    if ($s) { Add-KV "    driver $n" "$($s.Status) / StartType=$($s.StartType)" }
    else    { Add-KV "    driver $n" "not present" }
}

# ---------------------------------------------------------------- 3. Timed replication of the startup WMI calls
Add-Section "3. TIMED replication of the exact WMI queries run at app startup"
Add-Line "  Uses System.Management.ManagementObjectSearcher - the same API as the app."
Add-Line "  Each query is run in a background job with a ${WmiTimeoutSec}s timeout."
Add-Line "  A result of HUNG/TIMEOUT here is the direct explanation of the spinner."
Add-Line ""

$queries = [ordered]@{
    "Win32_Service SnSrvService"  = "SELECT State FROM Win32_Service WHERE Name='SnSrvService'"
    "Win32_Service SnHwSrv"       = "SELECT State FROM Win32_Service WHERE Name='SnHwSrv'"
    "Win32_Service SnPolicySrv"   = "SELECT State FROM Win32_Service WHERE Name='SnPolicySrv'"
    "Win32_Service OmsAgentGate"  = "SELECT State FROM Win32_Service WHERE Name='OmsAgentGate'"
    "Win32_SystemDriver Sn*"      = "SELECT Name, State FROM Win32_SystemDriver WHERE Name='SnDiskFilter' OR Name='SnFileControl' OR Name='SnSDD' OR Name='SnEraser'"
    "Win32_PnPEntity (monitoring)" = "SELECT DeviceID FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'"
    "Win32_DiskDrive (monitoring)" = "SELECT DeviceID, Model FROM Win32_DiskDrive"
}

$totalWmiMs = 0
$anyWmiHang = $false

foreach ($name in $queries.Keys) {
    $q = $queries[$name]
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $job = Start-Job -ScriptBlock {
        param($query)
        Add-Type -AssemblyName System.Management
        $searcher = New-Object System.Management.ManagementObjectSearcher($query)
        $n = 0
        foreach ($o in $searcher.Get()) { $n++ }
        $searcher.Dispose()
        return $n
    } -ArgumentList $q

    $done = Wait-Job -Job $job -Timeout $WmiTimeoutSec
    $sw.Stop()

    if (-not $done) {
        $anyWmiHang = $true
        Add-Line ("  {0,-30} : *** HUNG - no answer in {1}s ***" -f $name, $WmiTimeoutSec)
        Stop-Job -Job $job -ErrorAction SilentlyContinue
    } else {
        $err = $job.ChildJobs[0].Error
        if ($err -and $err.Count -gt 0) {
            Add-Line ("  {0,-30} : ERROR after {1,6} ms - {2}" -f $name, $sw.ElapsedMilliseconds, $err[0].Exception.Message)
        } else {
            $count = Receive-Job -Job $job
            $flag = if ($sw.ElapsedMilliseconds -gt 3000) { "  <== SLOW" } else { "" }
            Add-Line ("  {0,-30} : {1,6} ms, {2} object(s){3}" -f $name, $sw.ElapsedMilliseconds, $count, $flag)
        }
        $totalWmiMs += $sw.ElapsedMilliseconds
    }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
}

Add-Line ""
Add-KV 'Total measured WMI time (ms)' $totalWmiMs
if ($anyWmiHang) {
    Add-Line "  !!! At least one startup WMI query never returned."
    Add-Line "  !!! This alone reproduces the hang: the app runs these synchronously,"
    Add-Line "  !!! on the UI thread, with no timeout, before the window is shown."
} elseif ($totalWmiMs -gt 5000) {
    Add-Line "  !! Startup WMI is slow (> 5s). Expect a long unresponsive window at launch."
}

# ---------------------------------------------------------------- 4. WMI health
Add-Section "4. WMI subsystem health"
$winmgmt = Get-Service -Name Winmgmt -ErrorAction SilentlyContinue
if ($winmgmt) { Add-KV 'Winmgmt service' "$($winmgmt.Status) / StartType=$($winmgmt.StartType)" }
else          { Add-KV 'Winmgmt service' "NOT FOUND (!!)" }

try {
    $verify = & winmgmt /verifyrepository 2>&1
    Add-KV 'winmgmt /verifyrepository' ($verify -join ' | ')
} catch { Add-KV 'winmgmt /verifyrepository' "FAILED: $($_.Exception.Message)" }

$repo = Join-Path $env:WINDIR 'System32\wbem\Repository'
if (Test-Path $repo) {
    try {
        $size = (Get-ChildItem $repo -Recurse -Force -ErrorAction SilentlyContinue |
                 Measure-Object -Property Length -Sum).Sum
        Add-KV 'WMI repository size MB' ([math]::Round($size / 1MB, 1))
        $objData = Join-Path $repo 'OBJECTS.DATA'
        if (Test-Path $objData) {
            $f = Get-Item $objData
            Add-KV 'OBJECTS.DATA size MB' ([math]::Round($f.Length / 1MB, 1))
            Add-KV 'OBJECTS.DATA modified' $f.LastWriteTime
        }
    } catch { }
}

try {
    $wmiSvcHosts = Get-CimInstance Win32_Service -Filter "Name='Winmgmt'" -ErrorAction Stop
    Add-KV 'Winmgmt PID' $wmiSvcHosts.ProcessId
} catch { Add-KV 'Winmgmt PID lookup' "FAILED: $($_.Exception.Message)" }

$wmiProvHost = Get-Process -Name WmiPrvSE -ErrorAction SilentlyContinue
if ($wmiProvHost) {
    Add-KV 'WmiPrvSE instances' $wmiProvHost.Count
    foreach ($p in $wmiProvHost) {
        Add-Line ("      PID {0,-7} CPU {1,8:N1}s  WS {2,7:N0} MB  started {3}" -f
            $p.Id, $p.CPU, ($p.WorkingSet64 / 1MB), $p.StartTime)
    }
} else {
    Add-KV 'WmiPrvSE instances' 0
}

# ---------------------------------------------------------------- 5. Antivirus / security software
Add-Section "5. Security software (can block single-file extraction / device access)"
try {
    $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
    if ($av) {
        foreach ($a in $av) {
            Add-Line "  Product: $($a.displayName)"
            Add-Line "      path      : $($a.pathToSignedProductExe)"
            Add-Line "      stateHex  : 0x$('{0:X}' -f $a.productState)"
        }
    } else { Add-Line "  (no products reported)" }
} catch { Add-Line "  SecurityCenter2 query failed: $($_.Exception.Message)" }

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Add-KV 'Defender RealTimeProtection' $mp.RealTimeProtectionEnabled
    Add-KV 'Defender AntivirusEnabled'   $mp.AntivirusEnabled
    Add-KV 'Defender IsTamperProtected'  $mp.IsTamperProtected
} catch { Add-Line "  Get-MpComputerStatus unavailable: $($_.Exception.Message)" }

Add-Line ""
Add-Line "  Loaded minifilter drivers (fltmc):"
try {
    $flt = & fltmc.exe filters 2>&1
    foreach ($l in $flt) { Add-Line "      $l" }
} catch { Add-Line "      fltmc failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------- 6. Locate the app and its log
Add-Section "6. UsbForensicAudit binary, data directory and app.log"

$exeCandidates = New-Object System.Collections.Generic.List[string]
if ($ExePath -and (Test-Path $ExePath)) { $exeCandidates.Add((Resolve-Path $ExePath).Path) }

$searchRoots = @(
    [Environment]::GetFolderPath('Desktop'),
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Documents",
    'C:\UsbForensicAudit',
    "$pf\UsbForensicAudit"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

foreach ($root in $searchRoots) {
    Get-ChildItem -Path $root -Filter 'UsbForensicAudit.exe' -Recurse -Depth 3 -ErrorAction SilentlyContinue |
        ForEach-Object { if (-not $exeCandidates.Contains($_.FullName)) { $exeCandidates.Add($_.FullName) } }
}

if ($exeCandidates.Count -eq 0) {
    Add-Line "  UsbForensicAudit.exe not found automatically."
    Add-Line "  Re-run with -ExePath 'full\path\to\UsbForensicAudit.exe' for log analysis."
} else {
    foreach ($exe in $exeCandidates) {
        $f = Get-Item $exe
        Add-Line ""
        Add-Line "  EXE: $exe"
        Add-KV '    size MB'        ([math]::Round($f.Length / 1MB, 1))
        Add-KV '    modified'       $f.LastWriteTime
        Add-KV '    product version' $f.VersionInfo.ProductVersion
        Add-KV '    file version'    $f.VersionInfo.FileVersion
        try {
            $sig = Get-AuthenticodeSignature $exe
            Add-KV '    signature'   "$($sig.Status) $($sig.SignerCertificate.Subject)"
        } catch { }
        try {
            $zone = Get-Content -Path $exe -Stream Zone.Identifier -ErrorAction Stop
            Add-Line "    !! Mark-of-the-Web present (file came from internet):"
            foreach ($z in $zone) { Add-Line "        $z" }
            Add-Line "    !! Fix with: Unblock-File '$exe'"
        } catch { Add-KV '    Zone.Identifier' 'absent (not blocked)' }

        $dataDir = Join-Path (Split-Path $exe) 'data'
        $usedDir = $dataDir
        if (-not (Test-Path $dataDir)) {
            $usedDir = Join-Path $env:LOCALAPPDATA 'UsbForensicAudit'
            Add-Line "    portable data\ absent -> fallback: $usedDir"
        }
        Add-KV '    data directory' $usedDir

        if (Test-Path $usedDir) {
            foreach ($n in @('app.log', 'audit.sqlite', 'evidence.jsonl', 'external_utility_snapshot.json')) {
                $p = Join-Path $usedDir $n
                if (Test-Path $p) {
                    $i = Get-Item $p
                    Add-KV "    $n" ("{0:N0} bytes, modified {1}" -f $i.Length, $i.LastWriteTime)
                } else {
                    Add-KV "    $n" 'absent'
                }
            }

            $log = Join-Path $usedDir 'app.log'
            if (Test-Path $log) {
                $content = Get-Content $log -Encoding UTF8 -ErrorAction SilentlyContinue
                $startups = @($content | Select-String -SimpleMatch 'Application startup')
                Add-Line ""
                Add-KV "    'Application startup' lines" $startups.Count
                if ($startups.Count -eq 0) {
                    Add-Line "    >>> KEY FINDING: the log has no 'Application startup' line."
                    Add-Line "    >>> The app froze BEFORE reaching App.xaml.cs line 63, i.e. in the"
                    Add-Line "    >>> admin check, the Secret Net WMI probe, or single-file extraction."
                } else {
                    Add-Line "    Last 40 log lines:"
                    foreach ($l in ($content | Select-Object -Last 40)) { Add-Line "        $l" }
                }
            } else {
                Add-Line "    >>> KEY FINDING: app.log does not exist at all."
                Add-Line "    >>> The process never got as far as its first log write."
            }
        } else {
            Add-Line "    data directory does not exist"
        }
    }
}

# ---------------------------------------------------------------- 7. Single-file extraction
Add-Section "7. .NET single-file self-extraction (published with compression)"
Add-Line "  The exe is self-contained + PublishSingleFile + EnableCompressionInSingleFile."
Add-Line "  On first launch the whole runtime is decompressed into %TEMP%\.net."
Add-Line "  If that path is blocked, redirected or scanned, launch appears to hang."
Add-Line ""
$netExtract = Join-Path $env:TEMP '.net'
Add-KV 'DOTNET_BUNDLE_EXTRACT_BASE_DIR' ($(if ($env:DOTNET_BUNDLE_EXTRACT_BASE_DIR) { $env:DOTNET_BUNDLE_EXTRACT_BASE_DIR } else { '(not set - default %TEMP%\.net)' }))
Add-KV "$netExtract exists" (Test-Path $netExtract)
if (Test-Path $netExtract) {
    Get-ChildItem $netExtract -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $sz = (Get-ChildItem $_.FullName -Recurse -Force -ErrorAction SilentlyContinue |
               Measure-Object -Property Length -Sum).Sum
        Add-Line ("      {0,-30} {1,7:N1} MB  {2}" -f $_.Name, ($sz / 1MB), $_.LastWriteTime)
    }
}
try {
    $tempDrive = (Get-Item $env:TEMP).PSDrive
    $free = (Get-PSDrive $tempDrive.Name).Free
    Add-KV 'Free space on TEMP drive GB' ([math]::Round($free / 1GB, 1))
} catch { }

# ---------------------------------------------------------------- 8. Running instances / mutex
Add-Section "8. Running instances and storage mutex"
$procs = Get-Process -Name 'UsbForensicAudit' -ErrorAction SilentlyContinue
if ($procs) {
    Add-KV 'Running instances' $procs.Count
    foreach ($p in $procs) {
        Add-Line ("      PID {0,-7} CPU {1,8:N1}s  WS {2,7:N0} MB  Responding={3}  started {4}" -f
            $p.Id, $p.CPU, ($p.WorkingSet64 / 1MB), $p.Responding, $p.StartTime)
        Add-Line ("        MainWindowHandle: {0}  Title: '{1}'" -f $p.MainWindowHandle, $p.MainWindowTitle)
        try {
            Add-Line "        Threads: $($p.Threads.Count)"
            foreach ($t in ($p.Threads | Sort-Object -Property TotalProcessorTime -Descending | Select-Object -First 5)) {
                Add-Line ("          TID {0,-7} state={1} waitReason={2} cpu={3}" -f
                    $t.Id, $t.ThreadState, $t.WaitReason, $t.TotalProcessorTime)
            }
        } catch { }
    }
    Add-Line ""
    Add-Line "  >>> The app is running right now. If it is the hung instance:"
    Add-Line "  >>>   Task Manager -> Details -> UsbForensicAudit.exe -> right click"
    Add-Line "  >>>   -> 'Create dump file', then send the .dmp for stack analysis."
    Add-Line "  >>> A UI thread with waitReason=LpcReceive / Executive means it is"
    Add-Line "  >>> blocked in an RPC/DCOM call, which is what the WMI probe looks like."
} else {
    Add-KV 'Running instances' 0
    Add-Line "  Tip: launch the app, wait until the spinner appears, then re-run this"
    Add-Line "  script to capture thread states of the frozen process."
}

# ---------------------------------------------------------------- 9. Application event log
Add-Section "9. Recent .NET / application errors in the Windows event log"
try {
    $ev = Get-WinEvent -FilterHashtable @{
        LogName   = 'Application'
        Level     = 1, 2, 3
        StartTime = (Get-Date).AddDays(-14)
    } -MaxEvents 400 -ErrorAction Stop |
        Where-Object {
            $_.ProviderName -match 'Application Error|Application Hang|\.NET Runtime|Windows Error Reporting' -or
            $_.Message -match 'UsbForensicAudit'
        } | Select-Object -First 25

    if ($ev) {
        foreach ($e in $ev) {
            Add-Line ""
            Add-Line ("  [{0}] {1} (id {2}, level {3})" -f $e.TimeCreated, $e.ProviderName, $e.Id, $e.LevelDisplayName)
            $msg = ($e.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 6) -join ' | '
            Add-Line "      $msg"
        }
    } else {
        Add-Line "  No relevant Application-log errors in the last 14 days."
    }
} catch { Add-Line "  Application log query failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------- 10. Verdict
Add-Section "10. Automatic verdict"
if ($anyWmiHang) {
    Add-Line "  CAUSE FOUND (high confidence): a startup WMI query does not return."
    Add-Line "  The app performs it synchronously on the UI thread with no timeout,"
    Add-Line "  before the main window is made visible -> permanent spinner, no window."
} elseif ($snInstalled -and $totalWmiMs -gt 5000) {
    Add-Line "  LIKELY CAUSE: Secret Net Studio is present and its WMI queries are slow."
    Add-Line "  Launch will freeze for roughly $totalWmiMs ms or longer."
} elseif ($snInstalled) {
    Add-Line "  Secret Net Studio present, but its WMI queries answered quickly here."
    Add-Line "  Re-run this script WHILE the app is hung - WMI can degrade under load."
} else {
    Add-Line "  Secret Net Studio not detected, so the startup WMI probe is skipped."
    Add-Line "  Look instead at section 6 (app.log), section 7 (single-file extraction)"
    Add-Line "  and section 8 (thread wait reasons of the frozen process)."
}
Add-Line ""
Add-Line "  PRIMARY SUSPECT regardless of the above: the .NET 9+ CET default."
Add-Line "  The .NET 10 build of this app has /CETCOMPAT set in its PE header;"
Add-Line "  every earlier .NET 8 build did not. On a CET-capable Intel/AMD CPU"
Add-Line "  with an ntdll that lacks the KB5044273 fix, CoreCLR dies or hangs"
Add-Line "  before the main window appears (dotnet/runtime#110920)."
Add-Line "  Compare the ntdll version in section 1 against the reference points."
Add-Line "  Fix: rebuild with <CETCompat>false</CETCompat>, or fully patch Windows."

# ---------------------------------------------------------------- write report
$lines -join "`r`n" | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host ""
Write-Host "Report saved to: $reportPath" -ForegroundColor Green
