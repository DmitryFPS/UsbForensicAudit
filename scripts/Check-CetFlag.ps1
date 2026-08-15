<#
    Reads the PE "extended DLL characteristics" debug directory of an EXE and reports
    whether IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT (0x0001) is set.

    .NET 9+ apphosts set /CETCOMPAT by default; .NET 8 apphosts do not.
    On CET-capable CPUs with an ntdll that lacks the KB5044273 fix, a CET-compat
    process dies in CoreCLR's APC path (dotnet/runtime#110920).

    Usage: powershell -ExecutionPolicy Bypass -File .\Check-CetFlag.ps1 "path\to\app.exe" [more.exe ...]
#>

param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Paths)

function Get-CetCompat {
    param([string]$Path)

    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $br = New-Object System.IO.BinaryReader($fs)

        $fs.Position = 0x3C
        $peOffset = $br.ReadInt32()
        $fs.Position = $peOffset
        if ($br.ReadUInt32() -ne 0x00004550) { return [pscustomobject]@{ Error = 'not a PE file' } }

        $machine = $br.ReadUInt16()
        $numberOfSections = $br.ReadUInt16()
        $null = $br.ReadUInt32()   # TimeDateStamp
        $null = $br.ReadUInt32()   # PointerToSymbolTable
        $null = $br.ReadUInt32()   # NumberOfSymbols
        $sizeOfOptionalHeader = $br.ReadUInt16()
        $null = $br.ReadUInt16()   # Characteristics

        $optStart = $fs.Position
        $magic = $br.ReadUInt16()
        $isPe32Plus = ($magic -eq 0x20B)

        # DataDirectory offset from start of optional header
        $dataDirOffset = if ($isPe32Plus) { 112 } else { 96 }
        $fs.Position = $optStart + $dataDirOffset + (6 * 8)   # index 6 = Debug
        $debugRva = $br.ReadUInt32()
        $debugSize = $br.ReadUInt32()

        # Section headers follow the optional header
        $fs.Position = $optStart + $sizeOfOptionalHeader
        $sections = @()
        for ($i = 0; $i -lt $numberOfSections; $i++) {
            $nameBytes = $br.ReadBytes(8)
            $name = ([System.Text.Encoding]::ASCII.GetString($nameBytes)).TrimEnd([char]0)
            $virtualSize = $br.ReadUInt32()
            $virtualAddress = $br.ReadUInt32()
            $sizeOfRawData = $br.ReadUInt32()
            $pointerToRawData = $br.ReadUInt32()
            $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
            $null = $br.ReadUInt16(); $null = $br.ReadUInt16()
            $null = $br.ReadUInt32()
            $sections += [pscustomobject]@{
                Name = $name; VirtualAddress = $virtualAddress; VirtualSize = $virtualSize
                PointerToRawData = $pointerToRawData; SizeOfRawData = $sizeOfRawData
            }
        }

        function Convert-RvaToOffset {
            param([uint32]$Rva, $Sections)
            foreach ($s in $Sections) {
                $size = if ($s.VirtualSize -gt 0) { $s.VirtualSize } else { $s.SizeOfRawData }
                if ($Rva -ge $s.VirtualAddress -and $Rva -lt ($s.VirtualAddress + $size)) {
                    return $s.PointerToRawData + ($Rva - $s.VirtualAddress)
                }
            }
            return 0
        }

        if ($debugRva -eq 0 -or $debugSize -eq 0) {
            return [pscustomobject]@{ Machine = $machine; CetCompat = $false; Note = 'no debug directory' }
        }

        $debugOffset = Convert-RvaToOffset -Rva $debugRva -Sections $sections
        if ($debugOffset -eq 0) {
            return [pscustomobject]@{ Machine = $machine; CetCompat = $false; Note = 'debug dir RVA unmapped' }
        }

        $entryCount = [math]::Floor($debugSize / 28)
        $found = $false
        $raw = $null
        for ($i = 0; $i -lt $entryCount; $i++) {
            $fs.Position = $debugOffset + ($i * 28)
            $null = $br.ReadUInt32()   # Characteristics
            $null = $br.ReadUInt32()   # TimeDateStamp
            $null = $br.ReadUInt16()   # MajorVersion
            $null = $br.ReadUInt16()   # MinorVersion
            $type = $br.ReadUInt32()
            $sizeOfData = $br.ReadUInt32()
            $null = $br.ReadUInt32()   # AddressOfRawData
            $pointerToRawData = $br.ReadUInt32()

            # IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20
            if ($type -eq 20 -and $sizeOfData -ge 2 -and $pointerToRawData -gt 0) {
                $fs.Position = $pointerToRawData
                $raw = $br.ReadUInt16()
                $found = ($raw -band 0x0001) -ne 0
                break
            }
        }

        return [pscustomobject]@{
            Machine   = ('0x{0:X4}' -f $machine)
            CetCompat = $found
            RawFlags  = if ($null -ne $raw) { '0x{0:X4}' -f $raw } else { '(absent)' }
        }
    } finally {
        $fs.Dispose()
    }
}

if (-not $Paths) {
    Write-Host "Give one or more exe paths." -ForegroundColor Yellow
    exit 1
}

foreach ($p in $Paths) {
    if (-not (Test-Path $p)) { Write-Host "MISSING: $p" -ForegroundColor Red; continue }
    $item = Get-Item $p
    $res = Get-CetCompat -Path $item.FullName
    Write-Host ""
    Write-Host $item.FullName -ForegroundColor Cyan
    Write-Host ("  built            : {0:dd.MM.yyyy HH:mm}" -f $item.LastWriteTime)
    Write-Host ("  size             : {0:N1} MB" -f ($item.Length / 1MB))
    Write-Host ("  product version  : {0}" -f $item.VersionInfo.ProductVersion)
    Write-Host ("  machine          : {0}" -f $res.Machine)
    Write-Host ("  ext dllchars     : {0}" -f $res.RawFlags)
    if ($res.CetCompat) {
        Write-Host "  /CETCOMPAT       : YES  <== CET shadow stack enforced (.NET 9+ default)" -ForegroundColor Red
    } else {
        Write-Host "  /CETCOMPAT       : no        (.NET 8 apphost behaviour)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "=== Local ntdll.dll (needs the KB5044273 CET fix) ===" -ForegroundColor Cyan
$ntdll = Get-Item "$env:WINDIR\System32\ntdll.dll"
Write-Host ("  version  : {0}" -f $ntdll.VersionInfo.FileVersion)
Write-Host ("  modified : {0:dd.MM.yyyy}" -f $ntdll.LastWriteTime)

Write-Host ""
Write-Host "=== CPU CET capability ===" -ForegroundColor Cyan
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
Write-Host ("  {0}" -f $cpu.Name)
Write-Host "  Intel Tiger Lake (11th gen) and newer, or AMD Zen 3 and newer, support CET."
