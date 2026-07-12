#Requires -Version 5.1
<#
    Vedetta sensor installer for Windows. Mirrors deploy/install.sh.

    Run in an ELEVATED PowerShell (it self-elevates when launched from a file):
      .\install.ps1 -Core https://vedetta.example.com -EnrollCode <CODE>

    Notes:
    - The Windows sensor is driver-free: DNS via ETW, discovery via native ICMP/ARP.
      No Npcap and no nmap are installed or required.
    - Core is loopback-only by default; a REMOTE sensor must point -Core at the TLS
      reverse proxy (https://...), not http://<core-ip>:8080.
#>
[CmdletBinding()]
param(
    [string]$Core = "http://localhost:8080",
    [string]$EnrollCode = "",
    [switch]$Reset,
    [switch]$NoService,
    [string]$Binary = "" # escape hatch: install a caller-supplied .exe instead of downloading
)

$ErrorActionPreference = "Stop"
$Repo        = "MahdiHedhli/vedetta"
$Asset       = "vedetta-sensor_windows_amd64.zip"
$InstallDir  = Join-Path $env:ProgramFiles "Vedetta"
$ExePath     = Join-Path $InstallDir "vedetta-sensor.exe"
$DataDir     = Join-Path $env:ProgramData "Vedetta"
$ServiceName = "VedettaSensor"

function Info($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Die($m)  { Write-Host "!! $m" -ForegroundColor Red; exit 1 }

# --- Self-elevate (needs Administrator to install a service + write ProgramFiles) ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    if (-not $PSCommandPath) { Die "run this from an elevated PowerShell (Run as Administrator)" }
    Info "elevation required - re-launching as Administrator..."
    $a = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath, "-Core", $Core)
    if ($EnrollCode) { $a += @("-EnrollCode", $EnrollCode) }
    if ($Reset)      { $a += "-Reset" }
    if ($NoService)  { $a += "-NoService" }
    if ($Binary)     { $a += @("-Binary", $Binary) }
    Start-Process powershell -Verb RunAs -ArgumentList $a
    exit
}

$tmp = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP ("vedetta-" + [guid]::NewGuid()))
try {
    # --- Obtain the binary (caller-supplied, or checksum-verified from the release) ---
    if ($Binary) {
        Info "using caller-supplied binary: $Binary"
        Copy-Item $Binary (Join-Path $tmp "vedetta-sensor.exe") -Force
    } else {
        Info "resolving the latest release..."
        $tag = (Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$Repo/releases/latest").tag_name
        if (-not $tag) { Die "could not resolve the latest release tag" }
        $base = "https://github.com/$Repo/releases/download/$tag"
        Info "downloading $Asset ($tag)"
        Invoke-WebRequest -UseBasicParsing "$base/$Asset" -OutFile (Join-Path $tmp $Asset)
        Invoke-WebRequest -UseBasicParsing "$base/checksums.txt" -OutFile (Join-Path $tmp "checksums.txt")
        Info "verifying checksum"
        $want = ((Select-String -Path (Join-Path $tmp "checksums.txt") -SimpleMatch $Asset | Select-Object -First 1).Line -split '\s+')[0].ToLower()
        $got  = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $Asset)).Hash.ToLower()
        if (-not $want -or $want -ne $got) { Die "checksum FAILED (want '$want' got '$got')" }
        Expand-Archive -Path (Join-Path $tmp $Asset) -DestinationPath $tmp -Force
    }
    $srcExe = Join-Path $tmp "vedetta-sensor.exe"
    if (-not (Test-Path $srcExe)) { Die "vedetta-sensor.exe not found after extraction" }

    # --- Install the binary ---
    Info "installing to $ExePath"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    }
    Copy-Item $srcExe $ExePath -Force
    & $ExePath --version

    # --- Token directory ACL: SYSTEM + Administrators only (os.Chmod is a no-op on NTFS) ---
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

    if ($Reset) { Info "resetting sensor authentication"; & $ExePath --reset }

    if ($NoService) {
        Info "OK: binary installed (service skipped: -NoService)"
        $hint = if ($EnrollCode) { " --enroll-code $EnrollCode" } else { "" }
        Write-Host "    run it (elevated): `"$ExePath`" --core $Core$hint"
        return
    }

    # --- Register + start the Windows service (LocalSystem, auto-start, restart on failure) ---
    Info "configuring the $ServiceName service"
    $bin = "`"$ExePath`" --core $Core --cidr auto --dns"
    if ($EnrollCode) { $bin += " --enroll-code $EnrollCode" }
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { sc.exe delete $ServiceName | Out-Null; Start-Sleep 1 }
    $desc = "Vedetta network security sensor (DNS via ETW, native discovery)"
    New-Service -Name $ServiceName -BinaryPathName $bin -DisplayName "Vedetta Sensor" -StartupType Automatic -Description $desc | Out-Null
    sc.exe failure $ServiceName reset= 86400 actions= restart/10000 | Out-Null
    Start-Service $ServiceName
    Info "OK: service installed and started ($((Get-Service $ServiceName).Status))"

    if ($EnrollCode) {
        Write-Host ""
        Write-Host "    NOTE: the enrollment code is single-use. After the first successful"        -ForegroundColor Yellow
        Write-Host "    registration the sensor persists a token and no longer needs it. Re-run"    -ForegroundColor Yellow
        Write-Host "    this installer WITHOUT -EnrollCode so a service restart cannot replay a"     -ForegroundColor Yellow
        Write-Host "    now-consumed code:  .\install.ps1 -Core $Core"                               -ForegroundColor Yellow
    }
    Write-Host ""
    Info "Installation complete. Manage with:  Get-Service $ServiceName  /  Stop-Service $ServiceName"
    Write-Host "    Token: $DataDir\sensor-token (readable only by SYSTEM + Administrators)."
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
