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
    - Pin a release with -Tag v0.1.0-beta.2 (the release page lists the exact tag).
    - Override LAN auto-detection with -CIDR 192.168.1.0/24 if discovery looks wrong.
#>
[CmdletBinding()]
param(
    [string]$Core = "http://localhost:8080",
    [string]$EnrollCode = "",
    [string]$CIDR = "auto",
    [string]$Tag = "",     # pin a specific release tag (e.g. v0.1.0-beta.2)
    [switch]$Reset,
    [switch]$NoService,
    [string]$Binary = ""   # escape hatch: install a caller-supplied .exe instead of downloading
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
    $a = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath, "-Core", $Core, "-CIDR", $CIDR)
    if ($EnrollCode) { $a += @("-EnrollCode", $EnrollCode) }
    if ($Tag)        { $a += @("-Tag", $Tag) }
    if ($Reset)      { $a += "-Reset" }
    if ($NoService)  { $a += "-NoService" }
    if ($Binary)     { $a += @("-Binary", $Binary) }
    Start-Process powershell -Verb RunAs -ArgumentList $a
    exit
}

$tmp = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP ("vedetta-" + [guid]::NewGuid()))
try {
    # --- Obtain the binary (caller-supplied, or checksum-verified from a release) ---
    if ($Binary) {
        Info "using caller-supplied binary: $Binary"
        Copy-Item $Binary (Join-Path $tmp "vedetta-sensor.exe") -Force
    } else {
        # Resolve the release tag. GitHub's /releases/latest EXCLUDES prereleases, so a
        # beta would 404 there; resolve the newest non-draft release that ships the
        # Windows asset instead (or honour an explicit -Tag).
        if ($Tag) {
            $rtag = $Tag
        } else {
            Info "resolving the newest release with the Windows asset..."
            $rels = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$Repo/releases"
            $rel  = $rels | Where-Object { -not $_.draft -and ($_.assets.name -contains $Asset) } | Select-Object -First 1
            if (-not $rel) { Die "no published release contains $Asset (pass -Tag <version>, or -Binary <path>)" }
            $rtag = $rel.tag_name
        }
        $base = "https://github.com/$Repo/releases/download/$rtag"
        Info "downloading $Asset ($rtag)"
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

    # --- Token directory ACL: SYSTEM + Administrators only. This MUST happen before
    #     enrollment so the persisted token (and the service log) land in a locked dir.
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

    if ($Reset) { Info "resetting sensor authentication"; & $ExePath --reset }

    # --- Enrollment (B1a hardening): spend the one-time code HERE, elevated, with the
    #     code supplied via the ENVIRONMENT (never a command line), then persist the
    #     token. The long-running service is then created WITHOUT the code, so it never
    #     lives in the service ImagePath where a standard user could read it via `sc qc`.
    if ($EnrollCode) {
        Info "enrolling with Core (one-time code, kept out of the service configuration)"
        $env:VEDETTA_ENROLL_CODE = $EnrollCode
        try {
            & $ExePath --enroll-only --core $Core --cidr $CIDR
            $rc = $LASTEXITCODE
        } finally {
            Remove-Item Env:\VEDETTA_ENROLL_CODE -ErrorAction SilentlyContinue
        }
        if ($rc -ne 0) { Die "enrollment failed (exit $rc) - check the code, -Core, and connectivity" }
    }

    if ($NoService) {
        Info "OK: binary installed (service skipped: -NoService)"
        Write-Host "    run it (elevated): `"$ExePath`" --core $Core --cidr $CIDR --dns"
        return
    }

    # --- Register + start the service (LocalSystem, auto-start, restart on failure).
    #     No enrollment secret is placed in the service command line.
    Info "configuring the $ServiceName service"
    $bin = "`"$ExePath`" --core $Core --cidr $CIDR --dns --passive-discovery=false"
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { sc.exe delete $ServiceName | Out-Null; Start-Sleep 1 }
    $desc = "Vedetta network security sensor (DNS via ETW, native discovery)"
    New-Service -Name $ServiceName -BinaryPathName $bin -DisplayName "Vedetta Sensor" -StartupType Automatic -Description $desc | Out-Null
    sc.exe failure $ServiceName reset= 86400 actions= restart/10000 | Out-Null
    Start-Service $ServiceName
    Info "OK: service installed and started ($((Get-Service $ServiceName).Status))"

    Write-Host ""
    Info "Installation complete. Manage with:  Get-Service $ServiceName  /  Stop-Service $ServiceName"
    Write-Host "    Token: $DataDir\sensor-token   Log: $DataDir\sensor.log   (SYSTEM + Administrators only)."
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
