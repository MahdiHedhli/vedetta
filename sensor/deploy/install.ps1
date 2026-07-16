#Requires -Version 5.1
<#
    Vedetta sensor installer for Windows. Mirrors deploy/install.sh.

    Run in an ELEVATED 64-bit PowerShell:
      .\install.ps1 -Core https://vedetta.example.com
    The installer securely prompts for a code on a fresh install or reset.

    Notes:
    - The Windows sensor is driver-free: DNS via ETW, discovery via native ICMP/ARP.
      No Npcap and no nmap are installed or required.
    - Core is loopback-only by default; a REMOTE sensor must point -Core at the TLS
      reverse proxy (https://...), not http://<core-ip>:8080.
    - Pin a release with -Tag <published-tag> (the release page lists exact tags).
    - Override LAN auto-detection with -CIDR <LAN-CIDR> if discovery looks wrong.
#>
[CmdletBinding()]
param(
    [string]$Core = "http://localhost:8080",
    [string]$EnrollCode = "",
    [switch]$EnrollCodeStdin,
    [switch]$AllowInsecureEnrollCodeArgument,
    [string]$CIDR = "auto",
    [string]$Tag = "",     # pin a specific published release tag
    [switch]$Reset,
    [switch]$NoService,
    [string]$Binary = "",  # escape hatch: install a caller-supplied .exe instead of downloading
    [string]$BinarySha256 = "" # required trust anchor when -Binary is used
)

$ErrorActionPreference = "Stop"

$Repo        = "MahdiHedhli/vedetta"
$Asset       = "vedetta-sensor_windows_amd64.zip"
$ServiceName = "VedettaSensor"

function Info($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Die($m)  { Write-Host "!! $m" -ForegroundColor Red; exit 1 }
function Read-EnrollmentCodePrompt {
    $SecureCode = Read-Host "One-time Vedetta enrollment/reset code" -AsSecureString
    if (-not $SecureCode -or $SecureCode.Length -eq 0) { throw "an enrollment code is required" }
    $Pointer = [IntPtr]::Zero
    try {
        $Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureCode)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer).Trim()
    } finally {
        if ($Pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer) }
        $SecureCode.Dispose()
    }
}
function Read-EnrollmentCodeFromStdin {
    if (-not [Console]::IsInputRedirected) {
        throw "-EnrollCodeStdin requires the one-time code on redirected standard input"
    }
    $Code = [Console]::In.ReadLine()
    if ($null -eq $Code) { throw "redirected standard input ended before an enrollment code was read" }
    return $Code.Trim()
}
function Assert-EnrollmentCodeValue {
    param([string]$Code)
    if (-not $Code) { throw "an enrollment code is required" }
    if ($Code.Length -gt 512) { throw "the enrollment code is unexpectedly long" }
    if ($Code -notmatch '^[A-Za-z0-9_-]+$') { throw "the enrollment code contains an invalid character" }
}
function Assert-ReleaseTagValue {
    param([string]$Value)
    if (-not $Value) { return }

    # -Tag is a name inside MahdiHedhli/vedetta, not an arbitrary URL path. Keep
    # the grammar deliberately narrower than Git refs: slash, backslash, percent
    # encoding, query/fragment delimiters, and dot segments must never be able to
    # escape the repository's /releases/download/<tag> namespace.
    if ($Value.Length -gt 128 -or
        $Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]*$' -or
        $Value.Contains('..')) {
        throw "-Tag must be a simple Vedetta release tag (letters, digits, '.', '_', '+', and '-' only; no dot segments)"
    }
}
function Ensure-VedettaDataDirectory {
    param([string]$Path)

    # Create the directory with its final descriptor in the same filesystem
    # operation. Never "repair" an unexpected existing directory: ACL changes do
    # not revoke hostile handles that were already open, and name-based tools can
    # follow a junction to an attacker-chosen target.
    if (-not (Test-Path -LiteralPath $Path)) {
        $NewAcl = New-Object System.Security.AccessControl.DirectorySecurity
        $NewAcl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        try {
            [System.IO.Directory]::CreateDirectory($Path, $NewAcl) | Out-Null
        } catch {
            Die "could not atomically create protected data directory $Path ($_)"
        }
    }

    try {
        $Item = Get-Item -LiteralPath $Path -Force
        if (-not $Item.PSIsContainer -or (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            Die "$Path is not a regular directory (junctions/reparse points are refused)"
        }
        $DataAcl = Get-Acl -LiteralPath $Path
        $OwnerAccount = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $DataAcl.Owner
        $OwnerSid = $OwnerAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $Rules = @($DataAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        $ExpectedSids = @("S-1-5-18", "S-1-5-32-544")
        $ExpectedSidCounts = @{}
        foreach ($Rule in $Rules) {
            $RuleSid = [string]$Rule.IdentityReference.Value
            if (-not $ExpectedSidCounts.ContainsKey($RuleSid)) { $ExpectedSidCounts[$RuleSid] = 0 }
            $ExpectedSidCounts[$RuleSid]++
        }
        $ExpectedInheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $UnexpectedRules = @($Rules | Where-Object {
            $_.IsInherited -or
            $_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $_.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $_.InheritanceFlags -ne $ExpectedInheritance -or
            $_.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None -or
            $ExpectedSids -notcontains $_.IdentityReference.Value
        })
        $MissingOrDuplicateSids = @($ExpectedSids | Where-Object { $ExpectedSidCounts[$_] -ne 1 })
        if ($OwnerSid -ne "S-1-5-32-544" -or -not $DataAcl.AreAccessRulesProtected -or
            $Rules.Count -ne 2 -or $UnexpectedRules.Count -ne 0 -or $MissingOrDuplicateSids.Count -ne 0) {
            Die "$Path has an unexpected owner or ACL. Refusing to mutate it in place; stop processes using it, remove it (or reboot first), then retry."
        }
    } catch {
        Die "could not verify protected data directory $Path ($_)"
    }
}
function Assert-NoUnprivilegedWrite {
    param([string]$Path, [switch]$Directory)

    try {
        $Item = Get-Item -LiteralPath $Path -Force
        if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Path is a reparse point"
        }
        if ($Directory) {
            if (-not $Item.PSIsContainer) { throw "$Path is not a directory" }
        } elseif (-not $Item.PSIsContainer -and -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "$Path is not a regular file"
        } elseif ($Item.PSIsContainer) {
            throw "$Path is a directory, not a regular file"
        }

        $Acl = Get-Acl -LiteralPath $Path
        $RawDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Acl.Sddl)
        if (($RawDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0 -or
            $null -eq $RawDescriptor.DiscretionaryAcl) {
            throw "$Path has a null or absent DACL"
        }
        $OwnerAccount = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $Acl.Owner
        $OwnerSid = $OwnerAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $TrustedSids = @(
            "S-1-5-18",       # SYSTEM
            "S-1-5-32-544",   # BUILTIN\Administrators
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" # TrustedInstaller
        )
        if ($TrustedSids -notcontains $OwnerSid) {
            throw "$Path is owned by untrusted SID $OwnerSid"
        }

        $Rules = @($Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        if ($Rules.Count -eq 0) { throw "$Path has no inspectable DACL rules" }
        $WriteMask = [int64][System.Security.AccessControl.FileSystemRights]::WriteData
        $WriteMask = $WriteMask -bor [int64][System.Security.AccessControl.FileSystemRights]::AppendData
        $WriteMask = $WriteMask -bor [int64][System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
        $WriteMask = $WriteMask -bor [int64][System.Security.AccessControl.FileSystemRights]::WriteAttributes
        $WriteMask = $WriteMask -bor [int64][System.Security.AccessControl.FileSystemRights]::Delete
        $WriteMask = $WriteMask -bor [int64][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
        $WriteMask = $WriteMask -bor [int64][System.Security.AccessControl.FileSystemRights]::ChangePermissions
        $WriteMask = $WriteMask -bor [int64][System.Security.AccessControl.FileSystemRights]::TakeOwnership
        $WriteMask = $WriteMask -bor [int64]0x40000000 # GENERIC_WRITE
        $WriteMask = $WriteMask -bor [int64]0x10000000 # GENERIC_ALL
        foreach ($Rule in $Rules) {
            if ($Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
                (([int64]$Rule.FileSystemRights -band $WriteMask) -eq 0)) { continue }
            $RuleSid = $Rule.IdentityReference.Value
            $CreatorOwnerInheritOnly = $RuleSid -eq "S-1-3-0" -and
                (($Rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
            if ($TrustedSids -notcontains $RuleSid -and -not $CreatorOwnerInheritOnly) {
                throw "$Path grants write-like rights to untrusted SID $RuleSid"
            }
        }
    } catch {
        throw "unsafe install path: $($_.Exception.Message)"
    }
}
function Copy-ProtectedFile {
    param([string]$Source, [string]$Destination)

    $Security = New-Object System.Security.AccessControl.FileSecurity
    $Security.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
    $InputStream = $null
    $OutputStream = $null
    try {
        $InputStream = [System.IO.File]::Open($Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $OutputStream = [System.IO.FileStream]::new(
            $Destination,
            [System.IO.FileMode]::CreateNew,
            [System.Security.AccessControl.FileSystemRights]::Write,
            [System.IO.FileShare]::None,
            1048576,
            [System.IO.FileOptions]::SequentialScan,
            $Security
        )
        $InputStream.CopyTo($OutputStream)
        $OutputStream.Flush($true)
    } catch {
        if ($OutputStream) { $OutputStream.Dispose(); $OutputStream = $null }
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        throw
    } finally {
        if ($OutputStream) { $OutputStream.Dispose() }
        if ($InputStream) { $InputStream.Dispose() }
    }
    Assert-NoUnprivilegedWrite -Path $Destination
}
function Invoke-ScChecked {
    param([string[]]$Arguments, [string]$Action)
    & $script:ScExe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$Action failed (sc.exe exit $LASTEXITCODE)" }
}
function Set-VedettaServiceCommandLineChecked {
    param([string]$Name, [string]$CommandLine, [string]$Action)

    # Windows PowerShell 5.1's legacy native-argument binder strips the embedded
    # executable quotes from a command line passed through `sc.exe config`. Use
    # the typed SCM/WMI boundary so PathName remains one exact string.
    $Service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if (-not $Service) { throw "$Action failed (service missing)" }
    $Result = Invoke-CimMethod -InputObject $Service -MethodName Change -Arguments @{ PathName = $CommandLine } -ErrorAction Stop
    if ([uint32]$Result.ReturnValue -ne 0) {
        throw "$Action failed (Win32_Service.Change return $($Result.ReturnValue))"
    }
    $Actual = (Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop).PathName
    if (-not [string]::Equals($Actual, $CommandLine, [System.StringComparison]::Ordinal)) {
        throw "$Action failed (SCM did not retain the requested command line)"
    }
}
function Stop-VedettaServiceChecked {
    param([string]$Name)
    $Service = Get-Service $Name -ErrorAction SilentlyContinue
    if ($Service -and $Service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service $Name -Force -ErrorAction Stop
        $Service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
    }
}
function Assert-VedettaServiceStable {
    param([string]$Name)
    $Service = Get-Service $Name -ErrorAction Stop
    $Service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
    Start-Sleep -Seconds 3
    $First = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if ($First.State -ne "Running" -or $First.ProcessId -eq 0) { throw "$Name did not remain Running" }
    Start-Sleep -Seconds 2
    $Second = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if ($Second.State -ne "Running" -or $Second.ProcessId -ne $First.ProcessId) {
        throw "$Name restarted or stopped during the health-settle window"
    }
}
function Get-VedettaServiceCommand {
    param([string]$CommandLine)

    # Accept only the complete command lines emitted by a released Vedetta
    # installer: the historical form left Core/CIDR unquoted, while the current
    # form quotes them. A substring search is unsafe because Go's flag package
    # accepts repeated options (the last --core wins) and stops parsing at the
    # first positional argument. Anchoring the complete argv shape therefore
    # prevents an offline update from mistaking a different effective Core for
    # the first --core-looking substring in ImagePath.
    $Pattern = '^[ \t]*"([^"\r\n]+)"[ \t]+--core[ \t]+(?:"([^"\r\n]+)"|([^" \t\r\n]+))[ \t]+--cidr[ \t]+(?:"([^"\r\n]+)"|([^" \t\r\n]+))[ \t]+--dns[ \t]+--passive-discovery=false[ \t]*$'
    $Match = [regex]::Match($CommandLine, $Pattern)
    if (-not $Match.Success) { return $null }
    $CoreValue = if ($Match.Groups[2].Success) { $Match.Groups[2].Value } else { $Match.Groups[3].Value }
    $CIDRValue = if ($Match.Groups[4].Success) { $Match.Groups[4].Value } else { $Match.Groups[5].Value }
    # Backslash is not a URL path separator, and immediately before the closing
    # quote it changes Windows CommandLineToArgvW parsing. Never treat such a
    # serialized Core value as the logical argv emitted by Vedetta.
    if ($CoreValue.IndexOf('\') -ge 0) { return $null }
    return [pscustomobject]@{
        Executable = $Match.Groups[1].Value
        Core       = $CoreValue
        CIDR       = $CIDRValue
    }
}

# --- Require an already-elevated shell. Re-executing this script through UAC from a
# user-writable path creates a check/use race on the script and its staging inputs. ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Die "run this script from an elevated 64-bit PowerShell (right-click PowerShell, Run as Administrator)"
}
if (-not [Environment]::Is64BitProcess) {
    Die "run this script from 64-bit Windows PowerShell; the amd64 sensor must not be installed through a redirected 32-bit process"
}

# Resolve machine locations through Windows Known Folders, not inherited environment
# variables that an unelevated parent can poison before launching PowerShell.
$ProgramFilesRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$ProgramDataRoot  = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$SystemRootDir    = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
if (-not $ProgramFilesRoot -or -not $ProgramDataRoot -or -not $SystemRootDir) {
    Die "Windows Known Folder resolution failed"
}
$InstallDir = Join-Path $ProgramFilesRoot "Vedetta"
$ExePath    = Join-Path $InstallDir "vedetta-sensor.exe"
$DataDir    = Join-Path $ProgramDataRoot "Vedetta"
$ScExe      = Join-Path $SystemRootDir "sc.exe"

# --- Guards that prevent stranding a sensor (must run before any destructive step) ---
$TokenPath = Join-Path $DataDir "sensor-token"
$PriorTokenFile = [Environment]::GetEnvironmentVariable("VEDETTA_SENSOR_TOKEN_FILE", "Process")
$env:VEDETTA_SENSOR_TOKEN_FILE = $TokenPath
$PreserveTransaction = $false

# Core is eventually serialized into a Windows service command line. The staged
# binary validates URL semantics; reject the one character that could terminate
# our quoting before it ever reaches that check.
if ($Core.IndexOf('"') -ge 0 -or $Core.IndexOf('\') -ge 0 -or
    $Core.IndexOf("`r") -ge 0 -or $Core.IndexOf("`n") -ge 0) {
    Die "-Core contains a quote, backslash, or control character that cannot be represented safely in the service ImagePath"
}
try { $CoreUri = [System.Uri]::new($Core, [System.UriKind]::Absolute) } catch { Die "-Core must be an absolute http:// or https:// URL ($_)" }
if (($CoreUri.Scheme -ne "http" -and $CoreUri.Scheme -ne "https") -or
    -not $CoreUri.Host -or $CoreUri.UserInfo -or $CoreUri.Query -or $CoreUri.Fragment) {
    Die "-Core must be an absolute http:// or https:// URL with a host and without credentials, query, or fragment"
}
if ($EnrollCodeStdin -and $EnrollCode) {
    Die "choose one enrollment-code input mode: the secure prompt, -EnrollCodeStdin, or the deprecated -EnrollCode argument"
}
try { Assert-ReleaseTagValue -Value $Tag } catch { Die "invalid -Tag: $_" }
# Validate or atomically create machine state before downloading, stopping the old
# service, or replacing its binary. A fail-closed path rejection leaves the prior
# installation untouched.
Ensure-VedettaDataDirectory -Path $DataDir
$NeedEnrollmentCode = $Reset -or (-not $NoService -and -not (Test-Path -LiteralPath $TokenPath -PathType Leaf))
if ($EnrollCode) {
    if (-not $AllowInsecureEnrollCodeArgument) {
        Die "-EnrollCode exposes the one-time bearer in PowerShell history and process/audit logs. Omit it and answer the secure prompt (or add -AllowInsecureEnrollCodeArgument only for a controlled legacy automation environment)."
    }
    Write-Warning "-EnrollCode is a deprecated insecure compatibility path; the code may appear in PowerShell history and process/audit logs."
    try { Assert-EnrollmentCodeValue -Code $EnrollCode } catch { Die "invalid enrollment code: $_" }
}

$tmp = Join-Path $DataDir (".install-" + [guid]::NewGuid())
Ensure-VedettaDataDirectory -Path $tmp
try {
    # --- Obtain the binary (caller-supplied, or checksum-verified from a release) ---
    if ($Binary) {
        Info "using caller-supplied binary: $Binary"
        if ($BinarySha256 -notmatch '^[A-Fa-f0-9]{64}$') {
            Die "-Binary requires -BinarySha256 <64-hex SHA-256> so the reviewed file cannot be swapped while elevation is active"
        }
        Copy-Item -LiteralPath $Binary -Destination (Join-Path $tmp "vedetta-sensor.exe") -Force
        $StagedHash = (Get-FileHash -LiteralPath (Join-Path $tmp "vedetta-sensor.exe") -Algorithm SHA256).Hash
        if ($StagedHash -ne $BinarySha256) { Die "caller-supplied binary checksum FAILED" }
    } else {
        if ($BinarySha256) { Die "-BinarySha256 may only be used together with -Binary" }
        # Resolve the release tag. GitHub's /releases/latest EXCLUDES prereleases, so a
        # beta would 404 there; resolve the newest non-draft release that ships the
        # Windows asset instead (or honour an explicit -Tag).
        if ($Tag) {
            Info "verifying published Vedetta release $Tag..."
            $EncodedTag = [System.Uri]::EscapeDataString($Tag)
            try {
                $rel = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$Repo/releases/tags/$EncodedTag"
            } catch {
                Die "could not verify -Tag $Tag as a published Vedetta release ($_)."
            }
            if ($rel.draft -or
                -not [string]::Equals([string]$rel.tag_name, $Tag, [System.StringComparison]::Ordinal) -or
                ($rel.assets.name -notcontains $Asset) -or
                ($rel.assets.name -notcontains "checksums.txt")) {
                Die "-Tag $Tag is not a published Vedetta release containing $Asset and checksums.txt"
            }
            $rtag = [string]$rel.tag_name
        } else {
            Info "resolving the newest release with the Windows asset..."
            try {
                $rels = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$Repo/releases"
            } catch {
                Die "could not query GitHub releases ($_). Retry with network access to api.github.com, or use -Binary with its expected -BinarySha256."
            }
            $rel  = $rels | Where-Object {
                -not $_.draft -and
                ($_.assets.name -contains $Asset) -and
                ($_.assets.name -contains "checksums.txt")
            } | Select-Object -First 1
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
    if (-not (Test-Path -LiteralPath $srcExe -PathType Leaf)) { Die "vedetta-sensor.exe not found after extraction" }
    if (((Get-Item -LiteralPath $srcExe -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Die "the staged sensor binary is a reparse point; refusing to execute it"
    }

    # Snapshot and validate every local object before a one-time enrollment code can be
    # spent. These are read-only operations; failure leaves the old credential and
    # service untouched.
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        # Reuse the exact atomic SYSTEM+Administrators descriptor for a new install
        # directory. Existing beta directories may safely inherit read/execute ACEs
        # from Program Files, so they are accepted only after the no-unprivileged-write
        # audit below rather than rewritten in place.
        Ensure-VedettaDataDirectory -Path $InstallDir
    }
    Assert-NoUnprivilegedWrite -Path $InstallDir -Directory
    $HadBinary = Test-Path -LiteralPath $ExePath -PathType Leaf
    if ((Test-Path -LiteralPath $ExePath) -and -not $HadBinary) {
        Die "$ExePath is not a regular file"
    }
    if ($HadBinary -and (((Get-Item -LiteralPath $ExePath -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Die "$ExePath is a reparse point; refusing to replace it"
    }
    if ($HadBinary) { Assert-NoUnprivilegedWrite -Path $ExePath }
    $BinaryBackup = Join-Path $tmp "previous-sensor.exe"
    if ($HadBinary) { Copy-ProtectedFile -Source $ExePath -Destination $BinaryBackup }

    # Prepare the exact candidate on the destination volume before enrollment. The
    # final promotion is then an atomic same-directory rename/replace, not a partial
    # overwrite of the known-good executable.
    $TxnId = [guid]::NewGuid().ToString("N")
    $CandidatePath = Join-Path $InstallDir (".vedetta-sensor.candidate-$TxnId.exe")
    $PreviousPath = Join-Path $InstallDir (".vedetta-sensor.previous-$TxnId.exe")
    $FailedPath = Join-Path $InstallDir (".vedetta-sensor.failed-$TxnId.exe")
    Copy-ProtectedFile -Source $srcExe -Destination $CandidatePath
    & $CandidatePath --version
    if ($LASTEXITCODE -ne 0) { Die "destination-volume candidate failed its version check (exit $LASTEXITCODE)" }

    $ServiceController = $null
    $OldService = $null
    $NamedService = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($NoService -and $NamedService) {
        Die "$ServiceName already exists; omit -NoService so the installer can stop and update it transactionally"
    }
    if (-not $NoService) { $ServiceController = $NamedService }
    $ServiceExisted = $null -ne $ServiceController
    if ($ServiceExisted) {
        $OldService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        if ($OldService.State -ne "Running" -and $OldService.State -ne "Stopped") {
            Die "$ServiceName is $($OldService.State); wait for a stable Running/Stopped state and retry"
        }
        if ($OldService.StartMode -eq "Disabled") {
            Die "$ServiceName is disabled; enable it explicitly before asking the installer to start an update"
        }
        if ($OldService.StartName -ne "LocalSystem") {
            Die "an unrelated $ServiceName service already exists under account '$($OldService.StartName)'; refusing to overwrite it"
        }
        $OldCommand = Get-VedettaServiceCommand -CommandLine $OldService.PathName
        if (-not $OldCommand) {
            Die "$ServiceName does not have an exact supported Vedetta command line; refusing an update before its rollback target is known"
        }
        $OldServiceExe = [System.IO.Path]::GetFullPath($OldCommand.Executable)
        if (-not [string]::Equals($OldServiceExe, [System.IO.Path]::GetFullPath($ExePath), [System.StringComparison]::OrdinalIgnoreCase)) {
            Die "an unrelated $ServiceName service already points at '$OldServiceExe'; refusing to overwrite it"
        }
        if (-not $HadBinary) { Die "$ServiceName exists but its trusted binary is missing at $ExePath" }
        $OldCoreRaw = $OldCommand.Core
        try { $OldCoreUri = [System.Uri]::new($OldCoreRaw, [System.UriKind]::Absolute) } catch {
            Die "$ServiceName has no parseable --core URL; refusing an update before its rollback target is known"
        }
        $OldCoreNormalized = $OldCoreUri.AbsoluteUri
        $NewCoreNormalized = $CoreUri.AbsoluteUri
        # Fail closed on path case: URI hosts are canonicalized by System.Uri,
        # while reverse-proxy paths can route case-sensitively to different Cores.
        if (-not [string]::Equals($OldCoreNormalized, $NewCoreNormalized, [System.StringComparison]::Ordinal)) {
            Die "changing -Core is a credential migration, not an update; use the existing Core URL or perform a deliberate stopped-service migration"
        }
    }
    $ServiceWasRunning = $ServiceExisted -and $OldService.State -eq "Running"

    # Ask for the short-lived bearer only after the existing service and rollback
    # target have been validated. This keeps the normal Windows flow out of shell
    # history/process arguments and minimizes how long plaintext exists in memory.
    if (-not $EnrollCode -and ($NeedEnrollmentCode -or $EnrollCodeStdin)) {
        try {
            if ($EnrollCodeStdin) {
                $EnrollCode = Read-EnrollmentCodeFromStdin
            } else {
                $EnrollCode = Read-EnrollmentCodePrompt
            }
            Assert-EnrollmentCodeValue -Code $EnrollCode
        } catch {
            Die "could not read the required enrollment code securely: $_"
        }
    }
    if ($Reset -and -not $EnrollCode) {
        Die "-Reset rotates the sensor credential and requires a bound reset code from the secure prompt. Refusing an unguarded reset."
    }
    # A fresh install with neither a code nor an existing token would create a service
    # that can never register. Require a code unless a token is already persisted.
    if (-not $NoService -and -not $EnrollCode -and -not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) {
        Die "no enrollment code and no existing token at $TokenPath. Mint a one-time code in the dashboard and rerun the installer, then enter it at the secure prompt."
    }

    # Validate the exact staged binary, Core URL, token path, and CIDR before touching
    # the known-good binary/service or spending an enrollment code.
    Info "preflight: validating staged sensor configuration"
    $CheckArgs = @("--check", "--core", $Core, "--cidr", $CIDR)
    if (-not $EnrollCode -and (Test-Path -LiteralPath $TokenPath)) { $CheckArgs += "--require-token" }
    & $CandidatePath @CheckArgs
    if ($LASTEXITCODE -ne 0) { Die "staged sensor preflight failed; the existing installation was not changed" }

    $BinaryPromoted = $false
    $ServiceConfigChanged = $false
    $ServiceCreated = $false
    $EnrollmentAttempted = $false
    $EnrollmentUsable = $false
    try {
        # A bound enrollment code can rotate the old process's in-memory bearer (even
        # when the operator omitted -Reset after losing the local token). Stop a running
        # service before spending any code; every failure below restarts the old binary,
        # which reloads whichever credential is safely persisted on disk.
        if ($EnrollCode -and $ServiceWasRunning) {
            Stop-VedettaServiceChecked -Name $ServiceName
        }

        # Enroll from protected staging before binary/config mutation. Reset is one
        # guarded preflight+rotation action; never delete the working token with a bare
        # --reset.
        if ($EnrollCode) {
            Info "enrolling with Core (one-time code, kept out of the service configuration)"
            $env:VEDETTA_ENROLL_CODE = $EnrollCode
            try {
                $EnrollArgs = @("--enroll-only", "--core", $Core, "--cidr", $CIDR)
                if ($Reset) { $EnrollArgs = @("--reset") + $EnrollArgs }
                $EnrollmentAttempted = $true
                & $CandidatePath @EnrollArgs
                $rc = $LASTEXITCODE
            } finally {
                Remove-Item Env:\VEDETTA_ENROLL_CODE -ErrorAction SilentlyContinue
            }
            if ($rc -ne 0) { throw "enrollment failed (exit $rc); check the code, -Core, and connectivity" }
            if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf) -or (Get-Item -LiteralPath $TokenPath).Length -le 0) {
                throw "enrollment returned success but did not persist a non-empty token at $TokenPath"
            }
            & $CandidatePath --check --require-token --core $Core --cidr $CIDR
            if ($LASTEXITCODE -ne 0) { throw "the newly enrolled credential failed preflight" }
            $EnrollmentUsable = $true
        }

        Info "installing to $ExePath"
        if (-not $NoService) {
            Stop-VedettaServiceChecked -Name $ServiceName
        }
        # Arm rollback before the atomic filesystem call. A terminating error or
        # catchable interruption can occur after Windows commits the rename but
        # before PowerShell reaches the next statement. If the call fails with
        # the source still present and no destination-side evidence, disarm the
        # flag so a clean no-op failure does not replace an untouched old binary.
        $BinaryPromoted = $true
        try {
            if ($HadBinary) {
                [System.IO.File]::Replace($CandidatePath, $ExePath, $PreviousPath, $true)
            } else {
                [System.IO.File]::Move($CandidatePath, $ExePath)
            }
        } catch {
            if ($HadBinary) {
                if ((Test-Path -LiteralPath $CandidatePath -PathType Leaf) -and
                    -not (Test-Path -LiteralPath $PreviousPath)) {
                    $BinaryPromoted = $false
                }
            } elseif ((Test-Path -LiteralPath $CandidatePath -PathType Leaf) -and
                -not (Test-Path -LiteralPath $ExePath)) {
                $BinaryPromoted = $false
            }
            throw
        }
        Assert-NoUnprivilegedWrite -Path $ExePath
        & $ExePath --version
        if ($LASTEXITCODE -ne 0) { throw "installed sensor failed its version check (exit $LASTEXITCODE)" }

        if ($NoService) {
            Info "OK: binary installed (service skipped: -NoService)"
            Write-Host "    run it (elevated): `"$ExePath`" --core $Core --cidr $CIDR --dns"
            return
        }

        # No enrollment secret is placed in the service command line.
        Info "configuring the $ServiceName service"
        $bin = "`"$ExePath`" --core `"$Core`" --cidr `"$CIDR`" --dns --passive-discovery=false"
        $desc = "Vedetta network security sensor (DNS via ETW, native discovery)"
        if ($ServiceExisted) {
            # Preserve startup mode, display name, account, description, and recovery
            # policy. Only the command line is part of this update transaction.
            # Treat the SCM state as ambiguous before the typed Change call: the
            # mutation can succeed even if its follow-up verification query fails.
            # Rollback must restore the known-good PathName in either case.
            $ServiceConfigChanged = $true
            Set-VedettaServiceCommandLineChecked -Name $ServiceName -CommandLine $bin -Action "updating $ServiceName"
        } else {
            New-Service -Name $ServiceName -BinaryPathName $bin -DisplayName "Vedetta Sensor" -StartupType Automatic -Description $desc | Out-Null
            $ServiceCreated = $true
            Invoke-ScChecked -Arguments @("failure", $ServiceName, "reset=", "86400", "actions=", "restart/10000") -Action "setting $ServiceName recovery"
        }
        Start-Service $ServiceName -ErrorAction Stop
        Assert-VedettaServiceStable -Name $ServiceName

        Info "OK: one service PID remained stable ($((Get-Service $ServiceName).Status))"
        Write-Host ""
        Info "Installation complete. Manage with:  Get-Service $ServiceName  /  Stop-Service $ServiceName"
        Write-Host "    Token: $DataDir\sensor-token   Log: $DataDir\sensor.log   (SYSTEM + Administrators only)."
    } catch {
        $InstallError = $_.Exception.Message
        $RollbackErrors = @()
        $ServiceStopped = $NoService

        if (-not $NoService -and ($BinaryPromoted -or $ServiceConfigChanged -or $ServiceCreated)) {
            try {
                Stop-VedettaServiceChecked -Name $ServiceName
                $ServiceStopped = $true
            } catch { $RollbackErrors += "stop failed: $($_.Exception.Message)" }
        }

        if (-not $NoService -and $ServiceCreated -and (Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
            try {
                Invoke-ScChecked -Arguments @("delete", $ServiceName) -Action "removing failed new service"
                for ($i = 0; $i -lt 20 -and (Get-Service $ServiceName -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 250 }
                if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { throw "$ServiceName was marked for deletion but remains present" }
            } catch { $RollbackErrors += "new-service removal failed: $($_.Exception.Message)" }
        }

        if (-not $NoService -and $ServiceExisted -and $ServiceConfigChanged) {
            try {
                Set-VedettaServiceCommandLineChecked -Name $ServiceName -CommandLine $OldService.PathName -Action "restoring $ServiceName command line"
            } catch { $RollbackErrors += "service configuration restore failed: $($_.Exception.Message)" }
        }

        if ($BinaryPromoted -and $ServiceStopped) {
            try {
                if ($HadBinary) {
                    if (Test-Path -LiteralPath $PreviousPath -PathType Leaf) {
                        if (Test-Path -LiteralPath $ExePath -PathType Leaf) {
                            [System.IO.File]::Replace($PreviousPath, $ExePath, $FailedPath, $true)
                        } else {
                            [System.IO.File]::Move($PreviousPath, $ExePath)
                        }
                    } else {
                        if (Test-Path -LiteralPath $ExePath) { Remove-Item -LiteralPath $ExePath -Force -ErrorAction Stop }
                        Copy-ProtectedFile -Source $BinaryBackup -Destination $ExePath
                    }
                } else {
                    if (Test-Path -LiteralPath $ExePath) { Remove-Item -LiteralPath $ExePath -Force -ErrorAction Stop }
                }
            } catch { $RollbackErrors += "binary restore failed: $($_.Exception.Message)" }
        } elseif ($BinaryPromoted) {
            $RollbackErrors += "binary restore skipped because the service could not be stopped safely"
        }

        if (-not $NoService -and $ServiceExisted -and $ServiceWasRunning) {
            try {
                if ((Get-Service $ServiceName -ErrorAction Stop).Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
                    Start-Service $ServiceName -ErrorAction Stop
                }
                Assert-VedettaServiceStable -Name $ServiceName
            } catch { $RollbackErrors += "prior running state restore failed: $($_.Exception.Message)" }
        }

        if ($RollbackErrors.Count -gt 0) {
            $PreserveTransaction = $true
            Die "installation failed ($InstallError) AND rollback was incomplete ($($RollbackErrors -join '; ')); protected recovery files remain at $tmp and $InstallDir"
        }
        if ($EnrollmentAttempted -and -not $EnrollmentUsable) {
            Die "installation failed ($InstallError); prior binary/service configuration and running state were restored, but Core may have consumed the enrollment code. Retry the same code promptly for idempotent recovery, or mint a fresh bound reset code."
        }
        if ($EnrollmentUsable) {
            Die "installation failed ($InstallError); prior binary/service configuration and running state were restored and the newly persisted credential was retained"
        }
        Die "installation failed ($InstallError); prior binary/service state restored"
    }
} finally {
    Remove-Item Env:\VEDETTA_ENROLL_CODE -ErrorAction SilentlyContinue
    $EnrollCode = ""
    if ($null -eq $PriorTokenFile) {
        Remove-Item Env:\VEDETTA_SENSOR_TOKEN_FILE -ErrorAction SilentlyContinue
    } else {
        $env:VEDETTA_SENSOR_TOKEN_FILE = $PriorTokenFile
    }
    if (-not $PreserveTransaction) {
        foreach ($Path in @($CandidatePath, $PreviousPath, $FailedPath)) {
            if ($Path) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue }
        }
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
