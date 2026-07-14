#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Installer,
    [Parameter(Mandatory = $true)]
    [string]$SensorBinary
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

if ($env:GITHUB_ACTIONS -ne "true") {
    throw "This destructive service-install smoke test is restricted to an ephemeral GitHub Actions runner."
}
if (-not [Environment]::Is64BitProcess) {
    throw "The Windows installer smoke test requires 64-bit Windows PowerShell 5.1."
}

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "The GitHub Actions runner is not elevated; Windows service smoke tests cannot run."
}

$Installer = (Resolve-Path -LiteralPath $Installer).Path
$SensorBinary = (Resolve-Path -LiteralPath $SensorBinary).Path
$SensorRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
$PowerShellExe = Join-Path $PSHOME "powershell.exe"
$SystemDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$ProgramFilesRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$ProgramDataRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$ScExe = Join-Path $SystemDir "sc.exe"
$ServiceName = "VedettaSensor"
$InstallDir = Join-Path $ProgramFilesRoot "Vedetta"
$ExePath = Join-Path $InstallDir "vedetta-sensor.exe"
$DataDir = Join-Path $ProgramDataRoot "Vedetta"
$TokenPath = Join-Path $DataDir "sensor-token"
$CoreURL = $null
$CoreProcess = $null
$WorkDir = Join-Path $env:RUNNER_TEMP ("vedetta-windows-smoke-" + ([guid]::NewGuid()).ToString("N"))

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -ne $Expected) {
        throw "$Message (actual='$Actual', expected='$Expected')"
    }
}

function Get-FileSha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Get-VedettaServiceState {
    $Service = Get-Service $ServiceName -ErrorAction Stop
    $Cim = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    return [pscustomobject]@{
        Status = [string]$Service.Status
        ProcessId = [uint32]$Cim.ProcessId
        PathName = [string]$Cim.PathName
    }
}

function Set-SmokeServiceCommandLine {
    param([string]$CommandLine)
    $Service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    $Result = Invoke-CimMethod -InputObject $Service -MethodName Change -Arguments @{ PathName = $CommandLine } -ErrorAction Stop
    Assert-Equal ([uint32]$Result.ReturnValue) ([uint32]0) "smoke fixture could not change service command line"
    Assert-Equal (Get-VedettaServiceState).PathName $CommandLine "smoke fixture command line did not persist exactly"
}

function Invoke-InstallerChild {
    param([string[]]$Arguments, [string]$PromptInput = "")
    $ProcessArguments = @(
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $Installer
    ) + $Arguments
    $PreviousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 wraps every native stderr line in a non-terminating
        # NativeCommandError. The real sensor logs readiness on stderr, so the
        # harness must capture those lines without its global Stop policy aborting
        # before LASTEXITCODE can be inspected.
        $ErrorActionPreference = "Continue"
        if ($PromptInput) {
            $ProcessArguments = @("-NonInteractive") + $ProcessArguments + @("-EnrollCodeStdin")
            Assert-True (-not (($ProcessArguments -join " ").Contains($PromptInput))) "prompt secret appeared in installer argv"
            $Lines = @($PromptInput | & $PowerShellExe @ProcessArguments 2>&1)
        } else {
            $ProcessArguments = @("-NonInteractive") + $ProcessArguments
            $Lines = @(& $PowerShellExe @ProcessArguments 2>&1)
        }
        $ExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
    }
    foreach ($Line in $Lines) { Write-Host "[installer] $Line" }
    return [pscustomobject]@{ ExitCode = $ExitCode; Output = ($Lines -join "`n") }
}

function Wait-ServiceAbsent {
    for ($i = 0; $i -lt 40; $i++) {
        if (-not (Get-Service $ServiceName -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "$ServiceName remained registered after deletion"
}

function Remove-SmokeInstallation {
    $Service = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($Service) {
        try {
            if ($Service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                Stop-Service $ServiceName -Force -ErrorAction Stop
                $Service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(25))
            }
        } catch {
            $Cim = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if ($Cim -and $Cim.ProcessId -ne 0) {
                Stop-Process -Id $Cim.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
        & $ScExe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "could not delete $ServiceName during smoke cleanup" }
        Wait-ServiceAbsent
    }
    foreach ($Path in @($InstallDir, $DataDir)) {
        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        }
    }
}

function Build-GoFixture {
    param([string]$Output, [string]$Package, [string]$Ldflags = "")
    Push-Location $SensorRoot
    try {
        $Arguments = @("build", "-trimpath")
        if ($Ldflags) { $Arguments += @("-ldflags", $Ldflags) }
        $Arguments += @("-o", $Output, $Package)
        & go @Arguments
        if ($LASTEXITCODE -ne 0) { throw "go build failed for $Package (exit $LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
}

New-Item -ItemType Directory -Path $WorkDir | Out-Null
try {
    Remove-SmokeInstallation

    Write-Host "== unsafe release tags fail before download or mutation =="
    foreach ($UnsafeTag in @(
        "../../../../attacker/repo/releases/download/v1",
        "%2e%2e%2f%2e%2e%2fattacker%2frepo%2freleases%2fdownload%2fv1"
    )) {
        $UnsafeTagResult = Invoke-InstallerChild -Arguments @(
            "-Core", "http://127.0.0.1:9",
            "-CIDR", "192.0.2.1/32",
            "-Tag", $UnsafeTag,
            "-NoService",
            "-Binary", $SensorBinary,
            "-BinarySha256", (Get-FileSha256 $SensorBinary)
        )
        Assert-True ($UnsafeTagResult.ExitCode -ne 0) "unsafe release tag was accepted: $UnsafeTag"
        Assert-True ($UnsafeTagResult.Output -match "invalid -Tag") "unsafe release tag did not fail at the local validation gate"
        Assert-True (-not (Test-Path -LiteralPath $InstallDir)) "unsafe release tag mutated the install directory"
        Assert-True (-not (Test-Path -LiteralPath $DataDir)) "unsafe release tag mutated the data directory"
        Assert-True (-not (Get-Service $ServiceName -ErrorAction SilentlyContinue)) "unsafe release tag registered a service"
    }

    Write-Host "== Core backslashes fail before service argument serialization =="
    $BackslashCoreResult = Invoke-InstallerChild -Arguments @(
        "-Core", "http://127.0.0.1:9/bad\path",
        "-CIDR", "192.0.2.1/32",
        "-NoService",
        "-Binary", $SensorBinary,
        "-BinarySha256", (Get-FileSha256 $SensorBinary)
    )
    Assert-True ($BackslashCoreResult.ExitCode -ne 0) "Core URL containing a backslash was accepted"
    Assert-True ($BackslashCoreResult.Output -match "quote, backslash, or control") "unsafe Core did not fail at the local serialization gate"
    Assert-True (-not (Test-Path -LiteralPath $InstallDir)) "unsafe Core mutated the install directory"
    Assert-True (-not (Test-Path -LiteralPath $DataDir)) "unsafe Core mutated the data directory"
    Assert-True (-not (Get-Service $ServiceName -ErrorAction SilentlyContinue)) "unsafe Core registered a service"

    $FakeCore = Join-Path $WorkDir "fake-core.exe"
    $FailedService = Join-Path $WorkDir "failed-service.exe"
    $UpdatedSensor = Join-Path $WorkDir "vedetta-sensor-update.exe"
    Build-GoFixture -Output $FakeCore -Package ".\deploy\testdata\windows-smoke\fakecore"
    Build-GoFixture -Output $FailedService -Package ".\deploy\testdata\windows-smoke\failservice"
    Build-GoFixture -Output $UpdatedSensor -Package ".\cmd\vedetta-sensor" -Ldflags "-s -w -X main.buildVersion=ci-windows-smoke-update"

    Assert-True (Test-Path -LiteralPath $FakeCore -PathType Leaf) "fake Core fixture did not build"
    Assert-True (Test-Path -LiteralPath $FailedService -PathType Leaf) "failed-service fixture did not build"
    Assert-True (Test-Path -LiteralPath $UpdatedSensor -PathType Leaf) "updated real sensor did not build"
    Assert-True ((Get-FileSha256 $SensorBinary) -ne (Get-FileSha256 $UpdatedSensor)) "fresh and update sensor binaries must differ"

    $AddressFile = Join-Path $WorkDir "core-address.txt"
    $env:VEDETTA_SMOKE_ADDRESS_FILE = $AddressFile
    $env:VEDETTA_SMOKE_LISTEN = "127.0.0.1:0"
    $CoreProcess = Start-Process -FilePath $FakeCore -PassThru `
        -RedirectStandardOutput (Join-Path $WorkDir "fake-core.stdout.log") `
        -RedirectStandardError (Join-Path $WorkDir "fake-core.stderr.log")
    for ($i = 0; $i -lt 100 -and -not (Test-Path -LiteralPath $AddressFile); $i++) {
        $CoreProcess.Refresh()
        if ($CoreProcess.HasExited) { throw "fake Core exited before publishing its address" }
        Start-Sleep -Milliseconds 100
    }
    Assert-True (Test-Path -LiteralPath $AddressFile -PathType Leaf) "fake Core did not publish its address"
    $CoreURL = "http://$(([System.IO.File]::ReadAllText($AddressFile)).Trim())"
    $CoreReady = $false
    for ($i = 0; $i -lt 50; $i++) {
        try {
            $Response = Invoke-WebRequest -UseBasicParsing -Uri "$CoreURL/healthz" -TimeoutSec 2
            if ($Response.StatusCode -eq 200) { $CoreReady = $true; break }
        } catch {
            if ($i -eq 49) { throw }
            Start-Sleep -Milliseconds 100
        }
    }
    Assert-True $CoreReady "fake Core did not become healthy"

    $CIDR = "192.0.2.1/32"
    Write-Host "== fresh install with the real Windows sensor =="
    $FreshResult = Invoke-InstallerChild -Arguments @(
        "-Core", $CoreURL,
        "-CIDR", $CIDR,
        "-Binary", $SensorBinary,
        "-BinarySha256", (Get-FileSha256 $SensorBinary)
    ) -PromptInput "smoke-fresh-code"
    Assert-Equal $FreshResult.ExitCode 0 "fresh installer invocation failed"
    Assert-True (-not $FreshResult.Output.Contains("smoke-fresh-code")) "fresh enrollment code leaked into installer output"
    $FreshState = Get-VedettaServiceState
    $ExpectedPathName = "`"$ExePath`" --core `"$CoreURL`" --cidr `"$CIDR`" --dns --passive-discovery=false"
    Assert-Equal $FreshState.Status "Running" "fresh service is not running"
    Assert-True ($FreshState.ProcessId -ne 0) "fresh service has no PID"
    Assert-Equal (Get-FileSha256 $ExePath) (Get-FileSha256 $SensorBinary) "fresh binary hash mismatch"
    Assert-Equal ([System.IO.File]::ReadAllText($TokenPath).Trim()) "smoke-token-v1" "fresh token mismatch"
    Assert-True (-not $FreshState.PathName.Contains("smoke-fresh-code")) "enrollment code leaked into service ImagePath"
    Assert-Equal $FreshState.PathName $ExpectedPathName "fresh service command line mismatch"

    Write-Host "== successful update accepts the historical unquoted Core/CIDR shape =="
    $HistoricalPathName = "`"$ExePath`" --core $CoreURL --cidr $CIDR --dns --passive-discovery=false"
    Set-SmokeServiceCommandLine -CommandLine $HistoricalPathName
    $FreshTokenHash = Get-FileSha256 $TokenPath
    $UpdateResult = Invoke-InstallerChild -Arguments @(
        "-Core", $CoreURL,
        "-CIDR", $CIDR,
        "-Binary", $UpdatedSensor,
        "-BinarySha256", (Get-FileSha256 $UpdatedSensor)
    )
    Assert-Equal $UpdateResult.ExitCode 0 "running-service update failed"
    $UpdatedState = Get-VedettaServiceState
    Assert-Equal $UpdatedState.Status "Running" "updated service is not running"
    Assert-True ($UpdatedState.ProcessId -ne 0) "updated service has no PID"
    Assert-Equal (Get-FileSha256 $ExePath) (Get-FileSha256 $UpdatedSensor) "updated binary hash mismatch"
    Assert-Equal (Get-FileSha256 $TokenPath) $FreshTokenHash "ordinary update changed the token"
    Assert-Equal $UpdatedState.PathName $ExpectedPathName "ordinary update did not retain the exact service command line"

    Write-Host "== ambiguous prior command lines fail closed while requested Core is offline =="
    $OfflineCoreURL = "http://127.0.0.1:1"
    $AmbiguousCommands = @(
        [pscustomobject]@{
            Name = "duplicate Core override"
            PathName = "`"$ExePath`" --core `"$OfflineCoreURL`" --cidr `"$CIDR`" --dns --passive-discovery=false --core `"$CoreURL`""
        },
        [pscustomobject]@{
            Name = "equals-form Core option"
            PathName = "`"$ExePath`" --core=`"$OfflineCoreURL`" --cidr `"$CIDR`" --dns --passive-discovery=false"
        },
        [pscustomobject]@{
            Name = "pre-Core positional argument"
            PathName = "`"$ExePath`" unexpected-positional --core `"$OfflineCoreURL`" --cidr `"$CIDR`" --dns --passive-discovery=false"
        },
        [pscustomobject]@{
            Name = "unexpected trailing option"
            PathName = "`"$ExePath`" --core `"$OfflineCoreURL`" --cidr `"$CIDR`" --dns --passive-discovery=false --ports"
        },
        [pscustomobject]@{
            Name = "quoted Core containing a backslash"
            PathName = "`"$ExePath`" --core `"http://127.0.0.1:1/bad\path`" --cidr `"$CIDR`" --dns --passive-discovery=false"
        }
    )
    foreach ($Ambiguous in $AmbiguousCommands) {
        Set-SmokeServiceCommandLine -CommandLine $Ambiguous.PathName
        $BeforeAmbiguous = Get-VedettaServiceState
        $BeforeAmbiguousBinary = Get-FileSha256 $ExePath
        $BeforeAmbiguousToken = Get-FileSha256 $TokenPath
        $AmbiguousResult = Invoke-InstallerChild -Arguments @(
            "-Core", $OfflineCoreURL,
            "-CIDR", $CIDR,
            "-Binary", $UpdatedSensor,
            "-BinarySha256", (Get-FileSha256 $UpdatedSensor)
        )
        Assert-True ($AmbiguousResult.ExitCode -ne 0) "$($Ambiguous.Name) unexpectedly passed the update guard"
        Assert-True ($AmbiguousResult.Output -match "exact supported Vedetta command line") "$($Ambiguous.Name) did not fail at the prior-command guard"
        $AfterAmbiguous = Get-VedettaServiceState
        Assert-Equal $AfterAmbiguous.Status "Running" "$($Ambiguous.Name) stopped the prior service"
        Assert-Equal $AfterAmbiguous.ProcessId $BeforeAmbiguous.ProcessId "$($Ambiguous.Name) restarted the prior service"
        Assert-Equal $AfterAmbiguous.PathName $BeforeAmbiguous.PathName "$($Ambiguous.Name) changed ImagePath"
        Assert-Equal (Get-FileSha256 $ExePath) $BeforeAmbiguousBinary "$($Ambiguous.Name) changed the installed binary"
        Assert-Equal (Get-FileSha256 $TokenPath) $BeforeAmbiguousToken "$($Ambiguous.Name) changed the token"
        Set-SmokeServiceCommandLine -CommandLine $ExpectedPathName
    }

    Write-Host "== invalid bound reset preserves all local state =="
    $BeforeInvalid = Get-VedettaServiceState
    $BeforeInvalidBinary = Get-FileSha256 $ExePath
    $BeforeInvalidToken = Get-FileSha256 $TokenPath
    $InvalidResult = Invoke-InstallerChild -Arguments @(
        "-Core", $CoreURL,
        "-CIDR", $CIDR,
        "-Reset",
        "-Binary", $SensorBinary,
        "-BinarySha256", (Get-FileSha256 $SensorBinary)
    ) -PromptInput "smoke-invalid-reset-code"
    Assert-True ($InvalidResult.ExitCode -ne 0) "invalid bound reset unexpectedly succeeded"
    Assert-True (-not $InvalidResult.Output.Contains("smoke-invalid-reset-code")) "reset code leaked into installer output"
    Assert-True ($InvalidResult.Output -match "enrollment failed") "invalid reset did not reach the guarded enrollment failure path"
    $AfterInvalid = Get-VedettaServiceState
    Assert-Equal $AfterInvalid.Status "Running" "invalid reset stopped the prior service"
    Assert-True ($AfterInvalid.ProcessId -ne 0) "invalid reset recovery has no service PID"
    Assert-True ($AfterInvalid.ProcessId -ne $BeforeInvalid.ProcessId) "invalid reset did not restart the service to reload the retained token"
    Start-Sleep -Seconds 1
    $AfterInvalidStable = Get-VedettaServiceState
    Assert-Equal $AfterInvalidStable.ProcessId $AfterInvalid.ProcessId "invalid reset recovery did not keep one stable service PID"
    Assert-Equal $AfterInvalid.PathName $BeforeInvalid.PathName "invalid reset changed ImagePath"
    Assert-Equal (Get-FileSha256 $ExePath) $BeforeInvalidBinary "invalid reset changed the installed binary"
    Assert-Equal (Get-FileSha256 $TokenPath) $BeforeInvalidToken "invalid reset changed the persisted token"

    Write-Host "== failed SCM start restores the prior running service =="
    # Seed a semantically equivalent but byte-distinct Core URL. The failed
    # replacement must restore this exact prior PathName, proving the typed
    # rollback path works rather than merely rewriting the current value.
    $RollbackPathName = "`"$ExePath`" --core `"$CoreURL/`" --cidr `"$CIDR`" --dns --passive-discovery=false"
    Set-SmokeServiceCommandLine -CommandLine $RollbackPathName
    $BeforeRollback = Get-VedettaServiceState
    $BeforeRollbackBinary = Get-FileSha256 $ExePath
    $BeforeRollbackToken = Get-FileSha256 $TokenPath
    $RollbackResult = Invoke-InstallerChild -Arguments @(
        "-Core", $CoreURL,
        "-CIDR", $CIDR,
        "-Binary", $FailedService,
        "-BinarySha256", (Get-FileSha256 $FailedService)
    )
    Assert-True ($RollbackResult.ExitCode -ne 0) "non-service candidate unexpectedly installed"
    Assert-True ($RollbackResult.Output -match "prior binary/service state restored") "failed service did not exercise a complete installer rollback"
    $AfterRollback = Get-VedettaServiceState
    Assert-Equal $AfterRollback.Status "Running" "rollback did not restore a running service"
    Assert-True ($AfterRollback.ProcessId -ne 0) "rollback-restored service has no PID"
    Assert-Equal $AfterRollback.PathName $BeforeRollback.PathName "rollback did not restore ImagePath"
    Assert-Equal $AfterRollback.PathName $RollbackPathName "rollback did not restore the byte-exact prior command line"
    Assert-Equal (Get-FileSha256 $ExePath) $BeforeRollbackBinary "rollback did not restore the prior binary"
    Assert-Equal (Get-FileSha256 $TokenPath) $BeforeRollbackToken "rollback changed the token"

    $TransactionFiles = @(Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ".vedetta-sensor.*.exe" })
    Assert-Equal $TransactionFiles.Count 0 "successful rollback left executable transaction files"
    $StagingDirectories = @(Get-ChildItem -LiteralPath $DataDir -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ".install-*" })
    Assert-Equal $StagingDirectories.Count 0 "successful rollback left protected staging directories"

    Write-Host "OK: Windows installer fresh/update/reset/rollback smoke passed"
} finally {
    $CleanupErrors = @()
    Remove-Item Env:\VEDETTA_SMOKE_ADDRESS_FILE -ErrorAction SilentlyContinue
    Remove-Item Env:\VEDETTA_SMOKE_LISTEN -ErrorAction SilentlyContinue
    try { Remove-SmokeInstallation } catch { $CleanupErrors += "installation cleanup: $($_.Exception.Message)" }
    if ($CoreProcess) {
        try {
            $CoreProcess.Refresh()
            if (-not $CoreProcess.HasExited) {
                Stop-Process -Id $CoreProcess.Id -Force -ErrorAction Stop
                if (-not $CoreProcess.WaitForExit(5000)) { throw "fake Core did not exit after termination" }
            }
        } catch { $CleanupErrors += "fake Core cleanup: $($_.Exception.Message)" }
    }
    try {
        if (Test-Path -LiteralPath $WorkDir) { Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction Stop }
    } catch { $CleanupErrors += "workspace cleanup: $($_.Exception.Message)" }
    if ($CleanupErrors.Count -gt 0) {
        throw "Windows smoke cleanup was incomplete: $($CleanupErrors -join '; ')"
    }
}
