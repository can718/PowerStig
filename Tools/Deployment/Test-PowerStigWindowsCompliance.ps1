#Requires -Version 5.1
# Last modified: 2026-10-14

<#+
.SYNOPSIS
    Tests the local Windows computer against the matching PowerStig baseline.
.DESCRIPTION
    Compiles a fresh reference MOF and exports text, transcript, JSON, and CSV results.
    It does not apply the STIG baseline. It can stage DSC modules and change execution policy
    when those actions are explicitly requested. Keep it with PowerStig.Windows.Common.psm1.
.PARAMETER Target
    Target operating system. Auto detects the local operating system.
.PARAMETER ServerRole
    Windows Server role. Auto maps domain controllers to DC and other servers to MS.
.PARAMETER ModuleRoot
    Optional private PSModulePath root containing PowerStig and dependencies.
.PARAMETER InstallDependencies
    Downloads missing manifest dependencies into ModuleRoot with Save-Module.
.PARAMETER OrgSettingsPath
    Optional path to a customized PowerStig organization settings XML file.
.PARAMETER StageModulesForDsc
    Copies PowerStig and its exact dependencies into the system DSC module path.
.PARAMETER DscModuleRoot
    LCM-visible module root. Defaults to Program Files\WindowsPowerShell\Modules.
.PARAMETER ConfigureExecutionPolicy
    Sets LocalMachine execution policy to RemoteSigned when DSC would otherwise run as Restricted.
.PARAMETER OutputRoot
    Directory for generated reference MOF files.
.PARAMETER LogRoot
    Directory for detailed logs, JSON summaries, and CSV resource results.
.EXAMPLE
    .\Test-PowerStigWindowsCompliance.ps1 -ModuleRoot C:\Baseline\Modules -StageModulesForDsc -ConfigureExecutionPolicy
#>

[CmdletBinding()]
param
(
    [Parameter()]
    [ValidateSet('Auto', 'WindowsServer2019', 'WindowsServer2022', 'WindowsServer2025', 'Windows10', 'Windows11')]
    [string]
    $Target = 'Auto',

    [Parameter()]
    [ValidateSet('Auto', 'MS', 'DC')]
    [string]
    $ServerRole = 'Auto',

    [Parameter()]
    [string]
    $ModuleRoot,

    [Parameter()]
    [switch]
    $InstallDependencies,

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $PSItem -PathType Leaf })]
    [string]
    $OrgSettingsPath,

    [Parameter()]
    [switch]
    $StageModulesForDsc,

    [Parameter()]
    [string]
    $DscModuleRoot,

    [Parameter()]
    [switch]
    $ConfigureExecutionPolicy,

    [Parameter()]
    [string]
    $OutputRoot,

    [Parameter()]
    [string]
    $LogRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'PowerStig.Windows.Common.psm1'
if (-not (Test-Path -LiteralPath $commonModulePath -PathType Leaf))
{
    throw "Required common module was not found: $commonModulePath"
}
Import-Module -Name $commonModulePath -Force

if (Invoke-WindowsPowerShellRelaunch -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters)
{
    exit $LASTEXITCODE
}

if ([string]::IsNullOrWhiteSpace($OutputRoot))
{
    $OutputRoot = Join-Path -Path $PSScriptRoot -ChildPath 'ComplianceArtifacts'
}
if ([string]::IsNullOrWhiteSpace($LogRoot))
{
    $LogRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Logs'
}
if ([string]::IsNullOrWhiteSpace($DscModuleRoot))
{
    $DscModuleRoot = Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsPowerShell\Modules'
}

function Write-ComplianceLog
{
    param([string] $Level, [string] $Message)

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    Add-Content -LiteralPath $script:TextLogPath -Value $line -Encoding UTF8
    Write-Host $line
}

function ConvertTo-DscResourceRecord
{
    param([object] $Resource, [bool] $Desired)

    $resourcePropertyNames = @(Get-Member -InputObject $Resource -MemberType Properties -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    $resourceIdName = $resourcePropertyNames | Where-Object { $PSItem -in 'ResourceId', 'ResourceName' } | Select-Object -First 1
    if (-not $resourceIdName)
    {
        return
    }

    $moduleName = $resourcePropertyNames | Where-Object { $PSItem -eq 'ModuleName' } | Select-Object -First 1
    $moduleVersion = $resourcePropertyNames | Where-Object { $PSItem -eq 'ModuleVersion' } | Select-Object -First 1
    $duration = $resourcePropertyNames | Where-Object { $PSItem -eq 'DurationInSeconds' } | Select-Object -First 1
    $startDate = $resourcePropertyNames | Where-Object { $PSItem -eq 'StartDate' } | Select-Object -First 1
    $rebootRequested = $resourcePropertyNames | Where-Object { $PSItem -eq 'RebootRequested' } | Select-Object -First 1
    $sourceInfo = $resourcePropertyNames | Where-Object { $PSItem -eq 'SourceInfo' } | Select-Object -First 1
    $resourceError = $resourcePropertyNames | Where-Object { $PSItem -eq 'Error' } | Select-Object -First 1

    [pscustomobject]@{
        InDesiredState = $Desired
        ResourceId = if ($resourceIdName) { [string] $Resource.$resourceIdName } else { $null }
        ModuleName = if ($moduleName) { [string] $Resource.$moduleName } else { $null }
        ModuleVersion = if ($moduleVersion) { [string] $Resource.$moduleVersion } else { $null }
        DurationInSeconds = if ($duration) { $Resource.$duration } else { $null }
        StartDate = if ($startDate) { $Resource.$startDate } else { $null }
        RebootRequested = if ($rebootRequested) { $Resource.$rebootRequested } else { $null }
        SourceInfo = if ($sourceInfo) { [string] $Resource.$sourceInfo } else { $null }
        Error = if ($resourceError -and $Resource.$resourceError) { [string] ($Resource.$resourceError | Out-String) } else { $null }
    }
}

$logAction = { param($Level, $Message) Write-ComplianceLog -Level $Level -Message $Message }
New-Item -Path $OutputRoot -ItemType Directory -Force | Out-Null
New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
$runId = '{0}-{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss')
$script:TextLogPath = Join-Path -Path $LogRoot -ChildPath "Test-PowerStig-$runId.log"
$transcriptPath = Join-Path -Path $LogRoot -ChildPath "Test-PowerStig-$runId.transcript.log"
$summaryPath = Join-Path -Path $LogRoot -ChildPath "Test-PowerStig-$runId.summary.json"
$resourceCsvPath = Join-Path -Path $LogRoot -ChildPath "Test-PowerStig-$runId.resources.csv"
$summary = [ordered]@{
    SchemaVersion = 1
    ModifiedDate = '2026-10-14'
    RunId = $runId
    ComputerName = $env:COMPUTERNAME
    StartedAt = (Get-Date).ToUniversalTime().ToString('o')
    CompletedAt = $null
    Succeeded = $false
    InDesiredState = $false
    DesiredResourceCount = 0
    NoncompliantResourceCount = 0
    DetailedResultAvailable = $false
    Target = $null
    Module = $null
    DscModulesStaged = $false
    DscModuleRoot = $DscModuleRoot
    ExecutionPolicy = $null
    ReferenceMof = $null
    OrgSettingsPath = $null
    Resources = @()
    TextLog = $script:TextLogPath
    Transcript = $transcriptPath
    ResourceCsv = $resourceCsvPath
    Error = $null
    FailureStage = $null
    ExceptionType = $null
    ErrorDetails = $null
    ScriptStackTrace = $null
}
$executionErrorRecord = $null
$noncomplianceMessage = $null
$currentStage = 'Initialization'

Start-Transcript -LiteralPath $transcriptPath -Force | Out-Null
try
{
    Write-ComplianceLog -Level INFO -Message 'Starting PowerStig Windows compliance check.'
    Assert-PowerStigAdministrator
    Write-ComplianceLog -Level INFO -Message "PowerShell $($PSVersionTable.PSVersion), edition $($PSVersionTable.PSEdition), elevated administrator confirmed."
    $currentStage = 'ExecutionPolicy'
    $summary.ExecutionPolicy = Initialize-PowerStigDscExecutionPolicy -Configure $ConfigureExecutionPolicy.IsPresent -Required $true -Log $logAction

    $currentStage = 'TargetDetection'
    $targetInfo = Get-PowerStigWindowsTarget -RequestedTarget $Target -RequestedServerRole $ServerRole
    $summary.Target = $targetInfo
    Write-ComplianceLog -Level INFO -Message "Detected '$($targetInfo.ActualCaption)' version $($targetInfo.ActualVersion)."
    Write-ComplianceLog -Level INFO -Message "Selected $($targetInfo.Technology) $($targetInfo.OsVersion) role '$($targetInfo.ServerRole)' STIG $($targetInfo.StigVersion)."

    $currentStage = 'ModuleImport'
    $module = Import-PowerStigDeploymentModule -RequestedModuleRoot $ModuleRoot -DownloadDependencies $InstallDependencies.IsPresent -ScriptRoot $PSScriptRoot -Log $logAction
    $summary.Module = @{ Name = $module.Name; Version = [string] $module.Version; Path = $module.Path }
    if ($StageModulesForDsc)
    {
        $currentStage = 'ModuleStaging'
        Install-PowerStigDscModule -PowerStigModule $module -DestinationRoot $DscModuleRoot -Log $logAction
        $summary.DscModulesStaged = $true
    }
    else
    {
        Write-ComplianceLog -Level WARN -Message "DSC modules were not staged. Ensure PowerStig and dependencies exist in '$DscModuleRoot', or use -StageModulesForDsc."
    }

    if ($OrgSettingsPath)
    {
        $OrgSettingsPath = (Resolve-Path -LiteralPath $OrgSettingsPath).Path
        $summary.OrgSettingsPath = $OrgSettingsPath
        Write-ComplianceLog -Level INFO -Message "Using organization settings: $OrgSettingsPath"
    }
    else
    {
        Write-ComplianceLog -Level WARN -Message 'No OrgSettingsPath was supplied. Rules with empty organization defaults will be skipped by PowerStig.'
    }

    $currentStage = 'TargetValidation'
    Assert-PowerStigTargetAvailable -Target $targetInfo
    $configurationPath = Join-Path -Path $OutputRoot -ChildPath $runId
    Write-ComplianceLog -Level INFO -Message "Compiling compliance reference configuration to $configurationPath"
    $currentStage = 'MofCompilation'
    $compileOutput = @(New-PowerStigWindowsMof -Target $targetInfo -OrgSettingsPath $OrgSettingsPath -OutputPath $configurationPath *>&1)
    foreach ($outputItem in $compileOutput)
    {
        $level = if ($outputItem -is [Management.Automation.WarningRecord]) { 'WARN' } else { 'INFO' }
        Write-ComplianceLog -Level $level -Message ([string] $outputItem)
    }
    $mofPath = Join-Path -Path $configurationPath -ChildPath 'localhost.mof'
    $summary.ReferenceMof = $mofPath

    Write-ComplianceLog -Level INFO -Message 'Testing the generated reference MOF. Resource-level verbose output follows.'
    $currentStage = 'ReferenceComplianceTest'
    $referenceOutput = @(Test-DscConfiguration -ReferenceConfiguration $mofPath -Verbose -ErrorAction Stop *>&1)
    foreach ($outputItem in $referenceOutput)
    {
        Write-ComplianceLog -Level INFO -Message ([string] $outputItem)
    }
    $referenceResult = $referenceOutput |
        Where-Object { $PSItem -is [bool] -or $null -ne $PSItem.PSObject.Properties['InDesiredState'] } |
        Select-Object -Last 1
    if ($null -eq $referenceResult)
    {
        throw 'Test-DscConfiguration did not return a reference compliance result.'
    }

    $referenceInDesiredState = if ($referenceResult -is [bool]) { [bool] $referenceResult } else { [bool] $referenceResult.InDesiredState }
    $detailedResult = if ($null -ne $referenceResult.PSObject.Properties['ResourcesInDesiredState']) { $referenceResult } else { $null }
    if (-not $detailedResult)
    {
        Write-ComplianceLog -Level WARN -Message 'Reference-mode DSC returned only an overall compliance result; per-resource detail is unavailable for this PowerShell version.'
    }

    $currentStage = 'ResultConversion'
    $desiredResources = @()
    $noncompliantResources = @()
    if ($detailedResult)
    {
        $summary.DetailedResultAvailable = $true
        $desiredResources = @($detailedResult.ResourcesInDesiredState | ForEach-Object { ConvertTo-DscResourceRecord -Resource $PSItem -Desired $true } | Where-Object { $null -ne $PSItem })
        $noncompliantResources = @($detailedResult.ResourcesNotInDesiredState | ForEach-Object { ConvertTo-DscResourceRecord -Resource $PSItem -Desired $false } | Where-Object { $null -ne $PSItem })
    }
    $allResources = @($desiredResources + $noncompliantResources)
    $summary.Succeeded = $true
    $summary.InDesiredState = $referenceInDesiredState
    $summary.DesiredResourceCount = $desiredResources.Count
    $summary.NoncompliantResourceCount = $noncompliantResources.Count
    $summary.Resources = $allResources

    if ($allResources.Count -gt 0)
    {
        $allResources | Export-Csv -LiteralPath $resourceCsvPath -NoTypeInformation -Encoding UTF8
    }
    else
    {
        'InDesiredState,ResourceId,ModuleName,ModuleVersion,DurationInSeconds,StartDate,RebootRequested,SourceInfo,Error' |
            Set-Content -LiteralPath $resourceCsvPath -Encoding UTF8
    }
    foreach ($resource in $noncompliantResources)
    {
        Write-ComplianceLog -Level WARN -Message "NONCOMPLIANT: $($resource.ResourceId); module=$($resource.ModuleName) $($resource.ModuleVersion); source=$($resource.SourceInfo); error=$($resource.Error)"
    }

    if ($summary.InDesiredState)
    {
        Write-ComplianceLog -Level INFO -Message "Compliance check passed. $($desiredResources.Count) resources are in the desired state."
    }
    else
    {
        $detailText = if ($summary.DetailedResultAvailable) { "$($noncompliantResources.Count) reference resources are not in the desired state." } else { 'Structured details are unavailable; review the verbose log.' }
        $noncomplianceMessage = "Compliance check failed. $detailText"
        Write-ComplianceLog -Level WARN -Message $noncomplianceMessage
    }
}
catch
{
    $executionErrorRecord = $PSItem
    $summary.Error = $executionErrorRecord.Exception.Message
    $summary.FailureStage = $currentStage
    $summary.ExceptionType = $executionErrorRecord.Exception.GetType().FullName
    $summary.ErrorDetails = [string] $executionErrorRecord
    $summary.ScriptStackTrace = $executionErrorRecord.ScriptStackTrace
    Write-ComplianceLog -Level ERROR -Message "Stage '$currentStage' failed: $($summary.Error)"
    Write-ComplianceLog -Level ERROR -Message "Exception type: $($summary.ExceptionType)"
    if ($summary.ScriptStackTrace)
    {
        Write-ComplianceLog -Level ERROR -Message "Script stack: $($summary.ScriptStackTrace)"
    }
}
finally
{
    $summary.CompletedAt = (Get-Date).ToUniversalTime().ToString('o')
    $summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-ComplianceLog -Level INFO -Message "JSON summary: $summaryPath"
    Write-ComplianceLog -Level INFO -Message "Resource CSV: $resourceCsvPath"
    Write-ComplianceLog -Level INFO -Message "Transcript: $transcriptPath"
    Stop-Transcript | Out-Null
}

if ($executionErrorRecord)
{
    $PSCmdlet.ThrowTerminatingError($executionErrorRecord)
}
if ($noncomplianceMessage)
{
    throw $noncomplianceMessage
}
