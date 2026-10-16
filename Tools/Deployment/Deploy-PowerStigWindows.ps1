#Requires -Version 5.1
# Last modified: 2026-10-14

<#+
.SYNOPSIS
    Detects the local Windows edition and applies the matching PowerStig baseline.
.DESCRIPTION
    Supports Windows Server 2019, 2022, and 2025 plus Windows 10 and 11.
    Produces a text log, PowerShell transcript, JSON summary, and compiled MOF.
    Keep this file together with PowerStig.Windows.Common.psm1.
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
    Directory for generated MOF files.
.PARAMETER LogRoot
    Directory for detailed logs and JSON summaries.
.EXAMPLE
    .\Deploy-PowerStigWindows.ps1 -ModuleRoot C:\Baseline\Modules -StageModulesForDsc -WhatIf
.EXAMPLE
    .\Deploy-PowerStigWindows.ps1 -Target WindowsServer2025 -ServerRole MS -ModuleRoot C:\Baseline\Modules -StageModulesForDsc -ConfigureExecutionPolicy
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
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

$deploymentWhatIf = [bool] $PSBoundParameters['WhatIf']
$WhatIfPreference = $false
if ([string]::IsNullOrWhiteSpace($OutputRoot))
{
    $OutputRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Artifacts'
}
if ([string]::IsNullOrWhiteSpace($LogRoot))
{
    $LogRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Logs'
}
if ([string]::IsNullOrWhiteSpace($DscModuleRoot))
{
    $DscModuleRoot = Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsPowerShell\Modules'
}

function Write-DeploymentLog
{
    param([string] $Level, [string] $Message)

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    Add-Content -LiteralPath $script:TextLogPath -Value $line -Encoding UTF8
    Write-Host $line
}

$logAction = { param($Level, $Message) Write-DeploymentLog -Level $Level -Message $Message }
New-Item -Path $OutputRoot -ItemType Directory -Force | Out-Null
New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
$runId = '{0}-{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss')
$script:TextLogPath = Join-Path -Path $LogRoot -ChildPath "Deploy-PowerStig-$runId.log"
$transcriptPath = Join-Path -Path $LogRoot -ChildPath "Deploy-PowerStig-$runId.transcript.log"
$summaryPath = Join-Path -Path $LogRoot -ChildPath "Deploy-PowerStig-$runId.summary.json"
$summary = [ordered]@{
    SchemaVersion = 1
    ModifiedDate = '2026-10-14'
    RunId = $runId
    ComputerName = $env:COMPUTERNAME
    StartedAt = (Get-Date).ToUniversalTime().ToString('o')
    CompletedAt = $null
    Succeeded = $false
    InDesiredState = $false
    Applied = $false
    RebootRequested = $false
    WhatIf = $deploymentWhatIf
    Target = $null
    Module = $null
    DscModulesStaged = $false
    DscModuleRoot = $DscModuleRoot
    ExecutionPolicy = $null
    MofPath = $null
    OrgSettingsPath = $null
    TextLog = $script:TextLogPath
    Transcript = $transcriptPath
    Error = $null
}

Start-Transcript -LiteralPath $transcriptPath -Force | Out-Null
try
{
    Write-DeploymentLog -Level INFO -Message 'Starting PowerStig Windows deployment.'
    Assert-PowerStigAdministrator
    Write-DeploymentLog -Level INFO -Message "PowerShell $($PSVersionTable.PSVersion), edition $($PSVersionTable.PSEdition), elevated administrator confirmed."
    $summary.ExecutionPolicy = Initialize-PowerStigDscExecutionPolicy -Configure ($ConfigureExecutionPolicy.IsPresent -and -not $deploymentWhatIf) -Required (-not $deploymentWhatIf) -Log $logAction

    $targetInfo = Get-PowerStigWindowsTarget -RequestedTarget $Target -RequestedServerRole $ServerRole
    $summary.Target = $targetInfo
    Write-DeploymentLog -Level INFO -Message "Detected '$($targetInfo.ActualCaption)' version $($targetInfo.ActualVersion)."
    Write-DeploymentLog -Level INFO -Message "Selected $($targetInfo.Technology) $($targetInfo.OsVersion) role '$($targetInfo.ServerRole)' STIG $($targetInfo.StigVersion)."

    $module = Import-PowerStigDeploymentModule -RequestedModuleRoot $ModuleRoot -DownloadDependencies $InstallDependencies.IsPresent -ScriptRoot $PSScriptRoot -Log $logAction
    $summary.Module = @{ Name = $module.Name; Version = [string] $module.Version; Path = $module.Path }
    if ($StageModulesForDsc)
    {
        Install-PowerStigDscModule -PowerStigModule $module -DestinationRoot $DscModuleRoot -Log $logAction
        $summary.DscModulesStaged = $true
    }
    else
    {
        Write-DeploymentLog -Level WARN -Message "DSC modules were not staged. Ensure PowerStig and dependencies exist in '$DscModuleRoot', or use -StageModulesForDsc."
    }

    if ($OrgSettingsPath)
    {
        $OrgSettingsPath = (Resolve-Path -LiteralPath $OrgSettingsPath).Path
        $summary.OrgSettingsPath = $OrgSettingsPath
        Write-DeploymentLog -Level INFO -Message "Using organization settings: $OrgSettingsPath"
    }
    else
    {
        Write-DeploymentLog -Level INFO -Message 'Using built-in login defaults: full DoD notice, caption, and administrator credential prompt. Other empty organization values remain skipped.'
    }

    Assert-PowerStigTargetAvailable -Target $targetInfo
    $configurationPath = Join-Path -Path $OutputRoot -ChildPath $runId
    Write-DeploymentLog -Level INFO -Message "Compiling reference configuration to $configurationPath"
    $compileOutput = @(New-PowerStigWindowsMof -Target $targetInfo -OrgSettingsPath $OrgSettingsPath -OutputPath $configurationPath *>&1)
    foreach ($outputItem in $compileOutput)
    {
        $level = if ($outputItem -is [Management.Automation.WarningRecord]) { 'WARN' } else { 'INFO' }
        Write-DeploymentLog -Level $level -Message ([string] $outputItem)
    }
    $mofPath = Join-Path -Path $configurationPath -ChildPath 'localhost.mof'
    $summary.MofPath = $mofPath

    if ($deploymentWhatIf)
    {
        Write-DeploymentLog -Level WARN -Message "WHATIF: DSC configuration was compiled but will not be applied to $env:COMPUTERNAME."
    }
    elseif ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Apply $($targetInfo.Target) STIG $($targetInfo.StigVersion)"))
    {
        Write-DeploymentLog -Level INFO -Message 'Applying DSC configuration. Resource-level verbose output follows.'
        Start-DscConfiguration -Path $configurationPath -Wait -Force -Verbose -ErrorAction Stop *>&1 |
            ForEach-Object { Write-DeploymentLog -Level INFO -Message ([string] $PSItem) }
        $summary.Applied = $true

        Write-DeploymentLog -Level INFO -Message 'Running post-deployment DSC compliance test.'
        $testOutput = @(Test-DscConfiguration -ReferenceConfiguration $mofPath -Verbose -ErrorAction Stop *>&1)
        foreach ($outputItem in $testOutput)
        {
            Write-DeploymentLog -Level INFO -Message ([string] $outputItem)
        }
        $testResult = $testOutput |
            Where-Object { $PSItem -is [bool] -or $null -ne $PSItem.PSObject.Properties['InDesiredState'] } |
            Select-Object -Last 1
        if ($null -eq $testResult)
        {
            throw 'Test-DscConfiguration did not return a reference compliance result.'
        }
        $summary.InDesiredState = if ($testResult -is [bool]) { [bool] $testResult } else { [bool] $testResult.InDesiredState }
        if ($testResult -isnot [bool])
        {
            $testedResources = @($testResult.ResourcesInDesiredState) + @($testResult.ResourcesNotInDesiredState)
            $rebootResources = @(
                $testedResources | Where-Object {
                    $null -ne $PSItem -and
                    $null -ne $PSItem.PSObject.Properties['RebootRequested'] -and
                    [bool] $PSItem.RebootRequested
                }
            )
            $summary.RebootRequested = $rebootResources.Count -gt 0
        }
        if (-not $summary.InDesiredState)
        {
            throw 'Deployment completed, but the post-deployment compliance test is not in the desired state. Review the detailed log.'
        }
    }
    else
    {
        Write-DeploymentLog -Level WARN -Message 'Deployment confirmation was declined. The MOF was compiled only.'
    }

    $summary.Succeeded = $true
    Write-DeploymentLog -Level INFO -Message 'PowerStig deployment completed successfully.'
}
catch
{
    $summary.Error = $PSItem.Exception.Message
    Write-DeploymentLog -Level ERROR -Message $summary.Error
    throw
}
finally
{
    $summary.CompletedAt = (Get-Date).ToUniversalTime().ToString('o')
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-DeploymentLog -Level INFO -Message "JSON summary: $summaryPath"
    Write-DeploymentLog -Level INFO -Message "Transcript: $transcriptPath"
    Stop-Transcript | Out-Null
}
