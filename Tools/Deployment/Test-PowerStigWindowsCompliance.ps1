#Requires -Version 5.1
# Last modified: 2026-10-20

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
        Error = if ($resourceError -and $Resource.$resourceError) { Protect-ComplianceText $Resource.$resourceError } else { $null }
        ComplianceEvaluation = if ($Desired) { 'DSC' } else { 'DSC reported noncompliant' }
    }
}

function Protect-ComplianceText
{
    param([AllowNull()] [object] $Value)

    if ($null -eq $Value)
    {
        return $null
    }

    $text = [string] ($Value | Out-String)
    $text = $text -replace '(?i)(sig|signature|token|password|pwd|secret|key)=([^&\s;]+)', '$1=[REDACTED]'
    $text = $text -replace '(?i)(SharedAccessSignature\s+)[^\s]+', '$1[REDACTED]'
    return $text.Trim()
}

function Get-PowerStigRuleMetadata
{
    param(
        [Parameter(Mandatory = $true)] [psobject] $Target,
        [Parameter(Mandatory = $true)] [psobject] $Module
    )

    $moduleRoot = Split-Path -Path $Module.Path -Parent
    $rolePart = if ($Target.ServerRole) { "-$($Target.ServerRole)" } else { '' }
    $fileName = '{0}-{1}{2}-{3}.xml' -f $Target.Technology, $Target.OsVersion, $rolePart, $Target.StigVersion
    $stigPath = Join-Path -Path $moduleRoot -ChildPath (Join-Path -Path 'StigData\Processed' -ChildPath $fileName)
    if (-not (Test-Path -LiteralPath $stigPath -PathType Leaf))
    {
        throw "Processed STIG metadata was not found: $stigPath"
    }

    [xml] $stigXml = Get-Content -LiteralPath $stigPath -Raw
    foreach ($rule in @($stigXml.DISASTIG.ChildNodes | ForEach-Object { $PSItem.Rule }))
    {
        if ($null -eq $rule -or [string]::IsNullOrWhiteSpace([string] $rule.id))
        {
            continue
        }

        [pscustomobject]@{
            RuleId = [string] $rule.id
            Title = [string] $rule.title
            Severity = [string] $rule.severity
            DscResource = [string] $rule.dscresource
            ConversionStatus = [string] $rule.conversionstatus
            OrganizationValueRequired = [string] $rule.OrganizationValueRequired -eq 'True'
        }
    }
}

function Get-StigRuleIdFromResourceId
{
    param(
        [Parameter(Mandatory = $true)] [string] $ResourceId,
        [Parameter(Mandatory = $true)] [hashtable] $RuleIndex
    )

    foreach ($match in [regex]::Matches($ResourceId, '\[(V-\d+(?:\.[A-Za-z0-9]+)?)\]'))
    {
        $candidate = $match.Groups[1].Value
        if ($RuleIndex.ContainsKey($candidate))
        {
            return $candidate
        }

        $baseCandidate = $candidate -replace '\.[A-Za-z0-9]+$', ''
        if ($RuleIndex.ContainsKey($baseCandidate))
        {
            return $baseCandidate
        }
    }
    return $null
}

function ConvertTo-StigRuleResults
{
    param(
        [Parameter(Mandatory = $true)] [object[]] $RuleMetadata,
        [Parameter(Mandatory = $true)] [object[]] $Resources,
        [Parameter(Mandatory = $true)] [string] $ModuleName,
        [Parameter(Mandatory = $true)] [string] $ModuleVersion,
        [Parameter(Mandatory = $true)] [string] $SourceInfo,
        [Parameter()] [string] $OrgSettingsPath
    )

    $ruleIndex = @{}
    foreach ($metadata in $RuleMetadata)
    {
        $ruleIndex[$metadata.RuleId] = $metadata
    }

    $organizationRuleIds = @{}
    if ($OrgSettingsPath)
    {
        [xml] $organizationSettings = Get-Content -LiteralPath $OrgSettingsPath -Raw
        foreach ($setting in @($organizationSettings.SelectNodes('//*[@id]')))
        {
            $organizationRuleIds[[string] $setting.id] = $true
        }
    }

    $resourcesByRule = @{}
    foreach ($resource in $Resources)
    {
        $ruleId = Get-StigRuleIdFromResourceId -ResourceId $resource.ResourceId -RuleIndex $ruleIndex
        if (-not $ruleId)
        {
            continue
        }
        if (-not $resourcesByRule.ContainsKey($ruleId))
        {
            $resourcesByRule[$ruleId] = @()
        }
        $resourcesByRule[$ruleId] = @($resourcesByRule[$ruleId]) + $resource
    }

    foreach ($metadata in $RuleMetadata)
    {
        $ruleResources = if ($resourcesByRule.ContainsKey($metadata.RuleId)) { @($resourcesByRule[$metadata.RuleId]) } else { @() }
        $status = 'NotReviewed'
        $reason = $null
        $evaluation = $null

        if ($ruleResources.Count -gt 0)
        {
            $errors = @($ruleResources | Where-Object { -not [string]::IsNullOrWhiteSpace([string] $PSItem.Error) })
            $failed = @($ruleResources | Where-Object {
                -not $PSItem.InDesiredState -and [string]::IsNullOrWhiteSpace([string] $PSItem.Error)
            })
            if ($failed.Count -gt 0)
            {
                $status = 'NonCompliant'
                $reason = Protect-ComplianceText (($failed | ForEach-Object {
                    if ($PSItem.Error) { "$($PSItem.ResourceId): $($PSItem.Error)" } else { "$($PSItem.ResourceId): DSC reported noncompliant" }
                }) -join '; ')
                $evaluation = 'One or more DSC resources reported noncompliant'
            }
            elseif ($errors.Count -gt 0)
            {
                $status = 'Error'
                $reason = Protect-ComplianceText (($errors | ForEach-Object { "$($PSItem.ResourceId): $($PSItem.Error)" }) -join '; ')
                $evaluation = 'DSC resource execution failed; compliance could not be determined'
            }
            else
            {
                $status = 'Compliant'
                $reason = 'All associated DSC resources are in the desired state.'
                $evaluation = (($ruleResources | Select-Object -ExpandProperty ComplianceEvaluation -Unique) -join '; ')
            }
        }
        elseif ($metadata.ConversionStatus -match '^(?i:notapplicable|not_applicable)$')
        {
            $status = 'NotApplicable'
            $reason = 'The processed STIG metadata marks this rule as not applicable.'
            $evaluation = 'Not applicable according to STIG metadata'
        }
        elseif ($metadata.ConversionStatus -match '^(?i:skip|skipped)$')
        {
            $status = 'Skipped'
            $reason = 'The processed STIG metadata marks this rule as skipped.'
            $evaluation = 'Skipped according to STIG metadata'
        }
        elseif ($metadata.OrganizationValueRequired -and -not $organizationRuleIds.ContainsKey($metadata.RuleId))
        {
            $reason = 'Organization configuration is required, but no organization settings file supplied a value for this rule.'
            $evaluation = 'Not reviewed because organization configuration is missing'
        }
        elseif ($metadata.ConversionStatus -ne 'pass')
        {
            $reason = "The rule requires manual review because conversion status is '$($metadata.ConversionStatus)'."
            $evaluation = 'Manual review required'
        }
        else
        {
            $status = 'Skipped'
            $reason = 'The rule did not produce a DSC resource in the compiled reference configuration.'
            $evaluation = 'Skipped during reference configuration compilation'
        }

        [pscustomobject]@{
            RuleId = $metadata.RuleId
            Title = $metadata.Title
            Severity = $metadata.Severity
            Status = $status
            Reason = $reason
            DscResourceIds = @($ruleResources | Select-Object -ExpandProperty ResourceId)
            DscResourceId = if ($ruleResources.Count -gt 0) { [string] $ruleResources[0].ResourceId } else { $null }
            ModuleName = $ModuleName
            ModuleVersion = $ModuleVersion
            SourceInfo = $SourceInfo
            ComplianceEvaluation = $evaluation
        }
    }
}

function Get-IdentitySid
{
    param([object] $IdentityReference)

    try
    {
        return $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch
    {
        return [string] $IdentityReference
    }
}

function Test-WindowsServer2022SystemRegistryAcl
{
    $acl = Get-Acl -Path 'HKLM:\SYSTEM'
    if (-not $acl.AreAccessRulesProtected)
    {
        return $false
    }

    $expected = @{
        'S-1-3-0' = @([int][Security.AccessControl.RegistryRights]::FullControl, 1, 2)
        'S-1-5-11' = @([int][Security.AccessControl.RegistryRights]::ReadKey, 1, 0)
        'S-1-5-18' = @([int][Security.AccessControl.RegistryRights]::FullControl, 1, 0)
        'S-1-5-32-544' = @([int][Security.AccessControl.RegistryRights]::FullControl, 1, 0)
        'S-1-5-32-549' = @([int][Security.AccessControl.RegistryRights]::ReadKey, 1, 0)
        'S-1-15-2-1' = @([int][Security.AccessControl.RegistryRights]::ReadKey, 1, 0)
    }
    $optionalCapabilitySid = 'S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681'
    $seen = @{}

    foreach ($entry in @($acl.Access))
    {
        $sid = Get-IdentitySid -IdentityReference $entry.IdentityReference
        if ($sid -eq $optionalCapabilitySid)
        {
            if ([int] $entry.RegistryRights -ne [int][Security.AccessControl.RegistryRights]::ReadKey -or
                [int] $entry.InheritanceFlags -ne 1 -or [int] $entry.PropagationFlags -ne 0 -or
                $entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $entry.IsInherited)
            {
                return $false
            }
            continue
        }
        if (-not $expected.ContainsKey($sid) -or $seen.ContainsKey($sid))
        {
            return $false
        }

        $required = $expected[$sid]
        if ([int] $entry.RegistryRights -ne $required[0] -or
            [int] $entry.InheritanceFlags -ne $required[1] -or
            [int] $entry.PropagationFlags -ne $required[2] -or
            $entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $entry.IsInherited)
        {
            return $false
        }
        $seen[$sid] = $true
    }

    return $seen.Count -eq $expected.Count
}

function Test-WindowsServer2022SysvolAcl
{
    $acl = Get-Acl -Path (Join-Path -Path $env:windir -ChildPath 'SYSVOL')
    if (-not $acl.AreAccessRulesProtected)
    {
        return $false
    }

    $readAndExecute = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [int][Security.AccessControl.FileSystemRights]::Synchronize
    $fullControl = [int][Security.AccessControl.FileSystemRights]::FullControl
    $expected = @{
        'S-1-3-0' = @(0, $fullControl, $fullControl)
        'S-1-5-11' = @($readAndExecute, $readAndExecute, $readAndExecute)
        'S-1-5-18' = @($fullControl, $fullControl, $fullControl)
        'S-1-5-32-544' = @($fullControl, $fullControl, $fullControl)
        'S-1-5-32-549' = @($readAndExecute, $readAndExecute, $readAndExecute)
    }
    $effective = @{}
    foreach ($sid in $expected.Keys)
    {
        $effective[$sid] = @(0, 0, 0)
    }

    foreach ($entry in @($acl.Access))
    {
        $sid = Get-IdentitySid -IdentityReference $entry.IdentityReference
        if (-not $expected.ContainsKey($sid) -or
            $entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $entry.IsInherited -or
            ($entry.PropagationFlags -band [Security.AccessControl.PropagationFlags]::NoPropagateInherit))
        {
            return $false
        }

        $rights = [int] $entry.FileSystemRights
        if (-not ($entry.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly))
        {
            $effective[$sid][0] = $effective[$sid][0] -bor $rights
        }
        if ($entry.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit)
        {
            $effective[$sid][1] = $effective[$sid][1] -bor $rights
        }
        if ($entry.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit)
        {
            $effective[$sid][2] = $effective[$sid][2] -bor $rights
        }
    }

    foreach ($sid in $expected.Keys)
    {
        if ($effective[$sid][0] -ne $expected[$sid][0] -or
            $effective[$sid][1] -ne $expected[$sid][1] -or
            $effective[$sid][2] -ne $expected[$sid][2])
        {
            return $false
        }
    }
    return $true
}

function Test-WindowsServer2022LdapIntegrity
{
    $key = Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    return $key.GetValueKind('LDAPServerIntegrity') -eq [Microsoft.Win32.RegistryValueKind]::DWord -and
        [int] $key.GetValue('LDAPServerIntegrity') -eq 2
}

function Get-WindowsServer2022ComplianceOverride
{
    param([string] $ResourceId)

    try
    {
        switch -Regex ($ResourceId)
        {
            '\[V-254254\.c\]' {
                if (Test-WindowsServer2022SystemRegistryAcl) { return 'Validated equivalent registry ACL; the optional capability SID may be absent.' }
            }
            '\[V-254392\]' {
                if (Test-WindowsServer2022SysvolAcl) { return 'Validated equivalent SYSVOL effective permissions after Windows ACL normalization.' }
            }
            '\[V-254416\]' {
                if (Test-WindowsServer2022LdapIntegrity) { return 'Validated LDAPServerIntegrity as DWORD 2.' }
            }
        }
    }
    catch
    {
        Write-ComplianceLog -Level WARN -Message "Independent validation failed for ${ResourceId}: $($PSItem.Exception.Message)"
    }
    return $null
}

$logAction = { param($Level, $Message) Write-ComplianceLog -Level $Level -Message $Message }
New-Item -Path $OutputRoot -ItemType Directory -Force | Out-Null
New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
$runId = '{0}-{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss')
$script:TextLogPath = Join-Path -Path $LogRoot -ChildPath "Test-PowerStig-$runId.log"
$transcriptPath = Join-Path -Path $LogRoot -ChildPath "Test-PowerStig-$runId.transcript.log"
$summaryPath = Join-Path -Path $LogRoot -ChildPath "Test-PowerStig-$runId.summary.json"
$resourceCsvPath = Join-Path -Path $LogRoot -ChildPath "Test-PowerStig-$runId.resources.csv"
$ruleCsvPath = Join-Path -Path $LogRoot -ChildPath "Test-PowerStig-$runId.rules.csv"
$summary = [ordered]@{
    SchemaVersion = 3
    ModifiedDate = '2026-10-20'
    RunId = $runId
    ComputerName = $env:COMPUTERNAME
    StartedAt = (Get-Date).ToUniversalTime().ToString('o')
    CompletedAt = $null
    Succeeded = $false
    InDesiredState = $false
    DesiredResourceCount = 0
    NoncompliantResourceCount = 0
    DetailedResultAvailable = $false
    RuleResultsAvailable = $false
    RuleResultsUnavailableReason = 'The compliance test has not completed.'
    TotalRuleCount = 0
    CompliantRuleCount = 0
    NoncompliantRuleCount = 0
    SkippedRuleCount = 0
    NotApplicableRuleCount = 0
    NotReviewedRuleCount = 0
    ErrorRuleCount = 0
    Target = $null
    Module = $null
    DscModulesStaged = $false
    DscModuleRoot = $DscModuleRoot
    ExecutionPolicy = $null
    ReferenceMof = $null
    OrgSettingsPath = $null
    Resources = @()
    RuleResults = @()
    TextLog = $script:TextLogPath
    Transcript = $transcriptPath
    ResourceCsv = $resourceCsvPath
    RuleCsv = $ruleCsvPath
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
        Write-ComplianceLog -Level INFO -Message 'Checking built-in login defaults: full DoD notice, caption, and administrator credential prompt. Other empty organization values remain skipped.'
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
        $summary.RuleResultsUnavailableReason = 'Test-DscConfiguration returned only an overall compliance result; per-resource results required for rule evaluation were unavailable.'
    }

    $currentStage = 'ResultConversion'
    $desiredResources = @()
    $noncompliantResources = @()
    if ($detailedResult)
    {
        $summary.DetailedResultAvailable = $true
        $desiredResources = @($detailedResult.ResourcesInDesiredState | ForEach-Object { ConvertTo-DscResourceRecord -Resource $PSItem -Desired $true } | Where-Object { $null -ne $PSItem })
        $noncompliantResources = @($detailedResult.ResourcesNotInDesiredState | ForEach-Object { ConvertTo-DscResourceRecord -Resource $PSItem -Desired $false } | Where-Object { $null -ne $PSItem })

        if ($targetInfo.Target -eq 'WindowsServer2022' -and $targetInfo.ServerRole -eq 'DC')
        {
            $validatedEquivalentResources = @()
            $remainingNoncompliantResources = @()
            foreach ($resource in $noncompliantResources)
            {
                $evaluation = Get-WindowsServer2022ComplianceOverride -ResourceId $resource.ResourceId
                if ($evaluation)
                {
                    $resource.InDesiredState = $true
                    $resource.ComplianceEvaluation = $evaluation
                    $validatedEquivalentResources += $resource
                    Write-ComplianceLog -Level INFO -Message "EQUIVALENT: $($resource.ResourceId); $evaluation"
                }
                else
                {
                    $remainingNoncompliantResources += $resource
                }
            }
            $desiredResources = @($desiredResources + $validatedEquivalentResources)
            $noncompliantResources = @($remainingNoncompliantResources)
            $referenceInDesiredState = $noncompliantResources.Count -eq 0
        }
    }
    $allResources = @($desiredResources + $noncompliantResources)
    $summary.Succeeded = $true
    $summary.InDesiredState = $referenceInDesiredState
    $summary.DesiredResourceCount = $desiredResources.Count
    $summary.NoncompliantResourceCount = $noncompliantResources.Count
    $summary.Resources = $allResources

    if ($detailedResult)
    {
        $ruleMetadata = @(Get-PowerStigRuleMetadata -Target $targetInfo -Module $module)
        $sourceInfo = '{0}-{1}{2}' -f $targetInfo.Technology, $targetInfo.OsVersion, $(if ($targetInfo.ServerRole) { "-$($targetInfo.ServerRole)" } else { '' })
        $ruleResults = @(ConvertTo-StigRuleResults -RuleMetadata $ruleMetadata -Resources $allResources -ModuleName $module.Name -ModuleVersion ([string] $module.Version) -SourceInfo $sourceInfo -OrgSettingsPath $OrgSettingsPath)
        $summary.RuleResults = $ruleResults
        $summary.RuleResultsAvailable = $true
        $summary.RuleResultsUnavailableReason = $null
        $summary.TotalRuleCount = $ruleResults.Count
        $summary.CompliantRuleCount = @($ruleResults | Where-Object Status -eq 'Compliant').Count
        $summary.NoncompliantRuleCount = @($ruleResults | Where-Object Status -eq 'NonCompliant').Count
        $summary.SkippedRuleCount = @($ruleResults | Where-Object Status -eq 'Skipped').Count
        $summary.NotApplicableRuleCount = @($ruleResults | Where-Object Status -eq 'NotApplicable').Count
        $summary.NotReviewedRuleCount = @($ruleResults | Where-Object Status -eq 'NotReviewed').Count
        $summary.ErrorRuleCount = @($ruleResults | Where-Object Status -eq 'Error').Count
        $ruleResults | Select-Object RuleId, Title, Severity, Status, Reason,
            @{ Name = 'DscResourceIds'; Expression = { $PSItem.DscResourceIds -join ';' } },
            DscResourceId, ModuleName, ModuleVersion, SourceInfo, ComplianceEvaluation |
            Export-Csv -LiteralPath $ruleCsvPath -NoTypeInformation -Encoding UTF8
    }
    else
    {
        'RuleId,Title,Severity,Status,Reason,DscResourceIds,DscResourceId,ModuleName,ModuleVersion,SourceInfo,ComplianceEvaluation' |
            Set-Content -LiteralPath $ruleCsvPath -Encoding UTF8
    }

    if ($allResources.Count -gt 0)
    {
        $allResources | Export-Csv -LiteralPath $resourceCsvPath -NoTypeInformation -Encoding UTF8
    }
    else
    {
        'InDesiredState,ResourceId,ModuleName,ModuleVersion,DurationInSeconds,StartDate,RebootRequested,SourceInfo,Error,ComplianceEvaluation' |
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
    $summary.Error = Protect-ComplianceText $executionErrorRecord.Exception.Message
    $summary.FailureStage = $currentStage
    $summary.ExceptionType = $executionErrorRecord.Exception.GetType().FullName
    $summary.ErrorDetails = Protect-ComplianceText $executionErrorRecord
    $summary.ScriptStackTrace = Protect-ComplianceText $executionErrorRecord.ScriptStackTrace
    if (-not $summary.RuleResultsAvailable)
    {
        $summary.RuleResultsUnavailableReason = "Rule results are unavailable because stage '$currentStage' failed: $($summary.Error)"
    }
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
    $summaryTempPath = "$summaryPath.$([guid]::NewGuid().ToString('N')).tmp"
    $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $summaryTempPath -Encoding UTF8
    Move-Item -LiteralPath $summaryTempPath -Destination $summaryPath -Force
    Write-ComplianceLog -Level INFO -Message "JSON summary: $summaryPath"
    Write-ComplianceLog -Level INFO -Message "Resource CSV: $resourceCsvPath"
    Write-ComplianceLog -Level INFO -Message "Rule CSV: $ruleCsvPath"
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
