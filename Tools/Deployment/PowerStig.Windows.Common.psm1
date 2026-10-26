# Last modified: 2026-10-14

Set-StrictMode -Version Latest

$script:PowerStigVersion = [version] '4.30.0'
$script:TargetCatalog = @{
    WindowsServer2019 = @{ Technology = 'WindowsServer'; OsVersion = '2019'; StigVersion = '3.9' }
    WindowsServer2022 = @{ Technology = 'WindowsServer'; OsVersion = '2022'; StigVersion = '2.11' }
    WindowsServer2025 = @{ Technology = 'WindowsServer'; OsVersion = '2025'; StigVersion = '1.4' }
    Windows10 = @{ Technology = 'WindowsClient'; OsVersion = '10'; StigVersion = '3.6' }
    Windows11 = @{ Technology = 'WindowsClient'; OsVersion = '11'; StigVersion = '2.11' }
}

function Get-PowerStigRequiredVersion
{
    [CmdletBinding()]
    param()

    return $script:PowerStigVersion
}

function Invoke-WindowsPowerShellRelaunch
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ScriptPath,

        [Parameter(Mandatory = $true)]
        [hashtable]
        $BoundParameters
    )

    if ($PSVersionTable.PSEdition -eq 'Desktop')
    {
        return $false
    }

    $windowsPowerShell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf))
    {
        throw 'Windows PowerShell 5.1 is required but powershell.exe was not found.'
    }

    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
    foreach ($parameter in $BoundParameters.GetEnumerator())
    {
        if ($parameter.Value -is [switch] -or $parameter.Value -is [Management.Automation.SwitchParameter])
        {
            if ([bool] $parameter.Value)
            {
                $arguments += "-$($parameter.Key)"
            }
        }
        else
        {
            $arguments += "-$($parameter.Key)"
            $arguments += @($parameter.Value | ForEach-Object { [string] $PSItem })
        }
    }

    & $windowsPowerShell @arguments
    $global:LASTEXITCODE = $LASTEXITCODE
    return $true
}

function Assert-PowerStigAdministrator
{
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw 'Run this script from an elevated Windows PowerShell session.'
    }
}

function Initialize-PowerStigDscExecutionPolicy
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [bool]
        $Configure,

        [Parameter(Mandatory = $true)]
        [bool]
        $Required,

        [Parameter(Mandatory = $true)]
        [scriptblock]
        $Log
    )

    $policies = Get-ExecutionPolicy -List
    $machinePolicy = [string] ($policies | Where-Object Scope -eq 'MachinePolicy').ExecutionPolicy
    $localMachinePolicy = [string] ($policies | Where-Object Scope -eq 'LocalMachine').ExecutionPolicy
    $effectiveLcmPolicy = if ($machinePolicy -and $machinePolicy -ne 'Undefined') {
        $machinePolicy
    } elseif ($localMachinePolicy -and $localMachinePolicy -ne 'Undefined') {
        $localMachinePolicy
    } else {
        'Restricted'
    }

    if ($effectiveLcmPolicy -notin 'RemoteSigned', 'Unrestricted', 'Bypass')
    {
        if ($Configure)
        {
            if ($machinePolicy -and $machinePolicy -ne 'Undefined')
            {
                throw "MachinePolicy enforces execution policy '$machinePolicy'; LocalMachine cannot override Group Policy."
            }
            & $Log 'WARN' "Changing LocalMachine execution policy from '$localMachinePolicy' to 'RemoteSigned' for DSC LCM."
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction SilentlyContinue
            $configuredPolicy = Get-ExecutionPolicy -Scope LocalMachine
            if ($configuredPolicy -ne 'RemoteSigned')
            {
                throw "LocalMachine execution policy remains '$configuredPolicy' after requesting RemoteSigned."
            }
            $effectiveLcmPolicy = 'RemoteSigned'
        }
        elseif ($Required)
        {
            throw "DSC LCM execution policy resolves to '$effectiveLcmPolicy'. Rerun with -ConfigureExecutionPolicy or configure an approved machine policy."
        }
        else
        {
            & $Log 'WARN' "DSC LCM execution policy resolves to '$effectiveLcmPolicy'. Applying or testing through LCM requires -ConfigureExecutionPolicy or an approved machine policy."
        }
    }

    [pscustomobject]@{
        MachinePolicy = $machinePolicy
        LocalMachineBefore = $localMachinePolicy
        EffectiveForLcm = $effectiveLcmPolicy
        Changed = $Configure -and $effectiveLcmPolicy -eq 'RemoteSigned' -and $localMachinePolicy -ne 'RemoteSigned'
    }
}

function Get-PowerStigWindowsTarget
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $RequestedTarget,

        [Parameter(Mandatory = $true)]
        [string]
        $RequestedServerRole
    )

    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $resolvedTarget = $RequestedTarget

    if ($resolvedTarget -eq 'Auto')
    {
        $resolvedTarget = switch -Regex ($operatingSystem.Caption)
        {
            'Windows Server 2019' { 'WindowsServer2019'; break }
            'Windows Server 2022' { 'WindowsServer2022'; break }
            'Windows Server 2025' { 'WindowsServer2025'; break }
            'Windows 10' { 'Windows10'; break }
            'Windows 11' { 'Windows11'; break }
            default { throw "Unsupported operating system: $($operatingSystem.Caption)" }
        }
    }

    $targetData = $script:TargetCatalog[$resolvedTarget]
    if (-not $targetData)
    {
        throw "Unsupported target: $resolvedTarget"
    }

    $resolvedRole = $null
    if ($targetData.Technology -eq 'WindowsServer')
    {
        $resolvedRole = $RequestedServerRole
        if ($resolvedRole -eq 'Auto')
        {
            $resolvedRole = if ([int] $computerSystem.DomainRole -in 4, 5) { 'DC' } else { 'MS' }
        }
    }
    elseif ($RequestedServerRole -ne 'Auto')
    {
        throw 'ServerRole can only be specified for Windows Server targets.'
    }

    [pscustomobject]@{
        Target = $resolvedTarget
        Technology = $targetData.Technology
        OsVersion = $targetData.OsVersion
        ServerRole = $resolvedRole
        StigVersion = [version] $targetData.StigVersion
        ActualCaption = [string] $operatingSystem.Caption
        ActualVersion = [string] $operatingSystem.Version
        DomainRole = [int] $computerSystem.DomainRole
    }
}

function Import-PowerStigDeploymentModule
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [string]
        $RequestedModuleRoot,

        [Parameter(Mandatory = $true)]
        [bool]
        $DownloadDependencies,

        [Parameter(Mandatory = $true)]
        [string]
        $ScriptRoot,

        [Parameter(Mandatory = $true)]
        [scriptblock]
        $Log
    )

    $candidateRoots = [Collections.Generic.List[string]]::new()
    if ($RequestedModuleRoot)
    {
        if (-not (Test-Path -LiteralPath $RequestedModuleRoot -PathType Container))
        {
            throw "ModuleRoot does not exist: $RequestedModuleRoot"
        }
        $candidateRoots.Add((Resolve-Path -LiteralPath $RequestedModuleRoot).Path)
    }
    else
    {
        foreach ($candidate in @(
            (Join-Path -Path $ScriptRoot -ChildPath '..\..\Modules'),
            (Join-Path -Path $ScriptRoot -ChildPath '..\..\output')
        ))
        {
            if (Test-Path -LiteralPath $candidate -PathType Container)
            {
                $candidateRoots.Add((Resolve-Path -LiteralPath $candidate).Path)
            }
        }
    }

    $selectedRoot = $null
    $manifestPath = $null
    foreach ($candidateRoot in $candidateRoots)
    {
        $candidateManifest = Join-Path -Path $candidateRoot -ChildPath "PowerStig\$script:PowerStigVersion\PowerStig.psd1"
        if (Test-Path -LiteralPath $candidateManifest -PathType Leaf)
        {
            $selectedRoot = $candidateRoot
            $manifestPath = $candidateManifest
            break
        }
    }

    if (-not $manifestPath)
    {
        $availableModule = Get-Module -ListAvailable -Name PowerStig |
            Where-Object Version -eq $script:PowerStigVersion |
            Select-Object -First 1
        if (-not $availableModule)
        {
            throw "PowerStig $script:PowerStigVersion was not found. Export it to a Modules directory and pass -ModuleRoot."
        }
        $manifestPath = $availableModule.Path
        $selectedRoot = Split-Path -Path (Split-Path -Path (Split-Path -Path $manifestPath -Parent) -Parent) -Parent
    }

    $pathSeparator = [IO.Path]::PathSeparator
    $env:PSModulePath = "$selectedRoot$pathSeparator$env:PSModulePath"
    $manifestData = Import-PowerShellDataFile -LiteralPath $manifestPath
    $missingDependencies = @()
    foreach ($dependency in $manifestData.RequiredModules)
    {
        $dependencyName = [string] $dependency.ModuleName
        $dependencyVersion = [version] $dependency.ModuleVersion
        $installed = Get-Module -ListAvailable -Name $dependencyName |
            Where-Object Version -eq $dependencyVersion |
            Select-Object -First 1
        if (-not $installed)
        {
            $missingDependencies += [pscustomobject]@{ Name = $dependencyName; Version = $dependencyVersion }
        }
    }

    if ($missingDependencies.Count -gt 0 -and $DownloadDependencies)
    {
        if (-not (Get-Command -Name Save-Module -ErrorAction SilentlyContinue))
        {
            throw 'Save-Module is unavailable. Install PowerShellGet before using -InstallDependencies.'
        }
        foreach ($dependency in $missingDependencies)
        {
            & $Log 'INFO' "Downloading dependency $($dependency.Name) $($dependency.Version) to $selectedRoot"
            Save-Module -Name $dependency.Name -RequiredVersion $dependency.Version -Path $selectedRoot -Force
        }
        $missingDependencies = @()
    }

    if ($missingDependencies.Count -gt 0)
    {
        $missingText = $missingDependencies | ForEach-Object { "$($PSItem.Name) $($PSItem.Version)" }
        throw "Missing DSC dependencies: $($missingText -join ', '). Rerun with -InstallDependencies."
    }

    $builtInModuleRoot = Join-Path -Path $PSHOME -ChildPath 'Modules'
    $env:PSModulePath = @($selectedRoot, $builtInModuleRoot) -join $pathSeparator
    Import-Module -Name $manifestPath -Force -Global
    $loadedModule = Get-Module -Name PowerStig |
        Where-Object Version -eq $script:PowerStigVersion |
        Select-Object -First 1
    if (-not $loadedModule)
    {
        throw "PowerStig $script:PowerStigVersion did not load."
    }

    & $Log 'INFO' "Loaded PowerStig $($loadedModule.Version) from $($loadedModule.Path)"
    return $loadedModule
}

function Install-PowerStigDscModule
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Management.Automation.PSModuleInfo]
        $PowerStigModule,

        [Parameter(Mandatory = $true)]
        [string]
        $DestinationRoot,

        [Parameter(Mandatory = $true)]
        [scriptblock]
        $Log
    )

    New-Item -Path $DestinationRoot -ItemType Directory -Force | Out-Null
    $manifestPath = Join-Path -Path $PowerStigModule.ModuleBase -ChildPath 'PowerStig.psd1'
    $manifestData = Import-PowerShellDataFile -LiteralPath $manifestPath
    $modulesToStage = @([pscustomobject]@{
        Name = 'PowerStig'
        Version = $PowerStigModule.Version
        Source = $PowerStigModule.ModuleBase
    })

    foreach ($dependency in $manifestData.RequiredModules)
    {
        $dependencyName = [string] $dependency.ModuleName
        $dependencyVersion = [version] $dependency.ModuleVersion
        $dependencyModule = Get-Module -ListAvailable -Name $dependencyName |
            Where-Object Version -eq $dependencyVersion |
            Select-Object -First 1
        if (-not $dependencyModule)
        {
            throw "Cannot stage missing dependency $dependencyName $dependencyVersion."
        }
        $modulesToStage += [pscustomobject]@{
            Name = $dependencyName
            Version = $dependencyVersion
            Source = $dependencyModule.ModuleBase
        }
    }

    foreach ($moduleToStage in $modulesToStage)
    {
        $destinationVersion = Join-Path -Path $DestinationRoot -ChildPath "$($moduleToStage.Name)\$($moduleToStage.Version)"
        if ([IO.Path]::GetFullPath($moduleToStage.Source).TrimEnd('\') -eq [IO.Path]::GetFullPath($destinationVersion).TrimEnd('\'))
        {
            continue
        }
        & $Log 'INFO' "Staging $($moduleToStage.Name) $($moduleToStage.Version) for DSC LCM: $destinationVersion"
        if (Test-Path -LiteralPath $destinationVersion)
        {
            Remove-Item -LiteralPath $destinationVersion -Recurse -Force
        }
        New-Item -Path (Split-Path -Path $destinationVersion -Parent) -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $moduleToStage.Source -Destination $destinationVersion -Recurse -Force
    }

    $pathSeparator = [IO.Path]::PathSeparator
    $builtInModuleRoot = Join-Path -Path $PSHOME -ChildPath 'Modules'
    $env:PSModulePath = @($DestinationRoot, $builtInModuleRoot) -join $pathSeparator
}

function Assert-PowerStigTargetAvailable
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $Target
    )

    $availableStig = Get-Stig -ListAvailable | Where-Object {
        $PSItem.Technology -eq $Target.Technology -and
        [string] $PSItem.TechnologyVersion -eq $Target.OsVersion -and
        [version] $PSItem.Version -eq $Target.StigVersion -and
        ($Target.Technology -eq 'WindowsClient' -or $PSItem.TechnologyRole -eq $Target.ServerRole)
    }
    if (-not $availableStig)
    {
        throw "The selected STIG is not available in the loaded module: $($Target | ConvertTo-Json -Compress)"
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
    param(
        [string] $ResourceId,
        [scriptblock] $Log
    )

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
        if ($Log)
        {
            & $Log 'WARN' "Independent validation failed for ${ResourceId}: $($PSItem.Exception.Message)"
        }
    }
    return $null
}

function Resolve-PowerStigDscComplianceResult
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $Target,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ServerRole,

        [Parameter(Mandatory = $true)]
        [object] $Result,

        [Parameter()]
        [scriptblock] $Log,

        [Parameter()]
        [scriptblock] $ComplianceOverride
    )

    $rawInDesiredState = if ($Result -is [bool]) { [bool] $Result } else { [bool] $Result.InDesiredState }
    $resourcesInDesiredState = if ($Result -is [bool]) { @() } else { @($Result.ResourcesInDesiredState) }
    $resourcesNotInDesiredState = if ($Result -is [bool]) { @() } else { @($Result.ResourcesNotInDesiredState) }
    $originalNoncompliantCount = $resourcesNotInDesiredState.Count
    $validatedEquivalentResources = @()

    if (-not $rawInDesiredState -and
        $Target -eq 'WindowsServer2022' -and
        $ServerRole -eq 'DC' -and
        $originalNoncompliantCount -gt 0)
    {
        $remainingNoncompliantResources = @()
        foreach ($resource in $resourcesNotInDesiredState)
        {
            $evaluation = if ($ComplianceOverride)
            {
                & $ComplianceOverride $resource.ResourceId
            }
            else
            {
                Get-WindowsServer2022ComplianceOverride -ResourceId $resource.ResourceId -Log $Log
            }
            if ($evaluation)
            {
                $validatedEquivalentResources += [pscustomobject]@{
                    Resource = $resource
                    Evaluation = $evaluation
                }
                if ($Log)
                {
                    & $Log 'INFO' "EQUIVALENT: $($resource.ResourceId); $evaluation"
                }
            }
            else
            {
                $remainingNoncompliantResources += $resource
            }
        }
        $resourcesNotInDesiredState = @($remainingNoncompliantResources)
    }

    $inDesiredState = $rawInDesiredState -or
        ($originalNoncompliantCount -gt 0 -and $validatedEquivalentResources.Count -eq $originalNoncompliantCount)

    [pscustomobject]@{
        InDesiredState = $inDesiredState
        RawInDesiredState = $rawInDesiredState
        ResourcesInDesiredState = $resourcesInDesiredState
        ResourcesNotInDesiredState = $resourcesNotInDesiredState
        ValidatedEquivalentResources = $validatedEquivalentResources
    }
}

function New-PowerStigWindowsMof
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $Target,

        [Parameter()]
        [string]
        $OrgSettingsPath,

        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath
    )

    $configurationDefinition = @'
configuration PowerStigWindowsConfiguration
    {
        param
        (
            [Parameter(Mandatory = $true)] [string] $Technology,
            [Parameter(Mandatory = $true)] [string] $OsVersion,
            [Parameter(Mandatory = $true)] [version] $StigVersion,
            [Parameter()] [string] $OsRole,
            [Parameter()] [object] $OrgSettings,
            [Parameter()] [hashtable] $Exceptions,
            [Parameter()] [bool] $AddNoticeCaption
        )

        Import-DscResource -ModuleName @{ ModuleName = 'PowerStig'; RequiredVersion = '__POWERSTIG_VERSION__' }
        Import-DscResource -ModuleName PSDscResources -ModuleVersion 2.12.0.0

        Node localhost
        {
            if ($AddNoticeCaption)
            {
                Registry DefaultLoginNoticeCaption
                {
                    Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    ValueName = 'LegalNoticeCaption'
                    ValueData = 'DoD Notice and Consent Banner'
                    ValueType = 'String'
                    Ensure = 'Present'
                    Force = $true
                }
            }
            if ($Technology -eq 'WindowsServer')
            {
                if ($OrgSettings -and $Exceptions)
                {
                    WindowsServer OperatingSystemStig
                    {
                        OsVersion = $OsVersion
                        OsRole = $OsRole
                        StigVersion = $StigVersion
                        OrgSettings = $OrgSettings
                        Exception = $Exceptions
                    }
                }
                elseif ($OrgSettings)
                {
                    WindowsServer OperatingSystemStig
                    {
                        OsVersion = $OsVersion
                        OsRole = $OsRole
                        StigVersion = $StigVersion
                        OrgSettings = $OrgSettings
                    }
                }
                else
                {
                    WindowsServer OperatingSystemStig
                    {
                        OsVersion = $OsVersion
                        OsRole = $OsRole
                        StigVersion = $StigVersion
                    }
                }
            }
            else
            {
                if ($OrgSettings -and $Exceptions)
                {
                    WindowsClient OperatingSystemStig
                    {
                        OsVersion = $OsVersion
                        StigVersion = $StigVersion
                        OrgSettings = $OrgSettings
                        Exception = $Exceptions
                    }
                }
                elseif ($OrgSettings)
                {
                    WindowsClient OperatingSystemStig
                    {
                        OsVersion = $OsVersion
                        StigVersion = $StigVersion
                        OrgSettings = $OrgSettings
                    }
                }
                else
                {
                    WindowsClient OperatingSystemStig
                    {
                        OsVersion = $OsVersion
                        StigVersion = $StigVersion
                    }
                }
            }
        }
    }
'@
    $configurationDefinition = $configurationDefinition.Replace('__POWERSTIG_VERSION__', [string] $script:PowerStigVersion)
    . ([scriptblock]::Create($configurationDefinition))

    $configurationParameters = @{
        Technology = $Target.Technology
        OsVersion = $Target.OsVersion
        StigVersion = $Target.StigVersion
        OutputPath = $OutputPath
    }
    if ($Target.ServerRole)
    {
        $configurationParameters.OsRole = $Target.ServerRole
    }
    if ($OrgSettingsPath)
    {
        $configurationParameters.OrgSettings = $OrgSettingsPath
    }
    else
    {
        $defaultRuleIds = switch ($Target.Target)
        {
            'WindowsServer2019' { @('V-205631', 'V-205717', 'V-205632') }
            'WindowsServer2022' { @('V-254457', 'V-254484', '') }
            'WindowsServer2025' { @('V-278207', 'V-278234', '') }
            'Windows10' { @('V-220921', 'V-220945', 'V-220922') }
            'Windows11' { @('V-253445', 'V-253469', '') }
            default { throw "No login defaults are defined for '$($Target.Target)'." }
        }
        $noticeText = @'
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
'@
        $defaultSettings = @{}
        $defaultSettings[$defaultRuleIds[0]] = @{ ValueData = $noticeText }
        $defaultSettings[$defaultRuleIds[1]] = @{ ValueData = '1' }
        if ($defaultRuleIds[2])
        {
            $defaultSettings[$defaultRuleIds[2]] = @{ ValueData = 'DoD Notice and Consent Banner' }
        }
        $configurationParameters.OrgSettings = $defaultSettings
    }
    if (-not $OrgSettingsPath -and $Target.Target -in @('WindowsServer2025', 'Windows10', 'Windows11'))
    {
        $configurationParameters.Exceptions = @{}
        $configurationParameters.Exceptions[$defaultRuleIds[1]] = @{ ValueData = '1' }
    }
    $configurationParameters.AddNoticeCaption = $Target.Target -in @('WindowsServer2022', 'WindowsServer2025', 'Windows11')

    PowerStigWindowsConfiguration @configurationParameters
    $mofPath = Join-Path -Path $OutputPath -ChildPath 'localhost.mof'
    if (-not (Test-Path -LiteralPath $mofPath -PathType Leaf))
    {
        throw "Configuration compilation did not create $mofPath"
    }
    return $mofPath
}

Export-ModuleMember -Function @(
    'Get-PowerStigRequiredVersion',
    'Invoke-WindowsPowerShellRelaunch',
    'Assert-PowerStigAdministrator',
    'Initialize-PowerStigDscExecutionPolicy',
    'Get-PowerStigWindowsTarget',
    'Import-PowerStigDeploymentModule',
    'Install-PowerStigDscModule',
    'Assert-PowerStigTargetAvailable',
    'Resolve-PowerStigDscComplianceResult',
    'New-PowerStigWindowsMof'
)
