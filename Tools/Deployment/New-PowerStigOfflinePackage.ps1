#Requires -Version 5.1
# Last modified: 2026-10-14

<#+
.SYNOPSIS
    Builds one self-extracting PowerShell file for offline PowerStig deployment and compliance checks.
.DESCRIPTION
    Packages the deployment scripts, the configured PowerStig version, and every exact manifest
    dependency into one generated .ps1 file. The generated file defaults to Check mode, which
    does not apply the STIG baseline but stages packaged modules for DSC.
.PARAMETER ModuleRoot
    Module root containing PowerStig and all exact required module versions. Defaults to repository output.
.PARAMETER OutputPath
    Generated self-extracting .ps1 path. Defaults to Packages\PowerStig-Windows-Offline-<version>.ps1.
.PARAMETER OrgSettingsPath
    Optional organization settings XML to embed as the package default.
.PARAMETER Force
    Replaces an existing generated package.
.EXAMPLE
    .\New-PowerStigOfflinePackage.ps1 -Force
.EXAMPLE
    .\New-PowerStigOfflinePackage.ps1 -OrgSettingsPath C:\Baseline\OrgSettings.xml -Force
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param
(
    [Parameter()]
    [string]
    $ModuleRoot,

    [Parameter()]
    [string]
    $OutputPath,

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $PSItem -PathType Leaf })]
    [string]
    $OrgSettingsPath,

    [Parameter()]
    [switch]
    $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'PowerStig.Windows.Common.psm1'
$deployScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Deploy-PowerStigWindows.ps1'
$checkScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Test-PowerStigWindowsCompliance.ps1'
$guidePath = Join-Path -Path $PSScriptRoot -ChildPath 'PowerStig-Windows-Operator-Guide.zh-CN.md'

foreach ($requiredFile in @($commonModulePath, $deployScriptPath, $checkScriptPath, $guidePath))
{
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf))
    {
        throw "Required package source file was not found: $requiredFile"
    }
}

Import-Module -Name $commonModulePath -Force
$powerStigVersion = Get-PowerStigRequiredVersion
if ([string]::IsNullOrWhiteSpace($ModuleRoot))
{
    $ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\..\output'
}
$ModuleRoot = (Resolve-Path -LiteralPath $ModuleRoot).Path

if ([string]::IsNullOrWhiteSpace($OutputPath))
{
    $OutputPath = Join-Path -Path $PSScriptRoot -ChildPath "Packages\PowerStig-Windows-Offline-$powerStigVersion.ps1"
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if ((Test-Path -LiteralPath $OutputPath) -and -not $Force)
{
    throw "Package already exists: $OutputPath. Use -Force to replace it."
}

$powerStigManifestPath = Join-Path -Path $ModuleRoot -ChildPath "PowerStig\$powerStigVersion\PowerStig.psd1"
if (-not (Test-Path -LiteralPath $powerStigManifestPath -PathType Leaf))
{
    throw "PowerStig $powerStigVersion was not found under ModuleRoot: $powerStigManifestPath"
}
$manifestData = Import-PowerShellDataFile -LiteralPath $powerStigManifestPath
if ([version] $manifestData.ModuleVersion -ne $powerStigVersion)
{
    throw "Configured version $powerStigVersion does not match manifest version $($manifestData.ModuleVersion)."
}

$packageModules = @([pscustomobject]@{ Name = 'PowerStig'; Version = $powerStigVersion })
foreach ($dependency in $manifestData.RequiredModules)
{
    $packageModules += [pscustomobject]@{
        Name = [string] $dependency.ModuleName
        Version = [version] $dependency.ModuleVersion
    }
}
foreach ($packageModule in $packageModules)
{
    $moduleVersionPath = Join-Path -Path $ModuleRoot -ChildPath "$($packageModule.Name)\$($packageModule.Version)"
    if (-not (Test-Path -LiteralPath $moduleVersionPath -PathType Container))
    {
        throw "Required module is missing from the offline source: $($packageModule.Name) $($packageModule.Version) at $moduleVersionPath"
    }
}

if ($WhatIfPreference)
{
    $null = $PSCmdlet.ShouldProcess($OutputPath, "Create PowerStig $powerStigVersion self-extracting offline package")
    [pscustomobject]@{
        PackagePath = $OutputPath
        PackageCreated = $false
        PowerStigVersion = [string] $powerStigVersion
        ModuleCount = $packageModules.Count
        EmbeddedOrgSettings = [bool] $OrgSettingsPath
        PayloadSha256 = $null
        PackageSizeMB = $null
    }
    return
}

$workingRoot = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "PowerStigPackage-$([guid]::NewGuid().ToString('N'))"
$stagingRoot = Join-Path -Path $workingRoot -ChildPath 'Payload'
$zipPath = Join-Path -Path $workingRoot -ChildPath 'Payload.zip'
try
{
    $scriptsRoot = Join-Path -Path $stagingRoot -ChildPath 'Scripts'
    $modulesRoot = Join-Path -Path $stagingRoot -ChildPath 'Modules'
    New-Item -Path $scriptsRoot -ItemType Directory -Force | Out-Null
    New-Item -Path $modulesRoot -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath $commonModulePath, $deployScriptPath, $checkScriptPath -Destination $scriptsRoot -Force
    if ($guidePath -and (Test-Path -LiteralPath $guidePath -PathType Leaf))
    {
        Copy-Item -LiteralPath $guidePath -Destination (Join-Path -Path $scriptsRoot -ChildPath 'PowerStig-Deployment-Guide.zh-CN.md') -Force
    }

    foreach ($packageModule in $packageModules)
    {
        $sourcePath = Join-Path -Path $ModuleRoot -ChildPath "$($packageModule.Name)\$($packageModule.Version)"
        $destinationModuleRoot = Join-Path -Path $modulesRoot -ChildPath $packageModule.Name
        New-Item -Path $destinationModuleRoot -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $sourcePath -Destination $destinationModuleRoot -Recurse -Force
    }

    $accessControlDscPath = Join-Path -Path $modulesRoot -ChildPath 'AccessControlDsc\1.4.3'
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Update-AccessControlDsc.ps1') -ModulePath $accessControlDscPath

    $embeddedOrgSettings = $false
    if ($OrgSettingsPath)
    {
        $configurationRoot = Join-Path -Path $stagingRoot -ChildPath 'Configuration'
        New-Item -Path $configurationRoot -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $OrgSettingsPath -Destination (Join-Path -Path $configurationRoot -ChildPath 'OrgSettings.xml') -Force
        $embeddedOrgSettings = $true
    }

    $metadata = [ordered]@{
        SchemaVersion = 1
        CreatedAt = (Get-Date).ToUniversalTime().ToString('o')
        PowerStigVersion = [string] $powerStigVersion
        EmbeddedOrgSettings = $embeddedOrgSettings
        Modules = @($packageModules | ForEach-Object { [ordered]@{ Name = $PSItem.Name; Version = [string] $PSItem.Version } })
    }
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path -Path $stagingRoot -ChildPath 'PackageMetadata.json') -Encoding UTF8

    Compress-Archive -Path (Join-Path -Path $stagingRoot -ChildPath '*') -DestinationPath $zipPath -CompressionLevel Optimal -Force
    $zipBytes = [IO.File]::ReadAllBytes($zipPath)
    $payloadHash = ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($zipBytes))).Replace('-', '').ToLowerInvariant()
    $payloadBase64 = [Convert]::ToBase64String($zipBytes)
    $payloadLines = for ($offset = 0; $offset -lt $payloadBase64.Length; $offset += 120)
    {
        $length = [math]::Min(120, $payloadBase64.Length - $offset)
        "        '$($payloadBase64.Substring($offset, $length))'"
    }

    $launcherTemplate = @'
#Requires -Version 5.1
# Generated PowerStig offline package. Do not edit the embedded payload.
[CmdletBinding()]
param
(
    [Parameter()]
    [ValidateSet('Check', 'Deploy', 'ExtractOnly')]
    [string] $Mode = 'Check',

    [Parameter()]
    [ValidateSet('Auto', 'WindowsServer2019', 'WindowsServer2022', 'WindowsServer2025', 'Windows10', 'Windows11')]
    [string] $Target = 'Auto',

    [Parameter()]
    [ValidateSet('Auto', 'MS', 'DC')]
    [string] $ServerRole = 'Auto',

    [Parameter()]
    [string] $OrgSettingsPath,

    [Parameter()]
    [switch] $ConfigureExecutionPolicy,

    [Parameter()]
    [switch] $WhatIf,

    [Parameter()]
    [string] $ExtractRoot,

    [Parameter()]
    [switch] $ForceExtract
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packageVersion = '__POWERSTIG_VERSION__'
$payloadHash = '__PAYLOAD_HASH__'
if ([string]::IsNullOrWhiteSpace($ExtractRoot))
{
    $ExtractRoot = Join-Path -Path $env:ProgramData -ChildPath "PowerStigOffline\$packageVersion-$($payloadHash.Substring(0, 12))"
}

function Expand-PowerStigPayload
{
    $markerPath = Join-Path -Path $ExtractRoot -ChildPath '.payload.sha256'
    if (-not $ForceExtract -and (Test-Path -LiteralPath $markerPath -PathType Leaf) -and
        (Get-Content -LiteralPath $markerPath -Raw).Trim() -eq $payloadHash)
    {
        return
    }

    if (Test-Path -LiteralPath $ExtractRoot)
    {
        Remove-Item -LiteralPath $ExtractRoot -Recurse -Force
    }
    New-Item -Path $ExtractRoot -ItemType Directory -Force | Out-Null

    $payload = [string]::Concat(@(
__PAYLOAD_LINES__
    ))
    $zipBytes = [Convert]::FromBase64String($payload)
    $actualHash = ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($zipBytes))).Replace('-', '').ToLowerInvariant()
    if ($actualHash -ne $payloadHash)
    {
        throw "Embedded payload hash mismatch. Expected $payloadHash but found $actualHash. Copy or rebuild the package again."
    }
    $zipPath = Join-Path -Path $ExtractRoot -ChildPath '.payload.zip'
    [IO.File]::WriteAllBytes($zipPath, $zipBytes)
    try
    {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $ExtractRoot)
    }
    finally
    {
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    }
    Set-Content -LiteralPath $markerPath -Value $payloadHash -Encoding ASCII
}

Expand-PowerStigPayload
$metadataPath = Join-Path -Path $ExtractRoot -ChildPath 'PackageMetadata.json'
if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf))
{
    throw "Package extraction is incomplete: $metadataPath"
}
Write-Host "PowerStig offline package $packageVersion extracted to $ExtractRoot"
if ($Mode -eq 'ExtractOnly')
{
    Write-Host "Package metadata: $metadataPath"
    exit 0
}

$entryScript = if ($Mode -eq 'Deploy') { 'Deploy-PowerStigWindows.ps1' } else { 'Test-PowerStigWindowsCompliance.ps1' }
$entryPath = Join-Path -Path $ExtractRoot -ChildPath "Scripts\$entryScript"
$moduleRoot = Join-Path -Path $ExtractRoot -ChildPath 'Modules'
$arguments = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $entryPath,
    '-Target', $Target,
    '-ServerRole', $ServerRole,
    '-ModuleRoot', $moduleRoot,
    '-StageModulesForDsc'
)
if ($ConfigureExecutionPolicy)
{
    $arguments += '-ConfigureExecutionPolicy'
}
if ($Mode -eq 'Deploy' -and $WhatIf)
{
    $arguments += '-WhatIf'
}

$effectiveOrgSettings = $OrgSettingsPath
if ([string]::IsNullOrWhiteSpace($effectiveOrgSettings))
{
    $embeddedOrgSettingsPath = Join-Path -Path $ExtractRoot -ChildPath 'Configuration\OrgSettings.xml'
    if (Test-Path -LiteralPath $embeddedOrgSettingsPath -PathType Leaf)
    {
        $effectiveOrgSettings = $embeddedOrgSettingsPath
    }
}
if (-not [string]::IsNullOrWhiteSpace($effectiveOrgSettings))
{
    if (-not (Test-Path -LiteralPath $effectiveOrgSettings -PathType Leaf))
    {
        throw "OrgSettingsPath does not exist: $effectiveOrgSettings"
    }
    $arguments += @('-OrgSettingsPath', (Resolve-Path -LiteralPath $effectiveOrgSettings).Path)
}

$windowsPowerShell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $windowsPowerShell @arguments
exit $LASTEXITCODE

# Payload SHA256: __PAYLOAD_HASH__
# Payload begins below.
'@

    $launcher = $launcherTemplate.
        Replace('__POWERSTIG_VERSION__', [string] $powerStigVersion).
        Replace('__PAYLOAD_HASH__', $payloadHash).
        Replace('__PAYLOAD_LINES__', ($payloadLines -join [Environment]::NewLine))

    $packageCreated = $false
    if ($PSCmdlet.ShouldProcess($OutputPath, "Create PowerStig $powerStigVersion self-extracting offline package"))
    {
        $outputDirectory = Split-Path -Path $OutputPath -Parent
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
        [IO.File]::WriteAllText($OutputPath, $launcher, [Text.UTF8Encoding]::new($false))
        $packageCreated = $true
    }

    [pscustomobject]@{
        PackagePath = $OutputPath
        PackageCreated = $packageCreated
        PowerStigVersion = [string] $powerStigVersion
        ModuleCount = $packageModules.Count
        EmbeddedOrgSettings = $embeddedOrgSettings
        PayloadSha256 = $payloadHash
        PackageSizeMB = if ($packageCreated) { [math]::Round((Get-Item -LiteralPath $OutputPath).Length / 1MB, 2) } else { $null }
    }
}
finally
{
    if (Test-Path -LiteralPath $workingRoot)
    {
        Remove-Item -LiteralPath $workingRoot -Recurse -Force
    }
}
