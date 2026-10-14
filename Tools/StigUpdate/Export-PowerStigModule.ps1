#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param
(
    [Parameter(Mandatory = $true)]
    [string]
    $Destination,

    [Parameter()]
    [switch]
    $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '..\..')).Path
$sourceRoot = Join-Path -Path $repositoryRoot -ChildPath 'source'
$sourceManifestPath = Join-Path -Path $sourceRoot -ChildPath 'PowerStig.psd1'
$manifest = Import-PowerShellDataFile -LiteralPath $sourceManifestPath
$moduleVersion = [string] $manifest.ModuleVersion
$moduleRoot = Join-Path -Path $Destination -ChildPath 'PowerStig'
$versionRoot = Join-Path -Path $moduleRoot -ChildPath $moduleVersion

if ((Test-Path -LiteralPath $versionRoot) -and -not $Force)
{
    throw "'$versionRoot' already exists. Use -Force to replace this custom module export."
}

if ($PSCmdlet.ShouldProcess($versionRoot, "Export PowerStig $moduleVersion"))
{
    if (Test-Path -LiteralPath $versionRoot)
    {
        Remove-Item -LiteralPath $versionRoot -Recurse -Force
    }

    New-Item -Path $versionRoot -ItemType Directory -Force | Out-Null
    Copy-Item -Path (Join-Path -Path $sourceRoot -ChildPath '*') -Destination $versionRoot -Recurse -Force

    $exportedManifestPath = Join-Path -Path $versionRoot -ChildPath 'PowerStig.psd1'
    $exportedModulePath = Join-Path -Path $versionRoot -ChildPath 'PowerStig.psm1'
    if (-not (Test-Path -LiteralPath $exportedManifestPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $exportedModulePath -PathType Leaf))
    {
        throw "The module export to '$versionRoot' is incomplete."
    }

    [pscustomobject]@{
        Name = 'PowerStig'
        Version = $moduleVersion
        ModulePath = $versionRoot
        ManifestPath = $exportedManifestPath
    }
}