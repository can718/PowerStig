#Requires -Version 5.1
# Last modified: 2026-10-13

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param
(
    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]
    $InputPath,

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]
    $ConfigurationPath,

    [Parameter()]
    [string]
    $ReportPath,

    [Parameter()]
    [switch]
    $KeepWorkingDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($InputPath))
{
    $InputPath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\STIGS'
}
if ([string]::IsNullOrWhiteSpace($ConfigurationPath))
{
    $ConfigurationPath = Join-Path -Path $PSScriptRoot -ChildPath 'stig-update.json'
}
if ([string]::IsNullOrWhiteSpace($ReportPath))
{
    $ReportPath = Join-Path -Path $PSScriptRoot -ChildPath 'last-update-report.json'
}

function Get-StigQualityFinding
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [xml]
        $StigXml,

        [Parameter(Mandatory = $true)]
        [string]
        $FileName
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($rule in @($StigXml.SelectNodes('//RootCertificateRule/Rule')))
    {
        if ($rule.dscresource -ne 'none' -and [string]::IsNullOrWhiteSpace([string] $rule.Thumbprint))
        {
            $findings.Add([pscustomobject]@{
                Severity = 'Error'
                Issue = '#1561/#1472'
                RuleId = $rule.id
                Message = 'RootCertificateRule would emit CertificateImport without a Thumbprint.'
            })
        }
        elseif ($rule.dscresource -eq 'none')
        {
            $findings.Add([pscustomobject]@{
                Severity = 'Warning'
                Issue = '#1561/#1472'
                RuleId = $rule.id
                Message = 'RootCertificateRule is an intentional no-op fallback; review before enabling CertificateImport.'
            })
        }
    }

    foreach ($rule in @($StigXml.SelectNodes('//UserRightRule/Rule')))
    {
        if ([string] $rule.Identity -match '(?i)(^|,)\s*[^,]+\.\s*(,|$)')
        {
            $findings.Add([pscustomobject]@{
                Severity = 'Error'
                Issue = '#1560'
                RuleId = $rule.id
                Message = "User-right identity contains a trailing period: $($rule.Identity)"
            })
        }
    }

    if ($FileName -match '^WindowsServer-.+-MS-')
    {
        foreach ($rule in @($StigXml.SelectNodes('//PermissionRule/Rule')))
        {
            if (@($rule.AccessControlEntry.Entry.Principal) -contains 'Server Operators' -and
                [string] $rule.RawString -match 'Domain controllers only')
            {
                $findings.Add([pscustomobject]@{
                    Severity = 'Error'
                    Issue = '#1562'
                    RuleId = $rule.id
                    Message = 'Member Server permission contains the Domain Controller-only Server Operators principal.'
                })
            }
        }
    }

    foreach ($rule in @($StigXml.SelectNodes('//nxFileLineRule/Rule')))
    {
        if ([string] $rule.FilePath -match '[/\\]$')
        {
            $findings.Add([pscustomobject]@{
                Severity = 'Error'
                Issue = '#1563'
                RuleId = $rule.id
                Message = "nxFileLine FilePath resolves to a directory: $($rule.FilePath)"
            })
        }
    }

    $noOpRules = @($StigXml.SelectNodes('/*/*/Rule[translate(@dscresource,"NONE","none")="none"]') |
        Where-Object { $PSItem.ParentNode.Name -ne 'DocumentRule' })
    if ($noOpRules.Count -gt 0)
    {
        $findings.Add([pscustomobject]@{
            Severity = 'Warning'
            Issue = '#1533/#1535'
            RuleId = $noOpRules.id -join ','
            Message = "$($noOpRules.Count) non-Document rules use dscresource=None; review for unintended no-op regressions."
        })
    }

    return $findings
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '..\..')).Path
$sourceRoot = Join-Path -Path $repositoryRoot -ChildPath 'source'
$archiveRoot = Join-Path -Path $sourceRoot -ChildPath 'StigData\Archive'
$processedRoot = Join-Path -Path $sourceRoot -ChildPath 'StigData\Processed'
$convertModulePath = Join-Path -Path $sourceRoot -ChildPath 'PowerStig.Convert.psm1'
$configuration = Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json
$archives = @(Get-ChildItem -LiteralPath $InputPath -Filter '*.zip' -File | Sort-Object -Property Name)

if ($archives.Count -eq 0)
{
    throw "No STIG ZIP files were found in '$InputPath'."
}

$workingRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "PowerStig-$([guid]::NewGuid().ToString('N'))"
$results = [System.Collections.Generic.List[object]]::new()
$failure = $null

try
{
    New-Item -Path $workingRoot -ItemType Directory -Force -WhatIf:$false | Out-Null
    $convertModule = Import-Module -Name $convertModulePath -Force -PassThru

    foreach ($archive in $archives)
    {
        $result = $null
        $profile = $null
        $xccdfFile = $null
        $archiveDirectory = $null
        try
        {
            $archiveWorkingPath = Join-Path -Path $workingRoot -ChildPath $archive.BaseName
            Expand-Archive -LiteralPath $archive.FullName -DestinationPath $archiveWorkingPath -Force -WhatIf:$false
            $xccdfFiles = @(Get-ChildItem -LiteralPath $archiveWorkingPath -Filter '*-xccdf.xml' -File -Recurse)

            if ($xccdfFiles.Count -ne 1)
            {
                throw "Archive '$($archive.Name)' must contain exactly one *-xccdf.xml file; found $($xccdfFiles.Count)."
            }

            $xccdfFile = $xccdfFiles[0]
            $match = $null
            foreach ($candidate in $configuration.profiles)
            {
                if ($xccdfFile.Name -match $candidate.filePattern)
                {
                    $profile = $candidate
                    $match = $Matches.Clone()
                    break
                }
            }

            if ($null -eq $profile)
            {
                throw "No profile in '$ConfigurationPath' matches '$($xccdfFile.Name)'."
            }

        $archiveDirectoryName = $profile.archiveDirectory
        foreach ($key in @($match.Keys | Where-Object { $_ -is [string] }))
        {
            $archiveDirectoryName = $archiveDirectoryName.Replace("{$key}", [string] $match[$key])
        }

        $archiveDirectory = Join-Path -Path $archiveRoot -ChildPath $archiveDirectoryName
        $conversionFiles = @($xccdfFile)

        if ([bool] $profile.splitServerRoles)
        {
            Split-StigXccdf -Path $xccdfFile.FullName -Destination $archiveWorkingPath
            $conversionFiles = @(Get-ChildItem -LiteralPath $archiveWorkingPath -Filter '*_??_STIG_*-xccdf.xml' -File | Sort-Object -Property Name)
            if ($conversionFiles.Count -ne 2)
            {
                throw "Server STIG '$($xccdfFile.Name)' did not produce one MS and one DC XCCDF file."
            }
        }

        foreach ($conversionFile in $conversionFiles)
        {
            $correctionLogName = [System.IO.Path]::ChangeExtension($conversionFile.Name, '.log')
            $correctionLogPath = Join-Path -Path $archiveDirectory -ChildPath $correctionLogName
            if (-not (Test-Path -LiteralPath $correctionLogPath -PathType Leaf))
            {
                $normalizedLogName = $correctionLogName -replace '_V\d+R\d+_', '_VERSION_'
                $correctionLogPath = Get-ChildItem -LiteralPath $archiveDirectory -Filter '*.log' -File -ErrorAction SilentlyContinue |
                    Where-Object { ($_.Name -replace '_V\d+R\d+_', '_VERSION_') -eq $normalizedLogName } |
                    Sort-Object -Property Name -Descending |
                    Select-Object -First 1 -ExpandProperty FullName
            }

            if ($correctionLogPath)
            {
                Copy-Item -LiteralPath $correctionLogPath -Destination ([System.IO.Path]::ChangeExtension($conversionFile.FullName, '.log')) -Force
            }
        }

        $plannedProcessedFiles = [System.Collections.Generic.List[string]]::new()
        foreach ($conversionFile in $conversionFiles)
        {
            [xml] $xccdf = Get-Content -LiteralPath $conversionFile.FullName -Raw -Encoding UTF8
            $fileList = & $convertModule {
                param($StigDetails, $Destination, $Path)
                Get-PowerStigFileList -StigDetails $StigDetails -Destination $Destination -Path $Path
            } $xccdf $processedRoot $conversionFile.FullName
            $plannedProcessedFiles.Add($fileList.Settings.FullName)
            $plannedProcessedFiles.Add($fileList.OrgSettings.FullName)
        }

        $result = [ordered]@{
            Archive = $archive.Name
            Profile = $profile.name
            SourceXccdf = $xccdfFile.Name
            ArchiveDirectory = $archiveDirectory
            ProcessedFiles = @($plannedProcessedFiles)
            QualityFindings = @()
            Status = 'Planned'
            Error = $null
        }

        if ($PSCmdlet.ShouldProcess($archive.Name, "Archive and convert STIG using profile '$($profile.name)'"))
        {
            New-Item -Path $archiveDirectory -ItemType Directory -Force | Out-Null
            Copy-Item -LiteralPath $xccdfFile.FullName -Destination $archiveDirectory -Force

            foreach ($conversionFile in $conversionFiles)
            {
                Copy-Item -LiteralPath $conversionFile.FullName -Destination $archiveDirectory -Force
                $correctionLog = [System.IO.Path]::ChangeExtension($conversionFile.FullName, '.log')
                if (Test-Path -LiteralPath $correctionLog -PathType Leaf)
                {
                    Copy-Item -LiteralPath $correctionLog -Destination $archiveDirectory -Force
                }
                ConvertTo-PowerStigXml -Path $conversionFile.FullName -Destination $processedRoot -CreateOrgSettingsFile | Write-Verbose
            }

            foreach ($processedFile in $plannedProcessedFiles)
            {
                if (-not (Test-Path -LiteralPath $processedFile -PathType Leaf))
                {
                    throw "Expected converted file '$processedFile' was not created."
                }
                [xml] $processedXml = Get-Content -LiteralPath $processedFile -Raw -Encoding UTF8
                $failedRules = @($processedXml.SelectNodes('//*[@conversionstatus="fail"]'))
                if ($failedRules.Count -gt 0)
                {
                    throw "Converted file '$processedFile' contains failed rules: $($failedRules.id -join ', ')."
                }

                if ($processedFile -notlike '*.org.default.xml')
                {
                    $qualityFindings = @(Get-StigQualityFinding -StigXml $processedXml -FileName (Split-Path -Path $processedFile -Leaf))
                    $result.QualityFindings += $qualityFindings
                    $qualityErrors = @($qualityFindings | Where-Object Severity -eq 'Error')
                    if ($qualityErrors.Count -gt 0)
                    {
                        $qualitySummary = $qualityErrors | ForEach-Object { "$($PSItem.Issue) $($PSItem.RuleId): $($PSItem.Message)" }
                        throw "Quality validation failed for '$processedFile': $($qualitySummary -join '; ')"
                    }
                }
            }

            $result.Status = 'Converted'
        }

            $results.Add([pscustomobject] $result)
        }
        catch
        {
            $archiveFailure = $PSItem
            if ($null -eq $result)
            {
                $result = [ordered]@{
                    Archive = $archive.Name
                    Profile = if ($profile) { $profile.name } else { $null }
                    SourceXccdf = if ($xccdfFile) { $xccdfFile.Name } else { $null }
                    ArchiveDirectory = $archiveDirectory
                    ProcessedFiles = @()
                    QualityFindings = @()
                    Status = 'Failed'
                    Error = $archiveFailure.Exception.Message
                }
            }
            else
            {
                $result.Status = 'Failed'
                $result.Error = $archiveFailure.Exception.Message
            }
            $results.Add([pscustomobject] $result)
            throw
        }
    }
}
catch
{
    $failure = $_
}
finally
{
    Remove-Module -Name 'PowerStig.Convert' -Force -ErrorAction SilentlyContinue -WhatIf:$false
    if (-not $KeepWorkingDirectory -and (Test-Path -LiteralPath $workingRoot))
    {
        Remove-Item -LiteralPath $workingRoot -Recurse -Force -WhatIf:$false
    }
}

$report = [ordered]@{
    SchemaVersion = 1
    ModifiedDate = '2026-10-13'
    GeneratedAt = (Get-Date).ToUniversalTime().ToString('o')
    Succeeded = ($null -eq $failure)
    Error = if ($failure) { $failure.Exception.Message } else { $null }
    RepositoryRoot = $repositoryRoot
    InputPath = (Resolve-Path -LiteralPath $InputPath).Path
    Items = @($results)
}

$reportDirectory = Split-Path -Path $ReportPath -Parent
if ($reportDirectory -and -not (Test-Path -LiteralPath $reportDirectory))
{
    New-Item -Path $reportDirectory -ItemType Directory -Force | Out-Null
}

$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
$reportObject = [pscustomobject] $report
$reportObject

if ($failure)
{
    throw $failure
}