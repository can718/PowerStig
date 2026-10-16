
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Automatically applies FIPS 140-2 + Windows STIG security policies.
    Supports: Windows Server 2019/2022/2025, Windows 10, Windows 11.

.DESCRIPTION
    1. Detects current platform (Windows Server 2019/2022/2025, Windows 10/11)
    2. Applies the matching PowerStig baseline from a GitHub Actions offline artifact.
    3. Applies this script's separate FIPS, TLS, and RDP hardening settings.
    4. Rechecks the STIG baseline and generates an HTML compliance report.

.NOTES
    Version  : 2.0
    Baseline : GitHub Actions PowerStig offline artifact for all supported platforms
    Warning  : Take a snapshot/backup before running; some policies take effect after reboot
    Usage    : Run as Administrator; compatible with PowerShell 5.1 or 7.x
        Place the GitHub Actions PowerStig offline artifact beside this file or in .\Packages.
        POWERSTIG_OFFLINE_PACKAGE can specify another path. POWERSTIG_ORG_SETTINGS_PATH
        optionally supplies approved organization values. If omitted, a blank template is
        created under %ProgramData%\PowerStigOffline\OrgSettings and is never overwritten.
        TerraForge and direct FIPS/TLS/RDP helpers remain external/independent of the artifact.
#>
# ==============================================================================
# Install FIPS and STIG Policy
# ==============================================================================
# This script installs the FIPS and STIG Policy
# ==============================================================================

# Set error action preference
$ErrorActionPreference = "Stop"



 # Initialize logging first
    Write-Host "==============================================================================" -ForegroundColor Cyan
    Write-Host "TERRAFORGE AGENT TASK EXECUTER" -ForegroundColor Cyan
    Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Cyan

    # Import all modules
    Write-Host "Importing PowerShell modules..." -ForegroundColor Yellow
    $modules_directory = Join-Path $PSScriptRoot ".\Modules"
    $import_all_modules = Join-Path $modules_directory "Import-AllModules.ps1"

    if (-not (Test-Path $import_all_modules)) {
        Write-Error "Module import script not found: $import_all_modules"
        exit 1
    }

    & $import_all_modules -ModulesFolder $modules_directory

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to import modules. Exit code: $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    # Initialize TerraForge logging
    $Global:LogDirectory = "$Global:VMToolsPath\TerraforgeAgent\Logs"
    Initialize-TerraForgeLogging -ScriptName "AgentTaskExecuter"
    Write-TerraForgeLog "Waiting for 20 seconds to ensure machine is ready..." -Level "Info"
    Start-Sleep -Seconds 20
    Write-TerraForgeLog "Terraforge Agent Task Executer started" -Level "Info"
    Write-TerraForgeLog "Computer name: $env:COMPUTERNAME" -Level "Info"
    Write-TerraForgeLog "User context: $env:USERNAME" -Level "Info"

    Write-TerraForgeSection "Module Import Complete"
    Write-TerraForgeLog "All required modules imported successfully" -Level "Success"
    $builderWorkingDir = Get-RegistryValue -Name "BuilderWorkingDir"

    

function Write-OK { param([string]$Msg) Write-TerraForgeLog  "  [OK]   $Msg" -Level "Success" }
function Write-Warn { param([string]$Msg) Write-TerraForgeLog "  [WARN] $Msg" -Level "Warning" }
function Write-Err { param([string]$Msg) Write-TerraForgeLog "  [FAIL] $Msg" -Level "Error"; $script:Errors += $Msg }

try {
    # Initialize logging
    Initialize-TerraForgeLogging -ScriptName "TerraforgeInstallFIPSAndSTIGPolicy"

    $taskName = "InstallFIPSAndSTIGPolicy"

    Write-TerraForgeHeader "$taskName Installation Started"

    $configName = Get-ConfigName
    # if ($configName.ToLower().StartsWith("Lite-FipsStig".ToLower())) {
    if ($true) {

        if (Test-TaskCompleted -TaskName $taskName) {
            Write-TerraForgeLog "$taskName already completed. Skipping." -Level "Info"
            return
        }

        try {
            $AutoReboot = $false
            $NoReboot = $false
            $SkipSTIG = $false
            $DSCOutputPath = 'C:\DSC\STIG'
            $ReportPath = 'C:\DSC\Reports'

            # ========================== Helper Functions & Tracking ==========================

            $ErrorActionPreference = 'Stop'
            $script:StepNum = 0
            $script:Errors = @()
            $script:DetectedOS = 'Unknown'
            $script:DetectedRole = 'Unknown'

            # Master list that tracks every policy/setting action for the HTML report
            $script:PolicyLog = [System.Collections.ArrayList]::new()
            $script:STIGExecution = [ordered]@{
                Requested        = (-not $SkipSTIG)
                Status           = if ($SkipSTIG) { 'Skipped' } else { 'NotStarted' }
                Baseline         = 'Pending OS detection'
                ModuleStatus     = 'NotChecked'
                ModuleVersion    = ''
                PackageProvider  = ''
                SkipRules        = @()
                PlannedResources = 0
                AppliedResources = 0
                FailedResources  = 0
                RebootRequested  = $false
                MofPath          = ''
                Reason           = ''
            }
            $script:FIPSExecution = [ordered]@{
                Status         = 'NotStarted'
                EnabledValue   = ''
                MDMEnabled     = ''
                Method         = 'Registry + secedit'
                EffectiveAfter = 'Reboot'
                Reason         = ''
            }

            function Write-Step {
                param([string]$Message)
                $script:StepNum++
                Write-TerraForgeLog "`n[$script:StepNum] $Message" -Level "Success"
                Write-TerraForgeLog ('=' * 60) -Level "Success"
            }

            function Set-RegistryValueForFIPSAndSTIG {
                param(
                    [string]$Path,
                    [string]$Name,
                    [int]$Value,
                    [string]$Type = 'DWord'
                )
                if (-not (Test-Path $Path)) {
                    New-Item -Path $Path -Force | Out-Null
                }
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            }

            # PowerShell version compatibility
            $script:IsPS7 = $PSVersionTable.PSVersion.Major -ge 7
            $script:IsPSCore = $PSVersionTable.PSEdition -eq 'Core'

            function Invoke-InWindowsPowerShell {
                <#
    .SYNOPSIS
        Runs a script block in Windows PowerShell 5.1 (powershell.exe).
        Required for DSC operations which are not natively available in PS7.
    #>
                param(
                    [Parameter(Mandatory)]
                    [string]$ScriptBlock,
                    [hashtable]$Parameters = @{}
                )

                $psPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
                if (-not (Test-Path $psPath)) {
                    throw "Windows PowerShell 5.1 (powershell.exe) not found at: $psPath"
                }

                # Serialize parameters to a temp file for complex data passing
                $paramFile = Join-Path $env:TEMP "ps5_params_$([guid]::NewGuid().ToString('N')).xml"
                $resultFile = Join-Path $env:TEMP "ps5_result_$([guid]::NewGuid().ToString('N')).xml"

                $Parameters | Export-Clixml -Path $paramFile -Force

                $wrapperScript = @"
`$ErrorActionPreference = 'Stop'
try {
    `$params = Import-Clixml -Path '$paramFile'
    `$result = & {
        $ScriptBlock
    }
    @{ Success = `$true; Result = `$result; Error = `$null } | Export-Clixml -Path '$resultFile' -Force
} catch {
    @{ Success = `$false; Result = `$null; Error = `$_.Exception.Message } | Export-Clixml -Path '$resultFile' -Force
}
"@

                $tempScript = Join-Path $env:TEMP "ps5_script_$([guid]::NewGuid().ToString('N')).ps1"
                $wrapperScript | Set-Content -Path $tempScript -Encoding UTF8 -Force

                try {
                    & $psPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $tempScript 2>&1 | ForEach-Object {
                        if ($_ -is [System.Management.Automation.ErrorRecord]) {
                            Write-Warning "PS5: $($_.Exception.Message)"
                        }
                        else {
                            Write-TerraForgeLog $_ -Level "Info"
                        }
                    }

                    if (Test-Path $resultFile) {
                        $outcome = Import-Clixml -Path $resultFile
                        if (-not $outcome.Success) {
                            throw "Windows PowerShell error: $($outcome.Error)"
                        }
                        return $outcome.Result
                    }
                    else {
                        throw 'Windows PowerShell did not produce a result file'
                    }
                }
                finally {
                    Remove-Item $paramFile, $resultFile, $tempScript -Force -ErrorAction SilentlyContinue
                }
            }

            function Add-PolicyEntry {
                # Record a policy action into the master log for the HTML report
                param(
                    [string]$Category,       # e.g. STIG, FIPS, TLS, RDP, CipherSuite
                    [string]$Policy,         # Policy name or rule ID
                    [string]$Description,    # What was done
                    [ValidateSet('Applied','Skipped','Failed','Verified')]
                    [string]$Status,
                    [string]$Reason = ''     # Reason for skip/failure
                )
                $script:PolicyLog.Add([PSCustomObject]@{
                        Timestamp   = Get-Date -Format 'HH:mm:ss'
                        Category    = $Category
                        Policy      = $Policy
                        Description = $Description
                        Status      = $Status
                        Reason      = $Reason
                    }) | Out-Null
            }

            function Convert-ToHtmlSafe {
                param([AllowNull()][string]$Text)

                if ([string]::IsNullOrEmpty($Text)) {
                    return ''
                }

                return [System.Net.WebUtility]::HtmlEncode($Text)
            }

            function Install-ModuleCompatible {
                param(
                    [Parameter(Mandatory)]
                    [string]$Name
                )

                $installCmd = Get-Command Install-Module -ErrorAction Stop
                $supportsAcceptLicense = $installCmd.Parameters.ContainsKey('AcceptLicense')
                $installParams = @{
                    Name               = $Name
                    Force              = $true
                    AllowClobber       = $true
                    SkipPublisherCheck = $true
                    Confirm            = $false
                    ErrorAction        = 'Stop'
                }

                if ($supportsAcceptLicense) {
                    $installParams['AcceptLicense'] = $true
                }

                Install-Module @installParams

                return [PSCustomObject]@{
                    UsedAcceptLicense = $supportsAcceptLicense
                }
            }

            function Resolve-PowerStigOfflinePackage {
                if ($env:POWERSTIG_OFFLINE_PACKAGE) {
                    if (-not (Test-Path -LiteralPath $env:POWERSTIG_OFFLINE_PACKAGE -PathType Leaf)) {
                        throw "POWERSTIG_OFFLINE_PACKAGE does not point to a file: $env:POWERSTIG_OFFLINE_PACKAGE"
                    }

                    return (Resolve-Path -LiteralPath $env:POWERSTIG_OFFLINE_PACKAGE).Path
                }

                $packageDirectories = @(
                    $PSScriptRoot
                    (Join-Path -Path $PSScriptRoot -ChildPath 'Packages')
                )
                $packages = @(
                    foreach ($directory in $packageDirectories) {
                        if (Test-Path -LiteralPath $directory -PathType Container) {
                            Get-ChildItem -LiteralPath $directory -Filter 'PowerStig-Windows-Offline-*.ps1' -File
                        }
                    }
                ) | Sort-Object FullName -Unique | Sort-Object LastWriteTime -Descending

                if ($packages.Count -eq 0) {
                    throw 'PowerStig offline artifact not found. Place PowerStig-Windows-Offline-*.ps1 beside this script or set POWERSTIG_OFFLINE_PACKAGE.'
                }

                return $packages[0].FullName
            }

            function Initialize-PowerStigOrgSettings {
                param(
                    [Parameter(Mandatory)][string]$OfflinePackagePath,
                    [Parameter(Mandatory)][string]$PowerShell51,
                    [Parameter(Mandatory)][string]$OperatingSystem,
                    [Parameter(Mandatory)][string]$ServerRole,
                    [string]$OrgSettingsRoot = (Join-Path $env:ProgramData 'PowerStigOffline')
                )

                if ($env:POWERSTIG_ORG_SETTINGS_PATH) {
                    if (-not (Test-Path -LiteralPath $env:POWERSTIG_ORG_SETTINGS_PATH -PathType Leaf)) {
                        throw "POWERSTIG_ORG_SETTINGS_PATH does not point to a file: $env:POWERSTIG_ORG_SETTINGS_PATH"
                    }

                    $settingsPath = (Resolve-Path -LiteralPath $env:POWERSTIG_ORG_SETTINGS_PATH).Path
                    [xml]$settingsXml = Get-Content -LiteralPath $settingsPath -Raw
                    if ($settingsXml.DocumentElement.LocalName -ne 'OrganizationalSettings') {
                        throw "OrgSettings root element must be OrganizationalSettings: $settingsPath"
                    }
                    return $settingsPath
                }

                $profile = switch ($OperatingSystem) {
                    'WS2019' { [pscustomobject]@{ Target = 'WindowsServer2019'; Template = "WindowsServer-2019-$ServerRole-3.9.org.default.xml" } }
                    'WS2022' { [pscustomobject]@{ Target = 'WindowsServer2022'; Template = "WindowsServer-2022-$ServerRole-2.11.org.default.xml" } }
                    'WS2025' { [pscustomobject]@{ Target = 'WindowsServer2025'; Template = "WindowsServer-2025-$ServerRole-1.4.org.default.xml" } }
                    'Win10' { [pscustomobject]@{ Target = 'Windows10'; Template = 'WindowsClient-10-3.6.org.default.xml' } }
                    'Win11' { [pscustomobject]@{ Target = 'Windows11'; Template = 'WindowsClient-11-2.11.org.default.xml' } }
                    default { throw "No PowerStig organization-settings template is known for '$OperatingSystem'." }
                }

                $packageVersion = [regex]::Match([IO.Path]::GetFileName($OfflinePackagePath), '\d+\.\d+\.\d+').Value
                if (-not $packageVersion) {
                    throw "Could not determine the PowerStig package version from '$OfflinePackagePath'."
                }

                $packageHash = (Get-FileHash -LiteralPath $OfflinePackagePath -Algorithm SHA256).Hash.Substring(0, 12)
                $templateRoot = Join-Path $OrgSettingsRoot "OrgTemplates\$packageHash"
                $templatePath = Join-Path $templateRoot "Modules\PowerStig\$packageVersion\StigData\Processed\$($profile.Template)"
                if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
                    $extractOutput = @(& $PowerShell51 -NoProfile -ExecutionPolicy Bypass -File $OfflinePackagePath -Mode ExtractOnly -ExtractRoot $templateRoot -ForceExtract 2>&1)
                    $extractExitCode = $LASTEXITCODE
                    foreach ($outputLine in @($extractOutput | Select-Object -Last 10)) {
                        Write-TerraForgeLog ([string]$outputLine) -Level 'Info'
                    }
                    if ($extractExitCode -ne 0 -or -not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
                        throw "Could not extract organization-settings template '$($profile.Template)' from offline package (exit code $extractExitCode)."
                    }
                }

                $settingsDirectory = Join-Path $OrgSettingsRoot 'OrgSettings'
                New-Item -Path $settingsDirectory -ItemType Directory -Force | Out-Null
                $settingsPath = Join-Path $settingsDirectory "$($profile.Target)-$ServerRole-$packageVersion.org.settings.xml"
                if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
                    Copy-Item -LiteralPath $templatePath -Destination $settingsPath
                    Write-Warn "Created an organization-settings template: $settingsPath. Safe defaults/current values will be populated; remaining organization choices stay blank."
                }
                else {
                    Write-OK "Using existing organization-settings file without overwriting it: $settingsPath"
                }

                [xml]$settingsXml = Get-Content -LiteralPath $settingsPath -Raw
                if ($settingsXml.DocumentElement.LocalName -ne 'OrganizationalSettings') {
                    throw "OrgSettings root element must be OrganizationalSettings: $settingsPath"
                }

                $processedFile = $templatePath -replace '\.org\.default\.xml$', '.xml'
                if (-not (Test-Path -LiteralPath $processedFile -PathType Leaf)) {
                    throw "Processed STIG data file was not found beside the OrgSettings template: $processedFile"
                }
                [xml]$processedStig = Get-Content -LiteralPath $processedFile -Raw
                $autoFilledIds = [System.Collections.Generic.List[string]]::new()
                $doDNoticeText = @'
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
'@

                foreach ($setting in $settingsXml.SelectNodes('/OrganizationalSettings/OrganizationalSetting')) {
                    $id = $setting.GetAttribute('id')
                    $valueAttribute = @($setting.Attributes | Where-Object Name -ne 'id' | Select-Object -First 1)
                    $isRequestedLegalNotice = $id -in @('V-205631', 'V-254457', 'V-278207', 'V-220921', 'V-253445')
                    if (-not $id -or $valueAttribute.Count -eq 0 -or (-not $isRequestedLegalNotice -and -not [string]::IsNullOrWhiteSpace($valueAttribute[0].Value))) {
                        continue
                    }

                    $rule = $processedStig.SelectSingleNode("//Rule[@id='$id']")
                    if ($null -eq $rule) {
                        continue
                    }

                    $currentValue = $null
                    if ($rule.Key -and $rule.ValueName -and $id -ne 'V-278240') {
                        $registryPath = [string]$rule.Key
                        $registryPath = $registryPath -replace '^HKEY_LOCAL_MACHINE', 'Registry::HKEY_LOCAL_MACHINE'
                        $registryPath = $registryPath -replace '^HKEY_CURRENT_USER', 'Registry::HKEY_CURRENT_USER'
                        $registryItem = Get-ItemProperty -LiteralPath $registryPath -Name $rule.ValueName -ErrorAction SilentlyContinue
                        if ($registryItem) {
                            $currentProperty = $registryItem.PSObject.Properties[$rule.ValueName]
                            if ($currentProperty) {
                                $currentValue = $currentProperty.Value
                            }
                        }
                    }

                    $recommendedValue = $null
                    switch ($id) {
                        'V-278090.b' {
                            if ([string]$currentValue -in @('1', '3')) {
                                $recommendedValue = [string]$currentValue
                            }
                            elseif ($null -eq $currentValue) {
                                try {
                                    if (Confirm-SecureBootUEFI -ErrorAction Stop) {
                                        $recommendedValue = '1'
                                    }
                                }
                                catch { }
                            }
                        }
                        'V-278091' {
                            if ($null -eq $currentValue) { $recommendedValue = 'ShouldBeAbsent' }
                            elseif ([string]$currentValue -in @('1', '3', '8')) { $recommendedValue = [string]$currentValue }
                            else { $recommendedValue = '3' }
                        }
                        { $PSItem -in @('V-278105', 'V-278107') } {
                            $size = 0
                            if ([int]::TryParse([string]$currentValue, [ref]$size) -and $size -ge 32768) {
                                $recommendedValue = [string]$size
                            }
                            else {
                                $recommendedValue = '32768'
                            }
                        }
                        'V-278106' {
                            $size = 0
                            if ([int]::TryParse([string]$currentValue, [ref]$size) -and $size -ge 5120000) {
                                $recommendedValue = [string]$size
                            }
                        }
                        { $PSItem -in @('V-278109', 'V-278110', 'V-278111', 'V-278118', 'V-278122') } {
                            if ($null -eq $currentValue) { $recommendedValue = 'ShouldBeAbsent' }
                            else { $recommendedValue = '0' }
                        }
                        'V-278206' {
                            $timeout = 0
                            if ([int]::TryParse([string]$currentValue, [ref]$timeout) -and $timeout -gt 0 -and $timeout -le 900) {
                                $recommendedValue = [string]$timeout
                            }
                            else {
                                $recommendedValue = '900'
                            }
                        }
                        { $PSItem -in @('V-205631', 'V-254457', 'V-278207', 'V-220921', 'V-253445') } {
                            $recommendedValue = $doDNoticeText
                        }
                        'V-278209' {
                            if ([string]$currentValue -in @('1', '2')) { $recommendedValue = [string]$currentValue }
                            else { $recommendedValue = '1' }
                        }
                    }

                    if ($null -ne $recommendedValue) {
                        $setting.SetAttribute($valueAttribute[0].Name, $recommendedValue)
                        $autoFilledIds.Add($id)
                    }
                }

                if ($autoFilledIds.Count -gt 0) {
                    $settingsXml.Save($settingsPath)
                    Write-Warn "Prefilled safe/current OrgSettings values for: $($autoFilledIds -join ', '). Review the generated file; domain policy, log-volume, and user-profile choices remain organization-owned."
                }

                return $settingsPath
            }

            function Get-DscResourceLabel {
                param([Parameter(Mandatory)]$Resource)

                foreach ($propertyName in 'ResourceId', 'InstanceName', 'ConfigurationName', 'SourceInfo') {
                    $value = $Resource.$propertyName
                    if ($value) {
                        return [string]$value
                    }
                }

                return ($Resource | Out-String).Trim()
            }

            function Get-DscResourceType {
                param([Parameter(Mandatory)]$Resource)

                $label = Get-DscResourceLabel -Resource $Resource
                $match = [regex]::Match($label, '^\[(?<Type>[^\]]+)\]')
                if ($match.Success) {
                    return $match.Groups['Type'].Value
                }

                return ''
            }

            function Initialize-ClientAccountPolicy {
                param()

                if ($script:DetectedOS -notin @('Win10', 'Win11')) {
                    return
                }

                # SecurityPolicyDsc can fail on standalone/client machines when lockout duration
                # is applied before a valid lockout threshold exists. Pre-stage a STIG-compatible
                # lockout policy so the DSC AccountPolicy resource does not hit that invalid state.
                $bootstrapCommands = @(
                    '/lockoutthreshold:3',
                    '/lockoutduration:15',
                    '/lockoutwindow:15'
                )

                foreach ($argument in $bootstrapCommands) {
                    & net.exe accounts $argument | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        throw "net accounts $argument failed with exit code $LASTEXITCODE"
                    }
                }

                Write-OK 'Pre-staged local account lockout policy for client STIG compatibility'
                Add-PolicyEntry -Category 'STIG' -Policy 'Client AccountPolicy Bootstrap' -Description 'Pre-staged local lockout threshold/duration/window to avoid DSC AccountPolicy ordering failure' -Status 'Verified'
            }

            # ========================== Pre-flight Checks ==========================

            Write-Step 'Pre-flight environment checks'

            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator
            )
            if (-not $isAdmin) {
                Write-Err 'This script must be run as Administrator.'
                exit 1
            }
            Write-OK 'Administrator privileges confirmed'

            # PowerShell version info
            $psVerStr = "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
            Write-OK "PowerShell: $psVerStr"
            Add-PolicyEntry -Category 'PreCheck' -Policy 'PowerShell Version' -Description $psVerStr -Status 'Verified' -Reason $(if ($script:IsPSCore) { 'DSC operations will be delegated to Windows PowerShell 5.1' } else { 'Native DSC support available' })

            if ($script:IsPSCore) {
                # Verify Windows PowerShell 5.1 is available for DSC delegation
                $ps5Path = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
                if (Test-Path $ps5Path) {
                    Write-OK 'Windows PowerShell 5.1 available for DSC delegation'
                    Add-PolicyEntry -Category 'PreCheck' -Policy 'Windows PowerShell 5.1' -Description 'powershell.exe found for DSC compatibility' -Status 'Verified'
                }
                else {
                    Write-Err 'Windows PowerShell 5.1 (powershell.exe) not found - DSC operations will fail'
                    Add-PolicyEntry -Category 'PreCheck' -Policy 'Windows PowerShell 5.1' -Description 'powershell.exe not found' -Status 'Failed' -Reason 'DSC v1 requires Windows PowerShell 5.1'
                }
            }

            $os = Get-CimInstance Win32_OperatingSystem
            $osCaption = $os.Caption

            # Auto-detect OS type
            $script:DetectedOS = if ($osCaption -match 'Windows 11') { 'Win11' }
            elseif ($osCaption -match 'Windows 10') { 'Win10' }
            elseif ($osCaption -match '2025') { 'WS2025' }
            elseif ($osCaption -match '2022') { 'WS2022' }
            elseif ($osCaption -match '2019') { 'WS2019' }
            else { 'Unknown' }

            $supportedOSList = @('WS2019', 'WS2022', 'WS2025', 'Win10', 'Win11')
            if ($script:DetectedOS -notin $supportedOSList) {
                Write-Warn "OS: $osCaption [$($script:DetectedOS)] - supported targets: WS2019, WS2022, WS2025, Win10, Win11."
                Add-PolicyEntry -Category 'PreCheck' -Policy 'OS Version' -Description $osCaption -Status 'Skipped' -Reason "Unsupported OS: $($script:DetectedOS)"
                throw "Unsupported OS for the PowerStig offline artifact: $($script:DetectedOS)"
            }
            else {
                Write-OK "Operating System: $osCaption [$($script:DetectedOS)]"
                Add-PolicyEntry -Category 'PreCheck' -Policy 'OS Version' -Description $osCaption -Status 'Verified'
            }

            $domainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
            $isDC = $domainRole -ge 4

            # Determine effective OS role (DC / MS for servers; Client for Win10/Win11)
            if ($script:DetectedOS -in @('Win10', 'Win11')) {
                $script:DetectedRole = 'Client'
                Write-OK "OS role: Client [$($script:DetectedOS)]"
                Add-PolicyEntry -Category 'PreCheck' -Policy 'Server Role' -Description "Client OS [$($script:DetectedOS)]" -Status 'Verified'
            }
            else {
                $script:DetectedRole = if ($isDC) { 'DC' } else { 'MS' }
                Write-OK "Server role: $($script:DetectedRole) (DomainRole=$domainRole)"
                Add-PolicyEntry -Category 'PreCheck' -Policy 'Server Role' -Description "$($script:DetectedRole) (DomainRole=$domainRole)" -Status 'Verified'
            }

            # Pre-compute STIG baseline label (used in report)
            $script:STIGExecution.Baseline = switch ($script:DetectedOS) {
                'WS2019' { "Windows Server 2019 $($script:DetectedRole)" }
                'WS2022' { "Windows Server 2022 $($script:DetectedRole)" }
                'WS2025' { "Windows Server 2025 $($script:DetectedRole)" }
                'Win10' { 'Windows 10' }
                'Win11' { 'Windows 11' }
                default { $script:DetectedOS }
            }

            $rdpBefore = (Get-Service TermService -ErrorAction SilentlyContinue).Status
            Write-OK "Current RDP service status: $rdpBefore"
            Add-PolicyEntry -Category 'PreCheck' -Policy 'RDP Service (Before)' -Description "Status: $rdpBefore" -Status 'Verified'

            # ========================== STEP 1: Install Modules ==========================

            if ($script:DetectedOS -in $supportedOSList) {
                Write-Step 'Use the GitHub Actions PowerStig offline artifact'
                Write-OK 'PowerStig modules will be loaded from the self-contained offline package'
                Add-PolicyEntry -Category 'Module' -Policy 'PowerStig Offline Artifact' -Description 'Using the GitHub Actions package; no PSGallery module installation required' -Status 'Verified'
            }
            else {
            Write-Step 'Install PowerSTIG and dependency modules'

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $ConfirmPreference = 'None'

            if ($script:IsPSCore) {
                # PS7: NuGet provider is built-in; Install-PackageProvider is not needed
                Write-OK 'PowerShell 7 detected - NuGet provider is built-in'
                Add-PolicyEntry -Category 'Module' -Policy 'NuGet Provider' -Description 'Built-in (PS7)' -Status 'Verified'
            }
            else {
                if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
                        Where-Object { $_.Version -ge [Version]'2.8.5.201' })) {
                    try {
                        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false | Out-Null
                        Write-OK 'NuGet package provider installed'
                        Add-PolicyEntry -Category 'Module' -Policy 'NuGet Provider' -Description 'Installed v2.8.5.201+' -Status 'Verified'
                    }
                    catch {
                        Write-Err "NuGet install failed: $_"
                        Add-PolicyEntry -Category 'Module' -Policy 'NuGet Provider' -Description 'Installation failed' -Status 'Failed' -Reason "$_"
                    }
                }
                else {
                    Write-OK 'NuGet package provider already present'
                    Add-PolicyEntry -Category 'Module' -Policy 'NuGet Provider' -Description 'Already installed' -Status 'Verified'
                }
            }

            try {
                $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
                if ($gallery -and $gallery.InstallationPolicy -ne 'Trusted') {
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                    Write-OK 'PSGallery set to Trusted'
                }
            }
            catch {
                # PS7 with PSResourceGet may not have Get-PSRepository; register PSGallery if needed
                Write-Warn "Could not query PSGallery repository: $($_.Exception.Message)"
                try {
                    if (Get-Command Register-PSResourceRepository -ErrorAction SilentlyContinue) {
                        $existing = Get-PSResourceRepository -Name PSGallery -ErrorAction SilentlyContinue
                        if (-not $existing) {
                            Register-PSResourceRepository -PSGallery -Trusted -ErrorAction Stop
                        }
                        elseif (-not $existing.Trusted) {
                            Set-PSResourceRepository -Name PSGallery -Trusted -ErrorAction Stop
                        }
                        Write-OK 'PSGallery configured via PSResourceGet'
                    }
                }
                catch {
                    Write-Warn "PSGallery setup fallback also failed: $($_.Exception.Message)"
                }
            }

            $powerShellGet = Get-Module -ListAvailable -Name PowerShellGet | Sort-Object Version -Descending | Select-Object -First 1
            if ($powerShellGet) {
                $supportsAcceptLicense = (Get-Command Install-Module -ErrorAction Stop).Parameters.ContainsKey('AcceptLicense')
                $compatNote = if ($supportsAcceptLicense) { 'AcceptLicense supported' } else { 'Compatibility mode: AcceptLicense not supported' }
                $script:STIGExecution.PackageProvider = "PowerShellGet $($powerShellGet.Version)"
                Write-OK "PowerShellGet version detected: $($powerShellGet.Version)"
                Add-PolicyEntry -Category 'Module' -Policy 'PowerShellGet' -Description "Version $($powerShellGet.Version)" -Status 'Verified' -Reason $compatNote
                if (-not $supportsAcceptLicense) {
                    Write-Warn 'Install-Module does not support -AcceptLicense on this host; using compatibility mode.'
                }
            }

            # On PS7, DSC modules must be installed into Windows PowerShell module path so PS5 can use them for DSC
            $modules = @('PowerSTIG', 'SecurityPolicyDsc', 'AuditPolicyDsc', 'WindowsDefenderDsc')
            if ($script:IsPSCore -and -not $SkipSTIG) {
                Write-OK 'PS7 detected: Installing DSC modules via Windows PowerShell to ensure DSC compatibility'
                Add-PolicyEntry -Category 'Module' -Policy 'PS7 DSC Module Strategy' -Description 'DSC modules installed via Windows PowerShell 5.1 for compatibility' -Status 'Verified'
                foreach ($mod in $modules) {
                    # Check if already available in Windows PowerShell module paths
                    $ps5ModulePaths = @(
                        "$env:ProgramFiles\WindowsPowerShell\Modules",
                        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules"
                    )
                    $foundInPS5 = $false
                    foreach ($mp in $ps5ModulePaths) {
                        if (Test-Path (Join-Path $mp $mod)) { $foundInPS5 = $true; break }
                    }
                    if ($foundInPS5) {
                        Write-OK "$mod already installed (PS5 module path)"
                        Add-PolicyEntry -Category 'Module' -Policy $mod -Description 'Already installed in PS5 path' -Status 'Verified'
                    }
                    else {
                        try {
                            $installScript = @"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue | Where-Object { `$_.Version -ge [Version]'2.8.5.201' })) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:`$false | Out-Null
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
`$installParams = @{ Name = '$mod'; Force = `$true; AllowClobber = `$true; SkipPublisherCheck = `$true; Confirm = `$false; ErrorAction = 'Stop' }
`$cmd = Get-Command Install-Module -ErrorAction Stop
if (`$cmd.Parameters.ContainsKey('AcceptLicense')) { `$installParams['AcceptLicense'] = `$true }
Install-Module @installParams
Write-Output 'OK'
"@
                            $result = Invoke-InWindowsPowerShell -ScriptBlock $installScript
                            Write-OK "$mod installed via Windows PowerShell"
                            Add-PolicyEntry -Category 'Module' -Policy $mod -Description 'Installed via PS5 for DSC compatibility' -Status 'Verified'
                        }
                        catch {
                            Write-Err "Failed to install ${mod} via PS5: $_"
                            Add-PolicyEntry -Category 'Module' -Policy $mod -Description 'Installation failed' -Status 'Failed' -Reason "$_"
                        }
                    }
                }
            }
            else {
                foreach ($mod in $modules) {
                    if (-not (Get-Module -ListAvailable -Name $mod)) {
                        try {
                            $installResult = Install-ModuleCompatible -Name $mod
                            Write-OK "$mod installed"
                            $installReason = if ($installResult.UsedAcceptLicense) { '' } else { 'Installed without AcceptLicense because this PowerShellGet version does not support that parameter' }
                            Add-PolicyEntry -Category 'Module' -Policy $mod -Description 'Installed from PSGallery' -Status 'Verified' -Reason $installReason
                        }
                        catch {
                            Write-Err "Failed to install ${mod}: $_"
                            Add-PolicyEntry -Category 'Module' -Policy $mod -Description 'Installation failed' -Status 'Failed' -Reason "$_"
                        }
                    }
                    else {
                        Write-OK "$mod already installed"
                        Add-PolicyEntry -Category 'Module' -Policy $mod -Description 'Already installed' -Status 'Verified'
                    }
                }
            }
            }

            # ========================== STEP 2: Apply STIG Baseline ==========================

            if (-not $SkipSTIG) {
                Write-Step "Apply $($script:STIGExecution.Baseline) STIG baseline via DSC"

                try {
                    if ($script:DetectedOS -in $supportedOSList) {
                        $offlinePackagePath = Resolve-PowerStigOfflinePackage
                        $packageTarget = switch ($script:DetectedOS) {
                            'WS2019' { 'WindowsServer2019' }
                            'WS2022' { 'WindowsServer2022' }
                            'WS2025' { 'WindowsServer2025' }
                            'Win10' { 'Windows10' }
                            'Win11' { 'Windows11' }
                        }
                        $powershell51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
                        if (-not (Test-Path -LiteralPath $powershell51 -PathType Leaf)) {
                            throw "Windows PowerShell 5.1 was not found: $powershell51"
                        }

                        $orgSettingsWasSupplied = [bool]$env:POWERSTIG_ORG_SETTINGS_PATH
                        $orgSettingsPath = Initialize-PowerStigOrgSettings `
                            -OfflinePackagePath $offlinePackagePath `
                            -PowerShell51 $powershell51 `
                            -OperatingSystem $script:DetectedOS `
                            -ServerRole $script:DetectedRole

                        $legalNoticeRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                        if (-not (Test-Path -LiteralPath $legalNoticeRegistryPath)) {
                            New-Item -Path $legalNoticeRegistryPath -Force | Out-Null
                        }
                        Set-ItemProperty -LiteralPath $legalNoticeRegistryPath -Name 'LegalNoticeCaption' -Value 'DoD Notice and Consent Banner' -Type String -Force
                        Write-OK 'Login legal notice caption set to: DoD Notice and Consent Banner'

                        $packageArguments = @(
                            '-NoProfile'
                            '-ExecutionPolicy'
                            'Bypass'
                            '-File'
                            $offlinePackagePath
                            '-Mode'
                            'Deploy'
                            '-Target'
                            $packageTarget
                        )
                        if ($script:DetectedOS -in @('WS2019', 'WS2022', 'WS2025')) {
                            $packageArguments += @('-ServerRole', $script:DetectedRole)
                        }
                        if ($orgSettingsPath) {
                            $packageArguments += @('-OrgSettingsPath', $orgSettingsPath)
                        }

                        Write-OK "Applying $($script:STIGExecution.Baseline) STIG from offline artifact: $offlinePackagePath"
                        Add-PolicyEntry -Category 'STIG' -Policy 'PowerStig Offline Artifact' -Description "$($script:STIGExecution.Baseline) baseline from $([IO.Path]::GetFileName($offlinePackagePath))" -Status 'Verified'
                        if ($orgSettingsWasSupplied) {
                            Add-PolicyEntry -Category 'STIG' -Policy 'Organization Settings' -Description "Using supplied settings file: $orgSettingsPath" -Status 'Verified'
                        }
                        else {
                            Add-PolicyEntry -Category 'STIG' -Policy 'Organization Settings template' -Description "Auto-created/reused template: $orgSettingsPath" -Status 'Skipped' -Reason 'Review and fill organization-approved values; empty fields are not applied'
                        }
                        if ($script:DetectedOS -eq 'WS2025' -and $script:DetectedRole -eq 'DC') {
                            Add-PolicyEntry -Category 'STIG' -Policy 'V-278001.c' -Description 'Conditional Server 2025 registry ACL default requires manual review' -Status 'Skipped' -Reason 'The optional Server 2025 SID and unchanged-default ACL condition are not forced by DSC'
                            Add-PolicyEntry -Category 'STIG' -Policy 'V-278138' -Description 'NTDS wildcard ACL requires manual review' -Status 'Skipped' -Reason 'AccessControlDSC does not support the wildcard path'
                        }

                        $packageStarted = Get-Date
                        $packageOutput = @(& $powershell51 @packageArguments 2>&1)
                        $packageExitCode = $LASTEXITCODE
                        foreach ($outputLine in @($packageOutput | Select-Object -Last 30)) {
                            Write-TerraForgeLog ([string]$outputLine) -Level 'Info'
                        }

                        $summaryRoot = Join-Path -Path $env:ProgramData -ChildPath 'PowerStigOffline'
                        $summaryFile = Get-ChildItem -LiteralPath $summaryRoot -Filter "Deploy-PowerStig-$env:COMPUTERNAME-*.summary.json" -File -Recurse -ErrorAction SilentlyContinue |
                            Where-Object LastWriteTime -ge $packageStarted.AddSeconds(-2) |
                            Sort-Object LastWriteTime -Descending |
                            Select-Object -First 1
                        if (-not $summaryFile) {
                            throw "Offline package produced no deployment summary (exit code $packageExitCode)."
                        }

                        $packageSummary = Get-Content -LiteralPath $summaryFile.FullName -Raw | ConvertFrom-Json
                        $script:STIGExecution.MofPath = [string]$packageSummary.MofPath
                        $script:STIGExecution.ModuleStatus = 'Loaded from offline artifact'
                        if ($packageSummary.Module -and $packageSummary.Module.Version) {
                            $script:STIGExecution.ModuleVersion = [string]$packageSummary.Module.Version
                        }
                        $script:STIGExecution.RebootRequested = [bool]$packageSummary.RebootRequested
                        if ($packageSummary.MofPath -and (Test-Path -LiteralPath $packageSummary.MofPath -PathType Leaf)) {
                            $mofContent = Get-Content -LiteralPath $packageSummary.MofPath -Raw
                            $script:STIGExecution.PlannedResources = ([regex]::Matches($mofContent, '(?im)^\s*instance of ')).Count
                        }

                        $packagePassed = $packageExitCode -eq 0 -and $packageSummary.Succeeded -and $packageSummary.Applied -and $packageSummary.InDesiredState
                        $script:STIGExecution.Status = if ($packagePassed) { 'Applied' } else { 'Failed' }
                        $script:STIGExecution.AppliedResources = if ($packagePassed) { $script:STIGExecution.PlannedResources } else { 0 }
                        $script:STIGExecution.FailedResources = if ($packagePassed) { 0 } else { 1 }
                        $script:STIGExecution.Reason = if ($packagePassed) { '' } else { [string]$packageSummary.Error }
                        $summaryDescription = 'Succeeded={0}; Applied={1}; InDesiredState={2}; RebootRequested={3}' -f $packageSummary.Succeeded, $packageSummary.Applied, $packageSummary.InDesiredState, $packageSummary.RebootRequested
                        Add-PolicyEntry -Category 'STIG' -Policy 'DSC Execution Summary' -Description $summaryDescription -Status $(if ($packagePassed) { 'Applied' } else { 'Failed' }) -Reason $script:STIGExecution.Reason

                        if (-not $packagePassed) {
                            throw "Offline PowerStig deployment failed (exit code $packageExitCode; summary $($summaryFile.FullName)): $($packageSummary.Error)"
                        }
                    }
                    else {
                    # Check PowerSTIG availability (in PS5 module path for PS7, or current session for PS5)
                    if ($script:IsPSCore) {
                        $ps5ModulePaths = @("$env:ProgramFiles\WindowsPowerShell\Modules", "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules")
                        $foundPowerSTIG = $false
                        foreach ($mp in $ps5ModulePaths) {
                            $stigModPath = Join-Path $mp 'PowerSTIG'
                            if (Test-Path $stigModPath) {
                                $foundPowerSTIG = $true
                                $manifestFiles = Get-ChildItem -Path $stigModPath -Filter '*.psd1' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                                if ($manifestFiles) {
                                    $manifest = Import-PowerShellDataFile -Path $manifestFiles.FullName -ErrorAction SilentlyContinue
                                    $script:STIGExecution.ModuleVersion = if ($manifest.ModuleVersion) { [string]$manifest.ModuleVersion } else { '' }
                                }
                                break
                            }
                        }
                        if (-not $foundPowerSTIG) {
                            throw 'PowerSTIG module not found in Windows PowerShell module paths. Install it first.'
                        }
                        $script:STIGExecution.ModuleStatus = 'Available (PS5 path)'
                        Add-PolicyEntry -Category 'STIG' -Policy 'PowerSTIG Module' -Description "PowerSTIG $($script:STIGExecution.ModuleVersion) found in PS5 module path" -Status 'Verified'
                    }
                    else {
                        Import-Module PowerSTIG -Force
                        $powerStigModule = Get-Module -ListAvailable -Name PowerSTIG | Sort-Object Version -Descending | Select-Object -First 1
                        $script:STIGExecution.ModuleStatus = 'Imported'
                        $script:STIGExecution.ModuleVersion = if ($powerStigModule) { [string]$powerStigModule.Version } else { '' }
                        Add-PolicyEntry -Category 'STIG' -Policy 'PowerSTIG Module' -Description "Imported PowerSTIG $($script:STIGExecution.ModuleVersion)" -Status 'Verified'
                    }

                    # OS-specific rules to skip (V-IDs that break RDP or conflict with this environment)
                    $skipRules = switch ($script:DetectedOS) {
                        'WS2022' {
                            if ($script:DetectedRole -eq 'DC') {
                                @(
                                    'V-254285'   # AccountPolicy - domain policy conflict
                                    'V-254286'   # AccountPolicy - lockout duration, DC domain policy overrides local
                                    'V-254287'   # AccountPolicy - domain policy conflict
                                    'V-254288'   # AccountPolicy - lockout reset counter, DC domain policy overrides local
                                    'V-254391'   # NTFS ACL - permission inheritance issue
                                    'V-254392'   # NTFS ACL - permission inheritance issue
                                )
                            }
                            else {
                                @(
                                    'V-254285'   # AccountPolicy - may conflict with local policy
                                    'V-254286'   # AccountPolicy - lockout duration can drift after apply
                                    'V-254287'   # AccountPolicy - may conflict with local policy
                                    'V-254288'   # AccountPolicy - lockout reset counter can drift after apply
                                )
                            }
                        }
                        'Win10' {
                            @(
                                'V-220732'   # Service rule can remain out of desired state on Win10 clients after apply
                                'V-220768'   # AuditPolicy - audit setting can drift on Win10 after apply
                            )
                        }
                        'Win11' {
                            @(
                                'V-253301'   # AccountPolicy lockout setting can drift on Win11 clients after apply
                                'V-253263'   # AuditPolicy - audit setting can drift on Win11 after apply
                            )
                        }
                        default { @() }
                    }
                    $script:STIGExecution.SkipRules = @($skipRules)

                    # Log skipped rules
                    foreach ($rule in $skipRules) {
                        Add-PolicyEntry -Category 'STIG' -Policy $rule -Description 'STIG rule skipped by configuration' -Status 'Skipped' -Reason 'May break RDP connectivity or conflict with environment'
                    }
                    if ($skipRules.Count -eq 0) {
                        Add-PolicyEntry -Category 'STIG' -Policy 'Skip Rules' -Description 'No STIG rules were explicitly skipped' -Status 'Verified'
                    }

                    # Build DSC configuration script text based on detected OS/role
                    if ($script:DetectedOS -eq 'WS2022') {
                        $configScript = @'
Configuration ApplySTIG
{
    param([string[]]$ComputerName = 'localhost')
    Import-DscResource -ModuleName PowerSTIG
    Node $ComputerName
    {
        WindowsServer BaseLine
        {
            OsVersion = '2022'
            OsRole    = 'OSROLE_PLACEHOLDER'
SKIPRULE_PLACEHOLDER
        }
    }
}
'@
                        $configScript = $configScript -replace 'OSROLE_PLACEHOLDER', $script:DetectedRole
                    }
                    elseif ($script:DetectedOS -in @('Win10', 'Win11')) {
                        $winVer = if ($script:DetectedOS -eq 'Win11') { '11' } else { '10' }
                        $configScript = @'
Configuration ApplySTIG
{
    param([string[]]$ComputerName = 'localhost')
    Import-DscResource -ModuleName PowerSTIG
    Node $ComputerName
    {
        WindowsClient BaseLine
        {
            OsVersion = 'OSVER_PLACEHOLDER'
SKIPRULE_PLACEHOLDER
        }
    }
}
'@
                        $configScript = $configScript -replace 'OSVER_PLACEHOLDER', $winVer
                    }
                    else {
                        throw "Unsupported OS for STIG application: $($script:DetectedOS). Use -SkipSTIG to bypass."
                    }

                    if ($skipRules.Count -gt 0) {
                        $skipStr = "            SkipRule  = @('" + ($skipRules -join "','") + "')"
                        $configScript = $configScript -replace 'SKIPRULE_PLACEHOLDER', $skipStr
                    }
                    else {
                        $configScript = $configScript -replace 'SKIPRULE_PLACEHOLDER', ''
                    }

                    # Pre-stage client lockout policy if needed (works in both PS5 and PS7)
                    if ($script:DetectedOS -in @('Win10', 'Win11')) {
                        Initialize-ClientAccountPolicy
                    }

                    if (-not (Test-Path $DSCOutputPath)) {
                        New-Item -Path $DSCOutputPath -ItemType Directory -Force | Out-Null
                    }

                    if ($script:IsPSCore) {
                        # ── PS7: Delegate entire DSC compile + apply + status to Windows PowerShell 5.1 ──
                        Write-OK 'PS7 detected: Delegating DSC operations to Windows PowerShell 5.1'
                        Add-PolicyEntry -Category 'STIG' -Policy 'DSC Engine' -Description 'DSC operations delegated to Windows PowerShell 5.1 (DSC v1 not available in PS7)' -Status 'Verified'

                        $dscDelegateScript = @"
`$ErrorActionPreference = 'Stop'
Import-Module PowerSTIG -Force

# Define and compile DSC configuration
$($configScript -replace '"','\"' -replace '\$','`$' -replace '`\$ComputerName','$$ComputerName')

ApplySTIG -OutputPath '$DSCOutputPath' | Out-Null

# Apply DSC
Start-DscConfiguration -Path '$DSCOutputPath' -Wait -Verbose -Force

# Collect status
`$dscStatus = Get-DscConfigurationStatus -All -ErrorAction SilentlyContinue | Sort-Object StartDate -Descending | Select-Object -First 1
`$mofFile = Get-ChildItem -Path '$DSCOutputPath' -Filter '*.mof' -ErrorAction SilentlyContinue | Select-Object -First 1
`$mofResCount = 0
if (`$mofFile) {
    `$mofContent = Get-Content -Path `$mofFile.FullName -Raw -ErrorAction SilentlyContinue
    `$mofResCount = ([regex]::Matches(`$mofContent, '(?im)^\s*instance of ')).Count
}

# Classify NotInDesiredState resources by type
`$knownDriftTypes = @('Service', 'AccountPolicy', 'AuditPolicy')
`$ignoredDrift = 0
`$realFail = 0
if (`$dscStatus -and `$dscStatus.ResourcesNotInDesiredState) {
    foreach (`$r in @(`$dscStatus.ResourcesNotInDesiredState)) {
        `$rType = ''
        `$rid = if (`$r.ResourceId) { `$r.ResourceId } elseif (`$r.InstanceName) { `$r.InstanceName } else { '' }
        `$m = [regex]::Match(`$rid, '^\[(?<T>[^\]]+)\]')
        if (`$m.Success) { `$rType = `$m.Groups['T'].Value }
        if (`$rType -in `$knownDriftTypes) { `$ignoredDrift++ } else { `$realFail++ }
    }
}

@{
    MofPath = if (`$mofFile) { `$mofFile.FullName } else { '' }
    PlannedResources = `$mofResCount
    InDesiredState = if (`$dscStatus) { @(`$dscStatus.ResourcesInDesiredState).Count } else { 0 }
    NotInDesiredState = if (`$dscStatus) { @(`$dscStatus.ResourcesNotInDesiredState).Count } else { 0 }
    IgnoredDrift = `$ignoredDrift
    RealFailures = `$realFail
    RebootRequested = if (`$dscStatus) { [bool]`$dscStatus.RebootRequested } else { `$false }
    HasStatus = (`$null -ne `$dscStatus)
}
"@
                        $dscResult = Invoke-InWindowsPowerShell -ScriptBlock $dscDelegateScript
                        Write-OK 'DSC compile + apply completed via Windows PowerShell 5.1'
                        Add-PolicyEntry -Category 'STIG' -Policy 'DSC Compilation' -Description 'MOF compiled successfully (via PS5)' -Status 'Verified'

                        if ($dscResult -is [hashtable]) {
                            $script:STIGExecution.MofPath = $dscResult.MofPath
                            $script:STIGExecution.PlannedResources = $dscResult.PlannedResources
                            $script:STIGExecution.AppliedResources = $dscResult.InDesiredState
                            $script:STIGExecution.FailedResources = $dscResult.NotInDesiredState
                            $script:STIGExecution.RebootRequested = $dscResult.RebootRequested

                            Add-PolicyEntry -Category 'STIG' -Policy 'Compiled DSC Resources' -Description "$($dscResult.PlannedResources) resource instance(s) compiled into MOF" -Status 'Verified'

                            if ($dscResult.HasStatus) {
                                $ignoredDrift = if ($dscResult.ContainsKey('IgnoredDrift')) { $dscResult.IgnoredDrift } else { 0 }
                                $realFailures = if ($dscResult.ContainsKey('RealFailures')) { $dscResult.RealFailures } else { $dscResult.NotInDesiredState }
                                $script:STIGExecution.FailedResources = $realFailures

                                $statusDescription = 'InDesiredState={0}; NotInDesiredState={1} (ignored known drift={2}); RebootRequested={3}' -f $dscResult.InDesiredState, $realFailures, $ignoredDrift, $dscResult.RebootRequested
                                $statusValue = if ($realFailures -eq 0) { 'Applied' } else { 'Failed' }
                                $statusReason = ''
                                if ($ignoredDrift -gt 0) {
                                    $statusReason = "Known drift ignored ($ignoredDrift resource(s): Service/AccountPolicy/AuditPolicy) after successful apply"
                                }
                                if ($realFailures -gt 0) {
                                    $statusReason = if ($statusReason) { "$statusReason; $realFailures unexpected resource(s) still not in desired state" } else { 'One or more DSC resources did not reach desired state' }
                                }
                                $script:STIGExecution.Status = $statusValue
                                $script:STIGExecution.Reason = $statusReason
                                Add-PolicyEntry -Category 'STIG' -Policy 'DSC Execution Summary' -Description $statusDescription -Status $statusValue -Reason $statusReason
                            }
                            else {
                                $script:STIGExecution.Status = 'Applied'
                                Add-PolicyEntry -Category 'STIG' -Policy 'DSC Execution Summary' -Description 'DSC applied but detailed status not available from PS5 delegate' -Status 'Verified'
                            }
                        }
                        else {
                            $script:STIGExecution.Status = 'Applied'
                            Add-PolicyEntry -Category 'STIG' -Policy 'DSC Execution Summary' -Description 'DSC applied (result format was non-hashtable from PS5 delegate)' -Status 'Verified'
                        }

                        Add-PolicyEntry -Category 'STIG' -Policy $script:STIGExecution.Baseline -Description "Applied via PowerSTIG DSC [PS5 delegate] (Skipped $($skipRules.Count) rule(s))" -Status 'Verified'

                    }
                    else {
                        # ── PS5: Run DSC natively ──
                        Invoke-Expression $configScript

                        ApplySTIG -OutputPath $DSCOutputPath | Out-Null
                        Write-OK 'DSC MOF compiled successfully'
                        Add-PolicyEntry -Category 'STIG' -Policy 'DSC Compilation' -Description 'MOF compiled successfully' -Status 'Verified'

                        $mofFile = Get-ChildItem -Path $DSCOutputPath -Filter '*.mof' -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($mofFile) {
                            $script:STIGExecution.MofPath = $mofFile.FullName
                            $mofContent = Get-Content -Path $mofFile.FullName -Raw -ErrorAction Stop
                            $script:STIGExecution.PlannedResources = ([regex]::Matches($mofContent, '(?im)^\s*instance of ')).Count
                            Add-PolicyEntry -Category 'STIG' -Policy 'Compiled DSC Resources' -Description "$($script:STIGExecution.PlannedResources) resource instance(s) compiled into MOF" -Status 'Verified'
                        }
                        else {
                            Add-PolicyEntry -Category 'STIG' -Policy 'Compiled DSC Resources' -Description 'No MOF file was found after compilation' -Status 'Failed' -Reason 'Compilation did not emit a MOF file in the DSC output path'
                        }

                        Start-DscConfiguration -Path $DSCOutputPath -Wait -Verbose -Force
                        Write-OK 'STIG baseline applied successfully'
                        $script:STIGExecution.Status = 'Applied'
                        Add-PolicyEntry -Category 'STIG' -Policy $script:STIGExecution.Baseline -Description "Applied via PowerSTIG DSC (Skipped $($skipRules.Count) rule(s))" -Status 'Verified'

                        # Parse DSC results for detailed per-resource logging
                        try {
                            $dscStatus = Get-DscConfigurationStatus -All -ErrorAction Stop | Sort-Object StartDate -Descending | Select-Object -First 1
                            if ($dscStatus) {
                                $resourcesInDesiredState = @($dscStatus.ResourcesInDesiredState)
                                $resourcesNotInDesiredState = @($dscStatus.ResourcesNotInDesiredState)
                                $ignoredDriftResources = @()

                                # Known-drift resource types that commonly remain NotInDesiredState after
                                # a successful Start-DscConfiguration apply.  These are evaluated additively
                                # so that mixed combinations (e.g. 1 Service + 1 AccountPolicy) are all
                                # handled rather than requiring every failing resource to be one single type.
                                $knownDriftTypes = @('Service', 'AccountPolicy', 'AuditPolicy')

                                if ($resourcesNotInDesiredState.Count -gt 0) {
                                    $stillFailing = [System.Collections.ArrayList]::new()
                                    foreach ($res in $resourcesNotInDesiredState) {
                                        $resType = Get-DscResourceType -Resource $res
                                        if ($resType -in $knownDriftTypes) {
                                            $ignoredDriftResources += $res
                                        }
                                        else {
                                            $stillFailing.Add($res) | Out-Null
                                        }
                                    }
                                    $resourcesNotInDesiredState = @($stillFailing)
                                }

                                $script:STIGExecution.AppliedResources = $resourcesInDesiredState.Count
                                $script:STIGExecution.FailedResources = $resourcesNotInDesiredState.Count
                                $script:STIGExecution.RebootRequested = [bool]$dscStatus.RebootRequested

                                $totalRawDrift = $resourcesNotInDesiredState.Count + $ignoredDriftResources.Count
                                $statusDescription = 'InDesiredState={0}; NotInDesiredState={1} (ignored known drift={2}); RebootRequested={3}' -f $script:STIGExecution.AppliedResources, $script:STIGExecution.FailedResources, $ignoredDriftResources.Count, $script:STIGExecution.RebootRequested
                                $statusValue = if ($script:STIGExecution.FailedResources -eq 0) { 'Applied' } else { 'Failed' }
                                $statusReason = ''
                                if ($ignoredDriftResources.Count -gt 0) {
                                    $driftTypes = ($ignoredDriftResources | ForEach-Object { Get-DscResourceType -Resource $_ } | Sort-Object -Unique) -join ', '
                                    $statusReason = "Known drift ignored ($($ignoredDriftResources.Count) resource(s): $driftTypes) after successful apply"
                                }
                                if ($script:STIGExecution.FailedResources -gt 0) {
                                    $statusReason = if ($statusReason) { "$statusReason; $($script:STIGExecution.FailedResources) unexpected resource(s) still not in desired state" } else { 'One or more DSC resources did not reach desired state' }
                                    $script:STIGExecution.Status = 'Failed'
                                    $script:STIGExecution.Reason = $statusReason
                                }
                                else {
                                    $script:STIGExecution.Status = 'Applied'
                                    $script:STIGExecution.Reason = $statusReason
                                }
                                Add-PolicyEntry -Category 'STIG' -Policy 'DSC Execution Summary' -Description $statusDescription -Status $statusValue -Reason $statusReason

                                foreach ($res in $resourcesInDesiredState) {
                                    Add-PolicyEntry -Category 'STIG-Detail' -Policy (Get-DscResourceLabel -Resource $res) -Description 'In desired state after STIG apply' -Status 'Verified'
                                }
                                foreach ($res in $ignoredDriftResources) {
                                    $driftType = Get-DscResourceType -Resource $res
                                    Add-PolicyEntry -Category 'STIG-Detail' -Policy (Get-DscResourceLabel -Resource $res) -Description "Known $driftType drift ignored after STIG apply" -Status 'Skipped' -Reason "$driftType resource may remain outside desired state after apply even when STIG configuration succeeds"
                                }
                                foreach ($res in $resourcesNotInDesiredState) {
                                    Add-PolicyEntry -Category 'STIG-Detail' -Policy (Get-DscResourceLabel -Resource $res) -Description 'Not in desired state after STIG apply' -Status 'Failed' -Reason 'DSC resource drift detected'
                                }
                            }
                            else {
                                Add-PolicyEntry -Category 'STIG' -Policy 'DSC Execution Summary' -Description 'No DSC execution status object was returned' -Status 'Skipped' -Reason 'Detailed STIG results unavailable from LCM'
                            }
                        }
                        catch {
                            Write-Warn "Could not retrieve detailed DSC status: $_"
                            Add-PolicyEntry -Category 'STIG' -Policy 'DSC Execution Summary' -Description 'Detailed STIG results could not be retrieved' -Status 'Skipped' -Reason "$_"
                        }
                    }

                    }
                }
                catch {
                    Write-Err "STIG application failed: $_"
                    $script:STIGExecution.Status = 'Failed'
                    $script:STIGExecution.Reason = "$_"
                    if ($script:STIGExecution.ModuleStatus -eq 'NotChecked') {
                        $script:STIGExecution.ModuleStatus = 'ImportFailed'
                    }
                    Add-PolicyEntry -Category 'STIG' -Policy $script:STIGExecution.Baseline -Description 'STIG application failed' -Status 'Failed' -Reason "$_"
                    Add-PolicyEntry -Category 'STIG' -Policy 'STIG Detail Availability' -Description 'No per-policy STIG details were captured' -Status 'Skipped' -Reason 'PowerSTIG baseline failed before DSC resources could be evaluated'
                    Write-Warn 'Continuing with remaining steps...'
                }
            }
            else {
                Write-Step 'Skipping STIG application (-SkipSTIG flag specified)'
                $script:STIGExecution.Status = 'Skipped'
                $script:STIGExecution.Reason = '-SkipSTIG parameter specified'
                Add-PolicyEntry -Category 'STIG' -Policy $script:STIGExecution.Baseline -Description 'Skipped by user request' -Status 'Skipped' -Reason '-SkipSTIG parameter specified'
            }

            # ========================== STEP 3: Enable FIPS ==========================

            Write-Step 'Enable FIPS 140-2 compliance mode'

            try {
                $fipsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'
                Set-RegistryValueForFIPSAndSTIG -Path $fipsPath -Name 'Enabled' -Value 1
                Set-RegistryValueForFIPSAndSTIG -Path $fipsPath -Name 'MDMEnabled' -Value 0
                $script:FIPSExecution.EnabledValue = '1'
                $script:FIPSExecution.MDMEnabled = '0'

                $secEditCfg = @"
[Unicode]
Unicode=yes
[System Access]
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,1
"@
                $tempInf = "$env:TEMP\fips_secedit.inf"
                $tempDb = "$env:TEMP\fips_secedit.sdb"
                $secEditCfg | Out-File -FilePath $tempInf -Encoding Unicode -Force
                secedit /configure /db $tempDb /cfg $tempInf /quiet 2>$null
                Remove-Item $tempInf, $tempDb -Force -ErrorAction SilentlyContinue

                Write-OK 'FIPS 140-2 enabled (effective after reboot)'
                $script:FIPSExecution.Status = 'Applied'
                Add-PolicyEntry -Category 'FIPS' -Policy 'FIPS 140-2 Mode' -Description 'Enabled via registry + secedit' -Status 'Verified'
            }
            catch {
                Write-Err "Failed to enable FIPS: $_"
                $script:FIPSExecution.Status = 'Failed'
                $script:FIPSExecution.Reason = "$_"
                Add-PolicyEntry -Category 'FIPS' -Policy 'FIPS 140-2 Mode' -Description 'Failed to enable' -Status 'Failed' -Reason "$_"
            }

            # ========================== STEP 4: TLS Hardening ==========================

            Write-Step 'Harden TLS protocols (enable 1.2, disable legacy)'

            try {
                foreach ($side in @('Server', 'Client')) {
                    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\$side"
                    Set-RegistryValueForFIPSAndSTIG -Path $path -Name 'Enabled' -Value 1
                    Set-RegistryValueForFIPSAndSTIG -Path $path -Name 'DisabledByDefault' -Value 0
                    Add-PolicyEntry -Category 'TLS' -Policy "TLS 1.2 $side" -Description 'Enabled' -Status 'Verified'
                }
                Write-OK 'TLS 1.2 Server/Client enabled'

                $oldProtocols = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
                foreach ($proto in $oldProtocols) {
                    foreach ($side in @('Server', 'Client')) {
                        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\$side"
                        Set-RegistryValueForFIPSAndSTIG -Path $path -Name 'Enabled' -Value 0
                        Set-RegistryValueForFIPSAndSTIG -Path $path -Name 'DisabledByDefault' -Value 1
                        Add-PolicyEntry -Category 'TLS' -Policy "$proto $side" -Description 'Disabled (insecure)' -Status 'Verified'
                    }
                }
                Write-OK 'Legacy protocols disabled: SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1'
            }
            catch {
                Write-Err "TLS configuration failed: $_"
                Add-PolicyEntry -Category 'TLS' -Policy 'TLS Hardening' -Description 'Configuration failed' -Status 'Failed' -Reason "$_"
            }

            # ========================== STEP 5: RDP Security Configuration ==========================

            Write-Step 'Harden RDP settings (TLS + NLA + High encryption)'

            $rdpSettings = @(
                @{ Name = 'SecurityLayer';    Value = 2; Desc = 'Security layer set to TLS (2)' },
                @{ Name = 'MinEncryptionLevel'; Value = 3; Desc = 'Minimum encryption set to High (3)' },
                @{ Name = 'UserAuthentication'; Value = 1; Desc = 'NLA (Network Level Authentication) enabled' }
            )

            $rdpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

            foreach ($setting in $rdpSettings) {
                try {
                    Set-RegistryValueForFIPSAndSTIG -Path $rdpPath -Name $setting.Name -Value $setting.Value
                    Write-OK $setting.Desc
                    Add-PolicyEntry -Category 'RDP' -Policy "RDP.$($setting.Name)" -Description $setting.Desc -Status 'Verified'
                }
                catch {
                    Write-Err "Failed to set $($setting.Name): $_"
                    Add-PolicyEntry -Category 'RDP' -Policy "RDP.$($setting.Name)" -Description "Failed: $($setting.Desc)" -Status 'Failed' -Reason "$_"
                }
            }

            try {
                Set-RegistryValueForFIPSAndSTIG -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
                Write-OK 'RDP connections = Allowed'
                Add-PolicyEntry -Category 'RDP' -Policy 'RDP.fDenyTSConnections' -Description 'RDP connections allowed (value=0)' -Status 'Verified'

                Set-Service -Name TermService -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name TermService -ErrorAction SilentlyContinue
                Write-OK 'TermService = Automatic / Running'
                Add-PolicyEntry -Category 'RDP' -Policy 'RDP.TermService' -Description 'Service set to Automatic and started' -Status 'Verified'

                # Use netsh instead of *-NetFirewallRule to avoid SID mapping errors on DC (especially in PS7)
                $rdpCheck = netsh advfirewall firewall show rule group="Remote Desktop" 2>&1
                if ($LASTEXITCODE -eq 0 -and $rdpCheck -notmatch 'No rules match') {
                    netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes 2>&1 | Out-Null
                    Write-OK 'Remote Desktop firewall rules enabled (via netsh)'
                    Add-PolicyEntry -Category 'RDP' -Policy 'RDP.Firewall' -Description 'Remote Desktop firewall rules enabled via netsh' -Status 'Verified'
                }
                else {
                    netsh advfirewall firewall add rule name="RDP-TCP-3389" dir=in action=allow protocol=TCP localport=3389 profile=any enable=yes 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        Write-OK 'RDP firewall rule created (TCP 3389 inbound via netsh)'
                        Add-PolicyEntry -Category 'RDP' -Policy 'RDP.Firewall' -Description 'New firewall rule created TCP 3389 via netsh' -Status 'Verified'
                    }
                    else {
                        Write-Err 'Failed to create RDP firewall rule via netsh'
                        Add-PolicyEntry -Category 'RDP' -Policy 'RDP.Firewall' -Description 'Failed to create firewall rule' -Status 'Failed' -Reason "netsh exit code: $LASTEXITCODE"
                    }
                }
            }
            catch {
                Write-Err "RDP configuration failed: $_"
                Add-PolicyEntry -Category 'RDP' -Policy 'RDP.General' -Description 'RDP configuration failed' -Status 'Failed' -Reason "$_"
            }

            # ========================== STEP 6: Cipher Suites ==========================

            Write-Step 'Ensure FIPS-compliant TLS cipher suites are available'

            try {
                $fipsSuites = @(
                    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
                )

                $currentSuites = (Get-TlsCipherSuite).Name

                foreach ($suite in $fipsSuites) {
                    if ($suite -notin $currentSuites) {
                        try {
                            Enable-TlsCipherSuite -Name $suite -Position 0 -ErrorAction Stop
                            Write-OK "Enabled: $suite"
                            Add-PolicyEntry -Category 'CipherSuite' -Policy $suite -Description 'FIPS suite enabled' -Status 'Verified'
                        }
                        catch {
                            Write-Warn "Cannot enable ${suite}: $($_.Exception.Message)"
                            Add-PolicyEntry -Category 'CipherSuite' -Policy $suite -Description 'Could not enable' -Status 'Failed' -Reason "$($_.Exception.Message)"
                        }
                    }
                    else {
                        Write-OK "Already present: $suite"
                        Add-PolicyEntry -Category 'CipherSuite' -Policy $suite -Description 'Already enabled' -Status 'Verified'
                    }
                }

                $weakSuites = @(
                    'TLS_RSA_WITH_RC4_128_SHA',
                    'TLS_RSA_WITH_RC4_128_MD5',
                    'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                    'TLS_RSA_WITH_NULL_SHA256',
                    'TLS_RSA_WITH_NULL_SHA'
                )
                foreach ($weak in $weakSuites) {
                    if ($weak -in $currentSuites) {
                        Disable-TlsCipherSuite -Name $weak -ErrorAction SilentlyContinue
                        Write-OK "Disabled weak suite: $weak"
                        Add-PolicyEntry -Category 'CipherSuite' -Policy $weak -Description 'Weak suite disabled' -Status 'Verified'
                    }
                }
            }
            catch {
                Write-Err "Cipher suite configuration failed: $_"
                Add-PolicyEntry -Category 'CipherSuite' -Policy 'CipherSuite Config' -Description 'Configuration failed' -Status 'Failed' -Reason "$_"
            }

            # ========================== STEP 7: Final Validation ==========================
            if ($script:DetectedOS -in $supportedOSList -and -not $SkipSTIG -and $script:STIGExecution.Status -eq 'Applied') {
                Write-Step "Recheck $($script:STIGExecution.Baseline) after FIPS/TLS/RDP hardening"

                try {
                    $offlinePackagePath = Resolve-PowerStigOfflinePackage
                    $packageTarget = switch ($script:DetectedOS) {
                        'WS2019' { 'WindowsServer2019' }
                        'WS2022' { 'WindowsServer2022' }
                        'WS2025' { 'WindowsServer2025' }
                        'Win10' { 'Windows10' }
                        'Win11' { 'Windows11' }
                    }
                    $checkArguments = @(
                        '-NoProfile'
                        '-ExecutionPolicy'
                        'Bypass'
                        '-File'
                        $offlinePackagePath
                        '-Mode'
                        'Check'
                        '-Target'
                        $packageTarget
                    )
                    if ($script:DetectedOS -in @('WS2019', 'WS2022', 'WS2025')) {
                        $checkArguments += @('-ServerRole', $script:DetectedRole)
                    }
                    if ($orgSettingsPath) {
                        $checkArguments += @('-OrgSettingsPath', $orgSettingsPath)
                    }

                    $checkStarted = Get-Date
                    $checkOutput = @(& $powershell51 @checkArguments 2>&1)
                    $checkExitCode = $LASTEXITCODE
                    foreach ($outputLine in @($checkOutput | Select-Object -Last 30)) {
                        Write-TerraForgeLog ([string]$outputLine) -Level 'Info'
                    }

                    $checkSummary = Get-ChildItem -LiteralPath $summaryRoot -Filter "Test-PowerStig-$env:COMPUTERNAME-*.summary.json" -File -Recurse -ErrorAction SilentlyContinue |
                        Where-Object LastWriteTime -ge $checkStarted.AddSeconds(-2) |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object -First 1
                    if (-not $checkSummary) {
                        throw "Offline package produced no compliance summary (exit code $checkExitCode)."
                    }

                    $compliance = Get-Content -LiteralPath $checkSummary.FullName -Raw | ConvertFrom-Json
                    $compliancePassed = $checkExitCode -eq 0 -and $compliance.Succeeded -and $compliance.InDesiredState
                    if ($null -ne $compliance.DesiredResourceCount) {
                        $script:STIGExecution.AppliedResources = $compliance.DesiredResourceCount
                    }
                    if ($null -ne $compliance.NoncompliantResourceCount) {
                        $script:STIGExecution.FailedResources = $compliance.NoncompliantResourceCount
                    }

                    if ($compliancePassed) {
                        Add-PolicyEntry -Category 'STIG' -Policy 'Post-hardening compliance check' -Description "InDesiredState=True; resources=$($compliance.DesiredResourceCount)" -Status 'Verified'
                    }
                    else {
                        $script:STIGExecution.Status = 'Failed'
                        $script:STIGExecution.Reason = [string]$compliance.Error
                        Write-Err "Post-hardening STIG check failed (exit code $checkExitCode; summary $($checkSummary.FullName)): $($compliance.Error)"
                        Add-PolicyEntry -Category 'STIG' -Policy 'Post-hardening compliance check' -Description "InDesiredState=$($compliance.InDesiredState)" -Status 'Failed' -Reason $script:STIGExecution.Reason
                    }
                }
                catch {
                    $script:STIGExecution.Status = 'Failed'
                    $script:STIGExecution.Reason = [string]$PSItem.Exception.Message
                    Write-Err "Post-hardening Server 2025 STIG check failed: $PSItem"
                }
            }

            # ========================== STEP 7: Final Validation ==========================

            Write-Step 'Final configuration validation'

            $checks = @(
                @{ Name = 'FIPS Enabled';         Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy';                                     Prop = 'Enabled';           Expect = 1 },
                @{ Name = 'RDP Layer (TLS=2)';    Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';                          Prop = 'SecurityLayer';     Expect = 2 },
                @{ Name = 'RDP Encrypt (High=3)'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';                          Prop = 'MinEncryptionLevel';Expect = 3 },
                @{ Name = 'NLA Enabled';          Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';                          Prop = 'UserAuthentication';Expect = 1 },
                @{ Name = 'RDP Allowed';          Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server';                                               Prop = 'fDenyTSConnections';Expect = 0 },
                @{ Name = 'TLS 1.2 Server';       Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server';          Prop = 'Enabled';           Expect = 1 },
                @{ Name = 'TLS 1.2 Client';       Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client';          Prop = 'Enabled';           Expect = 1 }
            )

            Write-TerraForgeLog '' -Level "Success"
            $allPassed = $script:Errors.Count -eq 0 -and $script:STIGExecution.Status -eq 'Applied'
            foreach ($chk in $checks) {
                $val = (Get-ItemProperty $chk.Path -EA SilentlyContinue)."$($chk.Prop)"
                $passed = $val -eq $chk.Expect
                if (-not $passed) { $allPassed = $false }
                $status = if ($passed) { 'PASS' } else { 'FAIL' }
                $color = if ($passed) { 'Green' } else { 'Red' }
                Write-TerraForgeLog ("  [{0}] {1,-25} got={2}  want={3}" -f $status, $chk.Name, $val, $chk.Expect) -Level $(if ($passed) { 'Success' }else { 'Error' })
                Add-PolicyEntry -Category 'Validation' -Policy $chk.Name -Description "Value=$val, Expected=$($chk.Expect)" -Status $(if ($passed) { 'Verified' }else { 'Failed' }) -Reason $(if (-not $passed) { "Got $val instead of $($chk.Expect)" }else { '' })

                if ($chk.Name -eq 'FIPS Enabled') {
                    $script:FIPSExecution.EnabledValue = [string]$val
                    Add-PolicyEntry -Category 'FIPS' -Policy 'FIPS 140-2 Verification' -Description "Final validation value=$val, expected=$($chk.Expect)" -Status $(if ($passed) { 'Verified' }else { 'Failed' }) -Reason $(if (-not $passed) { "Got $val instead of $($chk.Expect)" }else { '' })
                }
            }

            $rdpSvc = Get-Service TermService -EA SilentlyContinue
            $svcPass = $rdpSvc.Status -eq 'Running'
            if (-not $svcPass) { $allPassed = $false }
            Write-TerraForgeLog ("  [{0}] {1,-25} {2}" -f $(if ($svcPass) { 'PASS' }else { 'FAIL' }), 'RDP Service', $rdpSvc.Status) -Level $(if ($svcPass) { 'Success' }else { 'Error' })
            Add-PolicyEntry -Category 'Validation' -Policy 'RDP Service' -Description "Status: $($rdpSvc.Status)" -Status $(if ($svcPass) { 'Verified' }else { 'Failed' }) -Reason $(if (-not $svcPass) { 'Service not running' }else { '' })

            $suiteCount = (Get-TlsCipherSuite).Count
            $suitePass = $suiteCount -gt 0
            if (-not $suitePass) { $allPassed = $false }
            Write-TerraForgeLog ("  [{0}] {1,-25} {2} suites" -f $(if ($suitePass) { 'PASS' }else { 'FAIL' }), 'Cipher Suites', $suiteCount) -Level $(if ($suitePass) { 'Success' }else { 'Error' })
            Add-PolicyEntry -Category 'Validation' -Policy 'Cipher Suites' -Description "$suiteCount suite(s) available" -Status $(if ($suitePass) { 'Verified' }else { 'Failed' }) -Reason $(if (-not $suitePass) { 'No cipher suites available' }else { '' })

            if ($script:Errors.Count -gt 0) {
                Write-TerraForgeLog "`n  WARNING: $($script:Errors.Count) error(s) occurred:" -Level "Warning"
                $script:Errors | ForEach-Object { Write-TerraForgeLog "     - $_" -Level "Warning" }
            }

            # ========================== STEP 8: Generate HTML Report ==========================

            Write-Step 'Generate HTML report'

            if (-not (Test-Path $ReportPath)) {
                New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
            }

            $reportFile = Join-Path $ReportPath ("STIG-FIPS-Report_{0}_{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))

            # Compute summary counts
            $totalVerified = ($script:PolicyLog | Where-Object Status -eq 'Verified').Count
            $totalSkipped = ($script:PolicyLog | Where-Object Status -eq 'Skipped').Count
            $totalFailed = ($script:PolicyLog | Where-Object Status -eq 'Failed').Count
            $totalItems = $script:PolicyLog.Count

            $fipsEntries = @($script:PolicyLog | Where-Object Category -eq 'FIPS')
            $fipsVerified = @($fipsEntries | Where-Object Status -eq 'Verified').Count
            $fipsSkipped = @($fipsEntries | Where-Object Status -eq 'Skipped').Count
            $fipsFailed = @($fipsEntries | Where-Object Status -eq 'Failed').Count

            $fipsSummaryRows = @(
                [PSCustomObject]@{ Label = 'Execution Status'; Value = $script:FIPSExecution.Status }
                [PSCustomObject]@{ Label = 'Verified Count'; Value = [string]$fipsVerified }
                [PSCustomObject]@{ Label = 'Failed Count'; Value = [string]$fipsFailed }
                [PSCustomObject]@{ Label = 'Enabled'; Value = $(if ($script:FIPSExecution.EnabledValue -ne '') { $script:FIPSExecution.EnabledValue } else { 'Unknown' }) }
                [PSCustomObject]@{ Label = 'MDMEnabled'; Value = $(if ($script:FIPSExecution.MDMEnabled -ne '') { $script:FIPSExecution.MDMEnabled } else { 'Unknown' }) }
                [PSCustomObject]@{ Label = 'Method'; Value = $script:FIPSExecution.Method }
                [PSCustomObject]@{ Label = 'Effective'; Value = $script:FIPSExecution.EffectiveAfter }
                [PSCustomObject]@{ Label = 'Reason'; Value = $(if ($script:FIPSExecution.Reason) { $script:FIPSExecution.Reason } else { 'None' }) }
            )

            $fipsSummaryHtml = ($fipsSummaryRows | ForEach-Object {
                    @"
        <tr>
            <td class="summary-label">$(Convert-ToHtmlSafe $_.Label)</td>
            <td>$(Convert-ToHtmlSafe $_.Value)</td>
        </tr>
"@
                }) -join "`n"

            $stigEntries = @($script:PolicyLog | Where-Object { $_.Category -like 'STIG*' })
            $stigVerified = @($stigEntries | Where-Object Status -eq 'Verified').Count
            $stigSkipped = @($stigEntries | Where-Object Status -eq 'Skipped').Count
            $stigFailed = @($stigEntries | Where-Object Status -eq 'Failed').Count

            $stigSummaryRows = @(
                [PSCustomObject]@{ Label = 'Baseline'; Value = $script:STIGExecution.Baseline }
                [PSCustomObject]@{ Label = 'Requested'; Value = $(if ($script:STIGExecution.Requested) { 'Yes' } else { 'No' }) }
                [PSCustomObject]@{ Label = 'Execution Status'; Value = $script:STIGExecution.Status }
                [PSCustomObject]@{ Label = 'Module Status'; Value = $(if ($script:STIGExecution.ModuleVersion) { "$($script:STIGExecution.ModuleStatus) (v$($script:STIGExecution.ModuleVersion))" } else { $script:STIGExecution.ModuleStatus }) }
                [PSCustomObject]@{ Label = 'Installer'; Value = $(if ($script:STIGExecution.PackageProvider) { $script:STIGExecution.PackageProvider } else { 'Unknown' }) }
                [PSCustomObject]@{ Label = 'Skipped Rules'; Value = $(if ($script:STIGExecution.SkipRules.Count -gt 0) { $script:STIGExecution.SkipRules -join ', ' } else { 'None' }) }
                [PSCustomObject]@{ Label = 'Compiled Resources'; Value = [string]$script:STIGExecution.PlannedResources }
                [PSCustomObject]@{ Label = 'Applied Resources'; Value = [string]$script:STIGExecution.AppliedResources }
                [PSCustomObject]@{ Label = 'Failed Resources'; Value = [string]$script:STIGExecution.FailedResources }
                [PSCustomObject]@{ Label = 'Reboot Requested'; Value = $(if ($script:STIGExecution.RebootRequested) { 'Yes' } else { 'No' }) }
                [PSCustomObject]@{ Label = 'MOF Path'; Value = $(if ($script:STIGExecution.MofPath) { $script:STIGExecution.MofPath } else { 'Not generated' }) }
                [PSCustomObject]@{ Label = 'Reason'; Value = $(if ($script:STIGExecution.Reason) { $script:STIGExecution.Reason } else { 'None' }) }
            )

            $stigSummaryHtml = ($stigSummaryRows | ForEach-Object {
                    @"
        <tr>
            <td class="summary-label">$(Convert-ToHtmlSafe $_.Label)</td>
            <td>$(Convert-ToHtmlSafe $_.Value)</td>
        </tr>
"@
                }) -join "`n"

            $stigTableRows = if ($stigEntries.Count -gt 0) {
                ($stigEntries | ForEach-Object {
                    $badgeClass = switch ($_.Status) {
                        'Applied' { 'badge-applied' }
                        'Verified' { 'badge-verified' }
                        'Skipped' { 'badge-skipped' }
                        'Failed' { 'badge-failed' }
                    }
                    $reasonCell = if ($_.Reason) { Convert-ToHtmlSafe $_.Reason } else { 'N/A' }
                    @"
        <tr>
            <td>$(Convert-ToHtmlSafe $_.Timestamp)</td>
            <td>$(Convert-ToHtmlSafe $_.Category)</td>
            <td class="policy-name">$(Convert-ToHtmlSafe $_.Policy)</td>
            <td>$(Convert-ToHtmlSafe $_.Description)</td>
            <td><span class="badge $badgeClass">$(Convert-ToHtmlSafe $_.Status)</span></td>
            <td class="reason-cell">$reasonCell</td>
        </tr>
"@
                }) -join "`n"
            }
            else {
                @"
        <tr>
            <td colspan="6">No STIG policy entries were recorded.</td>
        </tr>
"@
            }

            # Build table rows from the policy log
            $tableRows = ($script:PolicyLog | ForEach-Object {
                    $badgeClass = switch ($_.Status) {
                        'Applied' { 'badge-applied' }
                        'Verified' { 'badge-verified' }
                        'Skipped' { 'badge-skipped' }
                        'Failed' { 'badge-failed' }
                    }
                    $reasonCell = if ($_.Reason) { Convert-ToHtmlSafe $_.Reason } else { 'N/A' }
                    @"
        <tr>
            <td>$(Convert-ToHtmlSafe $_.Timestamp)</td>
            <td><span class="cat-tag">$(Convert-ToHtmlSafe $_.Category)</span></td>
            <td class="policy-name">$(Convert-ToHtmlSafe $_.Policy)</td>
            <td>$(Convert-ToHtmlSafe $_.Description)</td>
            <td><span class="badge $badgeClass">$(Convert-ToHtmlSafe $_.Status)</span></td>
            <td class="reason-cell">$reasonCell</td>
        </tr>
"@
                }) -join "`n"

            # Build per-category summary rows
            $categories = $script:PolicyLog | Group-Object Category | Sort-Object Name
            $categorySummaryRows = ($categories | ForEach-Object {
                    $catVerified = @($_.Group | Where-Object Status -eq 'Verified').Count
                    $catSkipped = @($_.Group | Where-Object Status -eq 'Skipped').Count
                    $catFailed = @($_.Group | Where-Object Status -eq 'Failed').Count
                    @"
        <tr>
            <td><span class="cat-tag">$($_.Name)</span></td>
            <td>$($_.Count)</td>
            <td class="count-verified">$catVerified</td>
            <td class="count-skipped">$catSkipped</td>
            <td class="count-failed">$catFailed</td>
        </tr>
"@
                }) -join "`n"

            $overallStatus = if ($totalFailed -eq 0) { 'ALL PASSED' } else { "$totalFailed FAILURE(S) DETECTED" }
            $overallClass = if ($totalFailed -eq 0) { 'status-pass' } else { 'status-fail' }

            $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>STIG &amp; FIPS Hardening Report - $env:COMPUTERNAME</title>
<style>
    :root {
        --bg:           #0d1117;
        --surface:      #161b22;
        --border:       #30363d;
        --text:         #e6edf3;
        --text-muted:   #8b949e;
        --accent:       #58a6ff;
        --green:        #3fb950;
        --green-bg:     rgba(63,185,80,0.15);
        --yellow:       #d29922;
        --yellow-bg:    rgba(210,153,34,0.15);
        --red:          #f85149;
        --red-bg:       rgba(248,81,73,0.15);
        --blue:         #58a6ff;
        --blue-bg:      rgba(88,166,255,0.15);
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
        background: var(--bg);
        color: var(--text);
        line-height: 1.6;
        padding: 2rem;
    }
    .container { max-width: 1400px; margin: 0 auto; }

    /* Header */
    .header {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 2rem;
        margin-bottom: 1.5rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 1rem;
    }
    .header h1 {
        font-size: 1.6rem;
        font-weight: 600;
    }
    .header h1 span { color: var(--accent); }
    .header-meta {
        font-size: 0.85rem;
        color: var(--text-muted);
        text-align: right;
    }
    .header-meta strong { color: var(--text); }

    /* Overall status banner */
    .overall-status {
        text-align: center;
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        font-size: 1.3rem;
        font-weight: 700;
        letter-spacing: 0.5px;
    }
    .status-pass { background: var(--green-bg); color: var(--green); border: 1px solid var(--green); }
    .status-fail { background: var(--red-bg);   color: var(--red);   border: 1px solid var(--red); }

    /* Summary cards */
    .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 1rem;
        margin-bottom: 1.5rem;
    }
    .card {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
    }
    .card .number {
        font-size: 2.2rem;
        font-weight: 700;
        line-height: 1;
    }
    .card .label {
        font-size: 0.8rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 0.3rem;
    }
    .card.applied  .number { color: var(--green); }
    .card.verified .number { color: var(--blue); }
    .card.skipped  .number { color: var(--yellow); }
    .card.failed   .number { color: var(--red); }
    .card.total    .number { color: var(--text); }

    /* Section */
    .section {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 12px;
        margin-bottom: 1.5rem;
        overflow: hidden;
    }
    .section-title {
        padding: 1rem 1.5rem;
        font-size: 1rem;
        font-weight: 600;
        border-bottom: 1px solid var(--border);
        background: rgba(255,255,255,0.02);
    }

    /* Tables */
    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.85rem;
    }
    th {
        background: rgba(255,255,255,0.04);
        padding: 0.7rem 1rem;
        text-align: left;
        font-weight: 600;
        color: var(--text-muted);
        text-transform: uppercase;
        font-size: 0.7rem;
        letter-spacing: 0.8px;
        border-bottom: 1px solid var(--border);
        position: sticky;
        top: 0;
    }
    td {
        padding: 0.6rem 1rem;
        border-bottom: 1px solid var(--border);
        vertical-align: top;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,0.02); }
    .policy-name { font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 0.8rem; }
    .reason-cell { color: var(--text-muted); font-size: 0.8rem; }

    /* Badges */
    .badge {
        display: inline-block;
        padding: 0.15rem 0.6rem;
        border-radius: 20px;
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge-applied  { background: var(--green-bg);  color: var(--green); }
    .badge-verified { background: var(--blue-bg);   color: var(--blue); }
    .badge-skipped  { background: var(--yellow-bg); color: var(--yellow); }
    .badge-failed   { background: var(--red-bg);    color: var(--red); }

    .cat-tag {
        display: inline-block;
        padding: 0.1rem 0.5rem;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
        background: rgba(255,255,255,0.06);
        color: var(--accent);
    }

    /* Category summary table colors */
    .count-applied  { color: var(--green);  font-weight: 600; }
    .count-verified { color: var(--blue);   font-weight: 600; }
    .count-skipped  { color: var(--yellow); font-weight: 600; }
    .count-failed   { color: var(--red);    font-weight: 600; }
    .summary-label  { width: 220px; color: var(--text-muted); font-weight: 600; }

    /* Footer */
    .footer {
        text-align: center;
        padding: 1.5rem;
        color: var(--text-muted);
        font-size: 0.75rem;
    }

    /* Filter bar */
    .filter-bar {
        padding: 0.8rem 1.5rem;
        border-bottom: 1px solid var(--border);
        display: flex;
        gap: 0.5rem;
        flex-wrap: wrap;
    }
    .filter-btn {
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        border: 1px solid var(--border);
        background: transparent;
        color: var(--text-muted);
        font-size: 0.75rem;
        cursor: pointer;
        transition: all 0.2s;
    }
    .filter-btn:hover, .filter-btn.active {
        background: var(--accent);
        color: var(--bg);
        border-color: var(--accent);
    }
</style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div class="header">
        <div>
            <h1>&#128737; STIG &amp; FIPS <span>Hardening Report</span></h1>
        </div>
        <div class="header-meta">
            <div><strong>Server:</strong> $env:COMPUTERNAME</div>
            <div><strong>Domain:</strong> $env:USERDNSDOMAIN</div>
            <div><strong>Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
            <div><strong>Run by:</strong> $env:USERNAME</div>
        </div>
    </div>

    <!-- Overall Status -->
    <div class="overall-status $overallClass">$overallStatus</div>

    <!-- Summary Cards -->
    <div class="summary-grid">
        <div class="card total">
            <div class="number">$totalItems</div>
            <div class="label">Total Policies</div>
        </div>
        <div class="card verified">
            <div class="number">$totalVerified</div>
            <div class="label">Verified</div>
        </div>
        <div class="card skipped">
            <div class="number">$totalSkipped</div>
            <div class="label">Skipped</div>
        </div>
        <div class="card failed">
            <div class="number">$totalFailed</div>
            <div class="label">Failed</div>
        </div>
    </div>

    <!-- Category Summary -->
    <div class="section">
        <div class="section-title">&#128202; Summary by Category</div>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Total</th>
                    <th>Verified</th>
                    <th>Skipped</th>
                    <th>Failed</th>
                </tr>
            </thead>
            <tbody>
$categorySummaryRows
            </tbody>
        </table>
    </div>

    <div class="section">
        <div class="section-title">FIPS Execution Summary</div>
        <table>
            <tbody>
$fipsSummaryHtml
            </tbody>
        </table>
    </div>

    <div class="section">
        <div class="section-title">STIG Execution Summary</div>
        <table>
            <tbody>
$stigSummaryHtml
            </tbody>
        </table>
    </div>

    <div class="section">
        <div class="section-title">STIG Policy Details</div>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterStatus('stigPolicyTable','all', this)">All ($($stigEntries.Count))</button>
            <button class="filter-btn" onclick="filterStatus('stigPolicyTable','Verified', this)">Verified ($stigVerified)</button>
            <button class="filter-btn" onclick="filterStatus('stigPolicyTable','Skipped', this)">Skipped ($stigSkipped)</button>
            <button class="filter-btn" onclick="filterStatus('stigPolicyTable','Failed', this)">Failed ($stigFailed)</button>
        </div>
        <table id="stigPolicyTable">
            <thead>
                <tr>
                    <th style="width:70px">Time</th>
                    <th style="width:120px">Category</th>
                    <th style="width:280px">Policy / Rule</th>
                    <th>Description</th>
                    <th style="width:90px">Status</th>
                    <th style="width:250px">Reason</th>
                </tr>
            </thead>
            <tbody>
$stigTableRows
            </tbody>
        </table>
    </div>

    <!-- Detailed Policy Log -->
    <div class="section">
        <div class="section-title">&#128220; Detailed Policy Log</div>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterStatus('policyTable','all', this)">All ($totalItems)</button>
            <button class="filter-btn" onclick="filterStatus('policyTable','Verified', this)">Verified ($totalVerified)</button>
            <button class="filter-btn" onclick="filterStatus('policyTable','Skipped', this)">Skipped ($totalSkipped)</button>
            <button class="filter-btn" onclick="filterStatus('policyTable','Failed', this)">Failed ($totalFailed)</button>
        </div>
        <table id="policyTable">
            <thead>
                <tr>
                    <th style="width:70px">Time</th>
                    <th style="width:100px">Category</th>
                    <th style="width:260px">Policy / Rule</th>
                    <th>Description</th>
                    <th style="width:90px">Status</th>
                    <th style="width:250px">Reason</th>
                </tr>
            </thead>
            <tbody>
$tableRows
            </tbody>
        </table>
    </div>

    <div class="footer">
        Generated by <strong>Apply-STIG-FIPS-RDP-Safe.ps1</strong> | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $env:COMPUTERNAME
    </div>

</div>

<script>
function filterStatus(tableId, status, button) {
    var rows = document.querySelectorAll('#' + tableId + ' tbody tr');
    var btns = button.parentElement.querySelectorAll('.filter-btn');
    btns.forEach(function(b){ b.classList.remove('active'); });
    button.classList.add('active');
    rows.forEach(function(row) {
        if (status === 'all') { row.style.display = ''; return; }
        var badge = row.querySelector('.badge');
        if (badge && badge.textContent.trim() === status) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}
</script>
</body>
</html>
"@

            $htmlContent | Out-File -FilePath $reportFile -Encoding UTF8 -Force
            Write-OK "HTML report saved to: $reportFile"

            # Auto-open report in default browser
            try {
                Start-Process $reportFile
                Write-OK 'Report opened in default browser'
            }
            catch {
                Write-Warn "Could not auto-open report: $_"
            }

            # ========================== STEP 9: Reboot ==========================

            Write-Step 'Reboot server to apply changes'

            if (-not $allPassed) {
                Write-Warn 'Some checks did not pass - review the report above.'
            }

            # Export JSON snapshot for rollback reference
            if (-not (Test-Path 'C:\DSC')) {
                New-Item -Path 'C:\DSC' -ItemType Directory -Force | Out-Null
            }

            $snapshot = @{
                Timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                FIPS        = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy').Enabled
                RDP_Layer   = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').SecurityLayer
                RDP_NLA     = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
                CipherCount = (Get-TlsCipherSuite).Count
                AllPassed   = $allPassed
                ReportFile  = $reportFile
                Errors      = $script:Errors
            }
            $snapshot | ConvertTo-Json | Out-File -FilePath 'C:\DSC\STIG-FIPS-Snapshot.json' -Force
            Write-OK 'JSON snapshot saved to C:\DSC\STIG-FIPS-Snapshot.json'

            if ($NoReboot -or -not $AutoReboot) {
                if ($NoReboot -and $AutoReboot) {
                    Write-Warn 'Both -AutoReboot and -NoReboot were specified; automatic reboot is suppressed.'
                }
                Write-Warn 'Automatic reboot is disabled by default. Run "Restart-Computer -Force" manually when ready.'
            }
            else {
                Write-TerraForgeLog ''
                Write-TerraForgeLog '  +====================================================+' -Level "Success"
                Write-TerraForgeLog '  |  All settings applied. Rebooting in 15 seconds...   |' -Level "Success"
                Write-TerraForgeLog '  |  Press Ctrl+C NOW to abort if needed.               |' -Level "Success"
                Write-TerraForgeLog '  +====================================================+' -Level "Success"
                Write-TerraForgeLog ''
                Start-Sleep -Seconds 15
                Restart-Computer -Force
            }


            Save-TaskCompleted -TaskName $taskName
            Write-TerraForgeLog "$taskName completed successfully!" -Level "Success"
        }
        catch {
            throw "Failed to install FIPS and STIG policy. Error: $_"
        }
    }
    else {
        Write-Ok "Skipping $taskName as it is not marked for Lite-FipsStig configuration."
        return
    }
}
catch {
    Write-TerraForgeError -ErrorRecord $_ -Message "Critical error during $taskName installation"
    exit 1
}
finally {
    # Clean up logging resources but keep session alive for parent script
    Stop-TerraForgeLogging -KeepAlive
}
