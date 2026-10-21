[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $PSItem -PathType Container })]
    [string]
    $ModulePath
)

$manifestPath = Join-Path -Path $ModulePath -ChildPath 'AccessControlDsc.psd1'
$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
if ([version] $manifest.ModuleVersion -ne [version] '1.4.3')
{
    throw "The AccessControlDsc package patch only supports version 1.4.3; found $($manifest.ModuleVersion)."
}

$resourcePath = Join-Path -Path $ModulePath -ChildPath 'DscResources\RegistryAccessEntry\RegistryAccessEntry.psm1'
$content = Get-Content -LiteralPath $resourcePath -Raw

$identityPattern = [regex]::Escape('$IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)')
if ([regex]::Matches($content, $identityPattern).Count -ne 4)
{
    throw 'The AccessControlDsc RegistryAccessEntry identity construction did not match the expected 1.4.3 source.'
}
$identityReplacement = @'
if ($Principal -match '^S-\d-')
            {
                $IdentityRef = [System.Security.Principal.SecurityIdentifier]::new($Identity.SID)
            }
            else
            {
                $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)
            }
'@
$content = [regex]::Replace($content, $identityPattern, $identityReplacement)

$parameterPattern = @'
        [System.Security.Principal.NTAccount]
        $IdentityRef
'@
$parameterReplacement = @'
        [System.Security.Principal.IdentityReference]
        $IdentityRef
'@
if ([regex]::Matches($content, [regex]::Escape($parameterPattern)).Count -ne 1)
{
    throw 'The AccessControlDsc RegistryAccessEntry identity parameter did not match the expected 1.4.3 source.'
}
$content = $content.Replace($parameterPattern, $parameterReplacement)

$sidConversionPattern = @'
    if ($Rule.IdentityReference.Value.Contains('\'))
    {
        [System.Security.Principal.NTAccount]$Principal = $Rule.IdentityReference.Value.split('\')[1]
    }
    else
    {
        [System.Security.Principal.NTAccount]$Principal = $Rule.IdentityReference.Value
    }

    $SID = $Principal.Translate([System.Security.Principal.SecurityIdentifier])
'@
$sidConversionReplacement = @'
    if ($Rule.IdentityReference -is [System.Security.Principal.SecurityIdentifier])
    {
        $SID = $Rule.IdentityReference
    }
    else
    {
        $SID = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
    }
'@
if ([regex]::Matches($content, [regex]::Escape($sidConversionPattern)).Count -ne 1)
{
    throw 'The AccessControlDsc RegistryAccessEntry SID conversion did not match the expected 1.4.3 source.'
}
$content = $content.Replace($sidConversionPattern, $sidConversionReplacement)

$failureHandlers = @(
    @{
        Pattern = @'
                $message = $LocalizedData.AclNotFound -f $($Rule.IdentityReference.Value)
                Write-Verbose -Message $message
'@
        Replacement = @'
                throw "Unable to update registry ACL '$Path' for principal '$($Rule.IdentityReference.Value)': $($_.Exception.Message)"
'@
    }
    @{
        Pattern = @'
                    $message = $LocalizedData.AclNotFound -f $($Rule.Rule.IdentityReference.Value)
                    Write-Verbose -Message $message
'@
        Replacement = @'
                    throw "Unable to update registry ACL '$Path' for principal '$($Rule.Rule.IdentityReference.Value)': $($_.Exception.Message)"
'@
    }
)
foreach ($failureHandler in $failureHandlers)
{
    if ([regex]::Matches($content, [regex]::Escape($failureHandler.Pattern)).Count -ne 1)
    {
        throw 'The AccessControlDsc RegistryAccessEntry error handling did not match the expected 1.4.3 source.'
    }
    $content = $content.Replace($failureHandler.Pattern, $failureHandler.Replacement)
}

[IO.File]::WriteAllText($resourcePath, $content, [Text.UTF8Encoding]::new($false))