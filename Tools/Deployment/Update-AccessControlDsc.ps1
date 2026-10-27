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

$inheritancePattern = '$Inheritance = Get-RegistryRuleInheritenceFlag -Inheritance $ace.Inheritance'
$inheritanceReplacement = @'
$Inheritance = Get-RegistryRuleInheritenceFlag -Inheritance $ace.Inheritance
        $creatorOwner = [System.Security.Principal.SecurityIdentifier]::new('S-1-3-0')
        $creatorOwnerName = $creatorOwner.Translate([System.Security.Principal.NTAccount]).Value
        if ($IdentityRef.Value -in @($creatorOwner.Value, $creatorOwnerName) -and $Inheritance.InheritanceFlag -eq '1' -and $Inheritance.PropagationFlag -eq '0')
        {
            $Inheritance.PropagationFlag = '2'
        }
'@
if ([regex]::Matches($content, [regex]::Escape($inheritancePattern)).Count -ne 1)
{
    throw 'The AccessControlDsc RegistryAccessEntry inheritance construction did not match the expected 1.4.3 source.'
}
$content = $content.Replace($inheritancePattern, $inheritanceReplacement)

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
        # Names such as 'APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES' only translate without the authority prefix.
        $SID = [System.Security.Principal.NTAccount]::new($Rule.IdentityReference.Value.Split('\')[-1]).Translate([System.Security.Principal.SecurityIdentifier])
    }
'@
if ([regex]::Matches($content, [regex]::Escape($sidConversionPattern)).Count -ne 1)
{
    throw 'The AccessControlDsc RegistryAccessEntry SID conversion did not match the expected 1.4.3 source.'
}
$content = $content.Replace($sidConversionPattern, $sidConversionReplacement)

$rightsPattern = '$SIDRule = [System.Security.AccessControl.RegistryAccessRule]::new($SID, $Rule.RegistryRights.value__, $Rule.InheritanceFlags.value__, $Rule.PropagationFlags.value__, $Rule.AccessControlType.value__)'
$rightsReplacement = @'
$accessMask = [int64] $Rule.RegistryRights.value__ -band 0xFFFFFFFFL
    $registryRights = $accessMask -band 0x0FFFFFFFL
    if ($accessMask -band 0x80000000L)
    {
        $registryRights = $registryRights -bor [int64] [System.Security.AccessControl.RegistryRights]::ReadKey
    }
    if ($accessMask -band 0x40000000L)
    {
        $registryRights = $registryRights -bor [int64] [System.Security.AccessControl.RegistryRights]::WriteKey
    }
    if ($accessMask -band 0x20000000L)
    {
        $registryRights = $registryRights -bor [int64] [System.Security.AccessControl.RegistryRights]::ExecuteKey
    }
    if ($accessMask -band 0x10000000L)
    {
        $registryRights = $registryRights -bor [int64] [System.Security.AccessControl.RegistryRights]::FullControl
    }
    $mappedRights = [System.Security.AccessControl.RegistryRights] $registryRights
    $SIDRule = [System.Security.AccessControl.RegistryAccessRule]::new($SID, $mappedRights, $Rule.InheritanceFlags, $Rule.PropagationFlags, $Rule.AccessControlType)
'@
if ([regex]::Matches($content, [regex]::Escape($rightsPattern)).Count -ne 1)
{
    throw 'The AccessControlDsc RegistryAccessEntry rights conversion did not match the expected 1.4.3 source.'
}
$content = $content.Replace($rightsPattern, $rightsReplacement)

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