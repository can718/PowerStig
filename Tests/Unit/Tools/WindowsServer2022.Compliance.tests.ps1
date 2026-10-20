$repositoryRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
$scriptPath = Join-Path $repositoryRoot 'Tools\Deployment\Test-PowerStigWindowsCompliance.ps1'
$tokens = $null
$parseErrors = $null
$scriptAst = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref] $tokens, [ref] $parseErrors)
if ($parseErrors.Count -gt 0)
{
    throw ($parseErrors.Message -join [Environment]::NewLine)
}

$functionNames = @(
    'Get-IdentitySid',
    'Test-WindowsServer2022SystemRegistryAcl',
    'Test-WindowsServer2022SysvolAcl',
    'Test-WindowsServer2022LdapIntegrity',
    'Get-WindowsServer2022ComplianceOverride'
)
$scriptAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $functionNames
    }, $true) | ForEach-Object { . ([scriptblock]::Create($PSItem.Extent.Text)) }

function Get-RegistryTestRule
{
    param(
        [string] $Sid,
        [Security.AccessControl.RegistryRights] $Rights,
        [Security.AccessControl.InheritanceFlags] $Inheritance,
        [Security.AccessControl.PropagationFlags] $Propagation
    )

    [pscustomobject]@{
        IdentityReference = [Security.Principal.SecurityIdentifier]::new($Sid)
        RegistryRights = $Rights
        InheritanceFlags = $Inheritance
        PropagationFlags = $Propagation
        AccessControlType = [Security.AccessControl.AccessControlType]::Allow
        IsInherited = $false
    }
}

function Add-FileTestRule
{
    param($Acl, [string] $Sid, $Rights, $Inheritance, $Propagation)

    $identity = [Security.Principal.SecurityIdentifier]::new($Sid)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        $Rights,
        $Inheritance,
        $Propagation,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $Acl.AddAccessRule($rule)
}

Describe 'Windows Server 2022 compliance equivalence' {
    It 'accepts the secure SYSTEM registry ACL without the optional capability SID' {
        $acl = [pscustomobject]@{
            AreAccessRulesProtected = $true
            Access = @(
                Get-RegistryTestRule 'S-1-3-0' ([Security.AccessControl.RegistryRights]::FullControl) ContainerInherit InheritOnly
                Get-RegistryTestRule 'S-1-5-11' ([Security.AccessControl.RegistryRights]::ReadKey) ContainerInherit None
                Get-RegistryTestRule 'S-1-5-18' ([Security.AccessControl.RegistryRights]::FullControl) ContainerInherit None
                Get-RegistryTestRule 'S-1-5-32-544' ([Security.AccessControl.RegistryRights]::FullControl) ContainerInherit None
                Get-RegistryTestRule 'S-1-5-32-549' ([Security.AccessControl.RegistryRights]::ReadKey) ContainerInherit None
                Get-RegistryTestRule 'S-1-15-2-1' ([Security.AccessControl.RegistryRights]::ReadKey) ContainerInherit None
            )
        }
        Mock Get-Acl { $acl }

        Test-WindowsServer2022SystemRegistryAcl | Should -BeTrue
    }

    It 'accepts the five normalized SYSVOL entries as equivalent to nine split entries' {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $both = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $read = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
        Add-FileTestRule $acl 'S-1-3-0' FullControl $both InheritOnly
        Add-FileTestRule $acl 'S-1-5-11' $read $both None
        Add-FileTestRule $acl 'S-1-5-18' FullControl $both None
        Add-FileTestRule $acl 'S-1-5-32-544' FullControl $both None
        Add-FileTestRule $acl 'S-1-5-32-549' $read $both None
        Mock Get-Acl { $acl }

        Test-WindowsServer2022SysvolAcl | Should -BeTrue
    }

    It 'rejects SYSVOL when authenticated users receive modify permission' {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $both = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        Add-FileTestRule $acl 'S-1-3-0' FullControl $both InheritOnly
        Add-FileTestRule $acl 'S-1-5-11' Modify $both None
        Add-FileTestRule $acl 'S-1-5-18' FullControl $both None
        Add-FileTestRule $acl 'S-1-5-32-544' FullControl $both None
        Add-FileTestRule $acl 'S-1-5-32-549' ReadAndExecute $both None
        Mock Get-Acl { $acl }

        Test-WindowsServer2022SysvolAcl | Should -BeFalse
    }

    It 'accepts LDAPServerIntegrity only when it is DWORD 2' {
        $key = [pscustomobject]@{}
        $key | Add-Member ScriptMethod GetValueKind { param($name) $null = $name; [Microsoft.Win32.RegistryValueKind]::DWord }
        $key | Add-Member ScriptMethod GetValue { param($name) $null = $name; 2 }
        Mock Get-Item { $key }

        Test-WindowsServer2022LdapIntegrity | Should -BeTrue
    }

    It 'routes only the three exact rule IDs to independent validation' {
        Mock Test-WindowsServer2022SystemRegistryAcl { $true }
        Mock Test-WindowsServer2022SysvolAcl { $true }
        Mock Test-WindowsServer2022LdapIntegrity { $true }

        Get-WindowsServer2022ComplianceOverride '[RegistryAccessEntry][V-254254.c][medium]::test' | Should -Match '^Validated equivalent registry ACL'
        Get-WindowsServer2022ComplianceOverride '[NTFSAccessEntry][V-254392][high]::test' | Should -Match '^Validated equivalent SYSVOL'
        Get-WindowsServer2022ComplianceOverride '[Registry][V-254416][medium]::test' | Should -Match '^Validated LDAPServerIntegrity'
        Get-WindowsServer2022ComplianceOverride '[Registry][V-254416.a][medium]::test' | Should -BeNullOrEmpty
    }

    It 'does not override a rule when independent validation fails' {
        Mock Test-WindowsServer2022SysvolAcl { $false }

        Get-WindowsServer2022ComplianceOverride '[NTFSAccessEntry][V-254392][high]::test' | Should -BeNullOrEmpty
    }
}