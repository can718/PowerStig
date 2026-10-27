Describe 'AccessControlDsc offline package patch' {
    BeforeAll {
        $projectRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
        $sourceModule = Join-Path -Path $projectRoot -ChildPath 'output\RequiredModules\AccessControlDSC\1.4.3'
        $patchScript = Join-Path -Path $projectRoot -ChildPath 'Tools\Deployment\Update-AccessControlDsc.ps1'
        $patchedModule = Join-Path -Path $TestDrive -ChildPath 'AccessControlDsc\1.4.3'
        New-Item -Path (Split-Path $patchedModule -Parent) -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $sourceModule -Destination $patchedModule -Recurse

        & $patchScript -ModulePath $patchedModule

        $resourcePath = Join-Path -Path $patchedModule -ChildPath 'DscResources\RegistryAccessEntry\RegistryAccessEntry.psm1'
        $script:patchedContent = Get-Content -LiteralPath $resourcePath -Raw
        $tokens = $null
        $script:parseErrors = $null
        $script:resourceAst = [Management.Automation.Language.Parser]::ParseFile(
            $resourcePath,
            [ref] $tokens,
            [ref] $script:parseErrors
        )
        $definition = $script:resourceAst.Find({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'ConvertTo-SidIdentityRegistryAccessRule'
            }, $true)
        . ([scriptblock]::Create($definition.Extent.Text))
    }

    It 'produces valid PowerShell and uses IdentityReference for registry rules' {
        $script:parseErrors.Count | Should Be 0
        $script:patchedContent | Should Match '\[System\.Security\.Principal\.IdentityReference\]'
    }

    It 'preserves an unresolvable capability SID when converting a registry rule' {
        $sidValue = 'S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681'
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $rule = [Security.AccessControl.RegistryAccessRule]::new($sid, 'ReadKey', 'ContainerInherit', 'None', 'Allow')

        (ConvertTo-SidIdentityRegistryAccessRule -Rule $rule).IdentityReference.Value | Should Be $sidValue
    }

    It 'maps registry mask <Mask> and preserves <AceType> ACE metadata' -TestCases @(
        @{ Mask = '80000000'; ExpectedRights = 131097; AceType = 'A' }
        @{ Mask = '40000000'; ExpectedRights = 131078; AceType = 'A' }
        @{ Mask = '20000000'; ExpectedRights = 131097; AceType = 'A' }
        @{ Mask = '10000000'; ExpectedRights = 983103; AceType = 'A' }
        @{ Mask = 'C0010000'; ExpectedRights = 196639; AceType = 'A' }
        @{ Mask = 'F0000000'; ExpectedRights = 983103; AceType = 'A' }
        @{ Mask = '00020019'; ExpectedRights = 131097; AceType = 'A' }
        @{ Mask = '000F003F'; ExpectedRights = 983103; AceType = 'A' }
        @{ Mask = '80000000'; ExpectedRights = 131097; AceType = 'D' }
    ) {
        param($Mask, $ExpectedRights, $AceType)

        $acl = [Security.AccessControl.RegistrySecurity]::new()
        $acl.SetSecurityDescriptorSddlForm("D:($AceType;CIIO;0x$Mask;;;S-1-15-2-1)")
        $rule = $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])[0]

        $converted = ConvertTo-SidIdentityRegistryAccessRule -Rule $rule

        [int] $converted.RegistryRights | Should Be $ExpectedRights
        $converted.IdentityReference.Value | Should Be $rule.IdentityReference.Value
        $converted.InheritanceFlags | Should Be $rule.InheritanceFlags
        $converted.PropagationFlags | Should Be $rule.PropagationFlags
        $converted.AccessControlType | Should Be $rule.AccessControlType
    }

    It 'normalizes <Principal> with <Inheritance> inheritance to <ExpectedPropagation>' -TestCases @(
        @{ Principal = 'S-1-3-0'; Inheritance = 'KeySubkeys'; ExpectedPropagation = 'InheritOnly' }
        @{ Principal = 'S-1-3-0'; Inheritance = 'Subkeys'; ExpectedPropagation = 'InheritOnly' }
        @{ Principal = 'S-1-5-32-544'; Inheritance = 'KeySubkeys'; ExpectedPropagation = 'None' }
        @{ Principal = 'S-1-5-32-544'; Inheritance = 'Key'; ExpectedPropagation = 'None' }
        @{ Principal = 'CREATOR OWNER'; Inheritance = 'KeySubkeys'; ExpectedPropagation = 'InheritOnly' }
        @{ Principal = 'APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES'; Inheritance = 'KeySubkeys'; ExpectedPropagation = 'None' }
    ) {
        param($Principal, $Inheritance, $ExpectedPropagation)

        $script:resourceAst.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -in @('ConvertTo-RegistryAccessRule', 'Get-RegistryRuleInheritenceFlag')
            }, $true) | ForEach-Object { . ([scriptblock]::Create($PSItem.Extent.Text)) }

        $namespace = 'root/Microsoft/Windows/DesiredStateConfiguration'
        $entry = New-CimInstance -ClassName AccessControlEntry -Namespace $namespace -ClientOnly -Property @{
            Rights = [string[]] @('FullControl')
            Inheritance = $Inheritance
            AccessControlType = 'Allow'
            Ensure = 'Present'
        }
        $acl = New-CimInstance -ClassName AccessControlList -Namespace $namespace -ClientOnly -Property @{
            Principal = $Principal
            AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]] @($entry)
        }
        $identity = if ($Principal -match '^S-\d-')
        {
            [Security.Principal.SecurityIdentifier]::new($Principal)
        }
        else
        {
            [Security.Principal.NTAccount]::new($Principal)
        }

        $converted = ConvertTo-RegistryAccessRule -AccessControlList $acl -IdentityRef $identity

        $converted.Rules.PropagationFlags.ToString() | Should Be $ExpectedPropagation
        $converted.Rules.RegistryRights | Should Be 'FullControl'
        $converted.Rules.IdentityReference.Value | Should Be $Principal
    }

    It 'translates account names without the authority prefix' {
        $script:patchedContent | Should Match ([regex]::Escape("Value.Split('\')[-1]"))
    }

    It 'turns fallback ACL write failures into terminating errors' {
        ([regex]::Matches($script:patchedContent, 'Unable to update registry ACL')).Count | Should Be 2
        $script:patchedContent | Should Not Match '\$message = \$LocalizedData\.AclNotFound -f \$\(\$Rule\.IdentityReference\.Value\)'
    }
}