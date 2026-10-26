Describe 'Windows Server 2022 compliance equivalence' {
    BeforeAll {
        $repositoryRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
        $scriptPath = Join-Path $repositoryRoot 'Tools\Deployment\PowerStig.Windows.Common.psm1'
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
            'Get-WindowsServer2022ComplianceOverride',
            'Resolve-PowerStigDscComplianceResult'
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
    }

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

    It 'accepts a DSC mismatch only when the SYSVOL permissions are independently equivalent' {
        Mock Test-WindowsServer2022SysvolAcl { $true }
        $resource = [pscustomobject]@{
            ResourceId = '[NTFSAccessEntry][V-254392][high]::test'
            InDesiredState = $false
        }
        $result = [pscustomobject]@{
            InDesiredState = $false
            ResourcesInDesiredState = @()
            ResourcesNotInDesiredState = @($resource)
        }

        $resolved = Resolve-PowerStigDscComplianceResult -Target WindowsServer2022 -ServerRole DC -Result $result

        $resolved.InDesiredState | Should -BeTrue
        $resolved.RawInDesiredState | Should -BeFalse
        $resolved.ValidatedEquivalentResources.Count | Should -Be 1
        $resolved.ResourcesNotInDesiredState.Count | Should -Be 0
    }

    It 'does not accept other or independently invalid DSC mismatches' {
        Mock Test-WindowsServer2022SysvolAcl { $false }
        $resource = [pscustomobject]@{
            ResourceId = '[NTFSAccessEntry][V-254392][high]::test'
            InDesiredState = $false
        }
        $result = [pscustomobject]@{
            InDesiredState = $false
            ResourcesInDesiredState = @()
            ResourcesNotInDesiredState = @($resource)
        }

        $resolved = Resolve-PowerStigDscComplianceResult -Target WindowsServer2022 -ServerRole DC -Result $result
        $otherTarget = Resolve-PowerStigDscComplianceResult -Target WindowsServer2025 -ServerRole DC -Result $result
        $summaryOnly = Resolve-PowerStigDscComplianceResult -Target WindowsServer2022 -ServerRole DC -Result $false

        $resolved.InDesiredState | Should -BeFalse
        $resolved.ResourcesNotInDesiredState.Count | Should -Be 1
        $otherTarget.InDesiredState | Should -BeFalse
        $otherTarget.ResourcesNotInDesiredState.Count | Should -Be 1
        $summaryOnly.InDesiredState | Should -BeFalse
    }
}

Describe 'STIG rule compliance results' {
    BeforeAll {
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
            'Protect-ComplianceText',
            'Get-StigRuleIdFromResourceId',
            'ConvertTo-StigRuleResults'
        )
        $scriptAst.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $functionNames
            }, $true) | ForEach-Object { . ([scriptblock]::Create($PSItem.Extent.Text)) }

        function New-TestMetadata($RuleId, $ConversionStatus = 'pass', $OrganizationValueRequired = $false)
        {
            [pscustomobject]@{
                RuleId = $RuleId
                Title = "Title for $RuleId"
                Severity = 'medium'
                DscResource = 'Registry'
                ConversionStatus = $ConversionStatus
                OrganizationValueRequired = $OrganizationValueRequired
            }
        }

        function New-TestResource($ResourceId, $Desired, $ResourceError = $null)
        {
            [pscustomobject]@{
                ResourceId = $ResourceId
                InDesiredState = $Desired
                Error = $ResourceError
                ComplianceEvaluation = if ($Desired) { 'DSC' } else { 'DSC reported noncompliant' }
            }
        }
    }

    It 'aggregates multiple DSC resources and emits all required statuses' {
        $metadata = @(
            New-TestMetadata 'V-1'
            New-TestMetadata 'V-2'
            New-TestMetadata 'V-3' 'skip'
            New-TestMetadata 'V-4' 'pass' $true
            New-TestMetadata 'V-5'
            New-TestMetadata 'V-6' 'notapplicable'
        )
        $resources = @(
            New-TestResource '[Registry][V-1.a][medium][Title]::Stig' $true
            New-TestResource '[Registry][V-1.b][medium][Title]::Stig' $true
            New-TestResource '[Registry][V-2.a][medium][Title]::Stig' $true
            New-TestResource '[Registry][V-2.b][medium][Title]::Stig' $false
            New-TestResource '[Registry][V-5][medium][Title]::Stig' $true 'provider failed; token=secret-value'
        )

        $results = @(ConvertTo-StigRuleResults -RuleMetadata $metadata -Resources $resources -ModuleName PowerStig -ModuleVersion 4.30.0 -SourceInfo WindowsServer-2022-MS)

        ($results | Where-Object RuleId -eq 'V-1').Status | Should -Be 'Compliant'
        ($results | Where-Object RuleId -eq 'V-1').DscResourceIds.Count | Should -Be 2
        ($results | Where-Object RuleId -eq 'V-2').Status | Should -Be 'NonCompliant'
        ($results | Where-Object RuleId -eq 'V-3').Status | Should -Be 'Skipped'
        ($results | Where-Object RuleId -eq 'V-4').Status | Should -Be 'NotReviewed'
        ($results | Where-Object RuleId -eq 'V-5').Status | Should -Be 'Error'
        ($results | Where-Object RuleId -eq 'V-5').Reason | Should -Not -Match 'secret-value'
        ($results | Where-Object RuleId -eq 'V-6').Status | Should -Be 'NotApplicable'
    }

    It 'keeps rule totals equal to the sum of status counts' {
        $metadata = @(
            New-TestMetadata 'V-10'
            New-TestMetadata 'V-11' 'skip'
            New-TestMetadata 'V-12' 'fail'
        )
        $resources = @(New-TestResource '[Registry][V-10][medium][Title]::Stig' $true)
        $orgSettingsPath = Join-Path $TestDrive 'org.xml'
        '<OrganizationalSettings><OrganizationalSetting id="V-99" /></OrganizationalSettings>' |
            Set-Content -LiteralPath $orgSettingsPath -Encoding UTF8
        $results = @(ConvertTo-StigRuleResults -RuleMetadata $metadata -Resources $resources -ModuleName PowerStig -ModuleVersion 4.30.0 -SourceInfo WindowsServer-2022-MS -OrgSettingsPath $orgSettingsPath)
        $statuses = @('Compliant', 'NonCompliant', 'Skipped', 'NotApplicable', 'NotReviewed', 'Error')
        $statusTotal = ($statuses | ForEach-Object { @($results | Where-Object Status -eq $PSItem).Count } | Measure-Object -Sum).Sum

        $statusTotal | Should -Be $results.Count
    }

    It 'serializes schema 3 rule results while preserving legacy fields' {
        $summary = [ordered]@{
            SchemaVersion = 3
            Resources = @([pscustomobject]@{ ResourceId = '[Registry]V-20' })
            ResourceCsv = 'resources.csv'
            RuleResults = @([pscustomobject]@{ RuleId = 'V-20'; DscResourceIds = @('[Registry]V-20') })
        }

        $json = $summary | ConvertTo-Json -Depth 20
        $roundTrip = $json | ConvertFrom-Json

        $roundTrip.SchemaVersion | Should -Be 3
        $roundTrip.Resources[0].ResourceId | Should -Be '[Registry]V-20'
        $roundTrip.ResourceCsv | Should -Be 'resources.csv'
        $roundTrip.RuleResults[0].DscResourceIds[0] | Should -Be '[Registry]V-20'
    }
}