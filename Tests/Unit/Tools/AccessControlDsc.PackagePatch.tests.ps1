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
    }

    It 'produces valid PowerShell and uses IdentityReference for registry rules' {
        $script:parseErrors.Count | Should Be 0
        $script:patchedContent | Should Match '\[System\.Security\.Principal\.IdentityReference\]'
    }

    It 'preserves an unresolvable capability SID when converting a registry rule' {
        $definition = $script:resourceAst.Find({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'ConvertTo-SidIdentityRegistryAccessRule'
            }, $true)
        . ([scriptblock]::Create($definition.Extent.Text))

        $sidValue = 'S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681'
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $rule = [Security.AccessControl.RegistryAccessRule]::new($sid, 'ReadKey', 'ContainerInherit', 'None', 'Allow')

        (ConvertTo-SidIdentityRegistryAccessRule -Rule $rule).IdentityReference.Value | Should Be $sidValue
    }

    It 'turns fallback ACL write failures into terminating errors' {
        ([regex]::Matches($script:patchedContent, 'Unable to update registry ACL')).Count | Should Be 2
        $script:patchedContent | Should Not Match '\$message = \$LocalizedData\.AclNotFound -f \$\(\$Rule\.IdentityReference\.Value\)'
    }
}