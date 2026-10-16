$repositoryRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
$commonModulePath = Join-Path $repositoryRoot 'Tools\Deployment\PowerStig.Windows.Common.psm1'
Import-Module $commonModulePath -Force

Describe 'Windows deployment login defaults' {
    $testCases = @(
        @{ Target = 'WindowsServer2019'; Role = 'DC' }
        @{ Target = 'WindowsServer2019'; Role = 'MS' }
        @{ Target = 'WindowsServer2022'; Role = 'DC' }
        @{ Target = 'WindowsServer2022'; Role = 'MS' }
        @{ Target = 'WindowsServer2025'; Role = 'DC' }
        @{ Target = 'WindowsServer2025'; Role = 'MS' }
        @{ Target = 'Windows10'; Role = 'Auto' }
        @{ Target = 'Windows11'; Role = 'Auto' }
    )

    It 'Compiles notice and credential defaults for <Target> <Role>' -TestCases $testCases -Skip:($PSVersionTable.PSEdition -ne 'Desktop') {
        param($Target, $Role)

        $targetInfo = Get-PowerStigWindowsTarget -RequestedTarget $Target -RequestedServerRole $Role
        $outputPath = Join-Path $TestDrive "$Target-$Role"
        New-PowerStigWindowsMof -Target $targetInfo -OutputPath $outputPath -WarningAction SilentlyContinue | Out-Null
        $mof = Get-Content (Join-Path $outputPath 'localhost.mof') -Raw
        $registryBlocks = [regex]::Matches($mof, '(?s)instance of MSFT_RegistryResource\b.*?\r?\n};')

        foreach ($valueName in @('LegalNoticeText', 'LegalNoticeCaption', 'ConsentPromptBehaviorAdmin'))
        {
            $resources = @($registryBlocks | Where-Object { $PSItem.Value -match "ValueName = `"$valueName`";" })
            $resources.Count | Should Be 1
            $resource = $resources[0].Value
            $resource | Should Match 'Ensure = "Present";'
            switch ($valueName)
            {
                'LegalNoticeText' {
                    $resource | Should Match 'You are accessing a U.S. Government'
                    $resource | Should Match 'See User Agreement for details'
                }
                'LegalNoticeCaption' { $resource | Should Match 'DoD Notice and Consent Banner' }
                'ConsentPromptBehaviorAdmin' { $resource | Should Match 'ValueData\s*=\s*\{\s*"1"\s*\}' }
            }
        }
    }

    It 'Preserves an explicitly supplied organization notice and the baseline UAC value' -Skip:($PSVersionTable.PSEdition -ne 'Desktop') {
        $targetInfo = Get-PowerStigWindowsTarget -RequestedTarget WindowsServer2025 -RequestedServerRole DC
        $template = Join-Path $repositoryRoot 'source\StigData\Processed\WindowsServer-2025-DC-1.4.org.default.xml'
        [xml]$settings = Get-Content $template -Raw
        $settings.SelectSingleNode('//OrganizationalSetting[@id="V-278207"]').SetAttribute('ValueData', 'Organization-approved login notice')
        $settingsPath = Join-Path $TestDrive 'Approved.org.xml'
        $settings.Save($settingsPath)
        $outputPath = Join-Path $TestDrive 'ExplicitSettings'
        New-PowerStigWindowsMof -Target $targetInfo -OrgSettingsPath $settingsPath -OutputPath $outputPath -WarningAction SilentlyContinue | Out-Null
        $mof = Get-Content (Join-Path $outputPath 'localhost.mof') -Raw
        $mof | Should Match 'Organization-approved login notice'
        $adminResource = @([regex]::Matches($mof, '(?s)instance of MSFT_RegistryResource\b.*?\r?\n};') |
            Where-Object { $PSItem.Value -match 'ValueName = "ConsentPromptBehaviorAdmin";' })
        $adminResource.Count | Should Be 1
        $adminResource[0].Value | Should Match 'ValueData\s*=\s*\{\s*"2"\s*\}'
    }
}