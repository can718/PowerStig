# PowerStig STIG 更新工具

> 修改日期：2026-10-13

## 这个项目如何使用 STIG

PowerStig 的数据流分为三层：

1. `STIGS/*.zip` 是待处理的 DISA 发布包，不会被 PowerStig 自动加载。
2. `source/StigData/Archive` 保存从 ZIP 提取的原始 XCCDF。Windows Server 的综合 XCCDF 还会拆成 `MS`（Member Server）和 `DC`（Domain Controller）。
3. `source/StigData/Processed/*.xml` 是 PowerStig 运行时真正读取的数据。`source` 被构建或导出后，这些 XML 会随模块一起分发。

本目录的工具把这条流程固定下来，避免每次手动解压、改名和转换。

## 日常更新

把新的 DISA ZIP 放入仓库根目录的 `STIGS` 文件夹，然后在仓库根目录运行：

```powershell
# 1. 预检：读取并拆分 ZIP，但不修改 StigData
.\Tools\StigUpdate\Invoke-StigUpdate.ps1 -WhatIf

# 2. 执行：归档 XCCDF，并生成 Processed XML 和组织默认值 XML
.\Tools\StigUpdate\Invoke-StigUpdate.ps1 -Verbose
```

工具会生成 `Tools/StigUpdate/last-update-report.json`。该报告适合 CI 或 AI 读取，包含输入包、匹配的配置、归档目录、预计输出和状态。自动化流程必须同时确认顶层 `Succeeded` 为 `true`，且每个项目的 `Status` 为 `Converted`；任意规则转换失败都会终止，不会把部分结果报告为成功。

报告中的 `QualityFindings` 会关联上游未关闭 issue：证书缺少 Thumbprint（#1561/#1472）、UserRight 身份尾句点（#1560）、Member Server 包含 DC-only principal（#1562）、Linux 文件路径被解析为目录（#1563）会阻止发布；非 Document 规则使用 `dscresource=None`（#1533/#1535）会生成警告，需人工确认是否为预期的手工检查。

全部未关闭 issue 的适用范围和处理状态见 [UPSTREAM-ISSUES.zh-CN.md](UPSTREAM-ISSUES.zh-CN.md)。

新产品或新命名规则只需在 `stig-update.json` 的 `profiles` 中增加一项：

```json
{
  "name": "ExampleProduct",
  "filePattern": "^U_Example_(?<version>\\d+)_STIG_.*-xccdf\\.xml$",
  "archiveDirectory": "Example.{version}",
  "splitServerRoles": false
}
```

`filePattern` 必须唯一匹配 ZIP 中的 XCCDF。命名捕获组可在 `archiveDirectory` 中用 `{名称}` 引用。

## 在其他项目中使用

先将更新后的模块导出到目标项目的 `Modules` 目录：

```powershell
.\Tools\StigUpdate\Export-PowerStigModule.ps1 `
    -Destination C:\src\MyProject\Modules `
    -Force
```

目标项目通过私有模块目录优先加载：

```powershell
$moduleRoot = Join-Path $PSScriptRoot 'Modules'
$env:PSModulePath = "$moduleRoot;$env:PSModulePath"
Import-Module PowerStig -RequiredVersion 4.30.0 -Force
Get-Stig -ListAvailable |
    Where-Object Technology -in 'WindowsClient', 'WindowsServer'
```

PowerStig 依赖多个 DSC 模块。首次准备目标项目时，可先让 PowerShellGet 下载官方模块及依赖，再用本工具覆盖其中的 PowerStig 目录：

```powershell
Save-Module -Name PowerStig -RequiredVersion 4.30.0 -Path C:\src\MyProject\Modules
.\Tools\StigUpdate\Export-PowerStigModule.ps1 -Destination C:\src\MyProject\Modules -Force
```

需要 NuGet 包或正式发布产物时，使用项目原有构建流程：

```powershell
.\build.ps1 -ResolveDependency -Tasks pack
```

## 验证与排错

更新完成后至少检查：

```powershell
# 所有处理后文件都能作为 XML 读取
Get-ChildItem .\source\StigData\Processed\*.xml |
    ForEach-Object { [xml](Get-Content $_ -Raw) | Out-Null }

# 导出后可看到目标版本
Get-Stig -ListAvailable |
    Sort-Object Technology, TechnologyVersion, TechnologyRole, StigVersion
```

常见问题：

- `No profile ... matches`：在 `stig-update.json` 增加或修正文件名规则。
- ZIP 中 XCCDF 数量不是 1：清理发布包，或为该产品增加专用处理逻辑。
- 转换报规则解析错误：新版 DISA 文本格式超出现有解析器能力。参考 `source/StigData/Archive/formatting.md`，添加同名 `.log` 修正规则或更新对应 Rule 转换器后重试。
- 导入模块提示缺少依赖：先执行上面的 `Save-Module`，或按 `source/PowerStig.psd1` 的 `RequiredModules` 安装依赖。

不要直接编辑 `Processed` XML。它们是可再生成产物，修复应落在原始 XCCDF 的同名 `.log`、转换器或更新配置中。