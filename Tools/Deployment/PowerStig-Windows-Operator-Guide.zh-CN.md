# PowerStig Windows 离线包运行指南

最后更新：2026-10-14

本文说明如何在 Windows 目标机上运行 GitHub Actions artifact 中的离线包，执行合规检查、部署预演、正式部署，以及查看运行结果和日志。

## 1. 准备目标机

从 GitHub Actions 下载并解压 artifact。目录中应包含：

```text
PowerStig-Windows-Offline-<版本>.ps1
PowerStig-Windows-Deployment-Guide.zh-CN.md
```

离线包已包含 PowerStig、精确版本依赖和运行脚本。不需要再单独复制 Modules 或其他脚本。

运行前确认：

- 使用管理员身份打开 Windows PowerShell 5.1。也可以从 PowerShell 7 启动，离线包会调用 Windows PowerShell 5.1。
- 目标系统为 Windows Server 2019、2022、2025，或 Windows 10、11。
- 生产环境准备经过审核的 `OrgSettings.xml`。部署与检查必须使用同一份文件。
- 如执行策略由域组策略 `MachinePolicy` 强制设置，应由管理员处理；脚本不会覆盖该策略。

在解压目录中运行：

```powershell
Set-Location C:\PowerStigDeployment
$package = Get-ChildItem .\PowerStig-Windows-Offline-*.ps1 -File |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $package) { throw '未找到 PowerStig 离线包。' }
```

以下命令均使用变量 `$package`。如需组织设置，将 `-OrgSettingsPath` 和路径加到对应命令中。

## 2. 运行合规检查

先运行只读检查，不会应用 STIG 配置：

```powershell
& $package -Mode Check
```

如执行策略阻止运行，可按组织要求增加 `-ConfigureExecutionPolicy`。此参数可能将 `LocalMachine` 执行策略设置为 `RemoteSigned`；不会覆盖域组策略。

```powershell
& $package -Mode Check `
    -OrgSettingsPath C:\Baseline\OrgSettings.xml `
    -ConfigureExecutionPolicy
```

检查会生成参考 MOF、日志和结果文件；使用 `-StageModulesForDsc` 准备 DSC 模块目录，但不会调用 `Start-DscConfiguration` 或应用基线。

检查结果以 JSON 摘要为准：

| JSON 结果 | 含义 |
|---|---|
| `Succeeded=true`, `InDesiredState=true` | 检查成功，符合基线 |
| `Succeeded=true`, `InDesiredState=false` | 检查成功，但存在不合规资源；退出码为 1 |
| `Succeeded=false` | 检查执行失败；查看 `Error`、`FailureStage` 和日志 |

不要只根据退出码判断失败：不合规和脚本执行错误都可能返回非零退出码。

## 3. 部署预演

部署会修改系统安全设置。先运行 `-WhatIf`，它会准备模块并编译 MOF，但不会应用配置：

```powershell
& $package -Mode Deploy -WhatIf
```

使用组织设置时：

```powershell
& $package -Mode Deploy `
    -OrgSettingsPath C:\Baseline\OrgSettings.xml `
    -WhatIf
```

预演成功后，确认部署摘要中 `Succeeded=true`、`Applied=false`，并检查生成的 MOF 和日志。预演不会验证最终的系统应用结果。

## 4. 正式部署

只在测试环境验证预演并审核 MOF 后执行。正式部署必须以管理员身份运行，且命令中不要带 `-WhatIf`：

```powershell
& $package -Mode Deploy
```

使用组织设置时，部署命令和后续检查都传同一份文件：

```powershell
& $package -Mode Deploy `
    -OrgSettingsPath C:\Baseline\OrgSettings.xml
```

正式部署会调用 DSC 修改系统。脚本会等待部署完成并自动进行一次合规测试。检查摘要中的 `Succeeded`、`Applied`、`InDesiredState` 和 `RebootRequested`。若要求重启，先重启，再重新运行第 2 节的检查。

## 5. 查看日志和结果

离线包默认将载荷解压到 `%ProgramData%\PowerStigOffline`。查找最近一次运行目录及日志目录：

```powershell
$extractRoot = Get-ChildItem "$env:ProgramData\PowerStigOffline" -Directory |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$logs = Join-Path $extractRoot.FullName 'Scripts\Logs'
Get-ChildItem $logs -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 15 Name, LastWriteTime
```

查看最新合规检查摘要：

```powershell
$summary = Get-ChildItem $logs -Filter 'Test-PowerStig-*.summary.json' -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

Get-Content $summary.FullName -Raw | ConvertFrom-Json |
    Format-List Succeeded, InDesiredState, FailureStage, ExceptionType, Error, ErrorDetails
```

查看部署摘要：

```powershell
$summary = Get-ChildItem $logs -Filter 'Deploy-PowerStig-*.summary.json' -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

Get-Content $summary.FullName -Raw | ConvertFrom-Json |
    Format-List Succeeded, Applied, InDesiredState, RebootRequested, FailureStage, ExceptionType, Error
```

相关文件：

- `Test-PowerStig-*.resources.csv`：逐资源合规结果。用 `InDesiredState` 筛选不合规项。
- `*.transcript.log`：完整 PowerShell 会话记录。发生错误时，先查看错误前最后一个 `[[资源类型][V-规则号]...]` 记录。
- `Deploy-PowerStig-*.summary.json`、`Test-PowerStig-*.summary.json`：机器可读的运行结果。
- `Artifacts`、`ComplianceArtifacts`：部署或检查生成的 MOF。

PowerShell Server 2025 DC 的规则 `V-278138` 使用 NTDS 通配路径。AccessControlDSC 不支持该通配路径，预演/检查时会显示跳过警告，要求按照原始 STIG 手工审核实际数据库和日志文件 ACL；不要把通配路径改成整个 NTDS 目录后强制应用 ACL。

## 6. 只解压检查包

如需确认包内版本、脚本和模块，不运行部署或合规检查：

```powershell
& $package -Mode ExtractOnly
```

如需指定解压位置：

```powershell
& $package -Mode ExtractOnly -ExtractRoot C:\PowerStigExtracted
```
