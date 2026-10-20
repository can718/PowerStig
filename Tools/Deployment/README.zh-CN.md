# PowerStig Windows 一键部署与检查

最后更新：2026-10-14

本目录提供两个入口脚本和一个公共模块：

- `Deploy-PowerStigWindows.ps1`：编译并应用 STIG 配置。
- `Test-PowerStigWindowsCompliance.ps1`：合规检查，不应用 STIG 基线；会生成日志/MOF，并可按参数暂存 DSC 模块或配置执行策略。
- `PowerStig.Windows.Common.psm1`：两个入口共用的系统识别、版本映射、模块准备和 MOF 编译实现。
- `New-PowerStigOfflinePackage.ps1`：生成只需复制一个 `.ps1` 的自解压离线运行包。
- `PowerStig-Offline-External-Integration.zh-CN.md`：可直接提供给外部 AI 或报告程序的 Check 模式调用与 Schema v3 数据契约。

两个脚本都会自动切换到 Windows PowerShell 5.1，并生成详细文本日志、Transcript 和 JSON 摘要。检查脚本还会生成逐资源 CSV。

复制到其他机器或项目时，这三个文件必须放在同一目录。完整的文件清单、目录结构和运行步骤见 [复制配置与运行指南.zh-CN.md](复制配置与运行指南.zh-CN.md)。

如果不希望手动复制目录，运行 `New-PowerStigOfflinePackage.ps1 -Force`，然后只复制 `Packages` 中生成的单文件。详细命令见指南第 12 节。

## 支持的系统

| 目标 | PowerStig 技术类型 | STIG 版本 |
|---|---|---|
| Windows Server 2019 | WindowsServer | 3.9 |
| Windows Server 2022 | WindowsServer | 2.11 |
| Windows Server 2025 | WindowsServer | 1.4 |
| Windows 10 | WindowsClient | 3.6 |
| Windows 11 | WindowsClient | 2.11 |

Windows Server 会根据域角色自动选择 `DC` 或 `MS`。也可以用 `-Target` 和 `-ServerRole` 显式指定。

## 使用前准备

以管理员身份打开 PowerShell。首次运行建议使用以下参数：

- `-ModuleRoot <路径>`：指定包含 `PowerStig\<配置版本>` 的模块目录；版本统一配置在公共模块顶部。
- `-InstallDependencies`：把缺少的精确版本依赖下载到模块目录。
- `-StageModulesForDsc`：把 PowerStig 及依赖复制到 DSC LCM 可见的系统模块目录。
- `-ConfigureExecutionPolicy`：当 LCM 的机器级执行策略为 `Restricted` 时，将 `LocalMachine` 设置为 `RemoteSigned`。如果组策略已强制执行策略，脚本不会覆盖组策略。

如果模块已经全局安装，可以省略 `-ModuleRoot`。如果依赖已经暂存到系统模块目录，后续运行可以省略 `-InstallDependencies` 和 `-StageModulesForDsc`。

## 安全部署流程

先编译验证，不应用配置：

```powershell
.\Deploy-PowerStigWindows.ps1 `
    -ModuleRoot C:\Baseline\Modules `
    -InstallDependencies `
    -StageModulesForDsc `
    -WhatIf
```

确认 MOF 和日志后，一键应用：

```powershell
.\Deploy-PowerStigWindows.ps1 `
    -ModuleRoot C:\Baseline\Modules `
    -InstallDependencies `
    -StageModulesForDsc `
    -ConfigureExecutionPolicy
```

显式部署 Windows Server 2022 成员服务器：

```powershell
.\Deploy-PowerStigWindows.ps1 `
    -Target WindowsServer2022 `
    -ServerRole MS `
    -ModuleRoot C:\Baseline\Modules `
    -StageModulesForDsc `
    -ConfigureExecutionPolicy
```

## 合规检查

```powershell
.\Test-PowerStigWindowsCompliance.ps1 `
    -ModuleRoot C:\Baseline\Modules `
    -StageModulesForDsc `
    -ConfigureExecutionPolicy
```

检查脚本只调用 `Test-DscConfiguration`，不会调用 `Start-DscConfiguration`。退出码含义：

- `0`：脚本成功且系统合规。
- `1`：发现不合规项，或者检查执行失败。通过 JSON 摘要中的 `Succeeded` 和 `Error` 区分：`Succeeded=true` 且 `InDesiredState=false` 表示检查成功但系统不合规。

## 组织设置

没有提供 `-OrgSettingsPath` 时，部署与检查共用以下默认配置，无需创建组织设置 XML：完整 USG/DoD 登录警告正文、标题 `DoD Notice and Consent Banner`，以及管理员在安全桌面输入凭据（`ConsentPromptBehaviorAdmin=1`）。适用于 Windows Server 2019/2022/2025 的 DC/MS 和 Windows 10/11；Windows Server 2018 不是受支持的产品名称。

这些默认值在部署工具的 MOF 生成层提供，不修改模块原始 STIG 数据。直接使用 PowerStig DSC 资源时仍使用模块自己的默认值。其他空白组织规则继续跳过，不能将自动检查通过视为完整 STIG 审核。登录交互需在重新登录后验证，部分 UAC 更改需要重启。生产环境应审核法律声明是否适用于本组织。

显式提供 `-OrgSettingsPath` 时，使用该 XML 和基线本身的 UAC 值，不注入上述正文和 UAC 默认值；缺少自动标题规则的平台仍配置默认标题。组织策略需要自定义时，部署与检查必须传入同一文件：

```powershell
.\Deploy-PowerStigWindows.ps1 `
    -OrgSettingsPath C:\Baseline\OrgSettings.xml `
    -ModuleRoot C:\Baseline\Modules `
    -StageModulesForDsc `
    -ConfigureExecutionPolicy
```

同一个 XML 可传给检查脚本，确保部署与检查使用完全相同的基线。

TerraForge `deployOld.ps1` 不再自动创建、填充或读取先前生成的组织设置文件；只有设置 `POWERSTIG_ORG_SETTINGS_PATH` 才显式传入 XML。旧文件不会被删除。脚本和离线包必须一起更新；已有任务完成标记可能导致再次运行被跳过，应按 TerraForge 的重跑流程处理。此变更只恢复上述三项体验，不迁移其他旧版组织默认值。

## 输出文件

默认输出位于本目录下：

- `Artifacts\`：部署参考 MOF。
- `ComplianceArtifacts\`：检查参考 MOF。
- `Logs\*.log`：时间戳文本日志。
- `Logs\*.transcript.log`：PowerShell Transcript。
- `Logs\*.summary.json`：机器可读摘要。
- `Logs\*.resources.csv`：逐资源检查结果。

可通过 `-OutputRoot` 和 `-LogRoot` 修改输出位置。JSON 摘要记录目标系统、STIG 版本、模块路径、执行策略、MOF、结果和错误信息。
