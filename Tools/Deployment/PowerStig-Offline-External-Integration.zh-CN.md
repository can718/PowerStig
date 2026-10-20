# PowerStig Windows 离线包外部集成说明

本文档可直接提供给负责调用 PowerStig 离线包、生成 HTML 报告或编写自动化程序的 AI 或开发人员。

## 1. 集成目标

使用单文件 PowerStig Windows 离线包执行只读合规检查，并读取 STIG Rule 级别结果。

必须遵守以下原则：

1. 使用离线包的 `Check` 模式，不得使用 `Deploy` 模式。
2. 必须以管理员身份运行。
3. 不得只根据进程退出码判断检查是否执行成功。
4. 必须从 summary JSON 的 `RuleResults` 读取 Rule ID、状态和原因。
5. 不得从 `ResourceId`、`DscResourceIds` 或 `SourceInfo` 中自行解析 STIG Rule ID。
6. 当 `RuleResultsAvailable=false` 时，不得伪造 Rule 级结果。

## 2. 输入文件

外部调用方需要：

- `PowerStig-Windows-Offline-4.30.0.ps1`：单文件离线包。
- `OrgSettings.xml`：可选。生产环境建议提供经过审核的组织配置。

离线包已经包含 PowerStig 和所需 DSC 模块，不需要另外安装或复制模块。

部署和检查必须使用同一份 `OrgSettings.xml`。如果不提供该文件，需要组织值的规则可能显示为 `NotReviewed`。

## 3. 运行环境

目标计算机必须满足：

- Windows Server 2019、2022、2025，或 Windows 10、11。
- Windows PowerShell 5.1 可用。
- 使用管理员权限运行。
- 没有其他 PowerStig 部署或检查任务同时运行。

离线包可以从 PowerShell 7 启动，但内部会调用 Windows PowerShell 5.1。

## 4. 标准调用命令

建议指定固定的解压目录，方便外部程序定位结果：

```powershell
$packagePath = 'C:\Baseline\PowerStig-Windows-Offline-4.30.0.ps1'
$extractRoot = 'C:\ProgramData\PowerStigOffline\ExternalCheck'
$orgSettingsPath = 'C:\Baseline\OrgSettings.xml'
$startedAt = Get-Date

& $packagePath `
    -Mode Check `
    -ExtractRoot $extractRoot `
    -OrgSettingsPath $orgSettingsPath

$processExitCode = $LASTEXITCODE
```

没有组织配置文件时，省略 `-OrgSettingsPath`：

```powershell
& $packagePath `
    -Mode Check `
    -ExtractRoot $extractRoot

$processExitCode = $LASTEXITCODE
```

只有在本机执行策略阻止 DSC，且组织允许修改 `LocalMachine` 执行策略时，才增加：

```powershell
-ConfigureExecutionPolicy
```

`Check` 模式不会调用 `Start-DscConfiguration`，不会应用 STIG 设置。

## 5. 定位本次 summary JSON

结果默认位于：

```text
<ExtractRoot>\Scripts\Logs
```

使用运行开始时间筛选本次结果，避免误读历史文件：

```powershell
$logRoot = Join-Path $extractRoot 'Scripts\Logs'
$summaryFile = Get-ChildItem -LiteralPath $logRoot `
    -Filter 'Test-PowerStig-*.summary.json' `
    -File |
    Where-Object LastWriteTime -ge $startedAt |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $summaryFile)
{
    throw 'PowerStig did not produce a summary JSON for this run.'
}

$result = Get-Content -LiteralPath $summaryFile.FullName -Raw -Encoding UTF8 |
    ConvertFrom-Json
```

## 6. 正确的结果判断顺序

必须按照以下顺序判断：

```powershell
if (-not $result.Succeeded)
{
    throw "PowerStig execution failed at stage '$($result.FailureStage)': $($result.Error)"
}

if (-not $result.RuleResultsAvailable)
{
    Write-Warning "Rule results unavailable: $($result.RuleResultsUnavailableReason)"
    # 只能展示整体 InDesiredState 和现有 Resources，不能生成 Rule 级结论。
}
elseif ($result.InDesiredState)
{
    Write-Output 'The computer is compliant with the evaluated baseline.'
}
else
{
    Write-Output 'The compliance check completed, but one or more evaluated resources are noncompliant.'
}
```

进程退出码含义：

- `0`：检查执行成功并且整体合规。
- `1`：可能是检查成功但不合规，也可能是检查执行失败。

因此，退出码只能用于进程层面的快速判断。最终结论必须读取 summary JSON 的 `Succeeded`、`InDesiredState` 和 `RuleResultsAvailable`。

## 7. Schema v3 结果契约

`SchemaVersion` 表示当前 JSON 文件的数据结构版本，用于告诉读取程序有哪些字段可用。它不是 PowerStig 模块版本，也不是 DISA STIG 基线版本。

对于 `Test-PowerStig-*.summary.json`：

| SchemaVersion | 能力 |
|---|---|
| `1` | 初始检查摘要，主要提供执行状态、整体 `InDesiredState`、资源数量、日志路径和基础 `Resources`。不同早期版本的资源详细字段可能不完全一致。 |
| `2` | 标准化 DSC Resource 级结果，增加或明确 `DetailedResultAvailable`、`Resources`、`DesiredResourceCount`、`NoncompliantResourceCount`、`ResourceCsv`、资源错误及评估信息。它仍然是 DSC Resource 视角，不是 STIG Rule 视角。 |
| `3` | 在保留 v2 字段的基础上新增 STIG Rule 级结果，包括 `RuleResults`、六种 Rule 状态、Rule 状态计数、`RuleResultsAvailable`、`RuleResultsUnavailableReason` 和 `RuleCsv`。 |

v3 保留了原有 `Resources` 和 `ResourceCsv`，因此只读取旧字段的调用方可以继续工作。需要生成 Rule 级报告的程序必须确认检查摘要的 `SchemaVersion >= 3`。

`Deploy-PowerStig-*.summary.json` 和离线包 `PackageMetadata.json` 是不同类型的 JSON，可能继续使用各自的 `SchemaVersion=1`。不要要求所有 PowerStig JSON 文件的 SchemaVersion 都等于 3。

外部调用方至少应读取以下 summary 字段：

| 字段 | 类型 | 含义 |
|---|---|---|
| `SchemaVersion` | Number | 当前 Rule 级结果版本为 `3` |
| `Succeeded` | Boolean | 检查流程是否成功完成 |
| `InDesiredState` | Boolean | DSC 整体合规状态 |
| `DetailedResultAvailable` | Boolean | DSC 是否返回资源级详细结果 |
| `RuleResultsAvailable` | Boolean | Rule 级结果是否可信且可用 |
| `RuleResultsUnavailableReason` | String/null | Rule 级结果不可用的原因 |
| `TotalRuleCount` | Number | Rule 总数 |
| `CompliantRuleCount` | Number | 合规 Rule 数量 |
| `NoncompliantRuleCount` | Number | 不合规 Rule 数量 |
| `SkippedRuleCount` | Number | 跳过 Rule 数量 |
| `NotApplicableRuleCount` | Number | 不适用 Rule 数量 |
| `NotReviewedRuleCount` | Number | 未检查 Rule 数量 |
| `ErrorRuleCount` | Number | 执行异常 Rule 数量 |
| `RuleResults` | Array | Rule 级结果列表 |
| `Resources` | Array | 兼容旧调用方的 DSC Resource 结果 |
| `ResourceCsv` | String | DSC Resource CSV 路径 |
| `RuleCsv` | String | Rule 级 CSV 路径 |

必须验证：

```text
TotalRuleCount =
    CompliantRuleCount +
    NoncompliantRuleCount +
    SkippedRuleCount +
    NotApplicableRuleCount +
    NotReviewedRuleCount +
    ErrorRuleCount
```

如果等式不成立，应将该结果视为格式错误，不应生成最终报告。

## 8. RuleResults 字段

每个 `RuleResults` 元素包含：

| 字段 | 含义 |
|---|---|
| `RuleId` | 明确的 STIG Rule ID，例如 `V-254253` |
| `Title` | STIG Rule 标题 |
| `Severity` | 严重级别，例如 `high`、`medium`、`low` |
| `Status` | Rule 合规状态 |
| `Reason` | 状态原因或失败说明 |
| `DscResourceIds` | 与该 Rule 关联的全部 DSC Resource ID |
| `DscResourceId` | 兼容单资源读取的第一个 DSC Resource ID |
| `ModuleName` | PowerStig 模块名称 |
| `ModuleVersion` | PowerStig 模块版本 |
| `SourceInfo` | STIG 基线来源信息 |
| `ComplianceEvaluation` | 状态评估方式 |

外部程序必须直接使用 `RuleId`。不要从其他字段提取 `V-xxxxx`。

## 9. Status 枚举

`Status` 只允许以下值：

| Status | 报告含义 |
|---|---|
| `Compliant` | Rule 关联的所有 DSC Resource 均合规 |
| `NonCompliant` | 至少一个关联资源明确不合规 |
| `Skipped` | Rule 被跳过或未生成 DSC Resource |
| `NotApplicable` | Rule 明确不适用于目标系统 |
| `NotReviewed` | 需要人工检查或缺少组织配置，尚未得出结论 |
| `Error` | 资源执行异常，无法确定合规状态 |

不得把 `Skipped`、`NotApplicable` 或 `NotReviewed` 当作 `Compliant`。

建议 HTML 报告分别显示六种状态，并优先突出：

1. `Error`
2. `NonCompliant`
3. `NotReviewed`
4. `Skipped`
5. `NotApplicable`
6. `Compliant`

## 10. 读取 Rule 级结果

读取所有 Rule：

```powershell
$rules = @($result.RuleResults)
```

读取需要关注的 Rule：

```powershell
$attentionRules = @($rules | Where-Object {
    $PSItem.Status -in 'NonCompliant', 'Error', 'NotReviewed'
})
```

读取明确不合规的 Rule：

```powershell
$noncompliantRules = @($rules | Where-Object Status -eq 'NonCompliant')
```

外部 HTML 表格建议包含：

```text
RuleId
Title
Severity
Status
Reason
DscResourceIds
ModuleVersion
SourceInfo
ComplianceEvaluation
```

`DscResourceIds` 是数组。显示到 HTML 时可以使用换行或无序列表，不建议拼成不可读的长字符串。

## 11. 使用 Rule CSV

summary JSON 中的 `RuleCsv` 是本次运行生成的 CSV 路径：

```powershell
if (Test-Path -LiteralPath $result.RuleCsv)
{
    $ruleRows = Import-Csv -LiteralPath $result.RuleCsv -Encoding UTF8
}
```

CSV 适合表格导入；JSON 是权威结果，能够保留数组和数据类型。生成 HTML 报告时优先使用 JSON。

CSV 中的 `DscResourceIds` 使用分号连接。如果需要保留一对多关系，使用 JSON 中的数组字段。

## 12. RuleResults 不可用时

如果 `RuleResultsAvailable=false`：

1. 显示 `RuleResultsUnavailableReason`。
2. 可以显示 `Succeeded`、`InDesiredState`、`DesiredResourceCount` 和 `NoncompliantResourceCount`。
3. 可以显示兼容字段 `Resources` 和 `ResourceCsv`。
4. 不得把 DSC Resource 数量当作 STIG Rule 数量。
5. 不得从 Resource ID 猜测或构造 Rule 级结果。

示例：

```powershell
if (-not $result.RuleResultsAvailable)
{
    [pscustomobject]@{
        OverallInDesiredState = $result.InDesiredState
        DesiredResourceCount = $result.DesiredResourceCount
        NoncompliantResourceCount = $result.NoncompliantResourceCount
        Reason = $result.RuleResultsUnavailableReason
    }
}
```

## 13. 面向自动化程序的完整示例

```powershell
$ErrorActionPreference = 'Stop'
$packagePath = 'C:\Baseline\PowerStig-Windows-Offline-4.30.0.ps1'
$extractRoot = 'C:\ProgramData\PowerStigOffline\ExternalCheck'
$orgSettingsPath = 'C:\Baseline\OrgSettings.xml'
$startedAt = Get-Date

& $packagePath `
    -Mode Check `
    -ExtractRoot $extractRoot `
    -OrgSettingsPath $orgSettingsPath

$processExitCode = $LASTEXITCODE
$logRoot = Join-Path $extractRoot 'Scripts\Logs'
$summaryFile = Get-ChildItem -LiteralPath $logRoot `
    -Filter 'Test-PowerStig-*.summary.json' `
    -File |
    Where-Object LastWriteTime -ge $startedAt |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $summaryFile)
{
    throw "PowerStig exited with code $processExitCode and did not produce a summary JSON."
}

$result = Get-Content -LiteralPath $summaryFile.FullName -Raw -Encoding UTF8 |
    ConvertFrom-Json

if ($result.SchemaVersion -lt 3)
{
    throw "PowerStig summary schema $($result.SchemaVersion) does not provide Rule-level results."
}

if (-not $result.Succeeded)
{
    throw "PowerStig failed at stage '$($result.FailureStage)': $($result.Error)"
}

if (-not $result.RuleResultsAvailable)
{
    Write-Warning $result.RuleResultsUnavailableReason
    return
}

$countSum =
    $result.CompliantRuleCount +
    $result.NoncompliantRuleCount +
    $result.SkippedRuleCount +
    $result.NotApplicableRuleCount +
    $result.NotReviewedRuleCount +
    $result.ErrorRuleCount

if ($countSum -ne $result.TotalRuleCount)
{
    throw 'PowerStig Rule status counts do not equal TotalRuleCount.'
}

$allowedStatuses = @(
    'Compliant',
    'NonCompliant',
    'Skipped',
    'NotApplicable',
    'NotReviewed',
    'Error'
)

$invalidRules = @($result.RuleResults | Where-Object {
    $PSItem.Status -notin $allowedStatuses -or
    [string]::IsNullOrWhiteSpace([string] $PSItem.RuleId)
})

if ($invalidRules.Count -gt 0)
{
    throw 'PowerStig returned an invalid Rule status or an empty RuleId.'
}

$result.RuleResults |
    Select-Object RuleId, Title, Severity, Status, Reason,
        @{ Name = 'DscResourceIds'; Expression = { $PSItem.DscResourceIds -join '; ' } },
        ModuleName, ModuleVersion, SourceInfo, ComplianceEvaluation
```

## 14. 安全要求

外部调用方还必须遵守：

- 不要把整个 transcript 或异常对象直接发布到公共 HTML。
- 不要在命令行参数、HTML 或日志中写入密码、Token、SAS Token 或其他凭据。
- HTML 输出必须对 `Title`、`Reason`、`SourceInfo` 等文本进行 HTML 编码，防止内容注入。
- 不要修改或覆盖离线包内部文件。
- 不要并行运行多个使用相同 `ExtractRoot` 的检查。
- 如需并行检查，为每个进程指定独立的 `ExtractRoot`。

## 15. 给外部 AI 的最终实现要求

外部 AI 应实现以下流程：

1. 验证离线包和可选组织配置文件存在。
2. 以管理员权限执行离线包 `-Mode Check`。
3. 记录运行开始时间和进程退出码。
4. 定位本次运行生成的最新 summary JSON。
5. 使用 Windows PowerShell 5.1 兼容方式读取 UTF-8 JSON。
6. 先检查 `SchemaVersion` 和 `Succeeded`。
7. 再检查 `RuleResultsAvailable`。
8. 验证 Rule 状态计数之和等于 `TotalRuleCount`。
9. 验证每条 Rule 都有 `RuleId`，且状态属于允许的六种值。
10. 直接使用 `RuleResults` 生成 HTML，不解析 DSC Resource 字符串来推导 Rule ID。
11. 将 `NotReviewed`、`Skipped`、`NotApplicable` 与 `Compliant` 分开显示。
12. 当 Rule 结果不可用时只报告整体和资源级结果，并明确说明原因。
