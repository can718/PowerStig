# 上游未关闭 Issue 预防矩阵

修改日期：2026-10-13

本文件记录 `microsoft/PowerStig` 未关闭 issue 与本仓库 STIG 更新流程的关系。状态以 2026-10-13 的上游 issue 为准。

| Issue | 风险 | 本仓库措施 | 发布策略 |
|---|---|---|---|
| #1560 | UserRight 身份带句末句点，生成无效账户名 | 转换器统一移除每个身份末尾句点；质量门槛扫描残留值；有单元测试 | 硬失败 |
| #1561、#1472 | CertificateImport 缺少 Thumbprint | 检查可执行 RootCertificateRule 的 Thumbprint；明确降级的 no-op 进入报告 | 缺 Thumbprint 硬失败，no-op 告警 |
| #1562 | Member Server ACL 包含仅适用于 Domain Controller 的 principal | Windows Server 2025 MS 修正日志移除该项；质量门槛检查 RawString 与 principal | 硬失败 |
| #1563 | 多路径或 glob 命令被解析为目录 | nxFileLine 正则选择第一个绝对文件路径并支持 glob；质量门槛拒绝目录结尾路径；有单元测试 | 硬失败 |
| #1533、#1535 | 非 Document 规则意外成为 `dscresource=None` | 将所有非 Document no-op 写入 `QualityFindings`，关联 issue 供人工复核 | 告警 |
| #1528 | PR 缺少 MOF/Test-DscConfiguration 验证 | 当前更新流程已做 XML、转换状态、语义质量和运行时发现验证；MOF 编译依赖完整 DSC 环境 | 后续 CI 增强 |
| #1536 | 缺少维护文档 | `README.zh-CN.md`、AI Skill 和本矩阵记录维护路径 | 已覆盖 |
| #1476 | SqlServerDsc 依赖版本更新 | 属于模块依赖升级，不是 STIG 数据转换问题 | 不在本工具范围 |
| #1552 | CKL 转 CKLB | 属于 checklist 格式转换，不是 STIG 数据发布问题 | 不在本工具范围 |

## 发布判断

自动化发布必须满足：

1. `last-update-report.json` 的 `Succeeded` 为 `true`。
2. 每个输入项目的 `Status` 为 `Converted`。
3. `QualityFindings` 中不存在 `Severity=Error`。
4. `Severity=Warning` 必须人工确认；不能仅因为 XML 可解析就忽略。
5. 使用仓库固定的 Pester 4.10.1 运行聚焦测试和 STIG 发布测试。

当前 Windows Server 2025 v1.4 的 #1560 与 #1562 签名均为 0。#1533/#1535 不能使用“所有 `dscresource=None` 都失败”的通用规则，因为仓库包含合法的人工检查和显式降级规则。
