---
name: update-powerstig-stigs
description: "Use when updating PowerStig with DISA STIG ZIP files, regenerating StigData, handling new STIG configuration or check-content formats, adding or extending rule converters, validating new Windows STIG versions, or exporting the customized PowerStig module for another project."
---

# Update PowerStig STIG Data

Last modified: 2026-10-13

Use `Tools/StigUpdate/Invoke-StigUpdate.ps1` as the only batch entry point. Do not manually edit `source/StigData/Processed`.

## Workflow

1. Confirm the input ZIP files are under `STIGS`, unless the user supplied another input path.
2. Run `Invoke-StigUpdate.ps1 -WhatIf` and inspect the returned `Items`. Stop if any archive is unmatched or has an unexpected output count.
3. Run `Invoke-StigUpdate.ps1` to archive and convert the inputs.
4. Read `Tools/StigUpdate/last-update-report.json`. Require `Succeeded` to be `true`, every item to have `Status` equal to `Converted`, and no `QualityFindings` item with `Severity` equal to `Error`.
5. Parse every newly listed `ProcessedFiles` entry as XML.
6. Import the module and use `Get-Stig -ListAvailable` to verify the requested versions and server roles.
7. When the user needs the module in another repository, run `Export-PowerStigModule.ps1 -Destination <project module path> -Force`.

## Extension Rules

- Add filename conventions to `Tools/StigUpdate/stig-update.json`; keep product-specific behavior declarative when possible.
- A ZIP must contain exactly one `*-xccdf.xml` source file.
- Windows Server profiles must set `splitServerRoles` to `true`; expected output is MS and DC settings plus their organization defaults.
- Preserve existing archive files and conversion logs. New versions are additive.
- Treat conversion errors as parser or source-format issues. Do not suppress them or publish partial output.

## Handling New Configuration Formats

When a new STIG introduces an unrecognized configuration or changes the wording of `check-content`, classify the change before editing:

1. **New ZIP or XCCDF naming only**: add a profile to `Tools/StigUpdate/stig-update.json`, then use `-WhatIf` to prove exactly one profile and the expected output files are selected.
2. **Source-specific spelling, punctuation, or layout variation**: add a same-name `.log` beside the archived XCCDF. Use `RuleId::OldText::NewText`; multiple entries for one rule are allowed. Use `RuleId::*::NewText` only when replacing all check content is intentional. An empty `NewText` is not parsed, so use a meaningful non-matching replacement or fix the converter.
3. **Reusable wording or semantic variation of an existing rule type**: update the owning converter under `source/Module/Rule.<Type>/Convert`:
	- update `Data.ps1` for shared patterns;
	- update `Methods.ps1` for extraction or normalization behavior;
	- update `<Type>Rule.Convert.psm1` only when matching, construction, or orchestration changes;
	- add the real DISA `CheckContent` and expected extracted properties to `Tests/Unit/Module/<Type>Rule.tests.ps1`.
4. **Entirely new rule type or DSC configuration shape**: first confirm no existing rule class can represent it. Mirror the nearest existing rule type, then use code-reference search to register every required surface. At minimum inspect:
	- `source/Module/Rule.<Type>/<Type>Rule.psm1` for the data class;
	- `source/Module/Rule.<Type>/Convert` for matching and extraction;
	- `source/Module/Rule/Convert/ConvertFactory.psm1` for converter import and ordered dispatch;
	- `source/PowerStig.Convert.psm1` for conversion-module loading;
	- the target DSC composite resource and module build inputs when the runtime resource shape also changes;
	- `Tests/Unit/Module/<Type>Rule.tests.ps1` and an integration configuration when a new DSC resource is emitted.

Prefer a converter fix when the format is expected to recur. Prefer a versioned `.log` correction when DISA supplied a one-off formatting defect. If the setting cannot be represented safely, explicitly convert it to a documented/manual rule rather than guessing automation values, and record the reason in the correction log or issue matrix.

## Validation After Converter Changes

1. Run the narrow Pester 4.10.1 test for the changed rule type immediately after the edit.
2. PowerShell class definitions remain loaded in a session. Run class-based converter tests and the next conversion in a fresh PowerShell process or job so stale classes cannot hide the change.
3. Run `Invoke-StigUpdate.ps1` again and require `Succeeded=true`, every item `Status=Converted`, and no error-severity quality findings.
4. Inspect the affected rule IDs in generated XML. Verify the rule type, `dscresource`, required values, role-specific behavior, and absence of `conversionstatus="fail"`.
5. Run the STIG release tests named `Conversion Status`, `Stale Log File Entries`, and `N-2 STIGs exist in repo`.
6. Export the module only after all checks pass. Never repair generated `source/StigData/Processed` XML directly.

See `Tools/StigUpdate/README.zh-CN.md` for architecture, commands, dependency setup, and troubleshooting.