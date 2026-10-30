---
title: OMv2 Web Filtering
description: Convert, review, provision, and export OMv2 web-filtering configuration while preserving OMv1 support.
---

# OMv2 web filtering

Use the existing vendor converter first, then
`ConvertTo-EntraInternetAccessV2Plan` to produce **reviewable OMv2 CSVs**.
Provision and export with the explicit `-PolicyModel OMv2` option.
Omitting that option keeps the existing OMv1 behavior.
This is Web Filtering OMv2, not Traffic Forwarding Profile V2.

**Target-environment validation is still required.** Local contract tests do not
establish production availability, service limits, URL-matching equivalence, or
effective enforcement. An unavailable endpoint or unsupported feature fails
explicitly; the toolkit never falls back to OMv1 or substitutes another default.

## Convert and review

```powershell
Import-Module ./Migrate2GSA/Migrate2GSA.psd1 -Force
$plan = ConvertTo-EntraInternetAccessV2Plan `
    -PoliciesCsvPath ./policies.csv `
    -SecurityProfilesCsvPath ./profiles.csv `
    -DefaultAction Block `
    -OutputPath ./output
```

`Block` is an explicit example, **not a universal recommended default**.
The converter does not authenticate or modify a tenant. It writes two UTF-8 BOM
CSV files and a log in a timestamped `EIA-OMv2Plan_*` folder. `-WhatIf` validates
the inputs without writing files.

Each profile gets one `<SecurityProfileName>-WebFilteringV2` policy. Source web
policy links are sorted by numeric priority; source CSV row order is preserved
within each policy. Rules receive priorities 100, 200, 300, and so on, and inherit
their source policy's Allow/Block action. Shared policies are expanded separately
for each profile.

Review the output in Excel or a CSV editor before selecting any rows:

- Generated rules and profiles start **Disabled**. `Provision` is not runtime
  state. Choose rule, profile, and link states explicitly.
- All generated rows start `ReviewNeeded=Yes` and `Provision=No`. After reviewing
  the complete target policy/profile, set `ReviewNeeded=No` and select the objects
  to create with `Provision=Yes`.
- FQDN input becomes a proposed URL rule with its source text unchanged. Validate
  domain boundaries, wildcards, root domains, paths, and TLS-inspection needs.
  No automatic wildcard rewrite or equivalence claim is made.
- Unsupported actions/types, empty destinations, source review notes, and omitted
  links remain visible for correction. Do not approve unresolved placeholders.
- Review CA assignments and all non-web dependencies separately.

`-IncludePolicyName` and `-ExcludePolicyName` support case-insensitive wildcard
filters on source names; exclusion wins. Omitted policies are recorded as
incomplete-profile warnings. Profiles without selected web rules are retained for
review but cannot be provisioned without a valid target web policy.

TLS inspection, threat intelligence, cloud firewall, and other non-web policies
are **not converted by this stage**. Their source links are retained for review,
not recreated. Use their existing workflows separately. No existing OMv1 or
non-web policy/link is removed.

## Provision

Connect to the intended Graph environment and tenant yourself. The OMv2 path uses
relative beta Graph URLs through the existing request/pagination/retry helper.

```powershell
Connect-MgGraph -Scopes NetworkAccess.ReadWrite.All

# First edit and review both CSVs; unchanged generated rows are not selected.
$parameters = @{
    PolicyModel = 'OMv2'
    PoliciesCsvPath = $plan.PoliciesCsvPath
    SecurityProfilesCsvPath = $plan.SecurityProfilesCsvPath
    SkipCAPoliciesProvisioning = $true
}
Start-EntraInternetAccessProvisioning @parameters -WhatIf

# Run only after checking the preflight log and authorizing tenant changes.
$result = Start-EntraInternetAccessProvisioning @parameters
```

Policy-only provisioning is supported by omitting `SecurityProfilesCsvPath`.
`-PolicyName` selects one exact CSV policy name and cannot be combined with
`SecurityProfilesCsvPath`. New policies/profiles/CA policies receive the
`[Migrate2GSA]` suffix; already-suffixed names do not receive another suffix.

Preflight checks **all selected objects before the first write**:

| Tenant state | Result |
|---|---|
| Missing selected object | Create and read back to verify. |
| Equivalent existing object | Reuse; do not write. |
| Same-name object differs | Report differing fields and stop. |
| Duplicate names or conflicting priorities | Stop; do not choose an arbitrary object. |
| Target policy has extra rules | Stop; those rules may change behavior. Do not delete them. |
| Profile links a different OMv2 policy | Stop; do not replace the link. |
| CA-linked profile needs a new web link | Stop rather than attempting an unsupported change. |
| Other tenant policies or non-web/OMv1 links | Leave untouched. |

Comparison includes defaults, descriptions, rule destinations/actions/priority/
status, profile settings, links, and requested CA configuration. Destination sets
can be reordered without causing a conflict; URL path case is preserved.
Service IDs/timestamps and null optional fields do not create false differences.
Unsupported non-empty settings are not silently ignored.

The CSV describes the complete desired rule set of each selected policy. A row
with `Provision=No` can serve as an existing-object reference during retry, but
its rule must already exist and match. Remove deliberately unwanted rows from
the reviewed input; do not expect `Provision=No` to disable or delete a rule.

After successful operations, retry CSV rows become `Provision=No`. Failed or
unattempted selected rows remain `Yes`. Keep both result files together so
profile retries can validate already-created policy/rule dependencies. Errors
remain terminating even when retry files are written.

`-WhatIf` performs authenticated read-only preflight; it makes no Graph writes
and writes no retry CSVs. `-Force` suppresses confirmation, **not validation or
WhatIf**. Preflight is not a transaction or lock: concurrent portal edits and
partial service failures can still occur. Re-run to discover and verify objects;
there is no rollback or automatic overwrite mode.

### Conditional Access

Without `-SkipCAPoliciesProvisioning`, profile provisioning also requires
`Policy.ReadWrite.ConditionalAccess`, `User.Read.All`, and `Group.Read.All`.
`CADisplayName`, `EntraUsers` (UPNs), and `EntraGroups` (display names) produce a
**disabled** CA policy targeting all client app types using the existing toolkit
assignment shape. Missing,
ambiguous, or unresolved assignments stop preflight.

OMv2 export can instead preserve full CA definitions in
`ConditionalAccessPoliciesJson`, including exclusions and additional conditions.
That column takes precedence over the simplified assignment columns; IDs inside
it are tenant-specific and need review when moving tenants. Profile references
are rebound to the target profile.
**The state in an exported CA definition is preserved, including Enabled.**
Review it explicitly before provisioning; use the skip switch when CA changes
are not intended.

## Export

```powershell
Connect-MgGraph -Scopes NetworkAccess.Read.All
$backup = Export-EntraInternetAccessConfig -PolicyModel OMv2 -OutputPath ./backup
```

Add `-IncludeConditionalAccessPolicies` and `Policy.Read.All` to export full CA
definitions. Without the switch, CA names are references only: supply assignments
or skip CA provisioning when importing.

Export writes policies (including unlinked and default-only policies), all their
rules, and profiles linked to OMv2 policies. All rows start review-required with
`Provision=No`; runtime states are preserved. Supported configurations can be
reviewed and imported without losing rule order, actions, defaults, or link state.
Unknown rule features are retained in source JSON columns and marked with
`UnsupportedDetails`, not silently flattened into less restrictive rules.
Selected rows with `UnsupportedDetails` are rejected. Resolve them deliberately;
simply changing `ReviewNeeded` is insufficient.

An API retrieval failure stops export rather than reporting an incomplete backup
as successful. This is an OMv2 web-filtering export, **not a complete tenant backup**.

## CSV contract: `EIA-OMv2/1.0`

The old offline `EIA-OMv2-Plan/0.1` contract is not accepted. Regenerate it with the
current converter. CSV fields are toolkit fields, not Graph property names.

### Policy/rule rows

| Columns | Meaning |
|---|---|
| `SchemaVersion`, `PolicyName`, `Description` | Contract and policy identity/description; description is optional. |
| `PolicyDefaultAction` | `Allow`, `Block`, or `ContinueEvaluation`; identical across a policy's rows. |
| `RuleName`, `RuleDescription`, `RulePriority` | Rule identity, optional description, and unique positive integer priority. |
| `RuleStatus`, `RuleAction` | `Enabled`/`Disabled` and `Allow`/`Block`. |
| `RuleType`, `RuleDestinations` | `URL` or `webCategory`, with semicolon-separated values. |
| `ReviewNeeded`, `Provision` | Explicit `Yes`/`No` review and import selection. |

A default-only policy has one row with `RuleType=None` and empty rule fields.
Source provenance, review details, unsupported details, and source JSON columns
are retained where available. Values containing literal semicolons and advanced
matching/action features cannot be represented by the simple destination columns;
export preserves them for review rather than silently changing their meaning.

### Profile rows

| Columns | Meaning |
|---|---|
| `SchemaVersion`, `SecurityProfileName`, `Description` | Contract and profile identity/optional description. |
| `Priority`, `ProfileState`, `LinkState` | Profile priority (1-65000) and explicit Enabled/Disabled states. |
| `WebFilteringPolicyName`, `PolicyDefaultAction` | Exactly one referenced policy, present in the policies CSV, with a matching default. |
| `CADisplayName`, `EntraUsers`, `EntraGroups` | Optional simplified CA assignment input. |
| `ConditionalAccessPoliciesJson` | Optional full CA definitions, taking precedence over simplified assignment columns. |
| `ReviewNeeded`, `Provision` | Review and import selection. |

## Evaluation and limits

Read [Microsoft's web-filtering documentation](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-web-filtering)
before choosing defaults:

- ContinueEvaluation applies only when no rule matches. If there is no next
  applicable profile, traffic is implicitly allowed. The baseline priority
  (65000) cannot use ContinueEvaluation.
- Allow/Block defaults terminate OMv2 evaluation. They are not automatically
  equivalent to OMv1 no-match behavior.
- OMv2 Allow can still be blocked by applicable OMv1 policy. This workflow does
  not perform migration cutover or unlink OMv1.
- Only basic Allow/Block URL/category rules are provisionable through this CSV
  contract. Advanced matching, redirects, and non-default action settings remain
  review-only when exported.
- Service quotas, effective access, and multi-profile behavior require testing in
  the intended environment before rollout.
