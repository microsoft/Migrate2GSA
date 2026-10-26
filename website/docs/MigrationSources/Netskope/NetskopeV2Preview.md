---
sidebar_position: 4
title: Netskope Secure Web Gateway V2 (Experimental)
description: Help validate experimental Destination Profile export and conversion from Netskope Secure Web Gateway to Entra Internet Access.
---

This preview covers **Netskope Secure Web Gateway (NSWG) to Entra Internet Access
(EIA)** migration. It does not add Netskope Private Access (NPA) to Entra Private
Access (EPA) conversion support.

## Status and choosing a command

:::warning[Experimental - community validation needed]

`Export-NetskopeConfigV2` and `Convert-NSWG2EIAV2` are **best-effort experimental
implementations, not yet validated against real Netskope tenants/exports**.

They are based on public documentation and API models, with local automated checks
using synthetic fixtures and mocked API responses. Those checks are not evidence
of real-tenant compatibility or end-to-end migration correctness.

Community validation, corrections, and contributions are welcome.
These commands are not a production-ready replacement for the original commands.

:::

**V2 refers to these experimental cmdlets, not GSA Filtering Policy Model V2.**
The converter still generates the existing GSA V1 CSV contract.

| Existing command (unchanged) | Experimental command (explicit opt-in) |
|---|---|
| `Export-NetskopeConfig` | `Export-NetskopeConfigV2` |
| `Convert-NSWG2EIA` | `Convert-NSWG2EIAV2` |

Both pairs are exported by the same module. No aliases, forwarding wrappers, or
automatic upgrades redirect existing scripts to the preview. The original commands
retain their current behavior and limitations, including the original converter's
exact `Enabled` status comparison. The V2 converter additionally trims status
whitespace. The original converter does **not** gain Destination Profile support.

Use matching export/conversion pairs and separate input/output directories.
V2 export envelopes are not guaranteed to work with the original converter.
Switching back means invoking the original names with their original inputs.

## What the experimental implementation adds

`Export-NetskopeConfigV2` keeps URL Lists and Destination Profiles distinct,
retaining `url_lists.json` and `destinations.json`. It requests modern Custom
Categories and Destination Profiles using `limit=100` and increasing `offset`,
and saves their combined `elements`/`total_count` envelopes with returned fields,
including applied/pending status.

Page failures, missing/repeated IDs, changing totals, or premature empty pages
abort export instead of saving an incomplete profile collection. Legacy category
responses retain a warning that completeness is unverified. Other endpoints keep
their existing best-effort behavior; this is not proof of a complete tenant backup.
Export against a stable configuration; pagination does not provide a transactional
snapshot. The exporter performs GET requests only, not Netskope apply/migrate actions.

`Convert-NSWG2EIAV2` accepts `-DestinationProfilesPath` in addition to URL Lists.
It supports modern category inclusion/exclusion arrays with separate source ID
namespaces. Missing references and incomplete modern collections stop conversion.
Its existing RTP input still resolves categories by name; duplicate category names
are rejected rather than guessed.

All Destination Profile rule candidates have `ReviewNeeded=Yes`, `Provision=No`.
Plain domains remain FQDN candidates; wildcard candidates include root and
subdomains. More complex entries use placeholders, preserving their original
strings in `ReviewDetails` instead of passing through legacy URL cleanup.
Empty and pending profiles remain visible for review.

Security profiles involving modern categories or Destination Profiles also have
`Provision=No`. **Other legacy rules/profiles can still have `Provision=Yes`; do
not feed preview output into production provisioning without independent validation.**
Changing `Provision` alone does not make placeholders or changed semantics safe.

## Try the exporter in an authorized test tenant

If you already have an export, skip to
[testing the converter with your own export](#test-the-converter-with-your-own-export).
Otherwise use PowerShell 7 from a repository checkout containing the V2 commands.
Keep export files outside the repository in a protected folder.

```powershell
Import-Module ./Migrate2GSA/Migrate2GSA.psd1 -Force
$token = Read-Host 'Netskope read-only API token' -AsSecureString
Export-NetskopeConfigV2 `
    -ApiToken $token `
    -TenantUrl 'https://your-test-tenant.goskope.com' `
    -OutputDirectory (Join-Path $HOME 'netskope-validation/exports')
```

Use the read permissions listed in [the original export guide](NetskopeExportConfig.md).
Confirm availability, schemas, and pagination against **your tenant Swagger**.
The public SDK informs this implementation; it does not guarantee tenant compatibility.

The exporter writes `backup_v2_preview_<timestamp>/` with
`Export-NetskopeConfigV2.log`. Its complete-backup metadata identifies the output
as `Netskope_Configuration_V2_Preview`. Original backups remain separate.

## Test the converter with your own export

### Prepare your files

Use **PowerShell 7**, with the current directory set to the repository root, and a
checkout containing these experimental commands. Do not assume the installed
PowerShell Gallery version includes them. The explicit module import below loads
your local checkout. If `Get-Command Convert-NSWG2EIAV2` fails after importing,
check the checkout/version rather than substituting the original converter.

**Conversion is offline:** it needs no Netskope token or GSA login, does not modify
the input JSON, and does not provision GSA objects. Work on copies of a consistent
export from one tenant; preserve IDs and references across files. Keep inputs,
outputs, and logs outside the repository in an access-controlled folder.

| File | Requirement |
|---|---|
| `real_time_protection_policies.json` | Your RTP policies in the converter's existing category-by-name format. Required. |
| `custom_categories.json` | Your matching legacy or modern Custom Categories. Required. |
| `destinations.json` | Complete Destination Profile collection; required to test profile references. A differently named file can be passed to `DestinationProfilesPath`. |
| `url_lists.json` | Required if your categories still reference legacy URL Lists. |
| Category mapping CSV | Start with the repository's `Netskope-to-GSA-CategoryMapping.rename_to_csv`; review unresolved mappings in output. |

**Neither exporter currently produces `real_time_protection_policies.json`.**
Obtain it separately in the supported format. The
[existing sample](https://github.com/microsoft/Migrate2GSA/blob/main/Samples/NSWG2EIA/sample_real_time_protection_policies.rename_to_json)
illustrates that format; it is not a confirmed current RTP API schema. Do not
substitute sample policies for your own when validating an actual export. If your
RTP schema differs or policies directly target profiles, report that gap rather
than reshaping away unsupported fields to make conversion succeed.

### Run locally

Set `$inputDir` to your prepared export folder (or the exporter backup folder
after adding your matching RTP file). The example assumes both source types are
present. For a profile-only export, remove the `-UrlListsPath` line only if no URL
List references remain. For URL Lists only, remove `-DestinationProfilesPath`;
that exercises legacy compatibility, not Destination Profile support.

```powershell
$env:MIGRATE2GSA_TELEMETRY_OPTOUT = '1'
Import-Module ./Migrate2GSA/Migrate2GSA.psd1 -Force
Get-Command Convert-NSWG2EIAV2

$inputDir = Join-Path $HOME 'netskope-validation/input' # Change to your export folder.
$outputDir = Join-Path $HOME ("netskope-validation/output-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
$result = Convert-NSWG2EIAV2 `
    -RealTimeProtectionPoliciesPath "$inputDir/real_time_protection_policies.json" `
    -UrlListsPath "$inputDir/url_lists.json" `
    -DestinationProfilesPath "$inputDir/destinations.json" `
    -CustomCategoriesPath "$inputDir/custom_categories.json" `
    -CategoryMappingsPath './Samples/NSWG2EIA/Netskope-to-GSA-CategoryMapping.rename_to_csv' `
    -OutputBasePath $outputDir

$result | Format-List *
$policies = Import-Csv $result.PoliciesCsvPath
$profiles = Import-Csv $result.SecurityProfilesCsvPath
$policies |
    Format-Table PolicyName, PolicyAction, RuleDestinations, ReviewNeeded, Provision -Wrap
$policies | Where-Object ReviewNeeded -eq 'Yes' |
    Format-List PolicyName, RuleDestinations, ReviewDetails, Provision
$profiles | Format-List *
Get-Content $result.LogFilePath
```

`RealTimeProtectionPoliciesPath`, `CustomCategoriesPath`, and `CategoryMappingsPath`
are required. Supply at least one of `UrlListsPath` or `DestinationProfilesPath`,
and both when both source types are referenced. Input files and `OutputBasePath`
must exist. `-EnableDebugLogging` enables detailed logging.

Profiles accept a direct array or complete `elements`/`total_count` collection.
The supported profile match types are `sensitive`, `insensitive`, and `regex`.
Modern categories use `included_url_lists`, `excluded_url_lists`,
`included_destination_profiles`, `excluded_destination_profiles`, and
`included_predefined_categories`.

Outputs are `<timestamp>_V2_PREVIEW_EIA_Policies.csv`,
`<timestamp>_V2_PREVIEW_EIA_SecurityProfiles.csv`, and
`<timestamp>_Convert-NSWG2EIAV2.log`. Return properties remain `PoliciesCsvPath`,
`SecurityProfilesCsvPath`, `LogFilePath`, `PoliciesCreated` (rule-row count), and
`SecurityProfilesCreated`.

### Check the result before reporting success

Completion means CSVs were generated, **not** that the source policy was faithfully
migrated. Rule-row counts are not policy counts, and your output is not expected
to match the synthetic sample's 17 rows and two profiles.

1. Trace representative enabled RTP policies through category inclusions/exclusions
   to the source URL List/profile IDs and then to output rules and profile links.
   Confirm users/groups, actions, and ordering; investigate missing policies and
   logged filtering/skips. Direct RTP profile targeting is a known unsupported case.
2. Check that every generated Destination Profile row is `ReviewNeeded=Yes`,
   `Provision=No`, and that affected security profiles are `Provision=No`.
   Check preserved source values/status in `ReviewDetails`, including paths,
   ports, queries, regex, and pending objects.
3. Review placeholders, `UNMAPPED:` entries, and all warnings. A review candidate
   is not an equivalent target rule. Do not change flags simply to bypass review,
   and do not run provisioning as part of this walkthrough.

If conversion fails, preserve the error and identify the input shape/reference
involved. Incomplete-collection errors require all pages, not a manually adjusted
`total_count`. Missing-reference errors require the matching source export, not
deleting the reference. Unsupported schemas should be reported with a sanitized
minimal example. Inspect logs locally; use `-EnableDebugLogging` only when needed
and treat the extra output as sensitive.

### Try synthetic inputs instead

For an offline run without credentials, see the source-backed synthetic fixtures
and walkthrough in
[`Samples/NSWG2EIA/DestinationProfiles/`](https://github.com/microsoft/Migrate2GSA/tree/main/Samples/NSWG2EIA/DestinationProfiles).
These fixtures are **not actual customer exports**.

## Known gaps

- RTP export and direct RTP Destination Profile targeting are not implemented.
- Numeric predefined-category IDs do not map through the existing name-based CSV;
  they produce unresolved, non-provisioning rows.
- Applied/pending effective-policy selection still needs tenant validation.
- Ports, paths/queries, case sensitivity, regex, IP/CIDR/ranges, resolved-IP
  matching, wildcard/root matching, and longest-prefix differences need semantic
  validation. Exclusions currently generate inverse-action candidates, which may
  not preserve source policy ordering or exception scope.
- No GSA Filtering Policy Model V2, delta reconciliation, or NPA converter changes
  are included.

## Help validate

Community validation and contributions are welcome, including reports from
existing authorized exports without live tenant access. Use authorized data and
[open a GitHub issue](https://github.com/microsoft/Migrate2GSA/issues) with
**Netskope V2 validation** in the title. Report:

1. Module version/commit, PowerShell version, Netskope release, and which V2 command ran.
2. Expected versus actual behavior, including object counts across pages.
3. Whether the tenant uses legacy lists, profiles, or both; applied/pending states;
   and category inclusion/exclusion or direct RTP references.
4. A minimal sanitized reproduction and relevant sanitized errors/output.
   Include authorized schema details that differ from the public SDK.

Reports of successful runs are useful too: state exactly what you checked and
what remains unverified. To contribute a correction, open a focused pull request
with a sanitized minimal fixture, a regression test, and an explanation of the
confirmed source behavior. Schema corrections, missing-reference handling,
matching semantics, and documentation improvements are especially helpful.
Follow the repository's contribution guidance; do not remove review safeguards
solely because a synthetic test or one export succeeds.

**Do not post API tokens, authentication headers, raw debug logs, complete backups,
tenant identifiers, user identities, internal destinations, or real customer
configurations.** Replace sensitive values consistently so references still join.
Share only data you are authorized to publish; report schema/count differences
without attachments when sanitization is uncertain.

Successful fixture checks do not establish production readiness. Real export
coverage, tenant Swagger confirmation, and source-to-target behavior validation
are required before promoting the experimental implementation or removing review safeguards.
