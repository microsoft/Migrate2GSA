# Destination Profile preview samples

These are **synthetic fixtures**, not customer data or captured Netskope responses.
They support offline development of the category-to-Destination-Profile path.
They do not establish live-tenant compatibility or GSA matching equivalence.

Use **`Export-NetskopeConfigV2` / `Convert-NSWG2EIAV2`** for this best-effort
experimental implementation, not yet validated against real Netskope exports.
Community validation and contributions are welcome.
The original `Export-NetskopeConfig` / `Convert-NSWG2EIA` commands remain unchanged.
V2 is a cmdlet version label, **not GSA Filtering Policy Model V2 support**.
See the [V2 community validation guide](../../../website/docs/MigrationSources/Netskope/NetskopeV2Preview.md)
for limitations and how to submit sanitized feedback. Do not publish raw exports,
tokens, customer data, or unsanitized debug logs.

## Test with your own export

Follow the [own-export walkthrough](../../../website/docs/MigrationSources/Netskope/NetskopeV2Preview.md#test-the-converter-with-your-own-export)
for prerequisites, required files, a copy/paste conversion command, output checks,
and troubleshooting. Conversion runs locally without Netskope or GSA credentials
and does not provision anything. Keep your exports and generated files outside
the repository in a protected folder.

You need matching RTP policies, Custom Categories, and all referenced URL Lists
and Destination Profiles from your tenant. **Neither exporter currently exports
RTP policies**; obtain those separately in the supported format. Do not substitute
the synthetic RTP fixture for your own policies when validating a real export.
The fixture walkthrough below is a separate way to explore the implementation,
not evidence of compatibility with your tenant.

## Evidence and provenance

The field names and collection shapes come from Netskope's public Terraform
provider at revision `105043f36af62092afd1f4948ceec5503b9c179f`:

- [Profile item](https://github.com/netskopeoss/terraform-provider-netskope/blob/105043f36af62092afd1f4948ceec5503b9c179f/internal/sdk/models/shared/destinationprofileitem.go):
  JSON `id` (not the Terraform attribute `profile_id`), `name`, `type`, `values`,
  and deployment `status`. Match types are `sensitive`, `insensitive`, `regex`.
- [Profile collection](https://github.com/netskopeoss/terraform-provider-netskope/blob/105043f36af62092afd1f4948ceec5503b9c179f/internal/sdk/models/shared/destinationprofilelistresponse.go):
  `elements` and `total_count`.
- [Profile list request](https://github.com/netskopeoss/terraform-provider-netskope/blob/105043f36af62092afd1f4948ceec5503b9c179f/internal/sdk/models/operations/listdestinationprofiles.go):
  `limit` (maximum 100) and zero-based `offset`.
- [Category item](https://github.com/netskopeoss/terraform-provider-netskope/blob/105043f36af62092afd1f4948ceec5503b9c179f/internal/sdk/models/shared/customcategoryitem.go):
  separate `included_url_lists`, `excluded_url_lists`,
  `included_destination_profiles`, `excluded_destination_profiles`,
  and numeric `included_predefined_categories` IDs.
- [Category collection](https://github.com/netskopeoss/terraform-provider-netskope/blob/105043f36af62092afd1f4948ceec5503b9c179f/internal/sdk/models/shared/customcategorylistresponse.go)
  and [list request](https://github.com/netskopeoss/terraform-provider-netskope/blob/105043f36af62092afd1f4948ceec5503b9c179f/internal/sdk/models/operations/listcustomcategories.go).

The destination syntax is based on Netskope's
[network target documentation](https://docs.netskope.com/en/adding-network-targets-to-destination-profiles)
and [migration documentation](https://docs.netskope.com/en/migrating-url-lists-to-destination-profiles).
Names, UUIDs, policy assignments, and test addresses were created for these tests.
The RTP fixture uses the repository's **existing category-by-name input format**;
it is not evidence of the current RTP API schema or direct profile targeting.

## Run locally

From the repository root in PowerShell 7 (no tenant credentials needed):

```powershell
$env:MIGRATE2GSA_TELEMETRY_OPTOUT = '1'
Import-Module ./Migrate2GSA/Migrate2GSA.psd1 -Force
$sample = './Samples/NSWG2EIA'
$output = Join-Path ([IO.Path]::GetTempPath()) ("netskope-profiles-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $output | Out-Null
$result = Convert-NSWG2EIAV2 `
    -RealTimeProtectionPoliciesPath "$sample/DestinationProfiles/real_time_protection_policies.rename_to_json" `
    -UrlListsPath "$sample/sample_url_lists.rename_to_json" `
    -DestinationProfilesPath "$sample/DestinationProfiles/destinations.rename_to_json" `
    -CustomCategoriesPath "$sample/DestinationProfiles/custom_categories.rename_to_json" `
    -CategoryMappingsPath "$sample/Netskope-to-GSA-CategoryMapping.rename_to_csv" `
    -OutputBasePath $output

Import-Csv $result.PoliciesCsvPath |
    Format-Table PolicyName, RuleDestinations, Provision -Wrap
Import-Csv $result.SecurityProfilesCsvPath |
    Format-List *
```

The converter reads JSON content, so copying/renaming the fixtures is optional.
Output CSV filenames contain `_V2_PREVIEW_` to separate them from original runs.
Expected output: **17 rule rows and 2 security profiles**:

- Six legacy `Whitelist URLs-Block` rows remain distinct from the same-named
  Destination Profile.
- Seven included Destination Profile Block candidates, two excluded profile
  Allow candidates, and one regex Allow placeholder are all `Provision=No`.
- One predefined-category row is unresolved (`UNMAPPED:NetskopeCategoryId:500`);
  the existing CSV maps category *names*, not numeric IDs.
- Both security profiles are `Provision=No`. The exclusion uses the inverse
  action as a review candidate, not a claim of equivalent evaluation order.

Exact domain candidates retain domains. A PQDN candidate includes both the root
and wildcard (`example.com;*.example.com`). Other values use non-provisioning
placeholders with the **unchanged original string in ReviewDetails**, including
case, ports, query strings, regex, and IP/CIDR/range syntax. Empty profiles also
produce a review placeholder rather than disappearing.

## Automated example validation

The regression suite validates both direct conversion of these fixtures and
an **export-to-conversion round trip**. From the repository root in PowerShell 7
with Pester installed:

```powershell
Invoke-Pester -Path ./tests/Netskope.DestinationProfiles.Tests.ps1 -Output Detailed
```

The integration test mocks only the exporter's HTTP requests. Destination Profiles
and Custom Categories are served from these exact fixtures one object per page;
URL Lists come from `../sample_url_lists.rename_to_json`. Unrelated export
endpoints use synthetic stub responses. The actual exporter writes JSON and logs,
and the actual converter reads those exported files, with the RTP fixture supplied
separately because RTP export is not implemented.

The test checks that exported source fields and references are preserved, all
generated profile links resolve, and the CSV content matches direct fixture
conversion: **17 rule rows, including 10 Destination Profile review rows, and two
security profiles**. All 10 Destination Profile rows and both security profiles
remain `Provision=No`. Logs are also written and checked. Pester uses temporary
test directories; use the local walkthrough above to retain output for inspection.

This validates the supplied synthetic examples and the file handoff between the
commands, **not** real API authentication, tenant schemas, or policy equivalence.

## Still required before production support

Obtain sanitized complete exports and the tenant Swagger contract from an
authorized Netskope tenant. Validate applied versus pending
objects, pagination, migrated category references, and destination matching in
both products. Establish numeric category-ID mapping and the direct RTP
Destination Profile representation. No guessed direct-target parser is included.
Keep `Provision=No` until those semantics have been reviewed; merely changing
the flag is not sufficient to make a placeholder deployable.
