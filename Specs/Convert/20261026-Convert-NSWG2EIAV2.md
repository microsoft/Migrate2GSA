# Convert-NSWG2EIAV2 preview specification

## Document Information

- Version: 0.1
- Date: 2026-10-26
- Status: Best-effort experimental implementation; not yet validated against real Netskope exports
- Target module: Migrate2GSA
- Function: Convert-NSWG2EIAV2
- Author: Migrate2GSA contributors

## Overview

Expose the best-effort Destination Profile implementation as a separate, explicitly invoked public
cmdlet. Preserve `Convert-NSWG2EIA` byte-for-byte; do not delegate either command
to the other. V2 is a cmdlet version, not GSA Filtering Policy Model V2.
Retain the existing converter architecture and shared helpers without altering
their behavior. The original [conversion specification](20251112-Convert-NSWG2EIA.md)
describes the inherited URL List algorithm; differences are specified here.

## Source Product Model

URL Lists and Destination Profiles coexist and have separate ID namespaces.
Modern categories refer to them through separate inclusion/exclusion arrays.
The source-backed synthetic samples and pinned public SDK contracts are documented
in [the fixture README](../../Samples/NSWG2EIA/DestinationProfiles/README.md).
Tenant Swagger and live export confirmation remain required.

## EIA Target Structure

Retain V1 filtering policies, security profiles, and CSV assignments. Every
Destination Profile rule is a review-only candidate with `Provision=No`.
Modern category/profile-linked security profiles are also `Provision=No`;
unaffected legacy rows retain the original flags. No provisioning is performed.

## Policy & Rule Naming Conventions

| Source | Policy name | Rule name |
|---|---|---|
| URL List / existing category | Original naming | Original naming |
| Destination Profile | `DestinationProfile-[id]-[Action]` | `Destination-[index]` |

The ID prefix separates profiles from same-named URL Lists; collisions with
generated legacy policy names and CSV link delimiters are rejected.

## Input File Structures

- RTP: existing category-by-name format; trim status whitespace before filtering.
  Direct RTP profile targeting is not supported.
- URL Lists: retain existing input path; optional if only profiles are referenced.
- Destination Profiles: direct array or complete `elements`/`total_count`
  envelope. Require unique `id`, `name`, `type` (`sensitive`, `insensitive`,
  `regex`), and `values` array. Preserve source `status` in review details.
- Categories: legacy structures or modern `elements`/`total_count` envelope.
  Modern fields are `included_url_lists`, `excluded_url_lists`,
  `included_destination_profiles`, `excluded_destination_profiles`,
  and `included_predefined_categories`. Validate typed ID arrays.
- Mapping CSV: unchanged name-based mapping; numeric category IDs remain unmapped.

## Output Files

Exactly three artifacts: `<timestamp>_V2_PREVIEW_EIA_Policies.csv`,
`<timestamp>_V2_PREVIEW_EIA_SecurityProfiles.csv`, and
`<timestamp>_Convert-NSWG2EIAV2.log`. Return the existing summary/path properties.
Emit a PowerShell warning and a log warning identifying experimental status.
Use a distinct telemetry event `Convert-NSWG2EIAV2`.

## Processing Logic

Load, validate, convert, aggregate, then export using the inherited pipeline.
Keep source ID namespaces separate. Reject missing references, incomplete
collections, invalid/duplicate profiles, and ambiguous category names.

Plain domains produce FQDN candidates; PQDN candidates include root and wildcard.
Other values produce placeholders with unchanged source strings in `ReviewDetails`.
Do not use legacy cleaning or case-insensitive deduplication on profiles.
Keep empty/pending profiles visible. Inclusions follow the source action;
exclusions use inverse-action candidates, requiring semantic review.

This isolation change deliberately retains the inherited assignment aggregation,
priorities, and lack of include/exclude policy-name filters rather than adding
unrelated conversion behavior. Source/target semantics, applied/pending selection,
and direct RTP references remain validation gaps.

## Function Interface

Required: `RealTimeProtectionPoliciesPath`, `CustomCategoriesPath`,
`CategoryMappingsPath`. Require at least one of `UrlListsPath` or
`DestinationProfilesPath`. All referenced sources must be supplied.
Optional: `OutputBasePath` (existing directory, defaults to current directory),
`EnableDebugLogging`. File inputs must exist.

The original command's parameters, logs, filenames, and behavior stay unchanged.
Synthetic regression checks and community reports do not establish production
readiness; see the [validation guide](../../website/docs/MigrationSources/Netskope/NetskopeV2Preview.md).
