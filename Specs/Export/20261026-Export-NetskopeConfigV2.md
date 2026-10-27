# Export-NetskopeConfigV2 preview specification

- Date: 2026-10-26
- Status: Best-effort experimental implementation; not yet validated against live Netskope tenants
- Function: Export-NetskopeConfigV2

## Isolation and compatibility

Expose the best-effort Destination Profile export implementation separately from
`Export-NetskopeConfig`, which remains byte-for-byte unchanged.
Do not redirect existing callers. V2 refers to the cmdlet, not GSA Filtering
Policy Model V2. Retain the original parameters (`ApiToken`, `TenantUrl`,
`OutputDirectory`, `RequestDelay`) and the read-only API operations.

## Export contract

Retain the original seven collection endpoints and filenames, including
`url_lists.json` and `destinations.json`. Modern Custom Categories and Destination
Profiles use `limit=100`, zero-based `offset`, and `elements`/`total_count`.
Save the accumulated envelope, retaining all returned fields and deployment
status. Abort on request failure, missing/repeated IDs, changing totals,
malformed responses, or premature empty pages; do not save partial collections.
Legacy categories retain existing response handling with a completeness warning.
Other endpoints retain existing best-effort behavior.

Do not extend the original specification's blanket no-pagination assumption to
this experimental implementation. The public SDK source contracts are linked in
[the sample provenance](../../Samples/NSWG2EIA/DestinationProfiles/README.md).
Verify routes, pagination, and schemas against tenant Swagger.
The exporter still does not export RTP policies, apply pending changes, or
migrate Netskope objects.

## Output and disclosure

Write `backup_v2_preview_<timestamp>/`, keeping internal JSON filenames unchanged.
Use `Export-NetskopeConfigV2.log`, complete-backup type
`Netskope_Configuration_V2_Preview`, and telemetry event `Export-NetskopeConfigV2`.
Emit an experimental warning on the PowerShell warning stream and in the log.
Successful completion does not certify a complete snapshot or tenant compatibility.

## Validation

Use mocked pagination/failure cases and side-by-side original/V2 regression tests.
Community validation with authorized test tenants is required; do not present
synthetic tests as live acceptance. See the
[community validation guide](../../website/docs/MigrationSources/Netskope/NetskopeV2Preview.md)
for safe reporting and remaining gaps.
