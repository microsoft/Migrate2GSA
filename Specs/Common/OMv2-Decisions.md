# Web Filtering OMv2 decisions

Date: 2026-10-27

Status: Agreed direction; local implementation complete, tenant validation pending.

## Scope and compatibility

- Add web-filtering OMv2 conversion, provisioning, and export. Keep OMv1 as the
  default; selecting OMv2 must be explicit. Traffic Forwarding V2 is out of scope.
- Reuse existing vendor conversion outputs as input to the OMv2 conversion stage.
  Preserve the CSV/Excel review workflow and source provenance.
- Generate one web policy per security profile, with ordered per-rule actions and
  an explicitly chosen policy default. Never infer runtime state from `Provision`.
- Generated rows start with `Provision=No`, `ReviewNeeded=Yes`, and disabled rules.
  Review destination semantics, defaults, assignments, and state before provisioning.

## Evaluation and coexistence

- Support Allow, Block, and ContinueEvaluation policy defaults. ContinueEvaluation
  applies on no rule match; it is not a rule action or a universal migration default.
- The baseline must terminate with Allow or Block. Without a next applicable
  profile, ContinueEvaluation implicitly allows traffic.
- An unavailable API or unsupported action must fail visibly. Never silently
  replace ContinueEvaluation with Allow/Block or fall back to OMv1.
- Leave OMv1 policies and links untouched. Cutover/unlinking is a separate,
  explicitly authorized operation.
- FQDN-to-URL equivalence is not assumed. Preserve source text and require review
  of host, wildcard, and path behavior; do not invent a wildcard rewrite.

## Reruns

- Create missing objects. Reuse existing objects only after comparing their
  meaningful configuration, not merely their names.
- Stop and report differences on conflicts. Do not overwrite, replace, delete,
  or silently skip changed configuration.
- Preflight the selected configuration before writes where possible. Preserve
  retry information after partial failures; a failed run is not a transaction.
- Compare policy defaults, rule actions/destinations/priority/status, profile
  settings, and links. Reject ambiguous duplicate names and priority collisions.
- Leave extra tenant objects untouched. Extra rules within a reused target
  policy require a conflict because they can change that policy's behavior.
- Automatic update/reconciliation is deferred to a separately reviewed mode.

## Validation and release

- A test tenant and reviewer are available. Tenant writes and enforcement tests
  still require separate authorization.
- ContinueEvaluation save/readback was observed in the test environment; this
  does not establish production rollout or multi-profile enforcement.
- Validate payloads, export/import round trips, reruns, partial failures, and
  OMv1 compatibility locally, then validate effective traffic in the test tenant.
- Local verification passes with 47 tests. The documentation build succeeds
  with existing, unrelated anchor warnings. No live Graph writes or traffic
  validation have been performed.
- A hidden schema flag alone is not treated as a publication blocker. Do not
  include internal source documents, tenant data, or credentials in public files.
- No commits, pushes, PR publication, or tenant changes are authorized by this
  implementation task.
