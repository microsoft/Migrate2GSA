# Multiple Traffic Forwarding Profiles (MTFP) — coverage gaps and fix ideas

> **Status:** Proposal / not scheduled.
> **Scope:** `Export-EntraPrivateAccessConfig`, `Export-EntraPrivateAccessAppDiscovery`,
> `Export-EntraInternetAccessConfig`, `Start-EntraPrivateAccessProvisioning`.
> **Related fix:** the feature-enablement validation fix (multiple profiles per
> `trafficForwardingType` no longer throws a false "not enabled" error).

---

## 1. Background

Global Secure Access is rolling out **multiple traffic forwarding profiles per traffic
type** as a private preview. Two previews exercise the same underlying mechanism:

| Preview | Traffic type | Goal |
| --- | --- | --- |
| Multiple Forwarding Profiles for Private Access | `private` | Scope *which* PA apps reach which users/devices |
| Fail-Close | `internet` | Give selected users/devices a profile that blocks traffic when the GSA edge is unreachable |

Historically `GET /beta/networkAccess/forwardingProfiles` returned exactly one profile per
`trafficForwardingType`. With the preview it returns several — a default profile plus up to
10 custom profiles per type.

Per-profile attributes reported by the preview guides:

| Attribute | Notes |
| --- | --- |
| `priority` | Lower number = higher precedence. Custom profiles: 101–199. Default profile sentinel value unconfirmed. |
| `state` | `enabled` / `disabled`, per profile. |
| `clientFallbackAction` | `bypass` (fail-open, default) or `block` (fail-close). Not in the public schema yet. |
| User/device assignment | `No users/devices`, `All users and devices`, or `Selected users and devices`. |
| Device platform assignment | All / None / subset (Windows, macOS, Android, iOS). |
| Assignment evaluation | **AND** between the two assignment axes. |

When a user/device matches more than one profile, the **lowest numeric priority wins**, and
the contest is evaluated **independently per traffic type**.

---

## 2. What was already fixed

The three feature-enablement guards assumed a single profile:

```powershell
$paProfile = Get-IntNetworkAccessForwardingProfile -ProfileType 'private'
if (-not $paProfile -or $paProfile.state -ne 'enabled') { throw }
```

With four `private` profiles, `$paProfile` is an array, `$paProfile.state` enumerates to
`@('enabled','disabled','disabled','disabled')`, and `-ne 'enabled'` returns the three
non-matching elements — a non-empty (truthy) array. The guard threw on a tenant where the
feature *was* enabled. The guards now evaluate the full collection and pass when at least
one profile of that traffic type is enabled.

**This only restores the on/off gate.** Everything below is still missing.

---

## 3. Remaining coverage gaps

### 3.1 Export loses profile topology

`Export-EntraPrivateAccessConfig` emits one CSV row per application segment:

```
EnterpriseAppName, SegmentId, isQuickAccess, destinationHost, DestinationType,
Protocol, Ports, ConnectorGroup, Provision, EntraGroups, EntraUsers
```

There is no representation of:

- which forwarding profiles exist, or their `priority` / `state` / `clientFallbackAction`;
- which apps belong to which profile;
- per-profile user / group / device / platform assignment.

An admin exporting a preview tenant gets a CSV that silently implies "every app is reachable
by every assigned user" — which is exactly the assumption the preview breaks.

### 3.2 Provisioning cannot reproduce a preview tenant

`Start-EntraPrivateAccessProvisioning` creates apps, segments, and app-level group
assignments. It has no concept of a forwarding profile, so a restore into a preview tenant
silently collapses everything into the default profile — a **security-relevant** difference,
since apps intended for a narrow custom profile become broadly reachable.

### 3.3 Internet Access export misses fail-close posture

`Export-EntraInternetAccessConfig` exports filtering policies and security profiles but no
forwarding-profile data, so a `clientFallbackAction: block` profile is invisible in the
export.

---

## 4. Proposed shape

The preview turns Private Access from a **flat app list** into a **two-entity model**:
profiles, and a many-to-many join between profiles and apps. A single flat CSV cannot carry
that — profile attributes and assignment lists are not per-segment, and a profile with zero
apps would disappear entirely.

Proposal: **two artifacts**, following the pattern `Export-EntraInternetAccessConfig`
already uses (separate Policies and SecurityProfiles CSVs).

**1. `{timestamp}_EPA_Config.csv` — one new column**

| Column | Description |
| --- | --- |
| `ForwardingProfiles` | Semicolon-separated profile names, same convention as `EntraGroups`. Empty = default profile only. |

Additive and backward compatible: existing CSVs keep importing unchanged.

**2. `{timestamp}_EPA_ForwardingProfiles.csv` — new file**

| Column | Description |
| --- | --- |
| `ProfileName` | Profile display name (join key for the column above). |
| `Priority` | 101–199 for custom profiles. |
| `State` | `enabled` / `disabled`. |
| `IsDefault` | Whether this is the tenant default profile. |
| `ClientFallbackAction` | `bypass` / `block`. |
| `QuickAccessEnabled` | Quick Access toggle for this profile. |
| `AssignedGroups` | Semicolon-separated group display names. |
| `AssignedUsers` | Semicolon-separated UPNs. |
| `DevicePlatforms` | Semicolon-separated platforms, or `All` / `None`. |
| `Provision` | Yes/No, consistent with the app CSV. |

Import side mirrors this with an optional `-ForwardingProfileConfigPath` parameter. When it
is absent, behaviour is identical to today.

---

## 5. Work breakdown

| # | Item | Size | Risk |
| --- | --- | --- | --- |
| 1 | Export all PA profiles (not first match); capture `priority`, `clientFallbackAction`, `associations` | S | Low |
| 2 | Extend `Get-IntNetworkAccessForwardingProfile` fields + `$expand=policies($expand=policy)` | S | Low |
| 3 | Resolve profile→app membership to populate `ForwardingProfiles` | M–L | **High — blocked** |
| 4 | Emit the second CSV; wire into export summary and stats | S | Low |
| 5 | `Import-ProvisioningConfig`: load, validate, cross-validate profile names against app rows | M | Low |
| 6 | `New-IntNetworkAccessForwardingProfile` / `Set-…` internal write helpers | M | **High — write API unverified** |
| 7 | Profile provisioning: create/match-by-name, idempotency, priority 101–199 and max-10 validation | M | Med |
| 8 | Sequencing: an app must exist in the default profile before a custom profile can reference it | M | Med |
| 9 | Link apps to profiles after app and segment creation | M | High |
| 10 | Assignment provisioning (users / groups / device platforms) | L | **Blocked** |
| 11 | `-WhatIf` plan output, `Show-ProvisioningPlan`, results CSV columns | M | Low |
| 12 | Spec under `Specs/`, `website/docs/` updates, sanitized sample files | M | Low |

Items 1–5 form a coherent, shippable read-only slice. Items 6–11 are the write slice.
Item 10 is separable and should be deferred.

---

## 6. Blockers

These determine whether the work is buildable at all, and should be resolved with the
preview product team before any of section 5 is committed to.

1. **Profile→app join has no confirmed public surface.** `forwardingRule` carries no `appId`
   in the public schema, and `private` profiles may not expose `policyRules` at all. Without
   a confirmed Graph representation, item 3 cannot be written — and item 3 is the most
   valuable part of the export. Everything else is metadata.
2. **`associations` is opaque.** No `@odata.type` values or field names are published for
   user / group / device / platform assignment, so item 10 is unimplementable and the export
   can only round-trip an opaque blob that will not survive a CSV.
3. **Write API unverified.** Nothing confirms that `POST` / `PATCH` on
   `/beta/networkAccess/forwardingProfiles` is available in the preview, or whether profile
   creation is portal-only. If it is portal-only, items 6–9 collapse to "export only, and
   document the manual step."
4. **Field details unconfirmed:** exact `clientFallbackAction` name and casing; the default
   profile's `priority` sentinel (100? absent? null?) — the latter is needed to reliably
   distinguish default from custom profiles.
5. **Scope requirements unknown.** Whether `NetworkAccess.Read.All` covers the expanded
   `policies` / `associations` reads, or whether the preview gates them behind an additional
   scope. This changes the consent story for the export.

---

## 7. Recommendation

Split into two work items rather than one.

**A — unblocked, do now.** Items 1, 2, 4: export every PA and IA forwarding profile and its
metadata into the new profiles CSV. Leave `ForwardingProfiles` blank on the app CSV and log a
warning when more than one profile of a traffic type is detected. This makes the export
*honest* — an admin can see the tenant really has four profiles — without asserting
membership the tool cannot determine. Small, low risk, no new Graph scopes.

**B — blocked.** Items 3 and 5–11, gated on blockers 1–3. A wrong guess about the join model
means rewriting the CSV contract, which is a breaking change for anyone who has already
adopted it.

---

## 8. Open questions

1. Can a `private` custom profile also set `clientFallbackAction: block`, or is fail-close
   exclusively an Internet Access scenario in this preview?
2. Does the preview API expose an explicit app reference on PA forwarding profiles? If not,
   is destination-matching against application segments an acceptable fallback, or is a
   separate Graph call required?
3. Should `Export-EntraPrivateAccessAppDiscovery` also become profile-aware, or is discovery
   inherently profile-agnostic?
4. Does the default profile always contain every app, making it a reliable superset for
   validation during provisioning?
