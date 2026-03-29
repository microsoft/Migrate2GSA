---
sidebar_position: 6
title: Support Matrix
description: Comprehensive overview of Migrate2GSA capabilities across migration scenarios including export, convert, and provisioning support.
keywords: [support matrix, migration capabilities, Entra Internet Access, Entra Private Access, Global Secure Access]
---

# Support Matrix

This support matrix provides a comprehensive overview of the migration toolkit's capabilities across different migration scenarios. Each migration path supports exporting configuration from source systems, transforming data to match Microsoft Entra's format, and provisioning to the target environment.

## Global Secure Access Export (Backup/Restore/Tenant Migration)

| Feature | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **Entra Private Access** | ✅ Supported | N/A | Supported | Direct export from GSA for backup, disaster recovery, or tenant-to-tenant migration. No transformation needed - exported CSV is directly compatible with provisioning function. |
| **Entra Internet Access** | ⏳ Coming Soon | N/A | Supported | Export functionality under development. Will export policies, security profiles, and Conditional Access assignments. |

:::info Use Case
Unlike migrations from third-party platforms, GSA export captures existing Global Secure Access configurations for backup, restore, or replication scenarios. This is ideal for tenant-to-tenant migrations, disaster recovery, or promoting configurations between environments.
:::

## Zscaler Internet Access to Entra Internet Access

| Feature | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **URL Filtering Rules** | Supported | Supported | Supported | |
| **URL Categories** | Supported | Supported | Supported | Transformation requires provided mapping file. |
| **SSL Inspection** | Supported | Not implemented | Supported | Manual CSV creation needed for provisioning (see sample files for format). |
| **Firewall Rules** | Supported | Not implemented | Not implemented | |
| **File Type Controls / File Type Filtering** | Supported | Not implemented | Not implemented | |

## Zscaler Private Access to Entra Private Access

| Feature | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **Application Segments** | Supported | Supported | Supported | Only app segments are processed from segment groups. If desired, Conditional Access policies to enforce controls to multiple Enterprise Apps. |
| **Segment Groups** | Supported | Supported | N/A | Server Group names are kept in the conversion output CSV for reference. Entra Private Access Connector Groups need to be manually specified for provisioning. |
| **Server Groups** | Supported | Partial | Supported | Server Group names are kept in the conversion output CSV for reference. Entra Private Access Connector Groups need to be manually specified for provisioning. |
| **Access Policies** | Supported | Supported | Supported | User, group and SCIM group assignments are parsed and converted. |
| **Client Forwarding Policy** | Supported | Not implemented | Not implemented | |
| **Identity Provider Controllers** | Supported | N/A | N/A | Used to parse SCIM groups |
| **SCIM Groups** | Supported | Supported | N/A | Used as part of Client Access policy group assignment conversion |

## Netskope Next Gen SWG to Entra Internet Access

| Feature / Object | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **Real-time Protection Policies** | Supported | Supported | Supported | |
| **URL Lists** (custom allow/block lists) | Supported | Supported | Supported | Converted as Web Content Filtering policies |
| **Predefined and Custom Categories** | Supported | Supported | Supported | Predefined categories transformation requires provided mapping file |
| **SSL Bypass / Exceptions** | Supported | N/A | Supported | Manual CSV creation needed for provisioning (see sample files for format). |

## Netskope Private Access to Entra Private Access

| Feature / Object | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **Private Applications** | Supported | Supported | Supported | |
| **NPA Policies** | Supported | Supported | Supported | |

## Forcepoint Web Security to Entra Internet Access

| Feature / Object | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **Web Category Policies** | Manual export | Supported | Supported | Matrix-style CSV with security groups and dispositions |
| **Predefined Categories** | Manual export | Supported | Supported | Transformation requires provided mapping file |
| **User-Defined FQDNs** | Manual export | Supported | Supported | FQDNs listed in User-Defined category |

## Citrix NetScaler Gateway to Entra Private Access

| Feature / Object | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **AAA Groups → Enterprise Applications** | Manual export | Supported | Supported | Each AAA group maps to one Entra Private Access Enterprise Application |
| **Authorization Policies** | Manual export | Supported | Supported | IP/subnet/FQDN/port rule expressions parsed. DENY, boolean, and negated policies skipped. |
| **VPN Intranet Applications** | Manual export | Supported | Supported | Multi-destination entries expanded. ICMP protocol skipped. |
| **Group Bindings (TCP/UDP consolidation)** | Manual export | Supported | Supported | Same policy bound for TCP+UDP consolidated into single segment |
| **Conflict Detection** | N/A | Supported | N/A | Cross-app overlap detection for IPs, FQDNs, and wildcards |

## Microsoft Defender for Endpoint to Entra Internet Access

| Feature / Object | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **Web Content Filtering Policies** | Supported | Supported | Supported | Exported from HAR file. Blocked categories mapped directly. Audited categories converted to Block with review flag. |
| **URL/Domain Indicators** | Supported | Supported | Supported | Exported from HAR file. Warn/AlertOnly actions flagged for review. |
| **IP Indicators** | Supported | Not supported | Not supported | Exported from HAR file.
| **Device Group Scoping** | Supported | Supported | Supported | Exported from HAR file. All device groups → Default profile. Specific groups → Override profiles with placeholder Entra groups. |

## Palo Alto Panorama to Entra Internet Access

| Feature / Object | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **Custom URL Categories** | Manual export | Supported | Supported | URL List type only. |
| **URL Filtering Profiles** | Manual export | Supported | Supported | Per-category actions mapped. Alert/continue/override actions flagged for review. |
| **PAN-DB Predefined Categories** | Manual export | Supported | Supported | Transformation requires provided mapping file. Partial mappings excluded and flagged. |
| **Security Rules** | Manual export | Supported | Supported | Only allow-action rules with URL filtering profiles processed. |
| **Application References (App-ID)** | Manual export | Supported | Supported | Optional app mapping file. Mapped apps with endpoints → FQDN policies. Unmapped apps flagged for review. |
| **Security Profile Aggregation** | N/A | Supported | Supported | Rules with same user/group assignments aggregated into single profile. |

## Cisco Umbrella to Entra Internet Access

| Feature / Object | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **DNS Policies** | Supported | Supported | Supported | Exported from HAR file. Category and destination list rules converted to EIA web content filtering policies. |
| **Web Policies** | Supported | Supported | Supported | Includes proxy rulesets. Application, destination list, and category rules converted. Warn/isolate actions converted to Block with review flag. |
| **Destination Lists** | Supported | Supported | Supported | Custom allow/block lists resolved to FQDN rules with dual-entry pattern. |
| **Category Settings** | Supported | Supported | Supported | Umbrella categories mapped to GSA web categories via provided mapping file. |
| **Application Settings** | Supported | Supported | Supported | Application controls converted to FQDN-based rules via provided app mapping file. |
| **Firewall Rules** | Supported | Not implemented | Not implemented | Exported from HAR file |
