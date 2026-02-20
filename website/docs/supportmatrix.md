---
sidebar_position: 10
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

## Cisco Umbrella to Entra Internet Access

| Feature / Object | Export | Transform | Provision | Notes |
|---------|--------|-----------|-----------|-------|
| **DNS Policies** | Supported | Not implemented | Not implemented | Exported from HAR file captured from Umbrella dashboard |
| **Firewall Rules** | Supported | Not implemented | Not implemented | Exported from HAR file |
| **Web Policies** | Supported | Not implemented | Not implemented | Includes proxy rulesets and ruleset settings |
| **Destination Lists** | Supported | Not implemented | Not implemented | Custom allow/block lists with entries |
| **Category Settings** | Supported | Not implemented | Not implemented | Full category arrays extracted from detail views |
| **Application Settings** | Supported | Not implemented | Not implemented | Includes system-inherited settings |
| **Security Settings** | Supported | Not implemented | Not implemented | MSP-inherited records tagged |
| **Selective Decryption Lists** | Supported | Not implemented | Not implemented | SSL/TLS inspection bypass settings |
