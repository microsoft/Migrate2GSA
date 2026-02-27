---
sidebar_position: 3
title: EPA CSV Configuration
description: Complete guide to Entra Private Access CSV file structure, validation, and samples.
---

# Entra Private Access CSV Configuration

This guide covers everything you need to know about working with CSV files for Entra Private Access (EPA), whether you're migrating from ZPA/NPA or deploying from scratch.

## CSV File Structure

Your Entra Private Access configuration consists of **ONE CSV file** that defines enterprise applications, their network segments, connector groups, and user assignments all together.

**Structure:** Each row = ONE application segment. Multiple rows with the same `EnterpriseAppName` form one multi-segment application.

:::info EPA Object Model
**Enterprise Application** (container) → **Application Segments** (destinations) → **ConnectorGroup** (gateway) → **User/Group Assignments** (access control)
:::

---

## Applications CSV

### Column Reference

| Column | Required | Description | Example Values |
|--------|----------|-------------|----------------|
| **SegmentId** | Yes | Unique identifier for this segment (for reporting/logging) | `SEG-001`, `HR-Portal-443` |
| **EnterpriseAppName** | Yes | Name of the EPA application (same name = multi-segment app) | `GSA-HR-Portal` |
| **destinationHost** | Yes | Target host/IP/range to access | `hr.contoso.local`, `10.1.2.3`, `192.168.1.0/24` |
| **DestinationType** | Yes | Format of the destination | `fqdn`, `ipAddress`, `ipRangeCidr`, `ipRange`, `dnsSuffix` |
| **Protocol** | Conditional* | Network protocol | `tcp`, `udp` (*Required except for Quick Access dnsSuffix) |
| **Ports** | Conditional* | Port numbers or ranges | `443`, `8080-8090`, `80,443,8080` (*Required except for Quick Access dnsSuffix) |
| **ConnectorGroup** | Yes | Connector group name for on-prem gateway | `Production-Connectors` |
| **EntraGroups** | No | Semicolon-separated group names | `HR-Users;HR-Admins` |
| **EntraUsers** | No | Semicolon-separated user emails | `john@contoso.com;jane@contoso.com` |
| **Provision** | Yes | Whether to deploy this segment | `Yes`, `No` |
| **isQuickAccess** | No | Quick Access application indicator | `yes`, `no` (default: `no`) |

### Destination Types Explained

#### Standard Application Segments

**fqdn** - Fully qualified domain name:
- Example: `webapp.contoso.local`
- Matches exact domain only
- Use for specific internal applications

**ipAddress** - Single IPv4 address:
- Example: `10.1.2.100`
- Use for specific servers

**ipRangeCidr** - IP range in CIDR notation:
- Example: `192.168.1.0/24`
- Matches entire subnet
- Use for network segments

**ipRange** - IP range from start to end:
- Example: `192.168.1.1..192.168.1.50`
- Matches specific IP range
- Alternative to CIDR notation

#### Quick Access Segments

**dnsSuffix** - DNS wildcard suffix (Quick Access only):
- Example: `*.contoso.local`, `*.internal.corp`
- Matches all subdomains
- **Requires:** `isQuickAccess=yes`
- **No Protocol/Ports:** Leave Protocol and Ports empty or use empty string

:::info Quick Access vs Standard Applications
**Quick Access** provides broader network access (entire DNS suffix or IP range) without per-application control. Standard applications provide granular per-application access with specific protocols and ports.

Learn more: [Microsoft Docs - Quick Access](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-quick-access)
:::

### Example: Single-Segment Application

```csv
SegmentId,EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,EntraGroups,EntraUsers,Provision,isQuickAccess
SEG-001,GSA-HR-Portal,hr.contoso.local,fqdn,tcp,443,Production-Connectors,HR-Users;HR-Admins,,Yes,no
```

This creates EPA application "GSA-HR-Portal" with one segment accessing `hr.contoso.local:443`.

### Example: Multi-Segment Application

```csv
SegmentId,EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,EntraGroups,EntraUsers,Provision,isQuickAccess
SEG-001,GSA-WebPortal,portal.contoso.local,fqdn,tcp,443,Prod-Connectors,Portal-Users,,Yes,no
SEG-002,GSA-WebPortal,admin.portal.contoso.local,fqdn,tcp,443;8080,Prod-Connectors,Portal-Admins,,Yes,no
SEG-003,GSA-WebPortal,api.portal.contoso.local,fqdn,tcp,8443,Prod-Connectors,Portal-Users;Portal-Admins,,Yes,no
```

This creates **one** EPA application "GSA-WebPortal" with **three segments**, each accessible on different hosts/ports.

### Example: Quick Access Application

```csv
SegmentId,EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,EntraGroups,EntraUsers,Provision,isQuickAccess
QA-001,GSA-QuickAccess,*.contoso.local,dnsSuffix,,,Prod-Connectors,All-Employees,,Yes,yes
QA-002,GSA-QuickAccess,10.0.0.0/8,ipRangeCidr,tcp,*,Prod-Connectors,All-Employees,,Yes,yes
```

This creates Quick Access application providing broad access to `*.contoso.local` DNS suffix and `10.0.0.0/8` IP range.

### Group Assignment Aggregation

Groups are aggregated across all segments of an application and deduplicated:

```csv
SegmentId,EnterpriseAppName,...,EntraGroups,Provision
SEG-001,GSA-Portal,...,Portal-Users;Portal-Admins,Yes
SEG-002,GSA-Portal,...,Portal-Admins;Support-Team,Yes
SEG-003,GSA-Portal,...,Portal-Users,Yes
```

**Result:** Application "GSA-Portal" has **three unique groups** assigned:
- `Portal-Admins`
- `Portal-Users`
- `Support-Team`

---

## Validation Checklist

Before provisioning your CSV file, validate these items:

### ✅ File Format

- [ ] CSV uses comma delimiter (not semicolon or tab)
- [ ] Values with commas are quoted: `"80,443,8080"`
- [ ] UTF-8 encoding (avoid special character issues)
- [ ] Column headers match exactly (case-sensitive)
- [ ] No empty rows between data

### ✅ Required Columns Present

- [ ] `SegmentId` - Unique identifier for each segment
- [ ] `EnterpriseAppName` - Application name
- [ ] `destinationHost` - Target host/IP/range
- [ ] `DestinationType` - Valid type (fqdn, ipAddress, ipRangeCidr, ipRange, dnsSuffix)
- [ ] `Protocol` - tcp or udp (or empty for Quick Access dnsSuffix)
- [ ] `Ports` - Port specification (or empty for Quick Access dnsSuffix)
- [ ] `ConnectorGroup` - Connector group name
- [ ] `Provision` - Yes or No

### ✅ Data Validation

- [ ] `SegmentId` is unique across all rows
- [ ] `EnterpriseAppName` follows naming convention (e.g., `GSA-` prefix)
- [ ] `DestinationType` matches destination format:
  - `fqdn` → Valid domain name
  - `ipAddress` → Valid IPv4 address
  - `ipRangeCidr` → Valid CIDR notation (e.g., `10.0.0.0/24`)
  - `ipRange` → Valid range format (e.g., `10.0.0.1..10.0.0.254`)
  - `dnsSuffix` → Valid wildcard (e.g., `*.contoso.local`)
- [ ] `Protocol` is either `tcp` or `udp` (or empty for Quick Access dnsSuffix)
- [ ] `Ports` format is valid:
  - Single port: `443`
  - Multiple ports: `80,443,8080` (comma-separated, no spaces)
  - Port range: `8080-8090` (hyphen, no spaces)
  - Mixed: `80,443,8080-8090`
  - Wildcard: `*` (Quick Access only)
- [ ] `ConnectorGroup` name exists in your Entra tenant
- [ ] `EntraGroups` match Entra ID display names exactly (case-sensitive!)
- [ ] `EntraUsers` use correct email format (UPN)
- [ ] `Provision` is either `Yes` or `No`
- [ ] `isQuickAccess` is either `yes` or `no` (or empty defaults to `no`)

### ✅ Quick Access Validation

If `isQuickAccess=yes`:
- [ ] `DestinationType` is `dnsSuffix` or `ipRangeCidr`
- [ ] `Protocol` is empty or comma (standard apps require protocol)
- [ ] `Ports` is empty or wildcard `*` (standard apps require ports)
- [ ] Application name typically generic (e.g., `GSA-QuickAccess`)

### ✅ Migration-Specific Placeholders

If your CSV came from a conversion tool, replace these placeholders:

- [ ] Replace `Placeholder_Replace_Me` in `ConnectorGroup` with actual connector group name
- [ ] Replace `No_Access_Policy_Found_Replace_Me` in `EntraGroups` with appropriate groups
- [ ] Review rows with `Conflict=Yes` (if column present)
- [ ] Check `ConflictingEnterpriseApp` column for overlaps (if present)
- [ ] Verify auto-assigned groups are correct

### ✅ Connector Group Validation

Before provisioning, verify connector groups exist:

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# List all connector groups
Get-MgBetaOnPremisePublishingProfileConnectorGroup -OnPremisesPublishingProfileId "applicationProxy" |
    Select-Object DisplayName, Id
```

### ✅ Entra ID Group Validation

Verify groups exist with exact names:

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Group.Read.All"

# Verify specific group
Get-MgGroup -Filter "displayName eq 'YourGroupName'"

# List all groups to find exact names
Get-MgGroup | Select-Object DisplayName, Id | Sort-Object DisplayName
```

---

## Common Issues & Fixes

### Issue: "Connector Group not found"

**Cause:** Connector group name in CSV doesn't exist or doesn't match exactly.

**Solution:**
1. List all connector groups:
   ```powershell
   Get-MgBetaOnPremisePublishingProfileConnectorGroup -OnPremisesPublishingProfileId "applicationProxy"
   ```
2. Update CSV with exact `DisplayName` from output
3. Ensure connector group has at least one active connector

### Issue: "Group not found" Error

**Cause:** Group name in CSV doesn't match Entra ID display name exactly (case-sensitive).

**Solution:**
1. Run `Get-MgGroup | Select-Object DisplayName` to get exact names
2. Update CSV with exact casing: `HR-Users` not `hr-users`
3. Check for extra spaces or special characters

### Issue: "Invalid port format"

**Cause:** Ports column has incorrect syntax.

**Solution:**
```csv
# Wrong formats:
80, 443, 8080          (spaces after commas)
8080 - 8090            (spaces around hyphen)
443; 8080              (semicolon instead of comma)

# Correct formats:
80,443,8080            (comma-separated, no spaces)
8080-8090              (hyphen, no spaces)
80,443,8080-8090       (mixed)
```

### Issue: "Destination type mismatch"

**Cause:** `DestinationType` doesn't match `destinationHost` format.

**Solution:**
```csv
# Mismatches to fix:
destinationHost: 10.1.2.3       DestinationType: fqdn        ❌ (should be ipAddress)
destinationHost: webapp.local   DestinationType: ipAddress   ❌ (should be fqdn)
destinationHost: 10.0.0.0/24    DestinationType: ipAddress   ❌ (should be ipRangeCidr)

# Correct matches:
destinationHost: webapp.local   DestinationType: fqdn        ✅
destinationHost: 10.1.2.3       DestinationType: ipAddress   ✅
destinationHost: 10.0.0.0/24    DestinationType: ipRangeCidr ✅
```

### Issue: "Application already exists" with conflicts

**Cause:** Application name already exists, or converted CSV flagged conflicts.

**Solution:**
1. **Check for conflicts:** Look for `Conflict=Yes` column in migration CSVs
2. **Review conflicting app:** Check `ConflictingEnterpriseApp` column for details
3. **Options:**
   - Rename application: Change `EnterpriseAppName` to unique value
   - Merge segments: Consolidate into existing application
   - Delete existing: Remove conflicting app from Entra, then provision

### Issue: Quick Access not working

**Cause:** Quick Access configuration requirements not met.

**Solution:**
```csv
# Wrong - Standard app format with dnsSuffix:
DestinationType: dnsSuffix
Protocol: tcp
Ports: 443
isQuickAccess: no              ❌ (should be yes)

# Correct - Quick Access format:
DestinationType: dnsSuffix
Protocol:                      (empty)
Ports:                         (empty or wildcard *)
isQuickAccess: yes             ✅
```

### Issue: CSV formatting errors in Excel

**Cause:** Excel auto-formatting corrupts data or adds spaces.

**Solution:**
1. **Use Text Import Wizard:**
   - Open Excel → Data tab → Get Data → From Text/CSV
   - Set delimiter to comma
   - Set all columns to "Text" format
2. **Or use VS Code** for safer editing
3. **Quote port lists:** Use `"80,443,8080"` if Excel removes commas
4. **Save as:** "CSV UTF-8 (Comma delimited) (*.csv)"

### Issue: Multi-segment app not grouping correctly

**Cause:** `EnterpriseAppName` has slight variations (spaces, casing, special characters).

**Solution:**
```csv
# Wrong - slight name differences create separate apps:
GSA-WebPortal                   ❌
GSA-Web Portal                  ❌ (space)
GSA-WebPortal                  ❌ (extra space)

# Correct - EXACT same name:
GSA-WebPortal                   ✅
GSA-WebPortal                   ✅
GSA-WebPortal                   ✅
```

### Issue: "Placeholder values detected"

**Cause:** Migration conversion created placeholder values not yet replaced.

**Solution:**
Find and replace these common placeholders:
- `Placeholder_Replace_Me` → Your actual connector group name
- `No_Access_Policy_Found_Replace_Me` → Appropriate Entra groups
- `TODO_Replace_Me` → Required values
- Any value ending in `_Replace_Me`

---

## Samples

Example CSV configurations for greenfield EPA deployments. Customize and deploy!

### Sample 1: Single Web Application

**Best for:** Publishing one internal web application

```csv
SegmentId,EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,EntraGroups,EntraUsers,Provision,isQuickAccess
SEG-001,GSA-IntranetPortal,intranet.contoso.local,fqdn,tcp,443,Production-Connectors,All-Employees,,Yes,no
```

**Customization:**
- Replace `intranet.contoso.local` with your internal app FQDN
- Replace `Production-Connectors` with your connector group name
- Replace `All-Employees` with your Entra group name

---

### Sample 2: Multi-Tier Application (Web + Database)

**Best for:** Publishing app with multiple tiers/services

```csv
SegmentId,EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,EntraGroups,EntraUsers,Provision,isQuickAccess
SEG-001,GSA-CRM-App,crm.contoso.local,fqdn,tcp,443,Prod-Connectors,CRM-Users;CRM-Admins,,Yes,no
SEG-002,GSA-CRM-App,crm-api.contoso.local,fqdn,tcp,8443,Prod-Connectors,CRM-Users;CRM-Admins,,Yes,no
SEG-003,GSA-CRM-App,crm-db.contoso.local,fqdn,tcp,1433,Prod-Connectors,CRM-Admins,,Yes,no
```

**What it does:**
- Main CRM web interface (all users)
- CRM API (all users)
- CRM database (admins only)

---

### Sample 3: File Server Access

**Best for:** SMB/CIFS file server access

```csv
SegmentId,EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,EntraGroups,EntraUsers,Provision,isQuickAccess
SEG-001,GSA-FileServer,files.contoso.local,fqdn,tcp,445,Prod-Connectors,File-Users,,Yes,no
SEG-002,GSA-FileServer,files.contoso.local,fqdn,tcp,135-139,Prod-Connectors,File-Users,,Yes,no
```

**Ports explained:**
- `445` - SMB file sharing
- `135-139` - NetBIOS/RPC services

---

### Sample 4: RDP/Remote Desktop Access

**Best for:** Remote desktop access to specific servers

```csv
SegmentId,EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,EntraGroups,EntraUsers,Provision,isQuickAccess
SEG-001,GSA-JumpServer,jumphost.contoso.local,fqdn,tcp,3389,Prod-Connectors,IT-Admins,,Yes,no
SEG-002,GSA-AppServers,10.1.10.10,ipAddress,tcp,3389,Prod-Connectors,Server-Admins,,Yes,no
SEG-003,GSA-AppServers,10.1.10.11,ipAddress,tcp,3389,Prod-Connectors,Server-Admins,,Yes,no
```

---

### Sample 5: Quick Access (Broad Network Access)

**Best for:** Replacing VPN with broad network/DNS access

```csv
SegmentId,EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,EntraGroups,EntraUsers,Provision,isQuickAccess
QA-001,GSA-QuickAccess,*.contoso.local,dnsSuffix,,,Prod-Connectors,QA-Users,,Yes,yes
QA-002,GSA-QuickAccess,*.internal.corp,dnsSuffix,,,Prod-Connectors,QA-Users,,Yes,yes
QA-003,GSA-QuickAccess,10.0.0.0/8,ipRangeCidr,tcp,*,Prod-Connectors,QA-Users,,Yes,yes
```

**What it provides:**
- Access to all `*.contoso.local` domains
- Access to all `*.internal.corp` domains
- Access to entire `10.0.0.0/8` private network

:::warning Quick Access Security
Quick Access provides broad network access. Use with caution and assign only to trusted user groups. Consider using standard applications for more granular control.
:::

---

## Next Steps

### Ready to Deploy?

1. **[Provision EPA Configuration](../Provision/EntraPrivateAccessProvisioning.md)** - Deploy your CSV file to Microsoft Graph
2. **[Best Practices](./best-practices.md)** - Learn testing strategies and deployment patterns
3. **[Understanding EPA Model](../UnderstandingGSA/EPA-Configuration-Model.md)** - Review conceptual architecture

### Need More Samples?

- **[Sample Files in GitHub](https://github.com/microsoft/Migrate2GSA/tree/main/Samples)** - Additional EPA examples
- **[Migration Scenarios](../migration-scenarios.md)** - Platform-specific conversion guides (ZPA, NPA, Citrix)

---

:::info Questions?
- Review [Understanding GSA](../UnderstandingGSA/EPA-Configuration-Model.md) for conceptual guidance
- Check [Provisioning Docs](../Provision/EntraPrivateAccessProvisioning.md) for deployment details
- Contact the team at **migrate2gsateam@microsoft.com**
:::
