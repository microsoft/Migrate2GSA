---
sidebar_position: 2
---

# Entra Private Access Configuration Model

This guide explains the core concepts you need to understand before deploying Entra Private Access (EPA) from scratch or when migrating from other platforms like Zscaler Private Access.

## The Four Core Components

Entra Private Access uses a four-layer architecture to provide secure remote access to internal applications:

<div style={{margin: '2rem 0', overflowX: 'auto'}}>
  <div style={{display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.75rem', minWidth: '600px'}}>
    <div style={{flex: '1', padding: '0.75rem', backgroundColor: '#e3f2fd', borderRadius: '8px', border: '2px solid #1976d2', textAlign: 'center', minWidth: '130px'}}>
      <strong>1. Segments</strong><br/>
      <small>Destination hosts</small>
    </div>
    <div style={{fontSize: '1.5rem', color: '#666', flexShrink: 0}}>→</div>
    <div style={{flex: '1', padding: '0.75rem', backgroundColor: '#fff3e0', borderRadius: '8px', border: '2px solid #f57c00', textAlign: 'center', minWidth: '150px'}}>
      <strong>2. Applications</strong><br/>
      <small>Group segments</small>
    </div>
    <div style={{fontSize: '1.5rem', color: '#666', flexShrink: 0}}>→</div>
    <div style={{flex: '1', padding: '0.75rem', backgroundColor: '#f3e5f5', borderRadius: '8px', border: '2px solid #7b1fa2', textAlign: 'center', minWidth: '140px'}}>
      <strong>3. Connector Groups</strong><br/>
      <small>On-prem gateway</small>
    </div>
    <div style={{fontSize: '1.5rem', color: '#666', flexShrink: 0}}>→</div>
    <div style={{flex: '1', padding: '0.75rem', backgroundColor: '#e8f5e9', borderRadius: '8px', border: '2px solid #388e3c', textAlign: 'center', minWidth: '150px'}}>
      <strong>4. Assignments</strong><br/>
      <small>Users & groups</small>
    </div>
  </div>
</div>

**In this guide:**
- [Segments - The Building Blocks](#1-segments---the-building-blocks)
- [Enterprise Applications - Grouping Segments](#2-enterprise-applications---grouping-segments)
- [Connector Groups - On-Premises Gateway](#3-connector-groups---on-premises-gateway)
- [User & Group Assignments - Access Control](#4-user--group-assignments---access-control)
- [Quick Access vs Standard Applications](#quick-access-vs-standard-applications)
- [Decision Guide - How to Structure Your Apps](#decision-guide-structuring-your-applications)
- [Common Configuration Patterns](#common-patterns)

### 1. Segments - The Building Blocks

**Application segments** define the specific network destinations that users can access. Each segment specifies:

- **Destination Host**: The target to access (FQDN, IP, IP range, or CIDR)
- **Destination Type**: Format of the host
- **Protocol**: TCP, UDP, or both
- **Ports**: Specific port numbers or ranges

#### Destination Types

| Type | Description | Example |
|------|-------------|---------|
| `FQDN` | Fully qualified domain name | `intranet.contoso.com` |
| `ipAddress` | Single IP address | `10.0.1.50` |
| `ipRange` | IP range (start..end format) | `10.0.1.1..10.0.1.254` |
| `ipRangeCidr` | CIDR notation subnet | `10.0.1.0/24` |
| `dnsSuffix` | DNS wildcard suffix | `*.contoso.local` |

:::info Segments vs Applications
A **Segment** is a single destination definition (e.g., "intranet.contoso.com on port 443"). An **Enterprise Application** is a container that groups one or more segments together and assigns connector groups and user access.
:::

#### Example Segments

```
Segment 1: HR Portal
├── Destination: hr.contoso.com
├── Type: FQDN
├── Protocol: tcp
└── Ports: 443

Segment 2: File Server Range
├── Destination: 10.0.5.0/24
├── Type: ipRangeCidr
├── Protocol: tcp
└── Ports: 445,135-139

Segment 3: RDP Access
├── Destination: 192.168.1.100
├── Type: ipAddress
├── Protocol: tcp
└── Ports: 3389
```

### 2. Enterprise Applications - Grouping Segments

**Enterprise Applications** are containers that bundle related segments together. Each application has:

- **Display Name**: User-friendly name shown in portals
- **One or more segments**: Related destinations
- **Connector Group**: Which on-prem gateway(s) to use
- **User/Group Assignments**: Who can access this application

#### Single vs Multi-Segment Applications

**Single-Segment Application:**
```
Enterprise App: "Corporate Intranet"
└── Segment: intranet.contoso.com:443/tcp
```

**Multi-Segment Application:**
```
Enterprise App: "Finance System"
├── Segment 1: finance-web.contoso.com:443/tcp (Web UI)
├── Segment 2: finance-api.contoso.com:8443/tcp (API Server)
└── Segment 3: finance-db.contoso.com:1433/tcp (Database)
```

:::tip When to Combine Segments
Combine segments into one application when they:
- Belong to the same logical system or service
- Require the same connector group
- Have the same user access requirements
- Should appear as one entry in My Apps portal
:::

### 3. Connector Groups - On-Premises Gateway

**Connector Groups** consist of one or more Private Access connectors installed on-premises that proxy traffic to your internal resources.

#### Connector Group Architecture

```
User (Remote) → Microsoft Cloud → Connector Group → Internal Network
                                   ├── Connector 1 (Active)
                                   └── Connector 2 (HA/Load Balance)
```

#### Planning Connector Groups

**By Geographic Location:**
```
Connector Group: "US-East-Datacenter"
├── App: Corporate Intranet (East Coast)
├── App: HR Portal (East Coast)
└── Connectors: 2x VMs in Virginia datacenter

Connector Group: "EMEA-Datacenter"
├── App: European Finance System
├── App: London Office Resources
└── Connectors: 2x VMs in London datacenter
```

**By Network Segment:**
```
Connector Group: "Production-Network"
├── Connectors in 10.0.0.0/16 network
└── Apps accessing prod servers

Connector Group: "DMZ-Network"
├── Connectors in DMZ segment
└── Apps accessing DMZ resources
```

:::info Connector Deployment Best Practices
- **High Availability**: Deploy at least 2 connectors per group
- **Network Access**: Connectors must reach destination segments
- **Outbound Only**: Connectors only need outbound HTTPS (443/tcp) to Azure
- **No Inbound Ports**: No firewall rules needed for inbound traffic
:::

### 4. User & Group Assignments - Access Control

**Assignments** control who can access each Enterprise Application. You can assign:

- **Entra Groups**: Recommended for scalability
- **Individual Users**: For exceptions or testing

#### Assignment Examples

```
Enterprise App: "HR Portal"
├── Assigned Groups:
│   ├── HR_Employees
│   ├── HR_Managers
│   └── Payroll_Team
└── Assigned Users:
    └── hr.admin@contoso.com (individual access)
```

:::tip Assignment Best Practices
- Use **groups** for standard access patterns
- Use **individual users** only for exceptions
- Keep group names descriptive and consistent
- Consider nesting groups for easier management
:::

#### Access Flow Example

When user `jane@contoso.com` (member of HR_Employees) tries to access `hr.contoso.com`:

1. **Authentication**: User authenticates to Entra ID
2. **Authorization**: Entra checks if user is assigned to "HR Portal" app ✓
3. **Routing**: Traffic routed to assigned Connector Group
4. **Proxy**: Connector proxies request to hr.contoso.com:443
5. **Response**: Response flows back through connector to user

## Quick Access vs Standard Applications

Entra Private Access offers two deployment models:

### Standard Applications (Default)

**Characteristics:**
- Full enterprise application configuration
- Appears in My Apps portal
- Requires user assignment (no "All Users" option)
- Best for: Named applications that users launch explicitly
- Discovery: Users find apps in My Apps

**Use Cases:**
- Line-of-business web applications
- Internal portals and dashboards
- Named RDP/SSH jump servers
- Applications requiring explicit user awareness

### Quick Access Applications

**Characteristics:**
- Simplified, auto-discovery model
- Does NOT appear in My Apps portal
- Access granted via Conditional Access policies
- Best for: Infrastructure, background services, transparent access
- Discovery: Automatic when network match occurs

**Use Cases:**
- Internal DNS servers
- File shares and storage
- Database servers
- API endpoints
- Infrastructure services
- Subnets or IP ranges

#### Quick Access CSV Configuration

```csv
EnterpriseAppName,isQuickAccess,destinationHost,DestinationType,Protocol,Ports
Internal_DNS,yes,10.0.0.53,ipAddress,udp,53
File_Shares,yes,10.0.5.0/24,ipRangeCidr,tcp,445
Corporate_Subnet,yes,10.0.0.0/16,ipRangeCidr,tcp,80;443
```

:::info Quick Access Assignment
Quick Access apps are assigned to users through **Conditional Access policies** that target the Global Secure Access traffic forwarding profile, not through direct app assignments.
:::

## Decision Guide: Structuring Your Applications

### Scenario 1: "Single internal web application"

**Question:** I need to publish `intranet.contoso.com` (HTTPS) to all employees.

**Solution:**
```csv
EnterpriseAppName: "Corporate Intranet"
Segments: 1
├── destinationHost: intranet.contoso.com
├── DestinationType: FQDN
├── Protocol: tcp
├── Ports: 443
ConnectorGroup: "US-Datacenter-Connectors"
Assignments: All_Employees
```

### Scenario 2: "Multi-tier application"

**Question:** I have a web app, API server, and database that form one system.

**Solution:** Combine into **one application** with **multiple segments**:

```csv
EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports
Finance_System,finance-web.contoso.com,FQDN,tcp,443
Finance_System,finance-api.contoso.com,FQDN,tcp,8443
Finance_System,finance-db.contoso.com,FQDN,tcp,1433
```

All segments share the same connector group and user assignments.

### Scenario 3: "Enable RDP to multiple servers"

**Option A: Named Applications** (users select specific servers)
```csv
EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports
Server01_RDP,server01.contoso.com,FQDN,tcp,3389
Server02_RDP,server02.contoso.com,FQDN,tcp,3389
Server03_RDP,server03.contoso.com,FQDN,tcp,3389
```
Each appears separately in My Apps. Users choose which server to access.

**Option B: Quick Access Subnet** (transparent access to range)
```csv
EnterpriseAppName,isQuickAccess,destinationHost,DestinationType,Protocol,Ports
Server_Subnet_RDP,yes,10.0.10.0/24,ipRangeCidr,tcp,3389
```
Users connect directly via RDP client. All servers in subnet accessible.

### Scenario 4: "Different departments need different internal apps"

**Solution:** Create separate applications with different assignments:

```
App: "HR_Portal"
├── Segment: hr.contoso.com:443/tcp
└── Assigned to: HR_Department

App: "Finance_Portal"
├── Segment: finance.contoso.com:443/tcp
└── Assigned to: Finance_Department

App: "IT_Tools"
├── Segment: tools.contoso.com:443/tcp
└── Assigned to: IT_Staff
```

### Scenario 5: "Entire office network subnet"

**Question:** I have an office at 192.168.50.0/24 and want to enable all protocols/ports.

**Solution:** Use Quick Access with broad port ranges:

```csv
EnterpriseAppName,isQuickAccess,destinationHost,DestinationType,Protocol,Ports
Branch_Office_Network,yes,192.168.50.0/24,ipRangeCidr,tcp,1-65535
Branch_Office_Network,yes,192.168.50.0/24,ipRangeCidr,udp,1-65535
```

Create two segments (tcp + udp) to cover all ports. Assign via Conditional Access.

## Common Patterns

### Pattern 1: Web Application Publishing
**Use Case:** Publish internal web portals to remote users

```csv
EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup
SharePoint_Intranet,sharepoint.contoso.local,FQDN,tcp,443,US-Connectors
Wiki_Portal,wiki.contoso.local,FQDN,tcp,80;443,US-Connectors
Helpdesk_System,helpdesk.contoso.local,FQDN,tcp,443,US-Connectors
```

**Characteristics:**
- Standard applications (not Quick Access)
- FQDN-based segments
- HTTPS (port 443), sometimes HTTP (80)
- Appear in My Apps for user discovery

### Pattern 2: File Share Access
**Use Case:** Enable access to internal file servers and SMB shares

```csv
EnterpriseAppName,isQuickAccess,destinationHost,DestinationType,Protocol,Ports
File_Server_Primary,yes,fileserver01.contoso.local,FQDN,tcp,445
File_Server_Backup,yes,fileserver02.contoso.local,FQDN,tcp,445
DFS_Namespace,yes,\\contoso.local\dfs,dnsSuffix,tcp,445;135-139
```

**Characteristics:**
- Quick Access (transparent to users)
- TCP ports 445 (SMB), 135-139 (NetBIOS)
- Often uses FQDN or dnsSuffix
- Users access via UNC paths

### Pattern 3: Database Access
**Use Case:** Allow remote access to SQL Server, Oracle, or other databases

```csv
EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports
SQL_Production,sql-prod.contoso.local,FQDN,tcp,1433
SQL_Reporting,sql-report.contoso.local,FQDN,tcp,1433
Oracle_ERP,oracle-db.contoso.local,FQDN,tcp,1521
```

**Characteristics:**
- Can be Standard or Quick Access depending on use case
- Specific database ports (SQL: 1433, Oracle: 1521, MySQL: 3306)
- Often restricted to specific user groups (DBAs, developers)

### Pattern 4: Remote Desktop (RDP) Access
**Use Case:** Enable RDP to Windows servers or desktops

**Named Server Approach:**
```csv
EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports
JumpBox_RDP,jumpbox.contoso.com,FQDN,tcp,3389
DevServer01_RDP,devserver01.contoso.com,FQDN,tcp,3389
```

**Subnet Approach (Quick Access):**
```csv
EnterpriseAppName,isQuickAccess,destinationHost,DestinationType,Protocol,Ports
Server_Subnet_RDP,yes,10.0.20.0/24,ipRangeCidr,tcp,3389
```

### Pattern 5: SSH Access
**Use Case:** Enable SSH to Linux servers

```csv
EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports
Linux_Bastion,bastion.contoso.local,FQDN,tcp,22
DevOps_Servers,10.0.30.0/24,ipRangeCidr,tcp,22
```

### Pattern 6: Network Segment Access
**Use Case:** Enable transparent access to an entire office or datacenter network

```csv
EnterpriseAppName,isQuickAccess,destinationHost,DestinationType,Protocol,Ports
Corporate_HQ_Network,yes,10.0.0.0/16,ipRangeCidr,tcp,1-65535
Corporate_HQ_Network,yes,10.0.0.0/16,ipRangeCidr,udp,1-65535
Branch_Office_LA,yes,192.168.10.0/24,ipRangeCidr,tcp,1-65535
Branch_Office_LA,yes,192.168.10.0/24,ipRangeCidr,udp,1-65535
```

**Characteristics:**
- Always Quick Access (transparent routing)
- Uses CIDR notation for subnets
- Requires two segments per network (TCP + UDP)
- Port range 1-65535 for all traffic
- Assigned via Conditional Access policies

## Best Practices

### Application Naming
- Use descriptive, consistent names
- Include location/environment if relevant
- Examples: `HR_Portal_Prod`, `Finance_System_EMEA`, `Dev_Environment_SSH`

### Segment Grouping
- **Group related segments** into same application
- **Separate by user base** if different teams need different access
- **Don't over-group** - keep applications logically distinct

### Connector Group Assignment
- Match connector groups to network topology
- Consider geographic proximity for performance
- Deploy 2+ connectors per group for HA

### User Assignments
- Prefer group-based assignments
- Use security groups, not distribution lists
- Document group membership criteria

### Quick Access Guidelines
- Use for infrastructure and transparent access
- Avoid for user-launched applications
- Consider security implications of broad ranges
- Document Quick Access apps separately (they're hidden from users)

---

## Next Steps

Now that you understand the EPA configuration model:

1. **[GreenField Deployment](../GreenField/EntraPrivateAccess.md)** - Deploy EPA from scratch using CSV templates
2. **[Migrate from ZPA](../MigrationSources/ZScaler/ZPA2EPA.md)** - Export and transform from Zscaler Private Access
3. **[Export Existing Configuration](../MigrationSources/GSA/EPAExport.md)** - Backup your current EPA setup for disaster recovery or tenant migration
4. **[Provisioning Reference](../Provision/EntraPrivateAccessProvisioning.md)** - Detailed provisioning function documentation

📖 **Additional Resources:**
- [Entra Private Access Documentation](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-private-access)
- [Private Access Connectors](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-connectors)
- [Quick Access Applications](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-quick-access)
