---
sidebar_position: 10
title: ZPA to EPA Migration Guide
---

# Migrating from Zscaler Private Access to Microsoft Entra Private Access

## Overview

This guide assists administrators in understanding the conceptual mapping between Zscaler Private Access and Microsoft Entra Private Access. It focuses on how configuration objects translate, providing a clear reference for migration planning.

> **Note** - This document focuses on configuration object mapping and architectural differences. It assumes familiarity with both product's concepts.

## Conceptual Mapping

The fundamental difference between Zscaler Private Access and Entra Private Access lies in how applications are defined and secured. Zscaler Private Access uses a coarse-grained model where a single object can contain mixed protocols and domains. Entra Private Access uses a fine-grained "Enterprise Application" model where definitions are explicit.

### High-Level Object Map

| Zscaler Private Access Object | Entra Private Access Object | Migration Behaviour |
|---|---|---|
| Application Segment | Enterprise Application | A one-to-one mapping. One Zscaler Private Access App Segment becomes one Entra Private Access Enterprise App container. |
| Domain/Port Entry | Application Segment | A one-to-many mapping. The contents of a Zscaler Private Access segment (domains times ports) are expanded into individual Entra Private Access segments. |
| Segment Group | None | Not migrated. Segment Groups are logical containers in Zscaler Private Access that do not have a functional equivalent in Entra Private Access configuration. |
| Server Group | None | Not migrated. Backend server definitions are handled by network routing via Connectors, not distinct configuration objects. |
| Connector Group | Connector Group | Direct mapping. Physical grouping of connectors for routing and redundancy. |
| Access Policy | User/Group Assignment & Conditional Access | Policy rules are converted into direct assignments (who can access) and Conditional Access Policies (under what conditions). |

## Detailed Configuration Mapping

### Application Segments

In Zscaler Private Access, an **Application Segment** is a container that can hold multiple unrelated domains, IP ranges, and port ranges. In Entra Private Access, an **Enterprise Application** acts as the container, but the underlying network destinations must be defined explicitly as individual **Entra Private Access Application Segments**.

#### The Expansion Effect

When migrating, a single Zscaler Private Access object often "explodes" into multiple Entra Private Access definitions.

**Zscaler Private Access Configuration Concept:**

- **Name**: Finance-Dashboard
- **Domains**: finance.corp, \*.finance.corp
- **Ports**: TCP 80, 443, 8080-8090

**Entra Private Access Configuration Result:** The single "Finance-Dashboard" Enterprise Application will contain **6 distinct segments**:

| Destination | Protocol | Port(s) |
|---|---|---|
| finance.corp | TCP | 80 |
| finance.corp | TCP | 443 |
| finance.corp | TCP | 8080-8090 |
| \*.finance.corp | TCP | 80 |
| \*.finance.corp | TCP | 443 |
| \*.finance.corp | TCP | 8080-8090 |

> [!TIP]
> This granularity provides better visibility and control but results in a higher number of configuration lines during migration.

### Access Policies

Zscaler Private Access uses a rule-based engine (If \<Criteria\> then Allow). Entra Private Access uses an identity-centric assignment model (Assign \<Group\> to \<App\>).

**Zscaler Private Access Logic:**

- **Policy**: "Allow HR Users"
- **Criteria**: If Application is HR-Portal AND User is in HR-Group

**Entra Private Access Logic:**

- **Assignment**: Assigning Users/Groups to the Enterprise App controls access to the app and its defined segments.
- **Conditional Access**: CA Policies can be used to enforce security controls dynamically based on conditions and security signals.

#### Policy Limitations

Zscaler Private Access allows complex boolean logic (OR, NOT) within a single policy rule. Entra Private Access assignments are additive (ALLOW).

- **Handling "OR" Conditions**: If a Zscaler Private Access policy allows Group A OR Group B, simply assign **both** groups to the Entra Private Access Enterprise Application.
- **Handling "AND" Conditions** (different attributes): Requires **Conditional Access Policies**.
- **Handling "Block" Rules**: Entra Private Access does not support direct "Block" assignments on the app itself. Don't assign users that should not have access to the app or use Conditional Access Policies to block specific scenarios.

## Traffic Forwarding & Client Behavior

Zscaler Private Access uses **Client Forwarding Policies** to determine which application traffic is intercepted by the client and whether it should be tunneled or bypassed.

### Conceptual Translation

| Zscaler Private Access Concept | Entra Private Access Concept | Description |
|---|---|---|
| Forward to Zscaler Private Access | Default Acquisition | In Entra Private Access, the Global Secure Access (GSA) client automatically acquires traffic for all defined Application Segments in the tenant. |
| Only Forward Allowed Applications | Token Acquisition Flow | The GSA client attempts to acquire an access token for the matched user/app. Traffic is forwarded only if the user is Assigned to the app and satisfies Conditional Access policies. |
| Bypass Zscaler Private Access | Intelligent Local Access | To bypass tunneling when on the corporate network (direct access), Entra Private Access uses "Intelligent Local Access" triggered by DNS probes. |

### Traffic Flow Comparison

**Zscaler Private Access Client Forwarding Policy:**

- Rules are evaluated to decide: "Tunnel" vs "Bypass".
- "Only Forward Allowed Applications" mode prevents the client from intercepting traffic for apps the user lacks access to.

**Entra Private Access / GSA Client Logic:**

- **Match**: Client detects traffic to a matching destination defined in *any* Private Access Application Segment.
- **Authorize**: Client attempts to obtain an access token for the associated Enterprise Application.
  - Validates **User Assignment**.
  - Validates **Conditional Access Policies** (MFA, Device Compliance, etc.).
- **Forward**: If authorized, traffic is tunneled to Entra Private Access.

### "Bypass" Configuration (Intelligent Local Access)

In Zscaler Private Access, you might configure a "Bypass" rule for users on the corporate LAN. In Entra Private Access, this is configured as **Intelligent Local Access**.

- **Mechanism**: The client checks for connectivity to a specific internal DNS server/FQDN (Probe).
- **Action**: If the probe succeeds (indicating the client is on the corporate network), traffic to specified Enterprise Apps is routed directly (bypassed), avoiding the cloud tunnel.

## Non-Migratable Configurations & Conflicts

Certain Zscaler Private Access configurations explicitly conflict with Entra Private Access's strict validation rules and must be resolved before provisioning.

### 1. Overlapping Segments (Clashing)

Entra Private Access enforces strict uniqueness for network destinations. Two different Enterprise Applications cannot claim the same traffic. A conflict occurs when there is an overlap in **Destination** (IP/FQDN), **Protocol**, AND **Port**.

**Migration Blocker**: If two Zscaler Private Access segments overlap on all three traffic parameters, the second one will fail to deploy in Entra Private Access.

**Conflict Scenario:**

- **App A**: Defines 192.168.1.0/24 (Entire subnet), TCP, Port 443
- **App B**: Defines 192.168.1.50 (Specific server in that subnet), TCP, Port 443

In Zscaler Private Access, policy priority determines access. In Entra Private Access, this is a conflict because the segment parameters match exactly for the overlapping IP. You must redefine App A to exclude the IP of App B, or consolidate them into a single Enterprise Application.

### 2. Segment Groups

**Zscaler Private Access Segment Groups** allow you to apply policies to a bundle of apps. Entra Private Access does not have an "App Bundle" object for assignment.

**Remediation:**

- Policies applied to a Zscaler Private Access Segment Group must be "unrolled" and applied individually to every Enterprise Application that was part of that group.

### 3. Server Groups

**Zscaler Private Access Server Groups** define the backend IPs explicitly for health monitoring. Entra Private Access does not currently provide this functionality.

**Remediation:**

- Explicit backend server definitions are not migrated. Ensure your internal DNS resolves the FQDNs to the correct backend IPs, or that the connectors can route to the defined IP addresses.
