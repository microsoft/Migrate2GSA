# Specification: Convert-CitrixNS2EPA Function

**Date**: February 25, 2026  
**Author**: Andres Canello  
**Status**: Draft  
**Version**: 1.1

---

## 1. Overview

### 1.1 Purpose
The `Convert-CitrixNS2EPA` function converts Citrix NetScaler Gateway configuration to Microsoft Entra Private Access (EPA) format. It parses the NetScaler text-based configuration containing AAA groups, authorization policies, VPN intranet applications, and group bindings, then generates a CSV file compatible with `Start-EntraPrivateAccessProvisioning`.

### 1.2 Code Reuse Requirement
**⚠️ IMPORTANT: This function MUST reuse significant portions of code from `Convert-ZPA2EPA.ps1` (#file:Convert-ZPA2EPA.ps1)**

The implementation should leverage the existing, tested codebase including:
- **All conflict detection logic** and data structures (`$ipRangeToProtocolToPorts`, `$hostToProtocolToPorts`, `$dnsSuffixes`)
- **Helper functions** for IP/CIDR processing, range overlap detection, destination type detection
- **Logging infrastructure** (`Write-LogMessage` with INFO, WARN, ERROR, SUCCESS, DEBUG, SUMMARY levels)
- **Progress reporting** (`Write-ProgressUpdate` with ETA calculation)
- **CSV export** functionality with UTF-8 BOM encoding
- **Overall code structure** and processing flow patterns

See Section 11.1 for the complete list of functions to reuse from `Convert-ZPA2EPA.ps1`.

### 1.3 Scope
- **Input**: Single plain-text file containing Citrix NetScaler Gateway configuration commands
- **Output**: CSV file with Entra Private Access Enterprise Application configuration
- **Features**: 
  - Parses `add aaa group`, `add authorization policy`, `add vpn intranetApplication`, and `bind aaa group` commands
  - Maps each AAA group to one Enterprise Application
  - Consolidates TCP+UDP bindings of the same policy into a single segment
  - Conflict detection for overlapping IP ranges, FQDNs, protocols, and ports across Enterprise Apps
  - Includes unbound policies in output with `Provision=No`
  - Uses AAA group name as `EntraGroups` value for manual remapping

### 1.4 Key Differences from Other Conversions
| Aspect | ZPA (Convert-ZPA2EPA) | NPA (Convert-NPA2EPA) | NetScaler (Convert-CitrixNS2EPA) |
|--------|----------------------|----------------------|----------------------------------|
| **Input Format** | JSON exports | JSON exports | Plain-text config commands |
| **Access Model** | App Segments + Policies | Private Apps + Policies | Auth Policies + VPN IntranetApps + AAA Groups |
| **Grouping** | Segment Groups | None (flat) | AAA Groups (explicit bindings) |
| **Protocol Source** | Per-segment definition | Array in private app | Policy rule expression + binding `-type` |
| **User/Group Model** | SCIM IDs | X500 paths | AAA group names (opaque identifiers) |
| **Multi-Protocol** | Per segment | Per app | Same policy bound multiple times with different `-type` |

---

## 2. Input File Structure

### 2.1 Format
The input is a single plain-text file (any extension) containing Citrix NetScaler Gateway configuration commands. Each command occupies one line. Lines may contain inline comments starting with `#`. Blank lines and comment-only lines are ignored.

### 2.2 Supported Commands

The function parses four command types:

#### 2.2.1 `add aaa group`
Defines an AAA user group. Each AAA group maps to one Enterprise Application in the output.

**Syntax:**
```
add aaa group <groupName> [-weight <number>] [-devno <number>]
```

Only `<groupName>` is relevant for conversion. `-weight` and `-devno` are ignored.

**Example:**
```
add aaa group vpn-warehouse-admins -weight 15000 -devno 21675
```

#### 2.2.2 `add authorization policy`
Defines a named authorization policy with a rule expression specifying destination IP/subnet and optional port/protocol constraints.

**Syntax:**
```
add authorization policy <policyName> "<ruleExpression>" <action>
```

**Supported rule expressions:**

| Expression | Meaning |
|------------|---------|
| `CLIENT.IP.DST.EQ(<ip>)` | Matches specific destination IP |
| `CLIENT.IP.DST.IN_SUBNET(<ip>/<mask>)` | Matches destination subnet (CIDR) |
| `CLIENT.TCP.DSTPORT.EQ(<port>)` | Matches specific TCP destination port |
| `CLIENT.UDP.DSTPORT.EQ(<port>)` | Matches specific UDP destination port |
| `<expr>.NOT` | Negates the preceding expression (see §3.9) |
| `&&` | Logical AND |
| `\|\|` | Logical OR |
| `( )` | Grouping parentheses |

The `<action>` is always `ALLOW` or `DENY`. Only `ALLOW` policies are converted. `DENY` policies are logged and skipped.

The expression may contain escaped double-quotes (`\"...\"`) for hostname-based expressions.

Boolean expressions (`TRUE` / `FALSE`) are valid NetScaler syntax for match-all / match-none policies. These contain no IP, subnet, or FQDN rules convertible to EPA and are skipped with a WARN log (see §3.8).

Negated expressions using the `.NOT` suffix (e.g., `CLIENT.IP.DST.IN_SUBNET(10.0.0.0/8).NOT`) define exclusion rules that cannot be represented as positive EPA application segments and are skipped with a WARN log (see §3.9).

**Examples:**
```
add authorization policy web-srv-443 "CLIENT.IP.DST.EQ(172.16.5.20) && CLIENT.TCP.DSTPORT.EQ(443)" ALLOW
add authorization policy lab-subnet "CLIENT.IP.DST.IN_SUBNET(172.16.10.0/24)" ALLOW
add authorization policy multi-dest "(CLIENT.IP.DST.IN_SUBNET(172.16.20.0/24) || CLIENT.IP.DST.IN_SUBNET(172.16.21.0/24)) && (CLIENT.TCP.DSTPORT.EQ(22) || CLIENT.TCP.DSTPORT.EQ(3306))" ALLOW
add authorization policy sap-layer "HTTP.REQ.HOSTNAME.CONTAINS(\"sap-servicelayer.conectcar.com\") && CLIENT.TCP.DSTPORT.EQ(50000)" ALLOW
add authorization policy besso-aws "(CLIENT.IP.DST.IN_SUBNET(192.168.0.0/16).NOT && CLIENT.IP.DST.IN_SUBNET(172.16.0.0/12).NOT && CLIENT.IP.DST.IN_SUBNET(10.0.0.0/8).NOT) && (CLIENT.TCP.DSTPORT.EQ(5432))" ALLOW
add authorization policy allow_dns TRUE ALLOW
add authorization policy deny_any TRUE DENY
```

#### 2.2.3 `add vpn intranetApplication`
Defines a VPN intranet application for split-tunnel routing, specifying protocol, destination (FQDNs, IPs, or wildcards), and port ranges.

**Syntax:**
```
add vpn intranetApplication <appName> <protocol> "<destination>" -destPort <portRange> [-interception <mode>] [-devno <number>]
```

| Parameter | Description |
|-----------|-------------|
| `<appName>` | Descriptive name for the application |
| `<protocol>` | `TCP`, `UDP`, `ANY` (TCP+UDP+ICMP), or `ICMP` |
| `<destination>` | Comma-separated FQDNs (optionally wildcarded), IP addresses, or IP ranges |
| `-destPort` | Port or port range (e.g., `1-65535` for all ports, `443` for single port) |

`-interception` and `-devno` are ignored.

**Examples:**
```
add vpn intranetApplication iT_warehouse.io ANY "*.warehouse.io" -destPort 1-65535 -interception TRANSPARENT -devno 22443
add vpn intranetApplication iT_logistics ANY "*.dev-logistics.com,*.prod-logistics.com" -destPort 1-65535 -interception TRANSPARENT -devno 22457
add vpn intranetApplication iT_jumpbox ANY 203.0.113.50 -destPort 1-65535 -interception TRANSPARENT -devno 22519
```

#### 2.2.4 `bind aaa group`
Links an authorization policy or intranet application to an AAA group. There are two forms:

**Authorization policy binding:**
```
bind aaa group <groupName> -policy <policyName> -priority <number> [-type <requestType>] [-gotoPriorityExpression <expr>] [-devno <number>]
```

- If `-type` is omitted, the binding type is `TCP` (default).
- `-type UDP_REQUEST` means the binding is for UDP.
- `-type ICMP_REQUEST` means the binding is for ICMP (ignored for EPA conversion).
- The same policy may be bound twice to the same group with different `-type` values (once for TCP, once for UDP).

**Intranet application binding:**
```
bind aaa group <groupName> -intranetApplication <appName> [-devno <number>]
```

`-priority`, `-gotoPriorityExpression`, and `-devno` are ignored.

**Examples:**
```
bind aaa group vpn-warehouse-admins -policy web-srv-443 -priority 21590 -gotoPriorityExpression END -devno 369098753
bind aaa group vpn-warehouse-admins -policy lab-subnet -priority 23800 -type UDP_REQUEST -gotoPriorityExpression END -devno 369098764
bind aaa group vpn-logistics-devs -intranetApplication iT_logistics -devno 402653186
```

### 2.3 Parsing Rules

1. **Line-by-line processing**: Each line is parsed independently.
2. **Comment handling**: Strip everything from `#` to end of line before parsing. Lines that become empty after stripping are skipped.
3. **Whitespace handling**: Trim leading/trailing whitespace. Multiple spaces between tokens are treated as single delimiters.
4. **Case insensitivity**: Command keywords (`add`, `aaa`, `group`, `bind`, etc.) are case-insensitive. Policy names, group names, and destinations are case-preserved.
5. **Quoted strings**: Destinations in `add authorization policy` and `add vpn intranetApplication` may be enclosed in double quotes. Expressions may contain escaped quotes (`\"...\"`) for hostname-based expressions. Quotes are stripped during parsing.
6. **Boolean expressions**: Authorization policies using unquoted `TRUE` or `FALSE` as the expression (match-all / match-none) are logged as WARN and skipped — they contain no convertible IP/FQDN/port rules.
7. **Unrecognized lines**: Lines not matching any supported command are skipped with a `DEBUG`-level warning (visible only when `-EnableDebugLogging` is specified).

---

## 3. Transformation Logic

### 3.1 AAA Group to Enterprise Application Mapping

Each `add aaa group` command becomes one Enterprise Application row set in the output.

#### 3.1.1 Enterprise App Name
- **Prefix `GSA-`**: Output names start with `GSA-` followed by the AAA group name.
- **Example**: `vpn-warehouse-admins` → `GSA-vpn-warehouse-admins`

#### 3.1.2 EntraGroups Assignment
- The AAA group name is used directly as the `EntraGroups` value.
- The user is expected to remap these to real Entra ID security groups after conversion.
- **Example**: AAA group `vpn-warehouse-admins` → `EntraGroups` = `vpn-warehouse-admins`

### 3.2 Authorization Policy to Segment Mapping

#### 3.2.1 Rule Expression Parsing

The rule expression inside `add authorization policy` must be parsed to extract destinations and port constraints. The parser must handle:

1. **Simple IP + Port**: `CLIENT.IP.DST.EQ(172.16.5.20) && CLIENT.TCP.DSTPORT.EQ(443)`
   → One destination `172.16.5.20`, port `443`, protocol `TCP`

2. **Subnet only (no port)**: `CLIENT.IP.DST.IN_SUBNET(172.16.10.0/24)`
   → One destination `172.16.10.0/24`, no port constraint (all ports derived from bindings)

3. **Multi-destination with ports**: `(CLIENT.IP.DST.IN_SUBNET(172.16.20.0/24) || CLIENT.IP.DST.IN_SUBNET(172.16.21.0/24)) && (CLIENT.TCP.DSTPORT.EQ(22) || CLIENT.TCP.DSTPORT.EQ(3306))`
   → Two destination subnets × two ports = 4 logical segments, protocol `TCP`

4. **UDP port in expression**: `CLIENT.IP.DST.EQ(172.16.5.30) && (CLIENT.UDP.DSTPORT.EQ(514))`
   → One destination, port `514`, protocol `UDP` (the expression itself indicates UDP)

5. **FQDN via hostname match**: `HTTP.REQ.HOSTNAME.CONTAINS(\"sap-servicelayer.conectcar.com\") && CLIENT.TCP.DSTPORT.EQ(50000)`
   → One wildcard FQDN destination `*.sap-servicelayer.conectcar.com`, port `50000`, protocol `TCP`

**Parsing algorithm:**

```
1. Tokenize: Extract all CLIENT.IP.DST.EQ(<ip>), CLIENT.IP.DST.IN_SUBNET(<cidr>),
   HTTP.REQ.HOSTNAME.CONTAINS(\"<domain>\"),
   CLIENT.TCP.DSTPORT.EQ(<port>), CLIENT.UDP.DSTPORT.EQ(<port>) tokens
2. Collect destinations: All IP/subnet tokens → destination list;
   all HOSTNAME.CONTAINS tokens → wildcard FQDN destinations (*.<domain>)
3. Collect ports: All DSTPORT tokens → port list, noting TCP vs UDP per port
4. If no ports in expression → ports are "1-65535" (all), protocol derived from binding -type
5. If ports in expression → protocol is derived from TCP.DSTPORT vs UDP.DSTPORT tokens
```

#### 3.2.2 Protocol Consolidation from Bindings

When the same policy is bound for both TCP and UDP via separate `bind aaa group` commands (different `-type`), the protocols are consolidated into a single segment:

**Example**: Policy `lab-subnet` (subnet, no port restriction in rule) bound twice:
```
bind aaa group vpn-warehouse-admins -policy lab-subnet -priority 23800 -gotoPriorityExpression END
bind aaa group vpn-warehouse-admins -policy lab-subnet -priority 23800 -type UDP_REQUEST -gotoPriorityExpression END
```
**Result**: One segment with `Protocol=TCP,UDP`, `Ports=1-65535`

**Consolidation rules:**
- Same policy bound to same group with different `-type` → merge protocols into `TCP,UDP`
- If only TCP binding → `Protocol=TCP`
- If only UDP binding → `Protocol=UDP`
- If both TCP + UDP bindings → `Protocol=TCP,UDP`
- ICMP bindings are skipped (not supported in Entra Private Access)

#### 3.2.3 Port Resolution

The port value for a segment depends on what is found in the rule expression:

| Rule expression contains | Port output |
|--------------------------|-------------|
| `TCP.DSTPORT.EQ(443)` | `443` |
| `TCP.DSTPORT.EQ(22) \|\| TCP.DSTPORT.EQ(3306)` | `22,3306` |
| No DSTPORT clause | `1-65535` |

When a rule expression contains explicit port clauses, the port protocol indicator (`TCP.DSTPORT` vs `UDP.DSTPORT`) determines the protocol for those ports, and the binding `-type` is used as a confirmation. If the binding `-type` contradicts the expression's protocol (e.g., rule says `TCP.DSTPORT` but binding says `UDP_REQUEST`), log a warning and use the expression's protocol indicator.

When a rule expression has no DSTPORT clause (e.g., subnet-only), the protocol is determined entirely by the binding `-type` parameter(s).

#### 3.2.4 Multi-Destination Expansion

Authorization policies with multiple destinations (via `||` in the expression) produce multiple segments — one per destination:

**Input** (policy with two subnets and two ports):
```
add authorization policy shared-services "(CLIENT.IP.DST.IN_SUBNET(172.16.20.0/24) || CLIENT.IP.DST.IN_SUBNET(172.16.21.0/24)) && (CLIENT.TCP.DSTPORT.EQ(22) || CLIENT.TCP.DSTPORT.EQ(3306))" ALLOW
```

**Output**: Two segments (one per subnet), each with ports `22,3306`:

| Segment | destinationHost | Ports | Protocol |
|---------|----------------|-------|----------|
| Segment-001 | 172.16.20.0/24 | 22,3306 | TCP |
| Segment-002 | 172.16.21.0/24 | 22,3306 | TCP |

Ports are combined per destination (not expanded into per-port segments) because the ports share the same protocol.

**Mixed-protocol destinations**: If a rule expression contains both `TCP.DSTPORT` and `UDP.DSTPORT` clauses, the ports ARE separated by protocol, producing separate segments per protocol:

**Input**:
```
add authorization policy media-server "CLIENT.IP.DST.EQ(172.16.5.30) && (CLIENT.TCP.DSTPORT.EQ(554) || CLIENT.UDP.DSTPORT.EQ(554))" ALLOW
```

**Output**: Two segments for the same destination:

| Segment | destinationHost | Ports | Protocol |
|---------|----------------|-------|----------|
| Segment-001 | 172.16.5.30 | 554 | TCP |
| Segment-002 | 172.16.5.30 | 554 | UDP |

### 3.3 VPN Intranet Application to Segment Mapping

#### 3.3.1 Destination Expansion
Each comma-separated destination in the `add vpn intranetApplication` command becomes a separate segment:

**Input**:
```
add vpn intranetApplication iT_logistics ANY "*.dev-logistics.com,*.prod-logistics.com" -destPort 1-65535
```

**Output**: Two segments:
| Segment | destinationHost | Ports |
|---------|----------------|-------|
| Segment-001 | *.dev-logistics.com | 1-65535 |
| Segment-002 | *.prod-logistics.com | 1-65535 |

#### 3.3.2 Protocol Mapping

| NetScaler Protocol | EPA Output |
|-------------------|------------|
| `TCP` | `TCP` |
| `UDP` | `UDP` |
| `ANY` | `TCP,UDP` |
| `ICMP` | Skipped (log warning) |

When the protocol is `ANY`, the segment is output with `Protocol=TCP,UDP`.

#### 3.3.3 Port Range Handling
- `1-65535` → `1-65535` (all ports)
- `443` → `443` (single port)
- Range format (e.g., `80-443`) is preserved as-is.

### 3.4 Destination Type Detection

| Input Format | DestinationType | Detection Logic |
|-------------|-----------------|-----------------|
| `*.warehouse.io` | `fqdn` | Starts with `*` or contains letters + dots |
| `app.warehouse.io` | `fqdn` | Contains letters and dots, no `/` |
| `172.16.5.20` | `ipAddress` | Dotted decimal, no `/` |
| `172.16.10.0/24` | `ipRangeCidr` | Contains `/` with prefix length |
| `172.16.5.20/32` | `ipRangeCidr` | Single IP in CIDR notation |

**Implementation**: Reuse `Get-DestinationType` from `Convert-ZPA2EPA.ps1`.

### 3.5 Segment ID Generation

Format: `SEG-{######}` — sequential, zero-padded to 6 digits, globally unique across the entire output.

**Example**:
- `SEG-000001`
- `SEG-000002`
- `SEG-000003`

### 3.6 Unbound Policies

Authorization policies that are defined (`add authorization policy`) but never bound to any group (`bind aaa group`) are:
- **Included** in the output as orphan segments
- **EnterpriseAppName**: `GSA-UnboundPolicies`
- **EntraGroups**: Empty
- **Provision**: `No`
- **Notes**: `"Unbound policy - defined but not assigned to any AAA group"`
- Logged as a warning: `"Policy '<policyName>' is defined but not bound to any group"`

### 3.7 DENY Policies

Authorization policies with action `DENY`:
- **Skipped** entirely (not included in output)
- Logged as info: `"Skipping DENY policy: '<policyName>'"`

### 3.8 Boolean Policies (TRUE / FALSE)

Authorization policies using an unquoted boolean expression instead of a quoted rule expression:
```
add authorization policy allow_dns TRUE ALLOW
add authorization policy allow_icmp TRUE ALLOW
add authorization policy deny_any TRUE DENY
```

- `TRUE` = match all traffic; `FALSE` = match no traffic
- These contain **no IP, subnet, FQDN, or port rules** and cannot be meaningfully converted to EPA application segments
- **Skipped** entirely (not included in output)
- Logged as warning: `"Skipping boolean authorization policy '<policyName>' (TRUE ALLOW): no IP/port rules to convert."`

### 3.9 Negated Policies (.NOT)

Authorization policies that use the `.NOT` suffix to negate destination or port clauses:
```
add authorization policy besso-aws "(CLIENT.IP.DST.IN_SUBNET(192.168.0.0/16).NOT && CLIENT.IP.DST.IN_SUBNET(172.16.0.0/12).NOT && CLIENT.IP.DST.IN_SUBNET(10.0.0.0/8).NOT) && (CLIENT.TCP.DSTPORT.EQ(5432))" ALLOW
```

- `.NOT` inverts the preceding match — e.g., `IN_SUBNET(10.0.0.0/8).NOT` means "destination is **not** in 10.0.0.0/8"
- These rules typically describe **public-internet access** (everything except private ranges), which is the domain of **Entra Internet Access (EIA)**, not EPA
- EPA application segments require **positive** destination definitions (specific IPs, CIDRs, or FQDNs); negation cannot be expressed
- **Skipped** entirely (not included in output)
- Logged as warning: `"Skipping authorization policy '<policyName>': contains negated (.NOT) expressions which cannot be converted to EPA application segments. Consider Entra Internet Access for public-internet rules."`

**Detection**: The parser checks for the pattern `.<EQ|IN_SUBNET>(<value>).NOT` anywhere in the rule expression. If any negated clause is present, the entire policy is skipped — partial negation within a compound expression cannot be reliably decomposed into positive-only segments.

---

## 4. Conflict Detection

### 4.1 Overview
**Reuse the conflict detection implementation from `Convert-ZPA2EPA.ps1` (#file:Convert-ZPA2EPA.ps1):**
- IP range overlaps with same protocol/port
- FQDN exact matches with same protocol/port
- Wildcard domain overlaps with same protocol/port

**Scope**: Conflict detection applies **across all Enterprise Apps** (i.e., across all AAA groups). The same subnet appearing in different groups with different ports does trigger a conflict check — if the IP ranges overlap and port ranges overlap for the same protocol, it is flagged.

### 4.2 Detection Algorithm
**Note:** These data structures and algorithms are already implemented in `Convert-ZPA2EPA.ps1` and should be reused as-is.

#### 4.2.1 Data Structures
```powershell
$ipRangeToProtocolToPorts = @{}      # IP ranges -> protocols -> ports -> app info
$hostToProtocolToPorts = @{}         # FQDNs -> protocols -> ports -> app info
$dnsSuffixes = @{}                   # Wildcard domains -> protocols -> ports -> app info
```

#### 4.2.2 IP Range Conflict Detection
1. Convert CIDR to integer range (start/end) using `Convert-CIDRToRange`
2. For each existing range with same protocol/port overlap:
   - Check if ranges overlap: `max(start1, start2) <= min(end1, end2)` using `Test-IntervalOverlap`
   - Check if ports overlap using `Test-PortRangeOverlap`
3. If overlap found:
   - Set `Conflict` = `Yes`
   - Set `ConflictingEnterpriseApp` = `{EnterpriseAppName}:{SegmentId}` of the conflicting segment

#### 4.2.3 FQDN Conflict Detection
1. Exact match: `host1 == host2` with same protocol/port
2. Wildcard match:
   - `*.warehouse.io` conflicts with `app.warehouse.io`
   - `*.warehouse.io` conflicts with `*.warehouse.io`

#### 4.2.4 Conflict Output Fields
- `Conflict` = `Yes` on the conflicting segment
- `ConflictingEnterpriseApp` = `{EnterpriseAppName}:{SegmentId}` identifying the first segment it conflicts with
- `Provision` = `No` (conflicts are automatically set to not provision — the user reviews and decides which side to enable)

---

## 5. Output Format

### 5.1 CSV Structure

**Columns** (in order, matching `Start-EntraPrivateAccessProvisioning` expected input):

| # | Column | Description |
|---|--------|-------------|
| 1 | `SegmentId` | Unique segment identifier (`SEG-000001`) |
| 2 | `OriginalAppName` | Source AAA group name (or intranet app name for VPN apps) |
| 3 | `EnterpriseAppName` | Target EPA app name (`GSA-` prefixed) |
| 4 | `destinationHost` | FQDN, IP address, or CIDR |
| 5 | `DestinationType` | `fqdn`, `ipAddress`, or `ipRangeCidr` |
| 6 | `Protocol` | `TCP`, `UDP`, or `TCP,UDP` |
| 7 | `Ports` | Comma-separated ports or range (e.g., `443` or `22,3306` or `1-65535`) |
| 8 | `EntraGroups` | AAA group name (user remaps to Entra ID group after conversion) |
| 9 | `EntraUsers` | Empty (NetScaler AAA groups do not expose individual users) |
| 10 | `ConnectorGroup` | Always `Placeholder_Replace_Me` |
| 11 | `Conflict` | `Yes` or `No` |
| 12 | `ConflictingEnterpriseApp` | `{EnterpriseAppName}:{SegmentId}` if conflicting, else empty |
| 13 | `Provision` | `Yes` or `No` |
| 14 | `isQuickAccess` | Always `no` (NetScaler configs do not map to Quick Access) |

### 5.2 Example: Authorization Policies (IP + Port Rules)

**Input** (NetScaler config):
```
add aaa group vpn-warehouse-admins -weight 15000 -devno 21675
add authorization policy wh-mgmt-ssh "CLIENT.IP.DST.EQ(172.16.5.20) && CLIENT.TCP.DSTPORT.EQ(22)" ALLOW
add authorization policy wh-mgmt-rdp "CLIENT.IP.DST.EQ(172.16.5.20) && CLIENT.TCP.DSTPORT.EQ(3389)" ALLOW
add authorization policy wh-cameras "CLIENT.IP.DST.EQ(172.16.5.30) && CLIENT.TCP.DSTPORT.EQ(554)" ALLOW
add authorization policy wh-cameras-udp "CLIENT.IP.DST.EQ(172.16.5.30) && (CLIENT.UDP.DSTPORT.EQ(554))" ALLOW
add authorization policy wh-lab-net "CLIENT.IP.DST.IN_SUBNET(172.16.10.0/24)" ALLOW
bind aaa group vpn-warehouse-admins -policy wh-mgmt-ssh -priority 1000 -gotoPriorityExpression END
bind aaa group vpn-warehouse-admins -policy wh-mgmt-rdp -priority 1010 -gotoPriorityExpression END
bind aaa group vpn-warehouse-admins -policy wh-cameras -priority 1020 -gotoPriorityExpression END
bind aaa group vpn-warehouse-admins -policy wh-cameras-udp -priority 1030 -type UDP_REQUEST -gotoPriorityExpression END
bind aaa group vpn-warehouse-admins -policy wh-lab-net -priority 2000 -gotoPriorityExpression END
bind aaa group vpn-warehouse-admins -policy wh-lab-net -priority 2000 -type UDP_REQUEST -gotoPriorityExpression END
```

**Output CSV**:

| SegmentId | OriginalAppName | EnterpriseAppName | destinationHost | DestinationType | Protocol | Ports | EntraGroups | EntraUsers | ConnectorGroup | Conflict | ConflictingEnterpriseApp | Provision | isQuickAccess |
|-----------|----------------|-------------------|-----------------|-----------------|----------|-------|-------------|------------|----------------|----------|--------------------------|-----------|---------------|
| SEG-000001 | vpn-warehouse-admins | GSA-vpn-warehouse-admins | 172.16.5.20 | ipAddress | TCP | 22 | vpn-warehouse-admins | | Placeholder_Replace_Me | No | | Yes | no |
| SEG-000002 | vpn-warehouse-admins | GSA-vpn-warehouse-admins | 172.16.5.20 | ipAddress | TCP | 3389 | vpn-warehouse-admins | | Placeholder_Replace_Me | No | | Yes | no |
| SEG-000003 | vpn-warehouse-admins | GSA-vpn-warehouse-admins | 172.16.5.30 | ipAddress | TCP | 554 | vpn-warehouse-admins | | Placeholder_Replace_Me | No | | Yes | no |
| SEG-000004 | vpn-warehouse-admins | GSA-vpn-warehouse-admins | 172.16.5.30 | ipAddress | UDP | 554 | vpn-warehouse-admins | | Placeholder_Replace_Me | No | | Yes | no |
| SEG-000005 | vpn-warehouse-admins | GSA-vpn-warehouse-admins | 172.16.10.0/24 | ipRangeCidr | TCP,UDP | 1-65535 | vpn-warehouse-admins | | Placeholder_Replace_Me | No | | Yes | no |

**Explanation:**
- `wh-mgmt-ssh` and `wh-mgmt-rdp` each get their own segment (same IP, different ports, both TCP-only bindings).
- `wh-cameras` (TCP) and `wh-cameras-udp` (UDP) target the same IP/port but different protocols. Because the rule expressions explicitly specify TCP vs UDP port clauses, these remain separate segments (TCP and UDP respectively).
- `wh-lab-net` is bound for both TCP and UDP (same group, no port in expression), so it consolidates to `Protocol=TCP,UDP` with `Ports=1-65535`.

### 5.3 Example: VPN Intranet Applications (FQDN Routing)

**Input** (NetScaler config):
```
add aaa group vpn-logistics-devs -devno 21835
add vpn intranetApplication iT_logistics.io ANY "*.logistics.io" -destPort 1-65535 -interception TRANSPARENT -devno 22443
add vpn intranetApplication iT_partners ANY "*.dev-partners.com,*.prod-partners.com" -destPort 1-65535 -interception TRANSPARENT -devno 22457
add vpn intranetApplication iT_jumpbox ANY 203.0.113.50 -destPort 1-65535 -interception TRANSPARENT -devno 22519
bind aaa group vpn-logistics-devs -intranetApplication iT_logistics.io -devno 402653185
bind aaa group vpn-logistics-devs -intranetApplication iT_partners -devno 402653186
bind aaa group vpn-logistics-devs -intranetApplication iT_jumpbox -devno 402653187
```

**Output CSV**:

| SegmentId | OriginalAppName | EnterpriseAppName | destinationHost | DestinationType | Protocol | Ports | EntraGroups | EntraUsers | ConnectorGroup | Conflict | ConflictingEnterpriseApp | Provision | isQuickAccess |
|-----------|----------------|-------------------|-----------------|-----------------|----------|-------|-------------|------------|----------------|----------|--------------------------|-----------|---------------|
| SEG-000006 | vpn-logistics-devs | GSA-vpn-logistics-devs | *.logistics.io | fqdn | TCP,UDP | 1-65535 | vpn-logistics-devs | | Placeholder_Replace_Me | No | | Yes | no |
| SEG-000007 | vpn-logistics-devs | GSA-vpn-logistics-devs | *.dev-partners.com | fqdn | TCP,UDP | 1-65535 | vpn-logistics-devs | | Placeholder_Replace_Me | No | | Yes | no |
| SEG-000008 | vpn-logistics-devs | GSA-vpn-logistics-devs | *.prod-partners.com | fqdn | TCP,UDP | 1-65535 | vpn-logistics-devs | | Placeholder_Replace_Me | No | | Yes | no |
| SEG-000009 | vpn-logistics-devs | GSA-vpn-logistics-devs | 203.0.113.50 | ipAddress | TCP,UDP | 1-65535 | vpn-logistics-devs | | Placeholder_Replace_Me | No | | Yes | no |

**Explanation:**
- `iT_logistics.io` with protocol `ANY` produces `Protocol=TCP,UDP`.
- `iT_partners` has two comma-separated wildcard domains, producing two separate segments.
- `iT_jumpbox` is a single IP with `ANY` protocol, producing one segment.

### 5.4 Example: Overlapping Subnets Across Groups (Conflict Detection)

**Input** (NetScaler config):
```
add aaa group vpn-ops-full -weight 15000 -devno 21745
add aaa group vpn-ops-web -weight 15000 -devno 21768
add aaa group vpn-ops-db -weight 15000 -devno 21614
add authorization policy ops-all "CLIENT.IP.DST.IN_SUBNET(192.168.0.0/16)" ALLOW
add authorization policy ops-web "CLIENT.IP.DST.IN_SUBNET(192.168.10.0/24) && CLIENT.TCP.DSTPORT.EQ(443) || CLIENT.IP.DST.IN_SUBNET(192.168.11.0/24) && CLIENT.TCP.DSTPORT.EQ(443)" ALLOW
add authorization policy ops-db "(CLIENT.IP.DST.IN_SUBNET(192.168.10.0/24) || CLIENT.IP.DST.IN_SUBNET(192.168.11.0/24)) && (CLIENT.TCP.DSTPORT.EQ(22) || CLIENT.TCP.DSTPORT.EQ(5432))" ALLOW
bind aaa group vpn-ops-full -policy ops-all -priority 18560 -gotoPriorityExpression END
bind aaa group vpn-ops-web -policy ops-web -priority 1000 -gotoPriorityExpression END
bind aaa group vpn-ops-db -policy ops-db -priority 1000 -gotoPriorityExpression END
```

**Output CSV** (conflict flags shown):

| SegmentId | EnterpriseAppName | destinationHost | DestinationType | Protocol | Ports | EntraGroups | Conflict | ConflictingEnterpriseApp | Provision |
|-----------|-------------------|-----------------|-----------------|----------|-------|-------------|----------|--------------------------|-----------|
| SEG-000010 | GSA-vpn-ops-full | 192.168.0.0/16 | ipRangeCidr | TCP | 1-65535 | vpn-ops-full | No | | Yes |
| SEG-000011 | GSA-vpn-ops-web | 192.168.10.0/24 | ipRangeCidr | TCP | 443 | vpn-ops-web | Yes | GSA-vpn-ops-full:SEG-000010 | No |
| SEG-000012 | GSA-vpn-ops-web | 192.168.11.0/24 | ipRangeCidr | TCP | 443 | vpn-ops-web | Yes | GSA-vpn-ops-full:SEG-000010 | No |
| SEG-000013 | GSA-vpn-ops-db | 192.168.10.0/24 | ipRangeCidr | TCP | 22,5432 | vpn-ops-db | Yes | GSA-vpn-ops-full:SEG-000010 | No |
| SEG-000014 | GSA-vpn-ops-db | 192.168.11.0/24 | ipRangeCidr | TCP | 22,5432 | vpn-ops-db | Yes | GSA-vpn-ops-full:SEG-000010 | No |

**Explanation:**
- `192.168.10.0/24` and `192.168.11.0/24` are subsets of `192.168.0.0/16`, so they conflict.
- All conflicting segments have `Conflict=Yes` and reference the first conflicting segment.
- `Provision` is set to `No` for conflicting segments — the user reviews and enables the side they want to keep.

### 5.5 Example: Unbound Policy

**Input**:
```
add authorization policy orphan-rule "CLIENT.IP.DST.IN_SUBNET(10.99.0.0/16)" ALLOW
```
(No `bind aaa group` references `orphan-rule`)

**Output CSV**:

| SegmentId | OriginalAppName | EnterpriseAppName | destinationHost | DestinationType | Protocol | Ports | EntraGroups | Provision | Notes |
|-----------|----------------|-------------------|-----------------|-----------------|----------|-------|-------------|-----------|-------|
| SEG-000015 | orphan-rule | GSA-UnboundPolicies | 10.99.0.0/16 | ipRangeCidr | TCP | 1-65535 | | No | Unbound policy - defined but not assigned to any AAA group |

---

## 6. Function Parameters

### 6.1 Parameter Definitions

```powershell
function Convert-CitrixNS2EPA {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path to NetScaler configuration file")]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$ConfigFilePath,
        
        [Parameter(Mandatory = $false, HelpMessage = "Base directory for output files")]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$OutputBasePath = $PWD,
        
        [Parameter(HelpMessage = "Wildcard pattern to include only matching AAA groups")]
        [string]$GroupFilter,
        
        [Parameter(HelpMessage = "Wildcard pattern to exclude matching AAA groups")]
        [string]$ExcludeGroupFilter,
        
        [Parameter(HelpMessage = "Enable verbose debug logging")]
        [switch]$EnableDebugLogging,
        
        [Parameter(HelpMessage = "Return results to pipeline (suppresses automatic console output)")]
        [switch]$PassThru
    )
}
```

### 6.2 Parameter Usage Examples

#### Example 1: Basic Conversion
```powershell
Convert-CitrixNS2EPA -ConfigFilePath "C:\Export\netscaler.conf"
```

#### Example 2: Output to Specific Directory
```powershell
Convert-CitrixNS2EPA `
    -ConfigFilePath ".\netscaler-gateway.txt" `
    -OutputBasePath "C:\Output"
```

#### Example 3: Filter by Group Name
```powershell
Convert-CitrixNS2EPA `
    -ConfigFilePath ".\netscaler.conf" `
    -GroupFilter "vpn-warehouse-*"
```

#### Example 4: Exclude Groups
```powershell
Convert-CitrixNS2EPA `
    -ConfigFilePath ".\netscaler.conf" `
    -ExcludeGroupFilter "*-test-*"
```

#### Example 5: Pipeline Integration
```powershell
$results = Convert-CitrixNS2EPA `
    -ConfigFilePath ".\netscaler.conf" `
    -PassThru

$results | Where-Object { $_.Conflict -eq "Yes" } | 
    Export-Csv ".\conflicts.csv" -NoTypeInformation
```

---

## 7. Processing Flow

### 7.1 High-Level Flow
```
1. Load and pre-process config file (strip comments, blank lines)
   ↓
2. Parse Phase: Extract all objects
   ├─ Parse "add aaa group" → Groups hashtable
   ├─ Parse "add authorization policy" → Policies hashtable
   ├─ Parse "add vpn intranetApplication" → IntranetApps hashtable
   └─ Parse "bind aaa group" → Bindings list
   ↓
3. Resolve Phase: Build relationships
   ├─ For each binding, link policy/app → group
   ├─ Identify policies bound for TCP, UDP, or both
   ├─ Identify unbound policies
   └─ Apply group filter/exclude
   ↓
4. Transform Phase: Generate segments
   ├─ For each group → Enterprise App:
   │   ├─ For each bound authorization policy:
   │   │   ├─ Parse rule expression → destinations + ports
   │   │   ├─ Determine consolidated protocol from bindings
   │   │   └─ Expand destinations to segments
   │   └─ For each bound intranet application:
   │       ├─ Expand comma-separated destinations
   │       ├─ Map protocol (ANY → TCP,UDP)
   │       └─ Generate segments
   ├─ For unbound policies:
   │   └─ Generate segments under GSA-UnboundPolicies
   └─ Assign Segment IDs
   ↓
5. Conflict Detection: Check all segments
   ├─ IP range overlaps
   ├─ FQDN exact matches
   └─ Wildcard domain overlaps
   ↓
6. Export to CSV (UTF-8 BOM)
   ↓
7. Display summary statistics
```

### 7.2 Internal Data Structures

#### 7.2.1 Parsed Objects

```powershell
# AAA Groups: name → metadata
$aaaGroups = @{}
# Key: group name
# Value: @{ Name = 'vpn-warehouse-admins'; Weight = 15000 }

# Authorization Policies: name → parsed rule
$authPolicies = @{}
# Key: policy name
# Value: @{
#     Name = 'wh-mgmt-ssh'
#     Action = 'ALLOW'
#     RawExpression = 'CLIENT.IP.DST.EQ(172.16.5.20) && CLIENT.TCP.DSTPORT.EQ(22)'
#     Destinations = @('172.16.5.20')      # IPs, CIDRs, and/or *.domain wildcard FQDNs
#     TcpPorts = @('22')
#     UdpPorts = @()
#     HasPortClause = $true
# }

# VPN Intranet Applications: name → parsed app
$intranetApps = @{}
# Key: app name
# Value: @{
#     Name = 'iT_logistics.io'
#     Protocol = 'ANY'
#     Destinations = @('*.logistics.io')
#     PortRange = '1-65535'
# }

# Bindings: list of binding records
$bindings = @()
# Each: @{
#     GroupName = 'vpn-warehouse-admins'
#     Type = 'policy' or 'intranetApp'
#     TargetName = 'wh-mgmt-ssh'
#     BindingProtocol = 'TCP' or 'UDP' or 'ICMP'
# }
```

#### 7.2.2 Resolved Relationships

```powershell
# Group → Bound items with consolidated protocols
$groupBindings = @{}
# Key: group name
# Value: @{
#     Policies = @{
#         'wh-mgmt-ssh' = @{ Protocols = @('TCP') }
#         'wh-lab-net' = @{ Protocols = @('TCP', 'UDP') }   # consolidated
#     }
#     IntranetApps = @('iT_logistics.io', 'iT_partners')
# }

# Unbound policies
$unboundPolicies = @()   # list of policy names not referenced in any binding
```

---

## 8. Error Handling and Validation

### 8.1 Input Validation
- **File existence**: Validate path before loading
- **File encoding**: Handle UTF-8 and ANSI encodings
- **Empty file**: Throw error if file has no parseable commands
- **Minimum content**: At least one `add aaa group` and one binding must be present (warn if not)

### 8.2 Parsing Validation
- **Malformed expressions**: If a rule expression cannot be parsed, log error with line number, skip the policy, and continue
- **Missing references**: If a binding references a policy/app that was not defined, log warning and skip that binding
- **Duplicate definitions**: If the same object name is defined twice, log warning and use the last definition

### 8.3 Warning Conditions
Log warnings for:
- Policies with `DENY` action (skipped)
- Boolean policies with `TRUE`/`FALSE` expression (no rules to convert, skipped)
- ICMP bindings (not supported in EPA, skipped)
- Unbound policies (included with `Provision=No`)
- Intranet applications with protocol `ICMP` (skipped)
- Binding references to undefined policies/apps
- AAA groups with no bindings (empty Enterprise App — skipped with warning)
- Binding protocol contradicts rule expression protocol

### 8.4 Error Conditions
Throw errors for:
- Input file not found
- File is empty or has no parseable commands
- Write failures during CSV export

---

## 9. Logging and Statistics

### 9.1 Logging Requirements
**All console and log file output must use `Write-LogMessage`:**
- Use `-Level INFO` for general operational messages
- Use `-Level WARN` for warning conditions
- Use `-Level ERROR` for error conditions
- Use `-Level SUCCESS` for completion messages
- Use `-Level DEBUG` for detailed diagnostic information (only shown when `-EnableDebugLogging` is specified)
- Use `-Level SUMMARY` for summary statistics at completion
- Include `-Component` parameter to identify the operation context (e.g., `'Parse'`, `'Resolve'`, `'Transform'`, `'Conflicts'`, `'Export'`)
- Log file name: `${timestamp}_Convert-CitrixNS2EPA.log` under `OutputBasePath`

**Progress updates must use `Write-ProgressUpdate`.**

### 9.2 Summary Statistics
Display at completion using `Write-LogMessage -Level SUMMARY`:
```
=== PARSE SUMMARY ===
Total lines processed: 64
AAA groups found: 4
Authorization policies found: 12
VPN intranet applications found: 3
Bindings found: 15
  Policy bindings (TCP): 10
  Policy bindings (UDP): 3
  Intranet app bindings: 3
  ICMP bindings (skipped): 0
DENY policies skipped: 0
Unbound policies: 1

=== CONVERSION SUMMARY ===
Enterprise Applications generated: 4
Total segments generated: 14
  From authorization policies: 10
  From intranet applications: 4
Conflicts detected: 3
Segments with Provision=No: 1

Output file: 20260225_143022_GSA_EnterpriseApps_CitrixNS.csv
Log file: 20260225_143022_Convert-CitrixNS2EPA.log
```

### 9.3 Conflict Report
For each conflict detected, use `Write-LogMessage -Level WARN -Component 'Conflicts'`:
```
CONFLICT DETECTED:
  Application: GSA-vpn-ops-web
  Segment: 192.168.10.0/24:TCP/443
  Conflicts with: GSA-vpn-ops-full (192.168.0.0/16:TCP/1-65535) [SEG-000010]
  Recommendation: Consolidate applications or restrict port ranges to avoid overlap
```

---

## 10. Next Steps After Conversion

### 10.1 Manual Review
1. **Review CSV file** for accuracy
2. **Remap EntraGroups**: Replace NetScaler AAA group names with corresponding Entra ID security group names
3. **Replace ConnectorGroup placeholders**: Set `Placeholder_Replace_Me` to the actual Private Access connector group names
4. **Review conflicts**: Resolve flagged overlapping segments
5. **Review unbound policies**: Decide whether to provision or discard
6. **Validate port ranges**: Ensure `1-65535` (all ports) segments are intentional; consider narrowing

### 10.2 Import to GSA
Use the generated CSV with `Start-EntraPrivateAccessProvisioning`:
```powershell
Start-EntraPrivateAccessProvisioning `
    -ProvisioningConfigPath ".\20260225_143022_GSA_EnterpriseApps_CitrixNS.csv" `
    -Force
```

---

## 11. Implementation Notes

### 11.1 Code Reuse from Convert-ZPA2EPA (#file:Convert-ZPA2EPA.ps1)
**⚠️ CRITICAL: The following functions and code blocks MUST be copied from `Convert-ZPA2EPA.ps1`:**

#### 11.1.1 Helper Functions to Reuse (Copy Directly)
- `Convert-CIDRToRange` - IP range conversion
- `Convert-IPToInteger` - IP to integer conversion
- `Test-IntervalOverlap` - Range overlap detection
- `Test-PortRangeOverlap` - Port range overlap detection
- `Get-DestinationType` - Destination type detection
- `Clear-Domain` - Domain string cleaning
- `Write-LogMessage` - Unified console and file logging (supports INFO, WARN, ERROR, SUCCESS, DEBUG, SUMMARY levels)
- `Write-ProgressUpdate` - Progress bar with ETA calculation

#### 11.1.2 Code Blocks to Reuse (Adapt as Needed)
- **Conflict Detection Loop** - The entire conflict detection logic from the main processing phase
- **Data Structure Initialization** - The hashtables for tracking IP ranges, hosts, and DNS suffixes (`$ipRangeToProtocolToPorts`, `$hostToProtocolToPorts`, `$dnsSuffixes`)
- **CSV Export** - The export logic with UTF-8 BOM encoding
- **Summary Statistics** - The final summary output format and calculations

### 11.2 New Functions Required

```powershell
function Read-NetScalerConfig {
    <#
    .SYNOPSIS
        Reads and pre-processes the NetScaler config file.
    .DESCRIPTION
        Strips comments, trims whitespace, skips blank lines.
        Returns array of clean lines.
    #>
    param([string]$FilePath)
}

function Parse-AAAGroup {
    <#
    .SYNOPSIS
        Parses an "add aaa group" line.
    .OUTPUTS
        Hashtable with Name, Weight.
    #>
    param([string]$Line)
}

function Parse-AuthorizationPolicy {
    <#
    .SYNOPSIS
        Parses an "add authorization policy" line.
    .DESCRIPTION
        Extracts policy name, action, and parses the rule expression
        to produce destinations, TCP ports, UDP ports.
    .OUTPUTS
        Hashtable with Name, Action, RawExpression, Destinations,
        TcpPorts, UdpPorts, HasPortClause.
    #>
    param([string]$Line)
}

function Parse-RuleExpression {
    <#
    .SYNOPSIS
        Parses a Citrix NetScaler policy rule expression string.
    .DESCRIPTION
        Extracts CLIENT.IP.DST.EQ/IN_SUBNET destinations and
        CLIENT.TCP.DSTPORT.EQ/CLIENT.UDP.DSTPORT.EQ port clauses.
        Handles &&, ||, and parenthesized groups.
    .OUTPUTS
        Hashtable with Destinations (array), TcpPorts (array),
        UdpPorts (array), HasPortClause (bool).
    #>
    param([string]$Expression)
}

function Parse-IntranetApplication {
    <#
    .SYNOPSIS
        Parses an "add vpn intranetApplication" line.
    .OUTPUTS
        Hashtable with Name, Protocol, Destinations (array), PortRange.
    #>
    param([string]$Line)
}

function Parse-GroupBinding {
    <#
    .SYNOPSIS
        Parses a "bind aaa group" line.
    .OUTPUTS
        Hashtable with GroupName, Type ('policy' or 'intranetApp'),
        TargetName, BindingProtocol ('TCP', 'UDP', or 'ICMP').
    #>
    param([string]$Line)
}

function Resolve-GroupBindings {
    <#
    .SYNOPSIS
        Consolidates bindings per group, merging TCP/UDP for same policy.
    .DESCRIPTION
        For each group, builds a map of bound policies with their
        consolidated protocols and list of bound intranet apps.
        Also identifies unbound policies.
    .OUTPUTS
        Hashtable of group bindings and array of unbound policy names.
    #>
    param(
        [hashtable]$AAAGroups,
        [hashtable]$AuthPolicies,
        [hashtable]$IntranetApps,
        [array]$Bindings
    )
}

function Convert-PolicyToSegments {
    <#
    .SYNOPSIS
        Converts a parsed authorization policy + consolidated protocols
        into one or more output segment objects.
    .DESCRIPTION
        Expands multi-destination policies, assigns ports, handles
        protocol consolidation from bindings.
    .OUTPUTS
        Array of PSCustomObject segments.
    #>
    param(
        [hashtable]$Policy,
        [array]$ConsolidatedProtocols,
        [string]$EnterpriseAppName,
        [string]$GroupName,
        [ref]$SegmentCounter
    )
}

function Convert-IntranetAppToSegments {
    <#
    .SYNOPSIS
        Converts a parsed VPN intranet application into one or more
        output segment objects.
    .DESCRIPTION
        Expands multi-destination apps, maps protocol ANY → TCP,UDP.
    .OUTPUTS
        Array of PSCustomObject segments.
    #>
    param(
        [hashtable]$IntranetApp,
        [string]$EnterpriseAppName,
        [string]$GroupName,
        [ref]$SegmentCounter
    )
}
```

### 11.3 Testing Recommendations
1. **Unit tests** for rule expression parsing:
   - Simple `IP + port`
   - Subnet only (no port)
   - Multi-destination with OR
   - Mixed TCP/UDP ports in expression
   - Nested parentheses
2. **Unit tests** for protocol consolidation:
   - TCP-only binding
   - UDP-only binding
   - Both TCP + UDP bindings
   - ICMP binding (should be skipped)
3. **Integration tests** with sample NetScaler configs:
   - Authorization-policy-only config
   - Intranet-app-only config
   - Mixed config
4. **Conflict detection tests**:
   - Overlapping CIDR ranges across groups
   - Same FQDN in different groups
   - Wildcard vs specific FQDN
5. **Edge cases**:
   - Empty config file
   - Config with only comments
   - Policies with DENY action
   - Unbound policies
   - Groups with no bindings
   - Duplicate object definitions
   - Intranet apps with ICMP protocol

---

## 12. Change Log

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-25 | Andres Canello | Initial specification |

---

## 13. References

- Convert-ZPA2EPA specification and implementation
- Convert-NPA2EPA specification (20251030-Convert-NPA2EPA.md)
- Start-EntraPrivateAccessProvisioning (provisioning script consuming the output CSV)
- Citrix NetScaler Gateway documentation (command syntax reference)
- Microsoft Entra Private Access documentation

---

**End of Specification**
