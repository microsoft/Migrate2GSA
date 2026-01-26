---
sidebar_position: 2
---

# Migration Workflow

This page explains the core concepts and workflow of the Migrate2GSA PowerShell module for migrating security configurations to Microsoft Global Secure Access (GSA).

## Overview

The Migrate2GSA tool follows a structured **4-phase migration workflow** that ensures data integrity, administrative control, and seamless provisioning to Microsoft Global Secure Access.

## Migration Flow

<div style={{display: 'flex', justifyContent: 'center', alignItems: 'center', margin: '2rem 0', flexWrap: 'wrap', gap: '1rem'}}>
  
  <div style={{textAlign: 'center', minWidth: '180px'}}>
    <div style={{backgroundColor: 'rgba(25, 118, 210, 0.15)', border: '2px solid #1976d2', borderRadius: '12px', padding: '1rem', marginBottom: '0.5rem'}}>
      <div style={{fontSize: '2rem', marginBottom: '0.5rem'}}>🔍</div>
      <div style={{fontWeight: 'bold', fontSize: '1.1rem', color: '#42a5f5'}}>EXPORT</div>
      <div style={{fontSize: '0.9rem', marginTop: '0.5rem', color: 'var(--ifm-font-color-base)'}}>Extract from Source Platform</div>
    </div>
    <div style={{fontSize: '0.8rem', color: 'var(--ifm-color-emphasis-700)', lineHeight: '1.4'}}>
      Security Policies<br/>
      URL Categories<br/>
      Access Rules<br/>
      User Groups
    </div>
  </div>

  <div style={{fontSize: '2.5rem', fontWeight: 'bold', color: '#1976d2', padding: '0 0.5rem'}}>→</div>

  <div style={{textAlign: 'center', minWidth: '180px'}}>
    <div style={{backgroundColor: 'rgba(123, 31, 162, 0.15)', border: '2px solid #7b1fa2', borderRadius: '12px', padding: '1rem', marginBottom: '0.5rem'}}>
      <div style={{fontSize: '2rem', marginBottom: '0.5rem'}}>🔄</div>
      <div style={{fontWeight: 'bold', fontSize: '1.1rem', color: '#ba68c8'}}>CONVERT</div>
      <div style={{fontSize: '0.9rem', marginTop: '0.5rem', color: 'var(--ifm-font-color-base)'}}>Transform to GSA Format</div>
    </div>
    <div style={{fontSize: '0.8rem', color: 'var(--ifm-color-emphasis-700)', lineHeight: '1.4'}}>
      Policy Translation<br/>
      Category Mapping<br/>
      Rule Optimization<br/>
      Identity Resolution
    </div>
  </div>

  <div style={{fontSize: '2.5rem', fontWeight: 'bold', color: '#ba68c8', padding: '0 0.5rem'}}>→</div>

  <div style={{textAlign: 'center', minWidth: '180px'}}>
    <div style={{backgroundColor: 'var(--ifm-color-warning-contrast-background)', border: '2px solid #f57c00', borderRadius: '12px', padding: '1rem', marginBottom: '0.5rem'}}>
      <div style={{fontSize: '2rem', marginBottom: '0.5rem'}}>📝</div>
      <div style={{fontWeight: 'bold', fontSize: '1.1rem', color: '#f57c00'}}>CSV REVIEW</div>
      <div style={{fontSize: '0.9rem', marginTop: '0.5rem', color: 'var(--ifm-font-color-base)'}}>Administrative Control Point</div>
    </div>
    <div style={{fontSize: '0.8rem', color: 'var(--ifm-color-emphasis-700)', lineHeight: '1.4'}}>
      Review & Edit<br/>
      Selective Migration<br/>
      Custom Modifications<br/>
    </div>
  </div>

  <div style={{fontSize: '2.5rem', fontWeight: 'bold', color: '#ff9800', padding: '0 0.5rem'}}>→</div>

  <div style={{textAlign: 'center', minWidth: '180px'}}>
    <div style={{backgroundColor: 'var(--ifm-color-success-contrast-background)', border: '2px solid #388e3c', borderRadius: '12px', padding: '1rem', marginBottom: '0.5rem'}}>
      <div style={{fontSize: '2rem', marginBottom: '0.5rem'}}>⚡</div>
      <div style={{fontWeight: 'bold', fontSize: '1.1rem', color: '#388e3c'}}>PROVISIONING</div>
      <div style={{fontSize: '0.9rem', marginTop: '0.5rem', color: 'var(--ifm-font-color-base)'}}>Deploy to Microsoft GSA</div>
    </div>
    <div style={{fontSize: '0.8rem', color: 'var(--ifm-color-emphasis-700)', lineHeight: '1.4'}}>
      Microsoft Graph API<br/>
      EIA/EPA Provisioning<br/>
      Validation<br/>
      Rollback Support
    </div>
  </div>

</div>

## Migration Phases

### 1. 🔍 Export Phase
**Extract configurations from source platforms**

The tool connects to your existing security platform and exports current configurations:

- **Security policies** and rules
- **URL filtering** configurations and categories
- **Application access** policies and segments
- **User and group** assignments

**Key Features:**
- Secure API connections using authenticated sessions
- Comprehensive data extraction including policies, rules, and user mappings
- Exported data is structured and validated for the next phase

### 2. 🔄 Convert Phase  
**Transform data into GSA-compatible format**

Raw exported data is processed and converted into Microsoft Global Secure Access format:

- **Policy Translation** → Maps source platform policies to GSA equivalents
- **Category Mapping** → Translates custom categories using predefined mappings
- **User/Group Resolution** → Resolves identities to Azure AD/Entra ID objects
- **Rule Optimization** → Consolidates and optimizes rules for GSA deployment

**Output:** Structured data ready for administrative review and provisioning.

### 3. 📝 CSV Review & Customization
**Administrative control point for migration decisions**

The conversion process generates **timestamped, editable CSV files** that administrators can review and modify:

#### Entra Internet Access (EIA) Migration Files

```
📁 Migration Output/
├── 📄 20250105_143022_EIA_Policies.csv          # Web filtering & TLS inspection policies
├── 📄 20250105_143022_EIA_SecurityProfiles.csv  # Security profile assignments
└── 📄 20250105_143022_Convert-ZIA2EIA.log       # Conversion log file
```

#### Entra Private Access (EPA) Migration Files

```
📁 Migration Output/
├── 📄 20250105_143022_GSA_EnterpriseApps_All.csv  # Application segments with access policies
└── 📄 20250105_143022_Convert-ZPA2EPA.log         # Conversion log file
```

:::note
File names include a timestamp prefix (yyyyMMdd_HHmmss) to prevent overwrites and maintain version history. The EIA_Policies.csv file contains both web content filtering rules and TLS inspection policies. The specific files generated depend on the migration type (ZIA→EIA, ZPA→EPA, NPA→EPA, NSWG→EIA).
:::

**Administrative Benefits:**
- **Review Before Deploy** → Validate all configurations before provisioning
- **Selective Migration** → Choose which policies to migrate or exclude
- **Custom Modifications** → Adjust policy names, descriptions, or parameters
- **Audit Trail** → Document migration decisions and modifications

### 4. ⚡ Provisioning Phase
**Deploy configurations to Microsoft Global Secure Access**

The final phase reads the CSV files and provisions configurations to GSA:

- **Microsoft Graph API** → Authenticates and connects to your tenant
- **Entra Internet Access (EIA)** → Provisions web security policies
- **Entra Private Access (EPA)** → Configures application access rules
- **Validation & Rollback** → Verifies successful deployment with error handling

---
