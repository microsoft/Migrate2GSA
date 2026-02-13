---
sidebar_position: 1
---

# Entra Private Access - Greenfield Deployment

:::info Coming Soon
Greenfield deployment documentation for **Entra Private Access** (EPA) is currently under development. 

In the meantime, you can use the toolkit's provisioning capabilities to deploy EPA configurations from CSV files.
:::

## What is Entra Private Access?

Entra Private Access provides Zero Trust Network Access (ZTNA) to private applications without requiring a traditional VPN. It enables secure access to:

- **Internal web applications** (on-premises or IaaS)
- **Legacy applications** (client-server, SSH, RDP)
- **Application segments** grouped by connector groups

## Using the Toolkit Today

While the greenfield deployment guide is in development, you can still deploy EPA configurations using the provisioning functions:

### Available Provisioning Capabilities

The toolkit currently supports provisioning:
- ✅ **Enterprise Applications** - Create EPA application registrations
- ✅ **Application Segments** - Define network segments and FQDN/IP ranges
- ✅ **Access Policies** - Configure user/group access with Conditional Access
- ✅ **Connector Group Assignments** - Link applications to connector groups

### Get Started

Head to the **[Entra Private Access Provisioning Guide](../../Provision/EntraPrivateAccessProvisioning.md)** to learn:
- How to structure your EPA configuration CSVs
- Required CSV columns and formats
- Step-by-step provisioning workflow
- Examples and best practices

---

## What's Coming in the Greenfield Guide?

The upcoming EPA greenfield deployment documentation will include:

### 📝 Conceptual Guide
- EPA architecture overview (Enterprise Apps → Application Segments → Connector Groups)
- Access policy structure and Conditional Access integration
- Security best practices for ZTNA deployments
- Planning worksheet for application inventory

### 📄 Ready-to-Use Templates
- **Template 1**: Basic internal web application
- **Template 2**: Multi-segment application (web + database)
- **Template 3**: Legacy client-server application
- **Template 4**: Remote desktop access (RDP)
- **Template 5**: SSH/administrative access

### 🧪 Testing & Validation
- Connector health checks
- Application segment connectivity testing
- User access verification
- Troubleshooting common EPA issues

---

## Current Status

**Development Timeline:**
- ✅ EPA Provisioning functions (Available now)
- 🔄 EPA Conceptual guide (In progress)
- 🔜 EPA Template library (Planned Q2 2026)
- 🔜 EPA Testing guide (Planned Q2 2026)

**Want to contribute?** If you have EPA deployment patterns you'd like to share, reach out to the community!

---

## Resources

**Current Documentation:**
- [Entra Private Access Provisioning](../../Provision/EntraPrivateAccessProvisioning.md) - Deploy EPA configurations
- [Microsoft Learn - Private Access Overview](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-private-access)
- [Microsoft Learn - Configure Quick Access](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-quick-access)
