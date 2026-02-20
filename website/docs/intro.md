---
sidebar_position: 1
---

# Introduction


## What is Migrate2GSA?
Migrate2GSA is PowerShell-based migration toolkit designed to help organizations transition from SSE solutions to Global Secure Access (GSA). This toolkit provides automated configuration export, transformation, and a set of common GSA provisioning tools to streamline the transition process.

## Does Migrate2GSA only help on migrations from other SSE solutions?
No! Migrate2GSA can simplify your deployments as well. Simply create a csv file with your configuration and use the Entra Private Access and Entra Internet Access provisioning tools to create the config for you.

Additionally, Migrate2GSA can **export existing Global Secure Access configurations** for backup, disaster recovery, tenant-to-tenant migrations, or configuration replication across environments. Think of it as "migrating from GSA to GSA" - perfect for backup/restore scenarios and promoting configurations between dev, test, and production tenants.

## Is this an official Microsoft product?
No. It is a community project that is maintained by Microsoft employees. The PowerShell toolkit is provided as-is and is not supported through any Microsoft support program or service. Please do not contact Microsoft support with any issues or concern.

## How we build these tools
Since we don't have access to third-party products, we rely on customers who generously share their configuration samples and export files. These real-world examples are essential for understanding how different platforms structure their policies and settings.

We also heavily leverage AI throughout our development process - from researching platform capabilities and writing detailed specifications, to generating and reviewing code. This AI-assisted approach allows us to build comprehensive migration tools efficiently, even without direct platform access.

## How to contact us
If you have a migration project and need assistance with Migrate2GSA, or you can work with us to build tools for other SSE solutions, contact us at migrate2gsateam@microsoft.com

## How to contribute
Please create a GitHub Issue to discuss the changes you are planning to make, then send us a PR.


