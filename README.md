# ZScaler2GSA

> **⚠️ Important Notice**: This is experimental code. Use it at your own risk and thoroughly test in a non-production environment before deploying to production systems.

## Overview

ZScaler2GSA is a PowerShell-based migration toolkit designed to help organizations transition from **Zscaler Private Access (ZPA)** to **Microsoft Entra Private Access (EPA)** within the Global Secure Access (GSA) solution. This toolkit provides automated configuration export, transformation, and migration planning capabilities to streamline the transition process.

## What This Repository Contains

This repository consists of two main PowerShell scripts that work together to facilitate ZPA to EPA migration:

### 1. **Export-ZPAConfig.ps1** - ZPA Configuration Export Tool

A comprehensive backup and export utility that connects to the ZPA management API and exports all critical configuration elements to JSON files.

**Key Capabilities:**

- Exports complete ZPA configuration including application segments, policies, connectors, and security settings
- Creates timestamped backups with both individual and consolidated JSON files  
- Uses secure OAuth2 authentication with encrypted client secrets
- Provides read-only operations with robust error handling and logging

### 2. **Transform-ZPA2EPA.ps1** - Configuration Transformation Engine

An intelligent transformation tool that converts exported ZPA application segments into EPA-compatible Enterprise Application configurations.

**Key Capabilities:**

- Transforms ZPA application segments to EPA Enterprise Application format
- Advanced conflict detection for IP ranges, port ranges, and domain overlaps
- Flexible filtering with wildcard pattern matching and skip options
- Generates Excel-compatible CSV output ready for EPA deployment
- Comprehensive validation and error handling

---

*For detailed usage instructions and advanced configuration options, see the [ZPA2EPA README](ZPA2EPA/README.md).*
