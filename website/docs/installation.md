---
sidebar_position: 2
---

# Installation and Setup

### Download the Module

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/microsoft/Migrate2GSA.git
   cd Migrate2GSA
   ```

2. **Or download as ZIP:**
   - Download the repository as a ZIP file from GitHub
   - Extract to your desired location

### Prerequisites

This module requires **PowerShell 7 or later**. If you don't have PowerShell 7 installed, please visit the [PowerShell installation guide](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.5) for instructions.

To check your PowerShell version:
```powershell
$PSVersionTable.PSVersion
```

### Required PowerShell Modules

The Migrate2GSA module requires the **Microsoft.Graph.Authentication** module for provisioning operations. This module is used to authenticate to Microsoft Graph and is essential for interacting with Microsoft Entra services.

The module will automatically validate that required dependencies are installed before executing provisioning commands. If the Microsoft.Graph.Authentication module is missing, you'll receive an error message with installation instructions.

To install the required module:
```powershell
Install-Module -Name Microsoft.Graph.Authentication -Force -AllowClobber
```

### Import the Module

Once you have the module files locally, you can import the module using one of these methods:

**Method 1: Import from local path**
```powershell
Import-Module "C:\Path\To\Migrate2GSA\Migrate2GSA\Migrate2GSA.psd1"
```

**Method 2: Install to PowerShell modules directory**
```powershell
# Copy the Migrate2GSA folder to your PowerShell modules directory
$ModulesPath = $env:PSModulePath -split ';' | Select-Object -First 1
Copy-Item -Path "C:\Path\To\Migrate2GSA\Migrate2GSA" -Destination "$ModulesPath\Migrate2GSA" -Recurse -Force

# Import the module
Import-Module Migrate2GSA
```

### Verify Installation

After importing, verify the module is loaded and check available functions:

```powershell
# Check if module is loaded
Get-Module Migrate2GSA

# List available functions
Get-Command -Module Migrate2GSA
```

