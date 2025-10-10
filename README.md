# Migrate2GSA

> **⚠️ Important Notice**: This is experimental code. Use it at your own risk and thoroughly test in a non-production environment before deploying to production systems.

## Overview

This is PowerShell-based migration toolkit designed to help organizations transition from SSE solutions to Global Secure Access (GSA). This toolkit provides automated configuration export, transformation, and a set of common GSA provisioning tools to streamline the transition process.

## How to contact us
If you have a migration project and need assistance with the migration tools, or you can work with us to build tools for other third party SSE solutions, contact us at migrate2gsateam@microsoft.com

## Installation and Setup

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

The module provides the following functions:
- `Export-ZPAConfig`
- `Convert-ZPA2EPA`
- `Export-ZIAConfig`
- `Start-EntraPrivateAccessProvisioning`

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.