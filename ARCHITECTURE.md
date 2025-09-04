# System Architecture

## Overview

The Vulnerability Assessment tool follows a modular architecture focused on separation of concerns: `workflow.py` orchestrates, while specialized modules implement functionality.

## Architecture Principles

1. **Single Responsibility** - Each module has one clear purpose
2. **High-Level Orchestration** - Workflow.py coordinates, doesn't implement
3. **Functional Modules** - Business logic is separated into dedicated modules
4. **Clean Imports** - Clear dependencies between modules

## Module Structure

```
modules/
├── workflow.py              # High-level orchestrator
├── asset_groups.py          # Asset group and software management
├── download_reports.py      # Report downloading functionality
├── gen_solution_report.py   # Solution report generation
├── gen_vuln_report.py       # Vulnerability report generation
├── send_email.py            # Email functionality
├── report_cleaner.py        # Report cleanup utilities
└── force_gen_reports.py     # Report generation triggers
```

## Module Responsibilities

### `workflow.py` - High-Level Orchestrator
- **Purpose**: Coordinate and orchestrate different modules
- **Responsibilities**:
  - Import functions from specialized modules
  - Execute workflow sequences
  - Handle scheduling and automation
  - Manage error handling and logging
  - Coordinate between different business processes

- **What it does NOT do**:
  - Implement detailed business logic
  - Handle API calls directly
  - Process data in detail
  - Manage file operations

### `asset_groups.py` - Asset and Software Inventory Module
- **Purpose**: Handle all asset group and software operations
- **Responsibilities**:
  - Connect to InsightVM API
  - Fetch asset groups and assets (by group and by site)
  - Retrieve installed software for assets
  - Normalize results and aggregate per software item
  - Export inventories to CSV (per group or per site)

### Other Specialized Modules
Each module handles its specific domain:
- **`download_reports.py`** - Report downloading from InsightVM
- **`gen_solution_report.py`** - Solution report generation
- **`gen_vuln_report.py`** - Vulnerability report generation
- **`send_email.py`** - Email sending functionality
- **`report_cleaner.py`** - File cleanup operations
- **`force_gen_reports.py`** - Report generation triggers

## Data Flow

```
User Command → main.py → workflow.py → Specialized Module → API/File System
                ↓
        Command Line Interface
                ↓
        High-Level Orchestration
                ↓
        Specialized Functionality
                ↓
        External Systems (InsightVM, Email, Files)
```

## Benefits of This Architecture

### 1. **Maintainability**
- Easy to locate specific functionality
- Changes in one module don't affect others
- Clear separation of concerns

### 2. **Testability**
- Individual modules can be tested in isolation
- Mock dependencies easily
- Unit tests are more focused

### 3. **Reusability**
- Functions can be imported by other modules
- Common functionality is centralized
- No code duplication

### 4. **Scalability**
- New features can be added as new modules
- Existing modules can be enhanced independently
- Easy to add new integrations

### 5. **Debugging**
- Issues are isolated to specific modules
- Clear call stack and dependencies
- Easier to trace problems

## Import Pattern

```python
# workflow.py - High-level imports
from modules.asset_groups import show_asset_groups, get_installed_software, get_installed_software_for_site
from modules.download_reports import download_reports
from modules.gen_solution_report import gen_solution_report

# Specialized modules - Direct imports
import requests
import csv
from datetime import datetime
```

## Adding New Functionality

When adding new features:

1. **Create a new module** in the `modules/` directory
2. **Implement the business logic** in the new module
3. **Import the functions** into `workflow.py`
4. **Add command line arguments** in `main.py`
5. **Update documentation** and requirements

### Example: Adding a new "network scan" feature

```python
# modules/network_scanner.py
def scan_network(network_range):
    """Scan a network range for vulnerabilities."""
    # Implementation here
    pass

# workflow.py
from modules.network_scanner import scan_network

# main.py
parser.add_argument('--scan-network', nargs=1, help='Scan network range')
```

## Best Practices

1. **Keep workflow.py thin** - It should orchestrate, not implement
2. **One module, one responsibility** - Each module has a clear purpose
3. **Clean interfaces** - Modules expose clear, simple functions
4. **Error handling** - Each module handles its own errors appropriately
5. **Logging** - Consistent logging across all modules
6. **Documentation** - Each module should be well-documented

## Migration Notes

The refactoring maintains **100% backward compatibility**:
- All existing command line arguments work the same
- All existing functionality is preserved
- Only the internal structure has changed
- Performance and behavior are identical

## Future Enhancements

This architecture makes it easy to add:
- **New asset management features** (e.g., asset tagging, grouping)
- **Additional report types** (e.g., compliance reports, risk assessments)
- **Integration modules** (e.g., SIEM integration, ticketing systems)
- **Automation features** (e.g., scheduled scans, auto-remediation)
- **API endpoints** (e.g., REST API for external tools)
