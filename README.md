# Vulnerability Assessment Automation

Automation toolkit to orchestrate Rapid7 InsightVM report workflows and export installed software inventories by asset group or site.

## Prerequisites
- Python 3.9+
- Rapid7 InsightVM credentials

Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration
Create a `.env` file in the project root:
```
INSIGHTVM_HOST=https://<insightvm-host>
USERNAME=<username>
PASSWORD=<password>
WAIT_TIME=120
EMAIL_DOMAIN=@example.com
WORKFLOW_OWNER=Automation Bot
DOWNLOAD_PATH=./reports
```
- WAIT_TIME: seconds to wait after triggering report generation
- EMAIL_DOMAIN: appended when receiver lacks a domain

## CLI
Entry point:
```bash
python main.py
```

- `--auto`: Run scheduled workflows from `workflow_schedule.yaml` (loops through individual workflows)
- `--workflow-status`: Show current workflow status and progress
- `--show [N|all]`: Show available report IDs (default N=10)
- `--check <report_id1> <report_id2> <receiver_email>`: Trigger generation, wait, process, email
- `--show-asset-groups`: List all InsightVM asset groups
- `--get-software <ids...>`: Export installed software for one or more asset group IDs (one CSV per group)
- `--get-software all [site_id]`: Export installed software for all assets in a site (default site_id=2) to a single CSV

## Usage Examples
Show workflow status and progress:
```bash
python main.py --workflow-status
```
Run automated workflows:
```bash
python main.py --auto
```
Show reports (top 10):
```bash
python main.py --show
```
Show all reports:
```bash
python main.py --show all
```
Manual check (generate + wait + process + email):
```bash
python main.py --check 123 456 security
```
List asset groups:
```bash
python main.py --show-asset-groups
```
Software by one group:
```bash
python main.py --get-software 12
```
Software by multiple groups:
```bash
python main.py --get-software 12 34 56
```
Software for default site (2):
```bash
python main.py --get-software all
```
Software for specific site:
```bash
python main.py --get-software all 5
```

## Workflow Scheduling System

The automated workflow system uses a looping schedule based on `workflow_schedule.yaml`:

### How it works:
- **Individual Workflow Execution**: Runs one workflow at a time (not entire groups)
- **1-based Counting**: Counter starts at 1 and loops through all workflows
- **Automatic Looping**: After reaching the last workflow, loops back to workflow 1
- **Error Handling**: If a workflow fails, the counter doesn't increment (retries same workflow)
- **Progress Tracking**: Use `--workflow-status` to see current progress

### Schedule File:
- **Location**: `workflow_schedule.yaml` (root directory)
- **Counter File**: `schedule_process.txt` (root directory)
- **Structure**: Groups contain workflow pairs with receiver emails

### Example Schedule:
```yaml
schedule_groups:
  first:
    - pair: [38, 39]
      receivers: ["datpq2"]
  second:
    - pair: [42, 43]
      receivers: ["datpq2"]
```

## Output

### Workflow Reports:
- **Email Attachments**: Solution and Vulnerability Excel files
- **Archive Location**: `archives/<Month - YYYY>/...`
- **Email Format**: HTML with professional signature

### Software Inventories:
- **Per group**: `software_asset_group_<GROUP_ID>_<TIMESTAMP>.csv`
- **Per site**: `software_asset_group_site_<SITE_ID>_<TIMESTAMP>.csv`
- **Columns**: Vendor, Family, Software Name, Version, Asset Count, Asset Details (IPs)

### Log Files:
- **Workflow Logs**: `logs/workflow.log` - Workflow execution details
- **Report Generation**: `logs/generate_reports.log` - Report generation activities
- **Download Logs**: `logs/download_reports.log` - Download activities

## Notes
- InsightVM API requests use `verify=False` by default; adjust for your environment.
- If assets are returned as integer IDs, the tool fetches full asset details to obtain IPs.

## Troubleshooting
- **Configuration**: Verify `.env` settings and InsightVM connectivity
- **Performance**: Increase `WAIT_TIME` for large report generation windows
- **Logging**: Check logs under `./logs` directory
- **Workflow Status**: Use `--workflow-status` to check current progress
- **Error Handling**: Failed workflows don't increment counter (will retry)
- **XML Issues**: Corrupted XML files will cause workflow failures (check Rapid7 server)
