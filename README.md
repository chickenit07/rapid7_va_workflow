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

- `--auto`: Run scheduled workflows from `workflow_schedule.yaml`
- `--show [N|all]`: Show available report IDs (default N=10)
- `--check <report_id1> <report_id2> <receiver_email>`: Trigger generation, wait, process, email
- `--show-asset-groups`: List all InsightVM asset groups
- `--get-software <ids...>`: Export installed software for one or more asset group IDs (one CSV per group)
- `--get-software all [site_id]`: Export installed software for all assets in a site (default site_id=2) to a single CSV

## Usage Examples
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

## Output
- Workflow outputs under `archives/<Month - YYYY>/...`
- Software CSVs in project root:
  - Per group: `software_asset_group_<GROUP_ID>_<TIMESTAMP>.csv`
  - Per site: `software_asset_group_site_<SITE_ID>_<TIMESTAMP>.csv`

Columns:
- Vendor, Family, Software Name, Version, Asset Count, Asset Details (IPs)

## Notes
- InsightVM API requests use `verify=False` by default; adjust for your environment.
- If assets are returned as integer IDs, the tool fetches full asset details to obtain IPs.

## Troubleshooting
- Verify `.env` settings and InsightVM connectivity
- Increase `WAIT_TIME` for large report generation windows
- Check logs under `./logs`
