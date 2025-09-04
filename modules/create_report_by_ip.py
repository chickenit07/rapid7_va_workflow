import logging
import os
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import urllib3
from datetime import datetime

# Disable SSL warnings (not recommended for production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------------
# Configuration & Logging
# ----------------------------
load_dotenv()

INSIGHTVM_HOST = os.getenv('INSIGHTVM_HOST')
USERNAME = os.getenv('USERNAME')
PASSWORD = os.getenv('PASSWORD')
LOG_DIR = './logs'
os.makedirs(LOG_DIR, exist_ok=True)

# Logging Configuration
logging.basicConfig(
    filename=os.path.join(LOG_DIR, 'create_report_by_ip.log'),
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s]: %(message)s'
)

HEADERS = {
    "Content-Type": "application/json"
}


# ----------------------------
# Utility Functions
# ----------------------------
def validate_env():
    """Ensure required environment variables are set."""
    missing_vars = [var for var in ['INSIGHTVM_HOST', 'USERNAME', 'PASSWORD'] if not os.getenv(var)]
    if missing_vars:
        raise EnvironmentError(f"Missing environment variables: {', '.join(missing_vars)}")


def debug_request(method, url, **kwargs):
    """Debug HTTP requests and responses."""
    try:
        logging.debug(f"Making {method} request to URL: {url}")
        response = requests.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        raise


# ----------------------------
# Core Function: Create a Single Report
# ----------------------------
def create_report(report_payload):
    """Helper function to create a single report."""
    url = f"{INSIGHTVM_HOST}/api/3/reports"
    logging.info(f"🔹 Sending report request: {report_payload['name']}")
    
    try:
        response = debug_request("POST", url, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False, json=report_payload)
        report_id = response.json().get("id")

        if not report_id:
            raise Exception(f"Failed to create report {report_payload['name']}. Response: {response.text}")

        logging.info(f"✅ Report {report_payload['name']} created successfully: {report_id}")
        print(f"✅ Report {report_payload['name']} created successfully: {report_id}")
        return report_id
    except Exception as e:
        logging.error(f"❌ Error creating report {report_payload['name']}: {e}")
        print(f"❌ Error creating report {report_payload['name']}: {e}")
        return None


# ----------------------------
# Core Function: Create Reports for Multiple IP IDs Sequentially
# ----------------------------
def create_reports_for_ips(asset_ids, site_id=2):
    """
    Create XML and CSV reports for multiple asset IDs sequentially.

    Args:
        asset_ids (list): List of asset IDs to scan.
        site_id (int): The site ID (default is 2).
    """
    validate_env()

    # Get current date in ddmmyyyy format
    current_date = datetime.now().strftime("%d%m%Y")

    report_ids = []

    for asset_id in asset_ids:
        print(f"\n🔄 Processing Asset ID: {asset_id}")
        logging.info(f"\n🔄 Processing Asset ID: {asset_id}")

        reports = [
            {
                "format": "xml-export-v2",
                "name": f"XML_Export_Asset_{asset_id}_{current_date}",
                "scope": {
                    "assets": [asset_id]
                },
                "filters": {
                    "severity": "critical",
                    "statuses": ["vulnerable", "vulnerable-version"]
                },
                "scope": {
                    "sites": [site_id]
                }
            },
            {
                "format": "csv-export",
                "name": f"CSV_Export_Asset_{asset_id}_{current_date}",
                "template": "basic-vulnerability-check-results",  # Required for CSV reports
                "scope": {
                    "assets": [asset_id]
                },
                "filters": {
                    "severity": "critical",
                    "statuses": ["vulnerable", "vulnerable-version"]
                },
                "scope": {
                    "sites": [site_id]
                }
            }
        ]

        asset_report_ids = []

        for report_payload in reports:
            report_id = create_report(report_payload)
            if report_id:
                asset_report_ids.append(report_id)
            else:
                logging.error(f"❌ Skipping Asset ID {asset_id} due to failure.")
                print(f"❌ Skipping Asset ID {asset_id} due to failure.")
                break  # Stop processing this asset and move to the next

        if len(asset_report_ids) == 2:
            logging.info(f"✅ Both reports generated successfully for Asset ID {asset_id}.")
            print(f"✅ Both reports generated successfully for Asset ID {asset_id}.")
            report_ids.extend(asset_report_ids)

    return report_ids


# ----------------------------
# Example Usage
# ----------------------------
if __name__ == "__main__":
    test_asset_ids = [1404, 1505]  # Replace with valid asset IDs
    created_report_ids = create_reports_for_ips(test_asset_ids)
    print(f"✅ Final Created Report IDs: {created_report_ids}")
