import logging
import os
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# Disable SSL warnings (not recommended for production)
import urllib3
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

# Create a logger for force_gen_reports module
logger = logging.getLogger('force_gen_reports')
logger.setLevel(logging.DEBUG)

# Create file handler if it doesn't exist
if not logger.handlers:
    file_handler = logging.FileHandler(os.path.join(LOG_DIR, 'generate_reports.log'))
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

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
        logger.error(f"Request failed: {e}")
        raise


# ----------------------------
# Core Functions
# ----------------------------
def fetch_report_ids(limit=10):
    """Fetch and display report IDs with pagination."""
    # Validate environment variables first
    validate_env()
    
    logger.info("Fetching report IDs from InsightVM.")
    reports = []
    page = 0
    page_size = 100  # Max results per page

    try:
        while True:
            url = f"{INSIGHTVM_HOST}/api/3/reports?page={page}&size={page_size}"
            response = debug_request("GET", url, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
            page_reports = response.json().get('resources', [])
            
            if not page_reports:
                break

            reports.extend(page_reports)
            page += 1

            # Break early if not fetching all
            if limit != 'all' and len(reports) >= int(limit):
                break

        if not reports:
            logging.warning("No reports found.")
            return []

        if limit != 'all':
            reports = reports[:int(limit)]

        logger.info(f"Fetched {len(reports)} reports.")
        return reports

    except Exception as e:
        logger.error(f"Failed to fetch report IDs: {e}")
        raise


def trigger_report_generation(report_id):
    """Trigger report generation."""
    if not isinstance(report_id, int):
        logging.warning(f"Invalid Report ID (must be an integer): {report_id}. Skipping.")
        print(f"Invalid Report ID (must be an integer): {report_id}. Skipping.")
        return
    print(f"Triggering report generation for Report ID: {report_id}")
    logger.info(f"Triggering report generation for Report ID: {report_id}")
    url = f"{INSIGHTVM_HOST}/api/3/reports/{report_id}/generate"
    try:
        debug_request("POST", url, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
        logger.info(f"Report generation triggered for Report ID: {report_id}")
        print(f"Report generation triggered for Report ID: {report_id}")
    except Exception as e:
        logger.error(f"Failed to trigger report generation for Report ID: {report_id}: {e}")
        print(f"Failed to trigger report generation for Report ID: {report_id}: {e}")


def trigger_multiple_reports(report_ids):
    """Trigger multiple report generations."""
    for report_id in report_ids:
        if isinstance(report_id, int):
            try:
                trigger_report_generation(report_id)
            except Exception as e:
                logging.warning(f"Skipping Report ID {report_id} due to error: {e}")
        else:
            logging.warning(f"Invalid Report ID (must be an integer): {report_id}. Skipping.")


def show_reports(limit=10):
    """Fetch and display available reports."""
    try:
        reports = fetch_report_ids(limit)
        if reports:
            print("\nAvailable Reports:")
            for i, report in enumerate(reports, start=1):
                print(f"{i}. {report.get('name', 'Unnamed Report')} (ID: {report.get('id')})")
    except Exception as e:
        logger.error(f"Failed to show reports: {e}")
        print(f"Failed to show reports: {e}")


# ----------------------------
# Example Usages for `main.py`
# ----------------------------
def force_show_reports(limit=10):
    """Wrapper function to show reports."""
    show_reports(limit)


def force_gen_trigger_reports(report_ids):
    """Wrapper function to trigger multiple reports."""
    trigger_multiple_reports(report_ids)
