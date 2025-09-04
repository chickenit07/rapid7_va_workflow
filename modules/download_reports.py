import logging
import os
import requests
from requests.auth import HTTPBasicAuth
import re
from dotenv import load_dotenv
import urllib3

# Disable SSL warnings (not recommended for production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------------
# Configuration & Logging
# ----------------------------
load_dotenv()

INSIGHTVM_HOST = os.getenv('INSIGHTVM_HOST')
USERNAME = os.getenv('USERNAME')
PASSWORD = os.getenv('PASSWORD')
DOWNLOAD_PATH = os.getenv('DOWNLOAD_PATH', './reports')

# Ensure the download directory exists
os.makedirs(DOWNLOAD_PATH, exist_ok=True)
LOG_DIR = './logs'
os.makedirs(LOG_DIR, exist_ok=True)

# Logging Configuration
logging.basicConfig(
    filename=os.path.join(LOG_DIR, 'download_reports.log'),
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


def sanitize_report_name(report_name):
    """Sanitize report name by removing text after the first '-'."""
    return re.split(r'\s*-\s*', report_name)[0].strip()


# ----------------------------
# Core Functions
# ----------------------------
def get_latest_instance_id(report_id):
    """Fetch the latest report instance ID."""
    logging.info(f"Fetching report history for Report ID: {report_id}")
    url = f"{INSIGHTVM_HOST}/api/3/reports/{report_id}/history"
    response = debug_request("GET", url, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
    
    history = response.json().get("resources", [])
    if not history:
        raise Exception(f"No history found for Report ID: {report_id}")
    
    history = sorted(history, key=lambda x: x.get('generated', ''), reverse=True)
    return history[0]["id"]


def get_report_metadata(report_id):
    """Fetch report metadata to get report name and format."""
    logging.info(f"Fetching metadata for Report ID: {report_id}")
    url = f"{INSIGHTVM_HOST}/api/3/reports/{report_id}"
    response = debug_request("GET", url, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
    
    report_data = response.json()
    report_name = report_data.get('name', f"report_{report_id}")
    report_format = report_data.get('format', 'pdf')
    format_mapping = {'csv-export': 'csv', 'xml-export-v2': 'xml'}
    return report_name, format_mapping.get(report_format, report_format)


def download_report(report_id, instance_id, report_name, report_extension):
    """Download the latest report."""
    logging.info(f"Downloading report (Report ID: {report_id}, Instance ID: {instance_id})")
    url = f"{INSIGHTVM_HOST}/api/3/reports/{report_id}/history/{instance_id}/output"
    filename = os.path.join(DOWNLOAD_PATH, f"{sanitize_report_name(report_name)}.{report_extension}")
    
    try:
        with open(filename, "wb") as file:
            response = debug_request("GET", url, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False, stream=True)
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    file.write(chunk)
        logging.info(f"✅ Report downloaded successfully: {filename}")
        return filename
    except Exception as e:
        logging.error(f"❌ Failed to download report {report_id}: {e}")
        raise


def download_multiple_reports(report_ids):
    """Download multiple reports by their IDs."""
    downloaded_files = []
    for report_id in report_ids:
        try:
            logging.info(f"🔄 Processing Report ID: {report_id}")
            instance_id = get_latest_instance_id(report_id)
            report_name, report_extension = get_report_metadata(report_id)
            filename = download_report(report_id, instance_id, report_name, report_extension)
            downloaded_files.append(filename)
        except Exception as e:
            logging.error(f"❌ Error processing Report ID {report_id}: {e}")
    return downloaded_files


# ----------------------------
# Example Usages for `main.py`
# ----------------------------
def download_reports(report_ids):
    """
    Wrapper function to download reports.
    
    Args:
        report_ids (list): List of report IDs to download.
    """
    validate_env()
    return download_multiple_reports(report_ids)
