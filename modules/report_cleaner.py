import os
import shutil
from datetime import datetime

# ----------------------------
# Configuration
# ----------------------------
DOWNLOAD_PATH = './reports'
ARCHIVE_BASE_PATH = './archives'


# ----------------------------
# Archive Reports
# ----------------------------
def clean_reports():
    """Move all files in DOWNLOAD_PATH to a monthly archive folder."""
    if not os.path.exists(DOWNLOAD_PATH):
        raise FileNotFoundError(f"❌ {DOWNLOAD_PATH} does not exist.")
    
    # Create Archive Folder
    current_month = datetime.now().strftime("%b - %Y")
    archive_path = os.path.join(ARCHIVE_BASE_PATH, current_month)
    os.makedirs(archive_path, exist_ok=True)
    
    # Move Files
    for file in os.listdir(DOWNLOAD_PATH):
        src = os.path.join(DOWNLOAD_PATH, file)
        dst = os.path.join(archive_path, file)
        shutil.move(src, dst)
        print(f"✅ Moved {file} to {archive_path}")
    
    print(f"\n✅ All reports have been archived to: {archive_path}")
