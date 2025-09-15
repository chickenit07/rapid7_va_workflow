import os
import logging
from datetime import datetime
from dotenv import load_dotenv
import yaml
import time

from modules.download_reports import download_reports
from modules.gen_solution_report import gen_solution_report
from modules.gen_vuln_report import gen_vuln_report
from modules.send_email import send_email
from modules.report_cleaner import clean_reports
from modules.force_gen_reports import force_show_reports, force_gen_trigger_reports
from modules.asset_groups import show_asset_groups, get_installed_software, get_installed_software_multiple_groups, get_installed_software_all_groups, get_installed_software_for_site

# Load environment variables
load_dotenv()
DOWNLOAD_PATH = os.getenv('DOWNLOAD_PATH', './reports')
EMAIL_DOMAIN = os.getenv('EMAIL_DOMAIN')
WORKFLOW_OWNER = os.getenv('WORKFLOW_OWNER')
WAIT_TIME = int(os.getenv('WAIT_TIME'))

# Logging Configuration
LOG_DIR = './logs'
os.makedirs(LOG_DIR, exist_ok=True)

# Create a logger for workflow module
logger = logging.getLogger('workflow')
logger.setLevel(logging.DEBUG)

# Create file handler if it doesn't exist
if not logger.handlers:
    file_handler = logging.FileHandler(os.path.join(LOG_DIR, 'workflow.log'))
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


# ----------------------------
# Load Workflow Schedule
# ----------------------------
def load_schedule():
    """Load the workflow schedule from YAML."""
    with open('workflow_schedule.yaml', 'r') as file:
        schedule = yaml.safe_load(file)
    return schedule.get('schedule_groups', {})


# ----------------------------
# Execute Workflow
# ----------------------------
def execute_workflow(report_ids, receiver_emails, cc_emails):
    """
    Execute the workflow for given report_ids, receiver_emails, and cc_emails.
    """
    try:
        # Step 1: Download Reports
        downloaded_files = download_reports(report_ids)

        # Retrieve latest CSV and XML files
        csv_file = next((f for f in downloaded_files if f.endswith('.csv')), None)
        xml_file = next((f for f in downloaded_files if f.endswith('.xml')), None)

        if not csv_file or not xml_file:
            raise FileNotFoundError("Missing required CSV or XML report files.")

        # Step 2: Generate Solution & Vulnerability Reports
        gen_solution_report(csv_file, xml_file)
        gen_vuln_report(csv_file, xml_file)
        
        # Email details
        date_str = datetime.now().strftime("%d/%m/%Y")
        
        # Extract the filename without the DOWNLOAD_PATH
        base_filename = os.path.basename(csv_file)
        filename = os.path.splitext(base_filename)[0]

        # Extract zone and OS from filename
        parts = filename.split(' ')
        zone = parts[0].strip() if len(parts) > 0 else "Unknown Zone"
        os_name = parts[1].strip() if len(parts) > 1 else "Windows and Unix"

        receiver_list = [
            email if "@" in email else email + EMAIL_DOMAIN
            for email in receiver_emails
        ]
        cc_list = [
            email if "@" in email else email + EMAIL_DOMAIN
            for email in cc_emails
        ] if cc_emails else []

        title = f"V/v vá lỗ hổng bảo mật định kỳ cho các máy chủ {filename}"
        
        # HTML email body
        html_body = f"""
        <html>
            <body>
                <p>Dear các anh, </p>
                <p>Em gửi thông tin các lỗ hổng bảo mật đang tồn tại trên các máy chủ dưới đây, tính đến thời điểm ngày <b>{date_str}</b></p>
                <ul>
                    <li>Vùng: <b>{zone}</b></li>
                    <li>OS: <b>{os_name}</b></li>
                    <li>Loại lỗ hổng: <b>NGHIÊM TRỌNG</b></li>
                </ul>
                <p>Nhờ các anh lên kế hoạch patch các lỗ hổng này sớm.</p>
                <p>Thanks & best regards,</p>
                <p style="font-family: Arial, sans-serif; font-size: 14px; line-height: 1.5; color: #000;">
                <hr style="border: 0; border-top: 1px solid #1E5AA8; margin: 8px 0;">
                <span style="font-weight: bold; font-size: 16px; color: #1E5AA8;">Mr. Phạm Quang Đạt</span><br>
                <span>CVCC An ninh thông tin | Trung tâm Vận hành</span><br>
                <span><b>P</b> (+84) 968 552 351 | <b>E</b> <a href="mailto:datpq2@tnteco.vn" style="color: #1E5AA8; text-decoration: none;">datpq2@tnteco.vn</a></span><br>
                <span><b>Địa chỉ:</b> Tầng 21, ROX Tower, 54A Nguyễn Chí Thanh, Đống Đa, Hà Nội</span><br></p>

            </body>
        </html>
        """


        # Step 3: Send Email with attachments
        attachments = [
            os.path.join(DOWNLOAD_PATH, f"{filename}_Solution.xlsx"),
            os.path.join(DOWNLOAD_PATH, f"{filename}_Vuln.xlsx")
        ]
        send_email(
            receiver_list,
            title,
            html_body,
            attachments,
            cc_emails=cc_list,
            is_html=True  # Use HTML format
        )

        # Step 4: Archive Reports
        clean_reports()

        print("✅ Workflow executed successfully!")
        logger.info("✅ Workflow executed successfully!")

    except Exception as e:
        logger.error(f"❌ Workflow failed for reports: {report_ids}. Error: {e}")
        print(f"❌ Workflow failed for reports: {report_ids}. Error: {e}")

        # Send error notification to WORKFLOW_OWNER
        error_title = "❌ Workflow Failed Notification"
        error_body = f"""
The workflow failed while processing the following reports:

- Report IDs: {report_ids}
- Error Message: {str(e)}
- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please review the logs for more details.

=========================
Thanks & best regards,

Automated Workflow System
        """
        send_email(
            [WORKFLOW_OWNER],
            error_title,
            error_body,
            None,
            [WORKFLOW_OWNER]
        )


# ----------------------------
# Auto Execute
# ----------------------------
def auto_execute():
    """Automatically execute workflows based on YAML schedule."""
    try:
        schedule = load_schedule()
        run_count_file = './schedule_process.txt'
        
        if not os.path.exists(run_count_file):
            with open(run_count_file, 'w') as f:
                f.write('1')

        with open(run_count_file, 'r') as f:
            run_count = int(f.read().strip())

        # Collect all workflow entries from all groups
        all_workflows = []
        for group_name, group_tasks in schedule.items():
            for task in group_tasks:
                all_workflows.append({
                    'group': group_name,
                    'task': task
                })

        if not all_workflows:
            print("❌ No workflows found in schedule")
            logger.error("❌ No workflows found in schedule")
            return

        # Get current workflow entry (convert 1-based to 0-based for array access)
        workflow_index = (run_count - 1) % len(all_workflows)
        current_workflow = all_workflows[workflow_index]
        current_group = current_workflow['group']
        current_task = current_workflow['task']

        print(f"🔄 Running workflow {run_count}/{len(all_workflows)} from group: {current_group}")
        logger.info(f"🔄 Running workflow {run_count}/{len(all_workflows)} from group: {current_group}")

        # Execute the current workflow
        report_ids = current_task['pair']
        receiver_emails = current_task['receivers']
        cc_emails = current_task.get('cc', None)
        
        force_gen_trigger_reports(report_ids)
        # Wait for gen report to be finished
        time.sleep(WAIT_TIME)
        execute_workflow(report_ids, receiver_emails, cc_emails)

        # Only update run count if workflow completed successfully
        next_run_count = ((run_count - 1) + 1) % len(all_workflows) + 1
        with open(run_count_file, 'w') as f:
            f.write(str(next_run_count))

        print(f"\n✅ Workflow {run_count}/{len(all_workflows)} completed successfully!")
        logger.info(f"✅ Workflow {run_count}/{len(all_workflows)} completed successfully!")

    except Exception as e:
        logger.error(f"❌ Workflow execution failed: {e}")
        print(f"❌ Workflow execution failed: {e}")
        print(f"⚠️  Counter not incremented - will retry same workflow next time")


# ----------------------------
# Show Workflow Status
# ----------------------------
def show_workflow_status():
    """Show current workflow status and progress."""
    try:
        schedule = load_schedule()
        run_count_file = './schedule_process.txt'
        
        if not os.path.exists(run_count_file):
            print("📊 No workflow runs recorded yet")
            return

        with open(run_count_file, 'r') as f:
            run_count = int(f.read().strip())

        # Collect all workflow entries from all groups
        all_workflows = []
        for group_name, group_tasks in schedule.items():
            for task in group_tasks:
                all_workflows.append({
                    'group': group_name,
                    'task': task,
                    'report_ids': task['pair'],
                    'receivers': task['receivers']
                })

        if not all_workflows:
            print("❌ No workflows found in schedule")
            return

        print(f"\n📊 Workflow Status:")
        print(f"   Total workflows: {len(all_workflows)}")
        print(f"   Current position: {run_count}")
        print(f"   Next workflow: {run_count}/{len(all_workflows)}")
        print(f"   Loop behavior: Resets to 1 after reaching {len(all_workflows)}")
        
        # Show next workflow details (convert 1-based to 0-based for array access)
        workflow_index = (run_count - 1) % len(all_workflows)
        next_workflow = all_workflows[workflow_index]
        print(f"\n🔄 Next workflow to run:")
        print(f"   Group: {next_workflow['group']}")
        print(f"   Report IDs: {next_workflow['report_ids']}")
        print(f"   Receivers: {next_workflow['receivers']}")
        
        # Show all workflows
        print(f"\n📋 All workflows:")
        for i, workflow in enumerate(all_workflows):
            workflow_number = i + 1  # Convert to 1-based numbering
            if workflow_number == run_count:
                status = "🔄"  # Current workflow
            elif workflow_number < run_count:
                status = "✅"  # Completed workflows
            else:
                status = "⏳"  # Pending workflows
            print(f"   {workflow_number:2d}. {status} {workflow['group']} - IDs: {workflow['report_ids']} - Receivers: {workflow['receivers']}")

    except Exception as e:
        print(f"❌ Error showing workflow status: {e}")


# ----------------------------
# Show Reports
# ----------------------------
def show_reports(limit):
    """Show available reports."""
    try:
        force_show_reports(limit)
    except Exception as e:
        logger.error(f"❌ Failed to fetch reports: {e}")
        print(f"❌ Failed to fetch reports: {e}")


# ----------------------------
# Check Reports
# ----------------------------
def check_reports(report_id1, report_id2, receiver_email):
    """Manually execute the workflow with provided report IDs and receiver email."""
    try:
        report_ids = [report_id1, report_id2]
        receiver_emails = [receiver_email]
        cc_emails = None  # No CC for manual execution

        print(f"🔄 Executing workflow for reports: {report_ids} with receiver: {receiver_email}")
        logger.info(f"🔄 Executing workflow for reports: {report_ids} with receiver: {receiver_email}")
        
        # Step 1: Trigger report generation (replaces the old --gen functionality)
        print("🔄 Triggering report generation...")
        force_gen_trigger_reports(report_ids)
        
        # Step 2: Wait for report generation to complete
        print(f"⏳ Waiting {WAIT_TIME} seconds for report generation to complete...")
        time.sleep(WAIT_TIME)
        
        # Step 3: Execute the workflow
        execute_workflow(report_ids, receiver_emails, cc_emails)

        print("\n✅ Manual workflow execution completed successfully!")
        logger.info("✅ Manual workflow execution completed successfully!")

    except Exception as e:
        logger.error(f"❌ Manual workflow execution failed: {e}")
        print(f"❌ Manual workflow execution failed: {e}")
