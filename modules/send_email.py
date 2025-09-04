from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import smtplib
import os
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Configuration
EMAIL_HOST = os.getenv('EMAIL_HOST')
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True') == 'True'
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_CC = os.getenv('EMAIL_CC')
EMAIL_DOMAIN = os.getenv('EMAIL_DOMAIN')

# Validate Required Variables
required_env_vars = {
    'EMAIL_HOST': EMAIL_HOST,
    'EMAIL_HOST_USER': EMAIL_HOST_USER,
    'EMAIL_HOST_PASSWORD': EMAIL_HOST_PASSWORD,
    'EMAIL_DOMAIN': EMAIL_DOMAIN,
}

missing_vars = [key for key, value in required_env_vars.items() if value is None]

if missing_vars:
    raise EnvironmentError(f"Missing environment variables: {', '.join(missing_vars)}")


# Send Email with Attachments to Multiple Recipients and CC
def send_email(receiver_emails, title, body_email, attachments=None, cc_emails=None, is_html=False):
    """
    Send an email with optional file attachments to multiple recipients and CC, with support for HTML format.

    Args:
        receiver_emails (list): List of recipient email addresses.
        title (str): Email subject.
        body_email (str): Email body (plain text or HTML content).
        attachments (list): List of file paths to attach.
        cc_emails (list): List of CC email addresses.
        is_html (bool): If True, send the body_email as HTML content. Defaults to False (plain text).
    """
    try:
        if not isinstance(receiver_emails, list):
            raise ValueError("❌ 'receiver_emails' must be a list of email addresses.")
        if cc_emails and not isinstance(cc_emails, list):
            raise ValueError("❌ 'cc_emails' must be a list of email addresses if provided.")
        
        msg = MIMEMultipart("mixed")
        msg['From'] = f"{EMAIL_HOST_USER}{EMAIL_DOMAIN}"
        msg['To'] = ', '.join(receiver_emails)
        msg['Subject'] = title
        if cc_emails:
            msg['CC'] = ', '.join(cc_emails)

        # Email Body (Plain Text or HTML)
        if is_html:
            msg.attach(MIMEText(body_email, 'html'))
        else:
            msg.attach(MIMEText(body_email, 'plain'))

        # Attachments
        if attachments:
            for file_path in attachments:
                if os.path.exists(file_path):
                    with open(file_path, "rb") as attachment:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(attachment.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename={os.path.basename(file_path)}'
                        )
                        msg.attach(part)
                else:
                    print(f"❌ Attachment not found: {file_path}")
                    raise FileNotFoundError(f"Attachment not found: {file_path}")

        # Send the email
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as smtp:
            smtp.ehlo()
            if EMAIL_USE_TLS:
                smtp.starttls()
                smtp.ehlo()

            smtp.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
            smtp.send_message(msg)

        print(f"✅ Email sent successfully to: {', '.join(receiver_emails)}")

    except smtplib.SMTPException as e:
        print(f"❌ Failed to send email: {e}")
        logging.error(f"❌ Failed to send email: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")
        logging.error(f"❌ Error: {e}")
