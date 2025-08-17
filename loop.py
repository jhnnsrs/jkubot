import imaplib
import email
import email.header
import base64
import configparser
import smtplib
import time
import signal
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, time as dt_time
from typing import Tuple, Optional

# Import from our separate auth module
from auth import get_gmail_service

# Scopes and constants
SCOPES = [
    "https://www.googleapis.com/auth/gmail.insert",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.labels",
]
GMAIL_MAX_SIZE_BYTES = 35 * 1024 * 1024  # 35 MB

# Loop configuration constants
DEFAULT_INTERVAL = 200  # 3 minutes in seconds
ACTIVE_INTERVAL = 60  # 1 minute when emails were recently found
OFF_HOURS_INTERVAL = 400  # 15 minutes during off hours
RETRY_DELAY = 15  # 30 seconds before retry
MAX_RETRIES = 3  # Maximum retries before sending error notification
ACTIVE_PERIOD_DURATION = 1800  # 30 minutes to stay in active mode after finding emails

# Office hours configuration (24-hour format)
OFFICE_HOURS_START = dt_time(8, 0)  # 8:00 AM
OFFICE_HOURS_END = dt_time(18, 0)  # 6:00 PM
OFFICE_DAYS = [0, 1, 2, 3, 4]  # Monday=0 to Friday=4

# Global state for loop control
should_exit = False


def signal_handler(signum, frame):
    """Handle graceful shutdown on SIGINT (Ctrl+C) or SIGTERM."""
    global should_exit
    print(f"\n📡 Received signal {signum}. Shutting down gracefully...")
    should_exit = True


def is_office_hours() -> bool:
    """Check if current time is during office hours."""
    now = datetime.now()
    current_time = now.time()
    current_weekday = now.weekday()

    # Check if it's a weekday and within office hours
    is_weekday = current_weekday in OFFICE_DAYS
    is_work_time = OFFICE_HOURS_START <= current_time <= OFFICE_HOURS_END

    return is_weekday and is_work_time


def get_current_interval(
    last_email_found: Optional[datetime], base_interval: int
) -> int:
    """Calculate the current polling interval based on recent activity and time of day."""
    now = datetime.now()

    # Check if we're in office hours
    if is_office_hours():
        current_base = DEFAULT_INTERVAL
    else:
        current_base = OFF_HOURS_INTERVAL
        print(f"🌙 Off hours mode - using {OFF_HOURS_INTERVAL}s interval")

    # If an email was found recently, use active interval
    if (
        last_email_found
        and (now - last_email_found).total_seconds() < ACTIVE_PERIOD_DURATION
    ):
        interval = min(ACTIVE_INTERVAL, current_base)
        print(f"⚡ Active mode - using {interval}s interval")
        return interval

    return current_base


def decode_header_value(header_value):
    """Decode email header values that might be encoded (RFC 2047)."""
    if not header_value:
        return "Unknown"

    decoded_parts = email.header.decode_header(header_value)
    decoded_string = ""

    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            if encoding:
                decoded_string += part.decode(encoding)
            else:
                decoded_string += part.decode("utf-8", errors="replace")
        else:
            decoded_string += part

    return decoded_string.strip()


def send_error_notification(config, error_message, email_details=None):
    """Send error notification email via SMTP when Gmail upload fails."""
    try:
        # Get SMTP configuration
        smtp_host = config["catch_error_smtp"]["host"]
        smtp_port = int(config["catch_error_smtp"]["port"])
        smtp_user = config["catch_error_smtp"]["user"]
        smtp_password = config["catch_error_smtp"]["password"]

        # Get error notification recipient
        error_email = config["send_error_to"]["email"].strip('"')

        # Create the error notification message
        msg = MIMEMultipart()
        msg["From"] = "jkubot@jku.bot"
        msg["To"] = error_email
        msg["Subject"] = "JKU Email Bot - Gmail Upload Error"

        # Create email body
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = f"""
JKU Email Bot encountered an error while uploading to Gmail.

Timestamp: {timestamp}
Error: {error_message}

"""

        # Add email details if available
        if email_details:
            body += f"""Email Details:
Subject: {email_details.get("subject", "Unknown")}
From: {email_details.get("sender", "Unknown")}
Date: {email_details.get("date", "Unknown")}
Message-ID: {email_details.get("message_id", "Unknown")}
Size: {email_details.get("size_mb", "Unknown")} MB

"""

        body += """Please check the email bot configuration and try again.

This is an automated notification from the JKU Email Bot.
"""

        msg.attach(MIMEText(body, "plain"))

        # Send the email
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)

        print(f"📧 Error notification sent to {error_email}")

    except Exception as smtp_error:
        print(f"⚠️  Failed to send error notification: {smtp_error}")


def send_auth_failure_notification(config):
    """Send high-priority email notification when authentication fails."""
    try:
        # Get SMTP configuration
        smtp_host = config["catch_error_smtp"]["host"]
        smtp_port = int(config["catch_error_smtp"]["port"])
        smtp_user = config["catch_error_smtp"]["user"]
        smtp_password = config["catch_error_smtp"]["password"]

        # Get error notification recipient
        error_email = config["send_error_to"]["email"].strip('"')

        # Create the high-priority authentication failure message
        msg = MIMEMultipart()
        msg["From"] = "jkubot@jku.bot"
        msg["To"] = error_email
        msg["Subject"] = "🚨 HIGH PRIORITY: JKU Email Bot - Authentication Required"
        msg["X-Priority"] = "1"  # High priority
        msg["X-MSMail-Priority"] = "High"
        msg["Importance"] = "High"

        # Create email body
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = f"""
🚨 HIGH PRIORITY NOTIFICATION 🚨

The JKU Email Bot authentication has failed and requires immediate attention.

Timestamp: {timestamp}
Issue: Gmail API authentication failure

ACTION REQUIRED:
The authentication token has expired or is invalid. You need to re-authenticate the application.

To fix this issue:
1. Log in to the server where the JKU Email Bot is running
2. Navigate to the bot directory: /Users/jhnnsrs/Code/scripts/jkubot
3. Run the authentication script: python auth.py
4. Follow the prompts to re-authenticate with Google
5. Test the authentication: python auth.py test

The email bot will remain non-functional until re-authentication is completed.

This is an automated high-priority notification from the JKU Email Bot.
"""

        msg.attach(MIMEText(body, "plain"))

        # Send the email
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)

        print(
            f"🚨 HIGH PRIORITY authentication failure notification sent to {error_email}"
        )

    except Exception as smtp_error:
        print(f"⚠️  Failed to send authentication failure notification: {smtp_error}")


def check_email_exists_in_gmail(gmail_service, user_id, message_id):
    """Check if an email with the given Message-ID already exists in Gmail."""
    if not message_id or message_id == "No Message ID":
        return False

    try:
        # Search for emails with the specific Message-ID
        # Gmail search uses rfc822msgid: prefix to search by Message-ID
        search_query = f"rfc822msgid:{message_id}"

        result = (
            gmail_service.users()
            .messages()
            .list(userId=user_id, q=search_query, maxResults=1)
            .execute()
        )

        messages = result.get("messages", [])
        if messages:
            print(
                f"📧 Email with Message-ID {message_id} already exists in Gmail (Gmail ID: {messages[0]['id']})"
            )
            return True
        else:
            print(
                f"📧 Email with Message-ID {message_id} not found in Gmail - safe to import"
            )
            return False

    except Exception as e:
        print(f"⚠️  Warning: Could not check if email exists in Gmail: {e}")
        # If we can't check, assume it doesn't exist to avoid blocking the import
        return False


def ensure_jku_label_exists(gmail_service, user_id):
    """Ensure the 'Jku' label exists in Gmail, create it if it doesn't."""
    try:
        # List all labels to check if 'Jku' exists
        labels_result = gmail_service.users().labels().list(userId=user_id).execute()
        labels = labels_result.get("labels", [])

        # Check if 'Jku' label already exists
        for label in labels:
            if label["name"] == "JKU":
                print(f"✅ 'Jku' label already exists (ID: {label['id']})")
                return label["id"]

        # Create the 'Jku' label if it doesn't exist
        print("🏷️  Creating 'Jku' label in Gmail...")
        label_body = {
            "name": "JKU",
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }

        created_label = (
            gmail_service.users()
            .labels()
            .create(userId=user_id, body=label_body)
            .execute()
        )

        print(f"✅ Created 'JKU' label (ID: {created_label['id']})")
        return created_label["id"]

    except Exception as e:
        print(f"⚠️  Warning: Could not create/verify 'JKU' label: {e}")
        print("📧 Email will be imported without the 'JKU' label")
        return None


def import_latest_unread_email() -> Tuple[bool, bool, Optional[str]]:
    """
    Connects to IMAP, imports the latest unread email to Gmail.

    Returns:
        Tuple[bool, bool, Optional[str]]: (success, email_found, error_message)
        - success: True if no errors occurred
        - email_found: True if an email was actually processed
        - error_message: Error description if success=False, None otherwise
    """
    config = configparser.ConfigParser()
    config.read("config.ini")

    # Load configuration
    SOURCE_HOST = config["source_imap"]["host"]
    SOURCE_USER = config["source_imap"]["user"]
    SOURCE_PASS = config["source_imap"]["password"]
    SOURCE_MAILBOX = config["source_imap"]["mailbox"]
    GMAIL_USER_ID = config["gmail"]["user_id"]

    print("Connecting to source IMAP server...")
    source_imap = None  # Initialize to ensure it's defined for the finally block
    try:
        source_imap = imaplib.IMAP4_SSL(SOURCE_HOST)
        source_imap.login(SOURCE_USER, SOURCE_PASS)
        source_imap.select(SOURCE_MAILBOX)
        print("✅ Connected successfully.")
    except Exception as e:
        error_msg = f"Failed to connect to source IMAP server: {str(e)}"
        print(f"❌ {error_msg}")
        send_error_notification(config, error_msg)
        return False, False, error_msg

    try:
        # Get authenticated Gmail service
        gmail_service = get_gmail_service()

        if gmail_service is None:
            error_msg = "Gmail authentication failed - token is invalid or expired"
            print(f"❌ {error_msg}")
            print("🚨 Sending high-priority authentication failure notification...")
            send_auth_failure_notification(config)
            print("🔧 Please run 'python auth.py' to re-authenticate")
            return False, False, error_msg

        print("✅ Gmail API service authenticated.")

        # Ensure the 'Jku' label exists
        jku_label_id = ensure_jku_label_exists(gmail_service, GMAIL_USER_ID)

        # Search for all unread emails
        status, messages = source_imap.search(None, "UNSEEN")
        if status != "OK" or not messages[0]:
            print("No unread emails found.")
            return True, False, None  # Success but no email found

        # Get the latest (last) message ID instead of the first
        message_ids = messages[0].split()
        latest_msg_id = message_ids[-1]  # Get the last (latest) message ID
        print(
            f"Found {len(message_ids)} unread email(s). Processing latest message ID: {latest_msg_id.decode()}"
        )

        # Fetch the full raw email
        status, msg_data = source_imap.fetch(latest_msg_id, "(RFC822)")
        if status != "OK" or not msg_data or not msg_data[0] or not msg_data[0][1]:
            error_msg = f"Failed to fetch email ID {latest_msg_id.decode()}"
            print(f"❌ {error_msg}")
            return False, False, error_msg

        raw_email = msg_data[0][1]

        # Ensure raw_email is bytes
        if isinstance(raw_email, bytes):
            # Parse the email to extract detailed information
            parsed_email = email.message_from_bytes(raw_email)
            subject = decode_header_value(parsed_email.get("Subject"))
            sender = decode_header_value(parsed_email.get("From"))
            date = parsed_email.get("Date", "Unknown Date")
            message_id = parsed_email.get("Message-ID", "No Message ID")
            email_size_mb = len(raw_email) / (1024 * 1024)

            # Check if this email already exists in Gmail using Message-ID as correlation ID
            if check_email_exists_in_gmail(gmail_service, GMAIL_USER_ID, message_id):
                print(
                    "🔄 Email already exists in Gmail. Skipping import to avoid duplicates."
                )
                # Mark as read since we've processed it (even if we didn't import it)
                source_imap.store(latest_msg_id, "+FLAGS", "\\Seen")
                print(f"✅ Marked original message {latest_msg_id.decode()} as read.")
                return True, False, None  # Success but email already exists

            # Additional details
            to = decode_header_value(parsed_email.get("To"))
            cc = (
                decode_header_value(parsed_email.get("Cc"))
                if parsed_email.get("Cc")
                else None
            )

            # Check for attachments
            attachments = []
            for part in parsed_email.walk():
                if part.get_content_disposition() == "attachment":
                    filename = part.get_filename()
                    if filename:
                        attachments.append(decode_header_value(filename))

            # Get a preview of the email body
            body_preview = ""
            if parsed_email.is_multipart():
                for part in parsed_email.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body_content = part.get_payload(decode=True)
                            if isinstance(body_content, bytes):
                                body_preview = body_content.decode(
                                    "utf-8", errors="replace"
                                )[:200]
                            break
                        except Exception:
                            pass
            else:
                try:
                    body_content = parsed_email.get_payload(decode=True)
                    if isinstance(body_content, bytes):
                        body_preview = body_content.decode("utf-8", errors="replace")[
                            :200
                        ]
                except Exception:
                    pass

            # Print detailed email information
            print("📧 Email Details:")
            print(f"   Subject: {subject}")
            print(f"   From: {sender}")
            print(f"   To: {to}")
            if cc:
                print(f"   CC: {cc}")
            print(f"   Date: {date}")
            print(f"   Message-ID: {message_id}")
            print(f"   Size: {email_size_mb:.2f} MB")
            if attachments:
                print(f"   Attachments ({len(attachments)}): {', '.join(attachments)}")
            else:
                print("   Attachments: None")
            if body_preview:
                print(
                    f"   Body Preview: {body_preview.strip()[:150]}{'...' if len(body_preview) > 150 else ''}"
                )
            else:
                print("   Body Preview: [Unable to extract preview]")
        else:
            error_msg = "Unexpected email data format received from IMAP server"
            print(f"❌ {error_msg}")
            return False, False, error_msg

        # Check size before attempting to import
        if len(raw_email) > GMAIL_MAX_SIZE_BYTES:
            print(
                f"❌ Skipping message {latest_msg_id.decode()} as it exceeds the 35MB size limit."
            )
            source_imap.store(
                latest_msg_id, "+FLAGS", "\\Seen"
            )  # Mark as read to avoid retrying
            return True, False, None  # Success but email too large

        # Encode for the API
        encoded_message = base64.urlsafe_b64encode(raw_email).decode("utf-8")

        # Prepare label IDs
        label_ids = ["INBOX", "UNREAD"]
        if jku_label_id:
            label_ids.append(jku_label_id)
        else:
            # Fallback to label name if ID couldn't be obtained
            label_ids.append("JKU")

        message_body = {
            "raw": encoded_message,
            "labelIds": label_ids,
            "internalDateSource": "dateHeader",
        }

        print(f"🏷️  Applying labels: {', '.join(label_ids)}")

        # Call the Gmail API to import
        try:
            imported_message = (
                gmail_service.users()
                .messages()
                .import_(userId=GMAIL_USER_ID, body=message_body)
                .execute()
            )

            print(
                f"✅ Successfully imported message. New Gmail ID: {imported_message['id']}"
            )

            # Mark the original email as read to prevent re-importing on next run
            source_imap.store(latest_msg_id, "+FLAGS", "\\Seen")
            print(f"✅ Marked original message {latest_msg_id.decode()} as read.")

            return True, True, None  # Success and email was processed

        except Exception as gmail_error:
            # Send error notification with email details
            error_details = {
                "subject": subject,
                "sender": sender,
                "date": date,
                "message_id": message_id,
                "size_mb": f"{email_size_mb:.2f}",
            }

            error_msg = f"Failed to import email to Gmail: {str(gmail_error)}"
            send_error_notification(config, error_msg, error_details)

            # Re-raise the exception to be handled by the outer try-catch
            raise gmail_error

    except Exception as e:
        error_msg = f"An error occurred during the import process: {str(e)}"
        print(f"❌ {error_msg}")
        send_error_notification(config, error_msg)
        return False, False, error_msg
    finally:
        if source_imap:
            print("Closing connection to source IMAP server.")
            source_imap.logout()


def run_email_loop():
    """
    Main loop function that continuously monitors and imports emails.
    Implements intelligent retry logic and adaptive intervals.
    """
    print("🚀 Starting JKU Email Bot Loop...")
    print(f"📅 Office hours: {OFFICE_HOURS_START} - {OFFICE_HOURS_END} on weekdays")
    print(
        f"⏱️  Default interval: {DEFAULT_INTERVAL}s, Active: {ACTIVE_INTERVAL}s, Off-hours: {OFF_HOURS_INTERVAL}s"
    )

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    last_email_found: Optional[datetime] = None
    consecutive_errors = 0
    last_error_notification = None

    while not should_exit:
        try:
            print(f"\n🔄 Checking for new emails... (Errors: {consecutive_errors})")

            # Try to import email
            success, email_found, error_msg = import_latest_unread_email()

            if success:
                consecutive_errors = 0  # Reset error count on success

                if email_found:
                    last_email_found = datetime.now()
                    print("✅ Email processed successfully!")
                else:
                    print("ℹ️  No new emails to process.")

                # Calculate next interval
                interval = get_current_interval(last_email_found, DEFAULT_INTERVAL)
                print(f"⏸️  Waiting {interval}s until next check...")

            else:
                # Handle error case
                consecutive_errors += 1
                print(
                    f"❌ Error occurred (attempt {consecutive_errors}/{MAX_RETRIES}): {error_msg}"
                )

                if consecutive_errors < MAX_RETRIES:
                    print(f"🔄 Retrying in {RETRY_DELAY}s...")
                    time.sleep(RETRY_DELAY)
                    continue
                else:
                    # Send error notification only if we haven't sent one recently
                    now = datetime.now()
                    if (
                        not last_error_notification
                        or (now - last_error_notification).total_seconds() > 3600
                    ):  # 1 hour
                        print(
                            f"📧 Sending persistent error notification after {MAX_RETRIES} failures"
                        )
                        # Error notification is already sent in import_latest_unread_email
                        last_error_notification = now

                    # Reset counter and use normal interval to keep trying
                    consecutive_errors = 0
                    interval = get_current_interval(last_email_found, DEFAULT_INTERVAL)
                    print(f"⏸️  Continuing with normal interval: {interval}s")

            # Sleep until next check (unless we should exit)
            sleep_start = time.time()
            while time.time() - sleep_start < interval and not should_exit:
                time.sleep(1)  # Check for exit signal every second

        except KeyboardInterrupt:
            print("\n⚡ Keyboard interrupt received. Shutting down...")
            break

        except Exception as unexpected_error:
            print(f"💥 Unexpected error in main loop: {unexpected_error}")
            consecutive_errors += 1

            if consecutive_errors >= MAX_RETRIES:
                print("💀 Too many consecutive unexpected errors. Exiting.")
                break

            print(f"🔄 Retrying after unexpected error in {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)

    print("\n🛑 Email bot loop stopped.")
    print("👋 Goodbye!")


if __name__ == "__main__":
    # Check command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "once":
        # Run once for testing
        print("🧪 Running email import once for testing...")
        success, email_found, error_msg = import_latest_unread_email()
        if success:
            print("✅ Single run completed successfully!")
            if email_found:
                print("📧 Email was processed.")
            else:
                print("ℹ️  No emails to process.")
        else:
            print(f"❌ Single run failed: {error_msg}")
            sys.exit(1)
    else:
        # Run the continuous loop
        run_email_loop()
