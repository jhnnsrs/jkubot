#!/usr/bin/env python3
"""
JKU Email Migration Script

This script migrates ALL emails from the JKU IMAP server to Gmail.
It includes duplicate prevention and adds a migration-date label.
"""

import imaplib
import email
import email.header
import base64
import configparser
import smtplib
import time
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Set, Optional, Tuple

# Import from our separate auth module
from auth import get_gmail_service

# Constants
GMAIL_MAX_SIZE_BYTES = 35 * 1024 * 1024  # 35 MB
BATCH_SIZE = 10  # Process emails in batches
RATE_LIMIT_DELAY = 1  # Seconds between API calls
PROGRESS_SAVE_INTERVAL = 50  # Save progress every N emails


class EmailMigration:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read("config.ini")

        self.source_host = self.config["source_imap"]["host"]
        self.source_user = self.config["source_imap"]["user"]
        self.source_pass = self.config["source_imap"]["password"]
        self.source_mailbox = self.config["source_imap"]["mailbox"]
        self.gmail_user_id = self.config["gmail"]["user_id"]

        self.gmail_service = None
        self.source_imap = None
        self.migration_label_id = None
        self.processed_message_ids: Set[str] = set()
        self.progress_file = "migration_progress.txt"

        # Statistics
        self.total_messages = 0
        self.processed_count = 0
        self.migrated_count = 0
        self.skipped_count = 0
        self.error_count = 0

    def load_progress(self):
        """Load previously processed message IDs from progress file."""
        try:
            with open(self.progress_file, "r") as f:
                for line in f:
                    message_id = line.strip()
                    if message_id:
                        self.processed_message_ids.add(message_id)
            print(
                f"📄 Loaded {len(self.processed_message_ids)} previously processed messages"
            )
        except FileNotFoundError:
            print("📄 No previous progress file found - starting fresh migration")

    def save_progress(self, message_id: str):
        """Save a processed message ID to the progress file."""
        with open(self.progress_file, "a") as f:
            f.write(f"{message_id}\n")
        self.processed_message_ids.add(message_id)

    def decode_header_value(self, header_value):
        """Decode email header values that might be encoded (RFC 2047)."""
        if not header_value:
            return "Unknown"

        decoded_parts = email.header.decode_header(header_value)
        decoded_string = ""

        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                if encoding:
                    decoded_string += part.decode(encoding, errors="replace")
                else:
                    decoded_string += part.decode("utf-8", errors="replace")
            else:
                decoded_string += part

        return decoded_string.strip()

    def send_error_notification(
        self, error_message: str, email_details: Optional[dict] = None
    ):
        """Send error notification email via SMTP."""
        try:
            smtp_host = self.config["catch_error_smtp"]["host"]
            smtp_port = int(self.config["catch_error_smtp"]["port"])
            smtp_user = self.config["catch_error_smtp"]["user"]
            smtp_password = self.config["catch_error_smtp"]["password"]
            error_email = self.config["send_error_to"]["email"].strip('"')

            msg = MIMEMultipart()
            msg["From"] = smtp_user
            msg["To"] = error_email
            msg["Subject"] = "JKU Email Migration - Error Notification"

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            body = f"""
JKU Email Migration encountered an error.

Timestamp: {timestamp}
Error: {error_message}

Migration Progress:
- Total messages: {self.total_messages}
- Processed: {self.processed_count}
- Migrated: {self.migrated_count}
- Skipped: {self.skipped_count}
- Errors: {self.error_count}

"""

            if email_details:
                body += f"""Email Details:
Subject: {email_details.get("subject", "Unknown")}
From: {email_details.get("sender", "Unknown")}
Date: {email_details.get("date", "Unknown")}
Message-ID: {email_details.get("message_id", "Unknown")}
Size: {email_details.get("size_mb", "Unknown")} MB

"""

            body += "This is an automated notification from the JKU Email Migration."

            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)

            print(f"📧 Error notification sent to {error_email}")

        except Exception as smtp_error:
            print(f"⚠️  Failed to send error notification: {smtp_error}")

    def ensure_migration_label_exists(self) -> Optional[str]:
        """Ensure the migration-date label exists in Gmail."""
        if not self.gmail_service:
            return None

        try:
            migration_date = datetime.now().strftime("%Y-%m-%d")
            label_name = f"migration-{migration_date}"

            # List all labels to check if migration label exists
            labels_result = (
                self.gmail_service.users()
                .labels()
                .list(userId=self.gmail_user_id)
                .execute()
            )
            labels = labels_result.get("labels", [])

            # Check if migration label already exists
            for label in labels:
                if label["name"] == label_name:
                    print(
                        f"✅ Migration label '{label_name}' already exists (ID: {label['id']})"
                    )
                    return label["id"]

            # Create the migration label if it doesn't exist
            print(f"🏷️  Creating migration label '{label_name}' in Gmail...")
            label_body = {
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            }

            created_label = (
                self.gmail_service.users()
                .labels()
                .create(userId=self.gmail_user_id, body=label_body)
                .execute()
            )

            print(
                f"✅ Created migration label '{label_name}' (ID: {created_label['id']})"
            )
            return created_label["id"]

        except Exception as e:
            print(f"⚠️  Warning: Could not create/verify migration label: {e}")
            return None

    def ensure_jku_label_exists(self) -> Optional[str]:
        """Ensure the 'Jku' label exists in Gmail."""
        if not self.gmail_service:
            return None

        try:
            labels_result = (
                self.gmail_service.users()
                .labels()
                .list(userId=self.gmail_user_id)
                .execute()
            )
            labels = labels_result.get("labels", [])

            for label in labels:
                if label["name"] == "Jku":
                    return label["id"]

            # Create the 'Jku' label if it doesn't exist
            label_body = {
                "name": "Jku",
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            }

            created_label = (
                self.gmail_service.users()
                .labels()
                .create(userId=self.gmail_user_id, body=label_body)
                .execute()
            )

            print(f"✅ Created 'Jku' label (ID: {created_label['id']})")
            return created_label["id"]

        except Exception as e:
            print(f"⚠️  Warning: Could not create/verify 'Jku' label: {e}")
            return None

    def check_email_exists_in_gmail(self, message_id: str) -> bool:
        """Check if an email with the given Message-ID already exists in Gmail."""
        if not message_id or message_id == "No Message ID" or not self.gmail_service:
            return False

        try:
            # Clean up message ID for search
            clean_message_id = message_id.strip("<>")
            search_query = f"rfc822msgid:{clean_message_id}"

            result = (
                self.gmail_service.users()
                .messages()
                .list(userId=self.gmail_user_id, q=search_query, maxResults=1)
                .execute()
            )

            messages = result.get("messages", [])
            return len(messages) > 0

        except Exception as e:
            print(f"⚠️  Warning: Could not check if email exists: {e}")
            return False

    def get_all_message_ids(self) -> List[bytes]:
        """Get all message IDs from the IMAP server."""
        if not self.source_imap:
            return []

        try:
            # Search for all messages (not just unseen)
            status, messages = self.source_imap.search(None, "ALL")
            if status != "OK" or not messages[0]:
                return []

            message_ids = messages[0].split()
            print(f"📊 Found {len(message_ids)} total messages in IMAP mailbox")
            return message_ids

        except Exception as e:
            print(f"❌ Failed to get message list: {e}")
            return []

    def migrate_single_email(self, imap_msg_id: bytes) -> Tuple[bool, bool, str]:
        """
        Migrate a single email from IMAP to Gmail.

        Returns:
            Tuple[bool, bool, str]: (success, migrated, message)
        """
        if not self.source_imap or not self.gmail_service:
            return False, False, "IMAP or Gmail service not available"

        try:
            # Convert bytes to string for the fetch call
            msg_id_str = imap_msg_id.decode()

            # Fetch the email
            status, msg_data = self.source_imap.fetch(msg_id_str, "(RFC822)")
            if status != "OK" or not msg_data or not msg_data[0] or not msg_data[0][1]:
                return False, False, f"Failed to fetch email ID {msg_id_str}"

            raw_email = msg_data[0][1]
            if not isinstance(raw_email, bytes):
                return False, False, "Invalid email data format"

            # Parse email headers
            parsed_email = email.message_from_bytes(raw_email)
            subject = self.decode_header_value(parsed_email.get("Subject"))
            sender = self.decode_header_value(parsed_email.get("From"))
            date = parsed_email.get("Date", "Unknown Date")
            message_id = parsed_email.get("Message-ID", "No Message ID")
            email_size_mb = len(raw_email) / (1024 * 1024)

            # Check if already processed
            if message_id in self.processed_message_ids:
                return True, False, f"Already processed: {subject[:50]}..."

            # Check size limit
            if len(raw_email) > GMAIL_MAX_SIZE_BYTES:
                self.save_progress(message_id)
                return (
                    True,
                    False,
                    f"Skipped large email ({email_size_mb:.2f}MB): {subject[:50]}...",
                )

            # Check for duplicates in Gmail
            if self.check_email_exists_in_gmail(message_id):
                self.save_progress(message_id)
                return True, False, f"Already exists in Gmail: {subject[:50]}..."

            # Prepare labels
            label_ids = ["INBOX"]
            if self.migration_label_id:
                label_ids.append(self.migration_label_id)

            jku_label_id = self.ensure_jku_label_exists()
            if jku_label_id:
                label_ids.append(jku_label_id)

            # Encode for Gmail API
            encoded_message = base64.urlsafe_b64encode(raw_email).decode("utf-8")
            message_body = {
                "raw": encoded_message,
                "labelIds": label_ids,
                "internalDateSource": "dateHeader",
            }

            # Import to Gmail
            imported_message = (
                self.gmail_service.users()
                .messages()
                .import_(userId=self.gmail_user_id, body=message_body)
                .execute()
            )

            # Save progress
            self.save_progress(message_id)

            return (
                True,
                True,
                f"Migrated: {subject[:50]}... (Gmail ID: {imported_message['id']})",
            )

        except Exception as e:
            error_msg = f"Failed to migrate email: {str(e)}"

            # Try to get email details for error notification
            try:
                email_details = {
                    "subject": subject,
                    "sender": sender,
                    "date": date,
                    "message_id": message_id,
                    "size_mb": f"{email_size_mb:.2f}",
                }
            except Exception:
                email_details = None

            self.send_error_notification(error_msg, email_details)
            return False, False, error_msg

    def print_progress(self):
        """Print current migration progress."""
        if self.total_messages > 0:
            progress_percent = (self.processed_count / self.total_messages) * 100
            print(
                f"📊 Progress: {self.processed_count}/{self.total_messages} ({progress_percent:.1f}%) "
                f"| Migrated: {self.migrated_count} | Skipped: {self.skipped_count} | Errors: {self.error_count}"
            )

    def run_migration(self):
        """Run the complete email migration process."""
        try:
            print("🚀 Starting JKU Email Migration...")

            # Load previous progress
            self.load_progress()

            # Connect to Gmail
            print("🔐 Authenticating with Gmail API...")
            self.gmail_service = get_gmail_service()
            if self.gmail_service is None:
                print("❌ Gmail authentication failed. Please run 'uv run auth.py'")
                return False

            print("✅ Gmail API authenticated")

            # Create migration label
            self.migration_label_id = self.ensure_migration_label_exists()

            # Connect to IMAP
            print("📨 Connecting to IMAP server...")
            self.source_imap = imaplib.IMAP4_SSL(self.source_host)
            self.source_imap.login(self.source_user, self.source_pass)
            self.source_imap.select(self.source_mailbox)
            print("✅ IMAP connected")

            # Get all message IDs
            message_ids = self.get_all_message_ids()
            if not message_ids:
                print("❌ No messages found in IMAP mailbox")
                return False

            self.total_messages = len(message_ids)
            print(f"📊 Starting migration of {self.total_messages} messages...")

            # Process messages
            for i, imap_msg_id in enumerate(message_ids, 1):
                try:
                    print(f"\n🔄 Processing message {i}/{self.total_messages}...")

                    success, migrated, message = self.migrate_single_email(imap_msg_id)

                    self.processed_count += 1

                    if success:
                        if migrated:
                            self.migrated_count += 1
                            print(f"✅ {message}")
                        else:
                            self.skipped_count += 1
                            print(f"⏭️  {message}")
                    else:
                        self.error_count += 1
                        print(f"❌ {message}")

                    # Print progress periodically
                    if i % 10 == 0:
                        self.print_progress()

                    # Rate limiting
                    time.sleep(RATE_LIMIT_DELAY)

                except KeyboardInterrupt:
                    print("\n⚡ Migration interrupted by user")
                    self.print_progress()
                    return False

                except Exception as e:
                    self.error_count += 1
                    print(f"❌ Unexpected error processing message {i}: {e}")
                    continue

            # Final report
            print("\n" + "=" * 60)
            print("🎉 Migration completed!")
            print("📊 Final Statistics:")
            print(f"   Total messages: {self.total_messages}")
            print(f"   Processed: {self.processed_count}")
            print(f"   Migrated: {self.migrated_count}")
            print(f"   Skipped: {self.skipped_count}")
            print(f"   Errors: {self.error_count}")
            print("=" * 60)

            return True

        except Exception as e:
            error_msg = f"Migration failed with error: {str(e)}"
            print(f"❌ {error_msg}")
            self.send_error_notification(error_msg)
            return False

        finally:
            if self.source_imap:
                try:
                    self.source_imap.logout()
                    print("📨 IMAP connection closed")
                except Exception:
                    pass


def main():
    """Main function."""
    print("=" * 60)
    print("📧 JKU Email Migration Tool")
    print("=" * 60)

    if len(sys.argv) > 1 and sys.argv[1] == "--dry-run":
        print("🧪 DRY RUN MODE - No emails will be migrated")
        print("This feature is not yet implemented")
        return

    migration = EmailMigration()
    success = migration.run_migration()

    if success:
        print("✅ Migration completed successfully!")
        sys.exit(0)
    else:
        print("❌ Migration failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
