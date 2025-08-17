#!/usr/bin/env python3
"""
Gmail Authentication Script for JKU Email Bot

This script handles the OAuth2 flow for Gmail API authentication.
Run this script manually when you need to authenticate or re-authenticate.
"""

import os
import sys
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Scopes required for the application
SCOPES = [
    "https://www.googleapis.com/auth/gmail.insert",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.labels",
]
TOKEN_FILE = "token.json"
CREDENTIALS_FILE = "credentials.json"


def authenticate_gmail():
    """
    Performs the OAuth2 flow to authenticate with Gmail API.

    Returns:
        bool: True if authentication was successful, False otherwise
    """
    creds = None

    print("🔐 Starting Gmail API authentication...")

    # Load existing credentials if available
    if os.path.exists(TOKEN_FILE):
        print("📄 Found existing token.json file")
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

        if creds and creds.valid:
            print("✅ Existing credentials are valid!")
            return True
        elif creds and creds.expired and creds.refresh_token:
            print("🔄 Attempting to refresh expired token...")
            try:
                creds.refresh(Request())
                print("✅ Token refreshed successfully!")

                # Save refreshed credentials
                with open(TOKEN_FILE, "w") as token:
                    token.write(creds.to_json())

                return True
            except Exception as e:
                print(f"❌ Failed to refresh token: {e}")
                print("🔄 Will proceed with full authentication flow...")

    # Check if credentials.json exists
    if not os.path.exists(CREDENTIALS_FILE):
        print("❌ credentials.json file not found!")
        print(
            "📋 Please download the OAuth2 credentials file from Google Cloud Console"
        )
        print("   and save it as 'credentials.json' in the current directory.")
        return False

    # Perform the OAuth2 flow
    try:
        print("🌐 Starting OAuth2 flow...")
        print("📱 Your browser will open for authentication")
        print("🔐 Please sign in and authorize the application")

        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        creds = flow.run_local_server(port=0)

        # Save the credentials
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

        print("✅ Authentication successful!")
        print("💾 Credentials saved to token.json")

        return True

    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        return False


def test_authentication():
    """
    Test the authentication by making a simple API call.

    Returns:
        bool: True if test was successful, False otherwise
    """
    try:
        print("🧪 Testing authentication...")

        if not os.path.exists(TOKEN_FILE):
            print("❌ No token.json file found. Please run authentication first.")
            return False

        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

        if not creds or not creds.valid:
            print("❌ Credentials are not valid. Please re-authenticate.")
            return False

        # Build the Gmail service
        service = build("gmail", "v1", credentials=creds)

        # Test with a simple profile call
        profile = service.users().getProfile(userId="me").execute()
        email_address = profile.get("emailAddress", "Unknown")

        print(f"✅ Authentication test successful!")
        print(f"📧 Authenticated as: {email_address}")
        print(f"📊 Messages in account: {profile.get('messagesTotal', 'Unknown')}")

        return True

    except Exception as e:
        print(f"❌ Authentication test failed: {e}")
        return False


def get_gmail_service():
    """
    Authenticates with Google and returns a Gmail API service object.
    This function is for compatibility with existing code.

    Returns:
        Gmail API service object or None if authentication fails
    """
    try:
        if not os.path.exists(TOKEN_FILE):
            return None

        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
                # Save refreshed credentials
                with open(TOKEN_FILE, "w") as token:
                    token.write(creds.to_json())
            else:
                return None

        return build("gmail", "v1", credentials=creds)

    except Exception:
        return None


def main():
    """Main function to handle command line usage."""
    print("=" * 60)
    print("🔐 JKU Email Bot - Gmail Authentication")
    print("=" * 60)

    if len(sys.argv) > 1 and sys.argv[1] == "test":
        # Test existing authentication
        success = test_authentication()
    else:
        # Perform authentication
        success = authenticate_gmail()

        if success:
            # Test the authentication
            print("\n" + "-" * 40)
            success = test_authentication()

    print("\n" + "=" * 60)
    if success:
        print("🎉 Authentication setup complete!")
        print("✅ Your JKU Email Bot is ready to use.")
    else:
        print("❌ Authentication setup failed!")
        print("🔧 Please check your credentials and try again.")
        sys.exit(1)


if __name__ == "__main__":
    main()
