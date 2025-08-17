# JKU Email Migration and Forwarding System

A comprehensive Python-based email management system that can forward JKU emails to Gmail with duplicate prevention, intelligent scheduling, and bulk migration capabilities.

## Features

- 📧 **Email Forwarding**: Forward the latest unread JKU email to Gmail
- 🔄 **Continuous Monitoring**: Intelligent loop with adaptive intervals and retry logic  
- 📊 **Bulk Migration**: Migrate ALL emails from JKU to Gmail with progress tracking
- 🚫 **Duplicate Prevention**: Message-ID based duplicate detection across all modes
- 🏷️ **Label Management**: Automatic "Jku" and "migration-date" label application
- ⚠️ **Error Notifications**: SMTP-based error alerts with detailed context
- 🔐 **OAuth2 Authentication**: Separated authentication handling for CLI usage
- 🖥️ **Production Ready**: Systemd service integration with graceful shutdown

## Scripts Overview

### Core Scripts
- **`try.py`** - Single-run email processor with enhanced information display
- **`loop.py`** - Continuous monitoring with intelligent scheduling
- **`migrate.py`** - Bulk migration tool for all IMAP messages
- **`auth.py`** - Standalone OAuth2 authentication handler

### Configuration
- **`config.ini`** - IMAP, SMTP, and Gmail configuration
- **`jkubot.service`** - Systemd service file for production deployment

## Quick Start

### 1. Install Dependencies
```bash
uv add google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
```

### 2. Configuration
Copy and configure the settings:
```bash
cp config.ini.example config.ini
# Edit config.ini with your credentials
```

### 3. Gmail OAuth Setup
Set up Gmail API credentials:
```bash
uv run auth.py
```

## Usage

### Single Email Forward
Process and forward the latest unread email once:
```bash
uv run try.py
```

### Continuous Monitoring
Start the intelligent monitoring loop:
```bash
uv run loop.py
```
- Adaptive intervals based on activity and office hours
- Automatic retry logic with exponential backoff
- Graceful shutdown with Ctrl+C

### Bulk Migration
Migrate ALL emails from JKU to Gmail:
```bash
# Run complete migration
uv run migrate.py

# Resume from last checkpoint (automatic)
uv run migrate.py
```

#### Migration Features:
- **Progress Tracking**: Persistent progress file for resume capability
- **Duplicate Prevention**: Skips emails already in Gmail
- **Batch Processing**: Processes emails in configurable batches
- **Rate Limiting**: Gmail API quota-aware processing
- **Size Filtering**: Automatically handles large email size limits
- **Label Management**: Applies both "Jku" and "migration-date" labels
- **Statistics Reporting**: Detailed progress and completion reports

### Authentication Setup
Set up Gmail OAuth2 credentials:
```bash
uv run auth.py
```

## Operation Modes

### Development/Testing
- Single runs with `try.py` for testing
- Manual authentication with `auth.py`
- Direct execution for debugging

### Production Deployment
- Continuous monitoring with `loop.py`
- Systemd service integration
- Automatic error notifications
- Log rotation and monitoring

### Migration Mode
- One-time bulk migration with `migrate.py`
- Resume capability for interrupted migrations
- Comprehensive duplicate prevention
- Progress tracking and statistics

## Configuration

### config.ini Structure
```ini
[imap]
server = your.imap.server
port = 993
username = your_username
password = your_password

[smtp]
server = smtp.gmail.com
port = 587
username = your_error_email@gmail.com
password = your_app_password

[gmail]
user_id = me
error_email = your_error_email@gmail.com

[settings]
check_interval = 300
retry_attempts = 3
batch_size = 10
```

## Production Deployment

### Systemd Service
1. Copy the service file:
```bash
sudo cp jkubot.service /etc/systemd/system/
```

2. Enable and start the service:
```bash
sudo systemctl enable jkubot
sudo systemctl start jkubot
```

3. Check status:
```bash
sudo systemctl status jkubot
```

## Error Handling

The system includes comprehensive error handling:

- **Authentication Failures**: High-priority email alerts
- **Network Issues**: Automatic retry with exponential backoff
- **Gmail API Limits**: Rate limiting and quota management
- **IMAP Errors**: Connection recovery and retry logic

## Security

- OAuth2 authentication for Gmail API
- App-specific passwords for SMTP
- No plain text credential storage in logs
- Secure token management

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify OAuth2 credentials
   - Check token expiration
   - Run `auth.py` to refresh

2. **Connection Issues**
   - Check network connectivity
   - Verify IMAP/SMTP settings
   - Check firewall settings

3. **Migration Problems**
   - Check Gmail API quotas
   - Verify label permissions
   - Review error notifications

### Logs and Monitoring
- Service logs: `journalctl -u jkubot -f`
- Error notifications sent via email
- Progress tracking files for migration

## Development

### Project Structure
```
jkubot/
├── try.py          # Single-run processor
├── loop.py         # Continuous monitoring
├── migrate.py      # Bulk migration tool
├── auth.py         # Authentication handler
├── config.ini      # Configuration file
├── jkubot.service  # Systemd service
├── pyproject.toml  # Dependencies
└── README.md       # Documentation
```

### Testing
```bash
# Test authentication
uv run auth.py

# Test single email processing
uv run try.py

# Test migration (dry run)
uv run migrate.py --dry-run
```

## License

This project is licensed under the MIT License.