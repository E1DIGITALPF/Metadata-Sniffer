# Metadata Sniffer - Forensic Metadata Extractor for Google Drive

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-success?style=for-the-badge)
![Google Drive](https://img.shields.io/badge/Google%20Drive-API-orange?style=for-the-badge&logo=google-drive&logoColor=white)
![Forensic](https://img.shields.io/badge/Forensic-Tool-red?style=for-the-badge)

A professional forensic tool designed to extract comprehensive metadata from Google Drive documents and folders. Ideal for legal cases, compliance audits, and forensic investigations where document chronology, ownership, and modification history are critical evidence.

## Overview

Metadata Sniffer provides a complete solution for extracting and analyzing metadata from Google Drive files. It generates legally admissible reports with deterministic forensic hashing, ensuring data integrity and reproducibility for court proceedings and legal documentation.

## Key Features

- 🔍 **Complete Metadata Extraction**: Comprehensive extraction of all file metadata including dates, ownership, permissions, and file properties
- 📅 **Forensic Date Tracking**: Creation dates, modification dates, and last viewed timestamps
- 🔐 **Deterministic Forensic Hashing**: SHA-256 hashing of immutable metadata ensures legal validity and reproducibility
- 📊 **Multiple Export Formats**: CSV for analysis, JSON for programmatic access, and PDF for court-ready reports
- 🌐 **Web-Based Interface**: Modern, user-friendly web application with real-time progress tracking
- ⏸️ **Pause/Resume/Stop Controls**: Full control over extraction process with ability to pause, resume, or stop operations
- 📁 **Flexible Scanning**: Extract from specific folders or entire Google Drive
- 🔗 **Shared Folder Support**: Scan shared folders using shared links - perfect for collaborative workspaces and client folders
- 📂 **Recursive Scanning**: Automatically scans all subfolders recursively, ensuring complete metadata extraction from nested folder structures
- 👤 **Permission Analysis**: Detailed owner and permission information
- 🔒 **Secure Authentication**: OAuth 2.0 authentication with read-only access

## Installation

### Prerequisites

- Python 3.8 or higher
- Google account with access to Google Drive
- Google Cloud Console project with Google Drive API enabled

### Step 1: Clone the Repository

```bash
git clone https://github.com/E1DIGITALPF/Metadata-Sniffer.git
cd Metadata-Sniffer
```

### Step 2: Create Virtual Environment (Recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Google Drive API Credentials

#### 4.1 Create a Google Cloud Project

1. Navigate to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Name your project (e.g., "metadata-sniffer")

#### 4.2 Enable Google Drive API

The Google Drive API may not appear in the default API list. Follow these steps:

1. In the side menu, navigate to **APIs & Services** > **Library**
2. **Important**: Use the search box at the top of the page (not the category filters)
3. Type exactly: **"Google Drive API"** (without quotes)
4. Select **"Google Drive API"** from the search results (identified by the Drive icon)
5. Click the **Enable** button

**Alternative Direct Link:**
- Go directly to: https://console.cloud.google.com/apis/library/drive.googleapis.com
- Click **Enable**

**Note**: Ensure you're working in the correct project (verify using the project selector at the top of the page)

#### 4.3 Create OAuth 2.0 Credentials

1. Navigate to **APIs & Services** > **Credentials**
2. Click **+ CREATE CREDENTIALS** > **OAuth client ID**
3. If this is your first time, you'll need to configure the OAuth consent screen:
   - **Application type**: External
   - **App name**: "Metadata Sniffer" (or your preferred name)
   - **User support email**: Your email address
   - **Developer contact information**: Your email address
   - Click **Save and Continue** through all steps
4. For the OAuth client:
   - **Application type**: Desktop app
   - **Name**: "Metadata Sniffer Desktop"
   - Click **Create**
5. Download the JSON credentials file
6. Rename the file to `credentials.json`
7. Place it in the project root directory

#### 4.4 Add Test Users (Critical for Testing)

If you encounter an "access_denied" error, you must add your email as a test user:

1. Navigate to **APIs & Services** > **OAuth consent screen**
2. Scroll to the **"Test users"** section
3. Click **+ ADD USERS**
4. Enter your Google account email address
5. Click **ADD**
6. Wait 2-3 minutes for changes to propagate

**Important Notes:**
- You can add up to 100 test users
- Each user must accept the consent screen once
- Changes may take a few minutes to take effect
- If you're the app owner, you should have access, but adding yourself as a test user ensures reliability

## Usage

### Web Interface (Recommended)

Launch the web-based interface for the easiest user experience:

```bash
python main.py
```

The application will:
1. Start a local web server (typically on port 5000)
2. Automatically open your default web browser
3. Display the extraction configuration interface

**Features:**
- Real-time progress tracking with progress bar
- Pause/Resume/Stop controls
- Automatic browser opening with results viewer
- Download generated files directly from the interface

### Command Line Interface

For automated or scripted extractions:

#### Extract Entire Google Drive

```bash
python main.py --cli --output forensic_report
```

#### Extract Specific Folder

```bash
python main.py --cli --folder-id <FOLDER_ID> --output folder_report
```

#### Include Trashed Files

```bash
python main.py --cli --include-trashed --output complete_report
```

#### Available Options

```bash
python main.py --help
```

**Command Line Options:**
- `--cli`: Run in command-line mode (instead of web interface)
- `--folder-id <ID>`: Extract from specific folder (leave empty for entire Drive)
- `--output <NAME>`: Base name for output files
- `--include-trashed`: Include files in trash
- `--format <csv|json|pdf>`: Export format (default: all formats)
- `--workers <N>`: Number of parallel workers (default: 1 for stability)

### Getting Folder ID or Using Shared Links

You can extract metadata from a specific folder in two ways:

#### Method 1: Using Folder ID

1. Open Google Drive in your web browser
2. Navigate to the desired folder
3. Examine the URL: `https://drive.google.com/drive/folders/ABC123XYZ...`
4. The folder ID is the string after `/folders/` (e.g., `ABC123XYZ...`)

#### Method 2: Using Shared Links (Recommended)

**Yes, you can use shared links directly!** This is perfect for scanning folders shared with you by clients, colleagues, or collaborators. Simply paste the shared link and the tool will automatically extract the folder ID and scan all contents recursively.

**Supported link formats:**
- `https://drive.google.com/drive/folders/FOLDER_ID`
- `https://drive.google.com/drive/folders/FOLDER_ID?usp=sharing`
- `https://drive.google.com/drive/folders/FOLDER_ID?usp=drive_link`
- `https://drive.google.com/open?id=FOLDER_ID`
- Direct folder ID: `FOLDER_ID`

**Key Features for Shared Folders:**
- ✅ **Automatic ID Extraction**: Just paste the shared link - no need to extract the folder ID manually
- ✅ **Recursive Scanning**: Automatically scans all subfolders and nested directories within the shared folder
- ✅ **Works with Any Access Level**: Viewer, commenter, or editor permissions - as long as you can see the folder
- ✅ **Public & Private Folders**: Works with both publicly shared folders and privately shared folders (with your access)

**Important Notes:**
- You still need your own Google Drive API credentials (OAuth) - the tool uses your credentials to access the shared folder
- You must have access to the shared folder (viewer, commenter, or editor permission)
- The tool uses your credentials to access the shared folder, not the folder owner's credentials
- This works for both public and private shared folders (as long as you have access)
- **Recursive scanning**: All files in all subfolders are automatically included in the extraction

**Examples:**

Using folder ID:
```bash
python main.py --cli --folder-id ABC123XYZ --output folder_report
```

Using shared link:
```bash
python main.py --cli --folder-id "https://drive.google.com/drive/folders/ABC123XYZ?usp=sharing" --output folder_report
```

In the web interface, simply paste the shared link in the "Folder ID or Shared Link" field.

## Output Files

All generated files are saved in the `output/` directory.

### CSV Format
- Tabular data suitable for Excel, Google Sheets, or data analysis tools
- All metadata fields in columns
- Sorted by file ID for consistency

### JSON Format
- Complete structured data with extraction metadata
- Includes forensic integrity hash (SHA-256)
- Suitable for programmatic processing and integration

### PDF Format
- Court-ready forensic report
- Statistical summary
- Detailed file information (all files included)
- Forensic integrity hash section
- Professional formatting for legal presentation
- **Forensic footer on every page**: SHA-256 hash and page numbering (X/Y format) for complete traceability

## Extracted Metadata

The tool extracts the following metadata for each file:

- **File Identification**
  - Unique Google Drive ID
  - File name
  - File type (MIME type)
  - Complete path in Drive hierarchy

- **Temporal Information**
  - Creation date (raw ISO format and formatted)
  - Last modification date (raw ISO format and formatted)
  - Last viewed date (if available)

- **File Properties**
  - File size (bytes and human-readable format)
  - MD5 checksum (if available)
  - Version number

- **Ownership & Permissions**
  - Owner email and name
  - Last modifier email and name
  - Sharing status
  - Permission count
  - Share link URL

- **Additional Information**
  - Trash status
  - Starred status
  - Description
  - Parent folder IDs

## Forensic Integrity Hash

Metadata Sniffer implements a deterministic forensic hash (SHA-256) that:

- **Changes only when files are actually modified**: The hash reflects real changes (additions, deletions, modifications, renames)
- **Remains constant for unchanged data**: Viewing files or changing permissions does not affect the hash
- **Ensures legal validity**: Same Drive content = same hash, regardless of extraction time
- **Provides reproducibility**: Any party can verify the integrity of extracted data

The hash is calculated on immutable forensic fields only:
- File IDs, names, types
- Creation and modification dates
- File sizes and MD5 checksums
- File descriptions
- Trash status

**Excluded from hash** (to ensure determinism):
- Last viewed dates (changes on access)
- Share links (can change without file modification)
- Permission details (order may vary)
- Path information (can change if files are moved)

## Use Cases

### Legal Proceedings
- **Labor Disputes**: Demonstrate work chronology with creation dates from hundreds or thousands of documents
- **Evidence Documentation**: Provide court-admissible metadata reports with forensic integrity hashing
- **Document Chronology**: Establish timeline of document creation and modification

### Compliance & Auditing
- **Forensic Audits**: Complete metadata extraction for compliance reviews
- **Data Governance**: Track file ownership, sharing, and access patterns
- **Document Verification**: Verify document authenticity and modification history

### Data Analysis
- **Drive Organization Analysis**: Understand file distribution, types, and ownership
- **Storage Optimization**: Identify large files and unused documents
- **Access Pattern Analysis**: Review viewing and modification patterns

## Troubleshooting

### Error: "credentials.json not found"

**Solution:**
1. Verify you've downloaded the credentials from Google Cloud Console
2. Ensure the file is named exactly `credentials.json` (case-sensitive)
3. Confirm the file is in the project root directory

### Error: "Access denied" or "Error 403: access_denied"

**This is the most common error.** It indicates your email is not in the test users list.

**Solution:**
1. Navigate to **APIs & Services** > **OAuth consent screen** in Google Cloud Console
2. Scroll to the **"Test users"** section
3. Click **+ ADD USERS**
4. Add your Google account email (the one you're using to sign in)
5. Click **ADD**
6. Wait 2-3 minutes for changes to propagate
7. Delete `token.json` if it exists: `rm token.json`
8. Run the application again

**Quick Fix:**
```bash
# Delete the old token
rm token.json

# Run again (will prompt for authorization)
python main.py
```

**Note**: For production use, you can publish the app (requires Google verification). For personal/testing use, adding test users is the fastest solution.

### Error: "Token expired" or Permission Denied

**Solution:**
1. Delete the `token.json` file: `rm token.json`
2. Run the application again
3. The authorization window will open automatically
4. Re-authorize the application

### Error: "Segmentation fault (core dumped)"

**Solution:**
- Use 1 worker (sequential processing) for maximum stability
- In the web interface, select "1 worker (Sequential - Recommended for Stability)"
- This is the default setting and recommended for most use cases

### Progress Shows Incorrect Values After Stop

**Solution:**
- The application automatically resets all progress values when Stop is pressed
- If you see incorrect values, refresh the browser page
- The state is completely cleared on the server side

## Project Structure

```
metadata-sniffer/
├── main.py                 # Main entry point
├── web_app.py              # Web application (Flask)
├── requirements.txt        # Python dependencies
├── credentials.json        # Google OAuth credentials (not in repo)
├── token.json             # OAuth token (generated, not in repo)
├── output/                # Generated reports directory
├── src/
│   ├── auth.py            # Google Drive authentication
│   ├── extractor.py       # Metadata extraction logic
│   ├── exporters.py       # CSV, JSON, PDF export
│   ├── helpers.py         # Utility functions
│   └── web_viewer.py      # Web viewer templates
└── README.md              # This file
```

## Dependencies

- `google-api-python-client`: Google Drive API client
- `google-auth-oauthlib`: OAuth 2.0 authentication
- `flask`: Web application framework
- `reportlab`: PDF generation
- `pandas`: Data processing
- `tqdm`: Progress bars

See `requirements.txt` for complete version specifications.

## Security & Privacy

- **Read-Only Access**: The application requests read-only access to Google Drive
- **Local Processing**: All processing occurs locally on your machine
- **No Data Transmission**: Metadata is not transmitted to external servers
- **Secure Storage**: OAuth tokens are stored locally in `token.json`
- **User Control**: You can revoke access at any time through Google Account settings

## Legal Disclaimer

This tool should only be used with documents to which you have legal access and proper authorization. Ensure you have the necessary permissions before extracting metadata from any document. The tool is provided "as-is" without warranty. Users are responsible for compliance with applicable laws and regulations regarding data access and privacy.

## License

MIT License

## Support

For issues, questions, or contributions, please visit the [project repository](https://github.com/E1DIGITALPF/Metadata-Sniffer).

## Acknowledgments

Made with ❤️ by [E1DIGITAL](https://e1digital.vercel.app)

---

**Version**: 1.0.0  
**Last Updated**: 2026
