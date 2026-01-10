"""
Helper functions for the metadata extractor
"""
import sys
import re
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from auth import authenticate


def extract_folder_id_from_url(url_or_id: str) -> Optional[str]:
    """
    Extracts folder ID from Google Drive shared link or returns the ID if already provided.
    
    Supports multiple URL formats:
    - https://drive.google.com/drive/folders/FOLDER_ID
    - https://drive.google.com/drive/folders/FOLDER_ID?usp=sharing
    - https://drive.google.com/drive/folders/FOLDER_ID/view?usp=sharing
    - https://drive.google.com/open?id=FOLDER_ID
    - Direct folder ID (returns as-is)

    Args:
        url_or_id: Google Drive URL or folder ID
    
    Returns:
        Folder ID string, or None if not found
    """
    if not url_or_id or not url_or_id.strip():
        return None
    
    url_or_id = url_or_id.strip()
    
    if not url_or_id.startswith('http') and '/' not in url_or_id and '?' not in url_or_id:
        return url_or_id
    
    pattern1 = r'/drive/folders/([a-zA-Z0-9_-]+)'
    match = re.search(pattern1, url_or_id)
    if match:
        return match.group(1)
    
    pattern2 = r'/open\?id=([a-zA-Z0-9_-]+)'
    match = re.search(pattern2, url_or_id)
    if match:
        return match.group(1)
    
    pattern3 = r'[?&]id=([a-zA-Z0-9_-]+)'
    match = re.search(pattern3, url_or_id)
    if match:
        return match.group(1)
    
    return None


def list_folders():
    """
    Lists all folders in Google Drive with their IDs.
    Useful for finding the ID of a specific folder.
    """
    try:
        service = authenticate()
        
        print("\n" + "="*60)
        print("GOOGLE DRIVE FOLDER LISTING")
        print("="*60 + "\n")
        
        query = "mimeType='application/vnd.google-apps.folder' and trashed = false"
        page_token = None
        folders = []
        
        while True:
            results = service.files().list(
                q=query,
                pageSize=100,
                fields="nextPageToken, files(id, name, createdTime)",
                pageToken=page_token,
                orderBy="name"
            ).execute()
            
            files = results.get('files', [])
            folders.extend(files)
            
            page_token = results.get('nextPageToken')
            if not page_token:
                break
        
        if not folders:
            print("No folders found.")
            return
        
        print(f"Total folders found: {len(folders)}\n")
        print(f"{'Name':<50} {'ID':<40} {'Creation Date':<20}")
        print("-" * 110)
        
        for folder in folders:
            name = folder.get('name', 'Unnamed')[:48]
            folder_id = folder.get('id', 'N/A')
            created = folder.get('createdTime', 'N/A')[:10] if folder.get('createdTime') else 'N/A'
            print(f"{name:<50} {folder_id:<40} {created:<20}")
        
        print("\n" + "="*60)
        print("To use a folder, copy its ID and use it with --folder-id")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    list_folders()
