"""
Authentication module with Google Drive API using OAuth2
"""
import os
import stat
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ['https://www.googleapis.com/auth/drive.readonly']


def authenticate():
    """
    Authenticates the user with Google Drive API using OAuth2.
    
    Returns:
        googleapiclient.discovery.Resource: Authenticated Google Drive service
    
    Raises:
        FileNotFoundError: If credentials.json doesn't exist
        Exception: If there are authentication errors

    """
    creds = None
    token_file = 'token.json'
    credentials_file = 'credentials.json'
    
    if not os.path.exists(credentials_file):
        raise FileNotFoundError(
            f"File {credentials_file} not found. "
            "Please download OAuth2 credentials from Google Cloud Console."
        )
    
    if os.path.exists(token_file):
        try:
            if os.access(token_file, os.R_OK):
                try:
                    creds = Credentials.from_authorized_user_file(token_file, SCOPES)
                except Exception as e:
                    print(f"⚠ Warning: Could not load credentials from {token_file}: {e}")
                    creds = None
            else:
                print(f"⚠ Warning: {token_file} exists but is not readable (permission denied).")
                print(f"   The file is owned by root. Will request new authorization.")
                print(f"   To fix permanently, run: sudo chown $USER:$USER {token_file}")
                creds = None
        except (OSError, PermissionError) as e:
            print(f"⚠ Warning: Could not read {token_file}: {e}. Will request new authorization.")
            creds = None
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                print(f"⚠ Warning: Could not refresh token: {e}. Requesting new authorization.")
                creds = None
        
        if not creds or not creds.valid:
            flow = InstalledAppFlow.from_client_secrets_file(
                credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)
        
        try:
            if os.path.exists(token_file) and not os.access(token_file, os.W_OK):
                try:
                    os.remove(token_file)
                    print(f"✓ Removed old {token_file} with incorrect permissions")
                except (OSError, PermissionError):
                    print(f"⚠ Cannot remove old {token_file}. Will try to create new one.")
                    temp_token_file = token_file + '.new'
                    try:
                        with open(temp_token_file, 'w') as token:
                            token.write(creds.to_json())
                        os.chmod(temp_token_file, 0o644)
                        try:
                            os.replace(temp_token_file, token_file)
                        except:
                            print(f"⚠ Created {temp_token_file} instead. Please remove old {token_file}")
                            return build('drive', 'v3', credentials=creds)
                    except Exception as e2:
                        raise PermissionError(
                            f"Cannot write token file. Error: {e2}. "
                            f"Please run: sudo chown $USER:$USER {token_file} or remove it manually."
                        )
            
            with open(token_file, 'w') as token:
                token.write(creds.to_json())
            
            try:
                os.chmod(token_file, 0o644)
            except:
                pass
                
        except (OSError, PermissionError) as e:
            raise PermissionError(
                f"Cannot write to {token_file}. Please check file permissions. "
                f"Error: {e}\n"
                f"To fix, run: sudo chown $USER:$USER {token_file} && sudo chmod 644 {token_file}"
            )
    
    try:
        service = build('drive', 'v3', credentials=creds)
        return service
    except HttpError as error:
        raise Exception(f"Error building Google Drive service: {error}")


def test_connection(service):
    """
    Tests the connection with Google Drive.
    
    Args:
        service: Authenticated Google Drive service
    
    Returns:
        bool: True if connection is successful
    """
    try:
        about = service.about().get(fields='user').execute()
        print(f"✓ Connected as: {about['user']['emailAddress']}")
        return True
    except HttpError as error:
        print(f"✗ Connection error: {error}")
        return False
