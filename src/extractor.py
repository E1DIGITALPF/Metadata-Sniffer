"""
Main module for extracting metadata from files in Google Drive
"""
import os
from datetime import datetime
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from googleapiclient.errors import HttpError
from tqdm import tqdm


class MetadataExtractor:
    """Forensic metadata extractor for Google Drive"""
    
    def __init__(self, service, max_workers: Optional[int] = None):
        """
        Initializes the extractor with an authenticated Google Drive service.
        
        Args:
            service: Authenticated Google Drive service
            max_workers: Maximum number of parallel workers (default: CPU count * 2)
        """
        self.service = service
        self.fields = (
            'id, name, mimeType, createdTime, modifiedTime, viewedByMeTime, '
            'size, owners, webViewLink, sharingUser, permissions, '
            'parents, md5Checksum, version, capabilities, shared, '
            'trashed, starred, description, lastModifyingUser'
        )
        self.path_cache = {}
        self.path_cache_lock = Lock()
        if max_workers is None:
            max_workers = 1
        self.max_workers = max(1, min(max_workers, 4))
    
    def format_datetime(self, dt_string: Optional[str]) -> Optional[str]:
        """
        Formats a Google Drive date to readable format.
        
        Args:
            dt_string: Date string in ISO 8601 format
        
        Returns:
            Formatted string or None
        """
        if not dt_string:
            return None
        try:
            dt = datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return dt_string
    
    def format_size(self, size_bytes: Optional[str]) -> str:
        """
        Formats size in bytes to readable format.
        
        Args:
            size_bytes: Size in bytes as string
        
        Returns:
            Formatted string (e.g., "1.5 MB")
        """
        if not size_bytes:
            return "N/A"
        try:
            size = int(size_bytes)
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size < 1024.0:
                    return f"{size:.2f} {unit}"
                size /= 1024.0
            return f"{size:.2f} PB"
        except:
            return size_bytes
    
    def get_file_path(self, file_id: str, file_name: str) -> str:
        """
        Gets the complete path of a file in Google Drive.
        Uses caching to avoid redundant API calls.
        Simplified to reduce API calls and memory usage.
        
        Args:
            file_id: File ID
            file_name: File name
        
        Returns:
            Complete file path (simplified to avoid too many API calls)
        """
        return file_name
        
        """
        with self.path_cache_lock:
            if file_id in self.path_cache:
                return self.path_cache[file_id]
        
        try:
            path_parts = []
            current_id = file_id
            visited_ids = set()
            max_depth = 10
            
            depth = 0
            while current_id and current_id not in visited_ids and depth < max_depth:
                visited_ids.add(current_id)
                depth += 1
                
                with self.path_cache_lock:
                    if current_id in self.path_cache:
                        cached_path = self.path_cache[current_id]
                        if path_parts:
                            return '/'.join([cached_path] + path_parts)
                        return cached_path
                
                try:
                    file = self.service.files().get(
                        fileId=current_id,
                        fields='name, parents'
                    ).execute()
                    
                    name = file.get('name', 'Unknown')
                    path_parts.insert(0, name)
                    
                    parents = file.get('parents')
                    if parents and len(parents) > 0:
                        current_id = parents[0]
                    else:
                        break
                except HttpError:
                    break
            
            result = '/'.join(path_parts) if path_parts else file_name
            
            with self.path_cache_lock:
                self.path_cache[file_id] = result
            
            return result
        except Exception:
            return file_name
        """
    
    def extract_file_metadata(self, file: Dict) -> Dict:
        """
        Extracts all forensic metadata from a file.
        
        Args:
            file: Dictionary with file data from Google Drive API
        
        Returns:
            Dictionary with extracted and formatted metadata
        """
        owners = file.get('owners', [])
        owner_email = owners[0].get('emailAddress', 'N/A') if owners else 'N/A'
        owner_name = owners[0].get('displayName', 'N/A') if owners else 'N/A'
        
        last_modifying_user = file.get('lastModifyingUser', {})
        last_modifier_email = last_modifying_user.get('emailAddress', 'N/A')
        last_modifier_name = last_modifying_user.get('displayName', 'N/A')
        
        sharing_user = file.get('sharingUser', {})
        sharing_user_email = sharing_user.get('emailAddress', 'N/A')
        
        file_path = self.get_file_path(file.get('id'), file.get('name', 'Unknown'))
        
        permissions = file.get('permissions', [])
        permission_types = []
        for perm in permissions:
            perm_type = perm.get('type', 'unknown')
            role = perm.get('role', 'unknown')
            permission_types.append(f"{perm_type}:{role}")
        
        metadata = {
            'id': file.get('id', 'N/A'),
            'name': file.get('name', 'N/A'),
            'mime_type': file.get('mimeType', 'N/A'),
            'file_type': self._get_file_type(file.get('mimeType', '')),
            'creation_date': self.format_datetime(file.get('createdTime')),
            'modification_date': self.format_datetime(file.get('modifiedTime')),
            'last_viewed_date': self.format_datetime(file.get('viewedByMeTime')),
            'creation_date_raw': file.get('createdTime', 'N/A'),
            'modification_date_raw': file.get('modifiedTime', 'N/A'),
            'size_bytes': file.get('size', '0'),
            'size_formatted': self.format_size(file.get('size')),
            'owner_email': owner_email,
            'owner_name': owner_name,
            'last_modifier_email': last_modifier_email,
            'last_modifier_name': last_modifier_name,
            'sharing_user_email': sharing_user_email,
            'full_path': file_path,
            'share_link': file.get('webViewLink', 'N/A'),
            'shared': file.get('shared', False),
            'trashed': file.get('trashed', False),
            'starred': file.get('starred', False),
            'description': file.get('description', ''),
            'md5_checksum': file.get('md5Checksum', 'N/A'),
            'version': file.get('version', 'N/A'),
            'permissions': '; '.join(permission_types) if permission_types else 'N/A',
            'permission_count': len(permissions),
            'parents': '; '.join(file.get('parents', [])),
        }
        
        return metadata
    
    def _get_file_type(self, mime_type: str) -> str:
        """Determines file type based on MIME type"""
        type_mapping = {
            'application/vnd.google-apps.folder': 'Folder',
            'application/vnd.google-apps.document': 'Google Docs',
            'application/vnd.google-apps.spreadsheet': 'Google Sheets',
            'application/vnd.google-apps.presentation': 'Google Slides',
            'application/pdf': 'PDF',
            'image/jpeg': 'JPEG Image',
            'image/png': 'PNG Image',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Word',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'Excel',
            'text/plain': 'Text',
        }
        return type_mapping.get(mime_type, mime_type.split('/')[-1].upper())
    
    def _process_file(self, file: Dict) -> Optional[Dict]:
        """
        Process a single file and extract its metadata.
        Used for parallel processing.
        
        Args:
            file: File dictionary from Google Drive API
        
        Returns:
            Metadata dictionary or None if error
        """
        try:
            return self.extract_file_metadata(file)
        except Exception as e:
            return None
    
    def _collect_files_recursively(self, folder_id: str, include_trashed: bool, 
                                   progress_callback=None, visited_folders=None) -> List[Dict]:
        """
        Recursively collects all files from a folder and its subfolders.
        
        Args:
            folder_id: ID of folder to scan
            include_trashed: Whether to include trashed files
            progress_callback: Optional callback function
            visited_folders: Set of already visited folder IDs to prevent infinite loops
        
        Returns:
            List of file dictionaries
        """
        if visited_folders is None:
            visited_folders = set()
        
        if folder_id in visited_folders:
            return []
        
        visited_folders.add(folder_id)
        all_files = []
        page_token = None
        
        query_parts = [f"'{folder_id}' in parents"]
        if not include_trashed:
            query_parts.append("trashed = false")
        
        query = " and ".join(query_parts)
        
        try:
            while True:
                results = self.service.files().list(
                    q=query,
                    pageSize=1000,
                    fields=f"nextPageToken, files(id, name, mimeType, {self.fields})",
                    pageToken=page_token,
                    orderBy="createdTime"
                ).execute()
                
                files = results.get('files', [])
                if not files:
                    break
                
                folders_to_scan = []
                for file in files:
                    if file.get('mimeType') == 'application/vnd.google-apps.folder':
                        folders_to_scan.append(file)
                    else:
                        all_files.append(file)
                
                if progress_callback:
                    progress_callback('collecting', len(all_files), 0, 
                                    f'Found {len(all_files)} files, scanning {len(folders_to_scan)} subfolders...')
                
                for folder in folders_to_scan:
                    subfolder_id = folder.get('id')
                    if subfolder_id and subfolder_id not in visited_folders:
                        subfolder_files = self._collect_files_recursively(
                            subfolder_id, include_trashed, progress_callback, visited_folders
                        )
                        all_files.extend(subfolder_files)
                
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
                    
        except HttpError as error:
            if progress_callback:
                progress_callback('error', 0, 0, f'API error scanning folder {folder_id}: {error}')
            raise
        
        return all_files
    
    def extract_folder(self, folder_id: Optional[str] = None, 
                      include_trashed: bool = False, 
                      progress_callback=None) -> List[Dict]:
        """
        Extracts metadata from all files in a folder or entire Drive.
        Recursively scans all subfolders when a folder_id is provided.
        Uses parallel processing for improved performance.
        
        Args:
            folder_id: ID of folder to scan (None for entire Drive)
            include_trashed: Whether to include trashed files
            progress_callback: Optional callback function(status, progress, total, message)
        
        Returns:
            List of dictionaries with metadata for each file
        """
        all_files = []
        page_token = None
        
        if progress_callback:
            progress_callback('collecting', 0, 0, 'Collecting file list from Google Drive...')
        
        try:
            if folder_id:
                all_files = self._collect_files_recursively(folder_id, include_trashed, progress_callback)
            else:
                query_parts = []
                if not include_trashed:
                    query_parts.append("trashed = false")
                
                query = " and ".join(query_parts) if query_parts else None
                
                page_count = 0
                while True:
                    try:
                        results = self.service.files().list(
                            q=query,
                            pageSize=1000,
                            fields=f"nextPageToken, files({self.fields})",
                            pageToken=page_token,
                            orderBy="createdTime"
                        ).execute()
                        
                        files = results.get('files', [])
                        if not files:
                            break
                        
                        all_files.extend(files)
                        page_count += 1
                        
                        if progress_callback:
                            progress_callback('collecting', len(all_files), 0, 
                                            f'Found {len(all_files)} files so far...')
                        
                        page_token = results.get('nextPageToken')
                        if not page_token:
                            break
                            
                    except HttpError as error:
                        if progress_callback:
                            progress_callback('error', 0, 0, f'API error: {error}')
                        raise
            
            if not all_files:
                if progress_callback:
                    progress_callback('error', 0, 0, 'No files found to extract')
                return []
            
            if progress_callback:
                progress_callback('processing', 0, len(all_files), 
                                f'Processing {len(all_files)} files with {self.max_workers} workers...')
            
            all_metadata = []
            errors = []
            processed_count = 0
            
            if self.max_workers == 1:
                for file in all_files:
                    try:
                        metadata = self._process_file(file)
                        if metadata:
                            all_metadata.append(metadata)
                        else:
                            errors.append(file.get('id', 'unknown'))
                        processed_count += 1
                        
                        if progress_callback:
                            progress_callback('processing', processed_count, len(all_files),
                                            f'Processed {processed_count}/{len(all_files)} files...')
                        
                        if processed_count % 50 == 0:
                            import gc
                            gc.collect()
                    except Exception as e:
                        errors.append(file.get('id', 'unknown'))
                        processed_count += 1
                        if progress_callback:
                            progress_callback('processing', processed_count, len(all_files),
                                            f'Processed {processed_count}/{len(all_files)} files...')
            else:
                metadata_lock = Lock()
                batch_size = min(10, len(all_files))
                
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    for batch_start in range(0, len(all_files), batch_size):
                        batch = all_files[batch_start:batch_start + batch_size]
                        
                        future_to_file = {}
                        for file in batch:
                            try:
                                future = executor.submit(self._process_file, file)
                                future_to_file[future] = file
                            except Exception as e:
                                errors.append(file.get('id', 'unknown'))
                                processed_count += 1
                        
                        for future in as_completed(future_to_file):
                            file = future_to_file[future]
                            try:
                                metadata = future.result(timeout=60)
                                if metadata:
                                    with metadata_lock:
                                        all_metadata.append(metadata)
                                    processed_count += 1
                                else:
                                    errors.append(file.get('id', 'unknown'))
                                    processed_count += 1
                                
                                if progress_callback:
                                    progress_callback('processing', processed_count, len(all_files),
                                                    f'Processed {processed_count}/{len(all_files)} files...')
                                
                            except Exception as e:
                                errors.append(file.get('id', 'unknown'))
                                processed_count += 1
                                if progress_callback:
                                    progress_callback('processing', processed_count, len(all_files),
                                                    f'Processed {processed_count}/{len(all_files)} files...')
                        
                        del future_to_file
                        import gc
                        gc.collect()
            
            if progress_callback:
                progress_callback('completed', len(all_metadata), len(all_files),
                                f'Successfully extracted {len(all_metadata)} files!')
            
            return all_metadata
            
        except Exception as e:
            if progress_callback:
                progress_callback('error', 0, 0, f'Error: {str(e)}')
            raise
