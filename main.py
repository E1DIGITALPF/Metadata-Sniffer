#!/usr/bin/env python3
"""
Main script for forensic metadata extraction from Google Drive
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'src'))

from auth import authenticate, test_connection
from extractor import MetadataExtractor
from exporters import CSVExporter, JSONExporter, PDFExporter
from web_viewer import WebViewer
from helpers import extract_folder_id_from_url


def main():
    """Main script function"""
    parser = argparse.ArgumentParser(
        description='Forensic Metadata Extractor for Google Drive',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python main.py --output complete_report
  
  python main.py --folder-id 1ABC123XYZ --output folder_report
  
  python main.py --include-trashed --output complete_report
        """
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='forensic_metadata',
        help='Base name for output files (without extension)'
    )
    
    parser.add_argument(
        '--folder-id', '-f',
        type=str,
        default=None,
        help='ID of specific folder or shared link to scan (optional, defaults to entire Drive). Can be a folder ID or a Google Drive shared link URL.'
    )
    
    parser.add_argument(
        '--include-trashed',
        action='store_true',
        help='Include files that are in the trash'
    )
    
    parser.add_argument(
        '--format',
        type=str,
        choices=['all', 'csv', 'json', 'pdf'],
        default='all',
        help='Output format (default: all)'
    )
    
    parser.add_argument(
        '--workers', '-w',
        type=int,
        default=None,
        help='Number of parallel workers (default: CPU count * 2, max 32)'
    )
    
    args = parser.parse_args()
    
    print("="*60)
    print("METADATA SNIFFER - Forensic Extractor for Google Drive")
    print("="*60)
    print()
    
    try:
        print("🔐 Authenticating with Google Drive...")
        service = authenticate()
        
        if not test_connection(service):
            print("✗ Error: Could not establish connection with Google Drive")
            sys.exit(1)
        
        print()
        
        folder_id = None
        if args.folder_id:
            folder_id = extract_folder_id_from_url(args.folder_id)
            if not folder_id:
                print(f"✗ Error: Invalid folder ID or shared link format: {args.folder_id}")
                print("   Please provide a valid Google Drive folder ID or shared link.")
                sys.exit(1)
            if folder_id != args.folder_id:
                print(f"ℹ Extracted folder ID from shared link: {folder_id[:20]}...")
        
        extractor = MetadataExtractor(service, max_workers=args.workers)
        
        metadata = extractor.extract_folder(
            folder_id=folder_id,
            include_trashed=args.include_trashed
        )
        
        if not metadata:
            print("⚠ No files found to extract")
            sys.exit(0)
        
        output_formats = []
        if args.format == 'all':
            output_formats = ['csv', 'json', 'pdf']
        else:
            output_formats = [args.format]
        
        print("\n" + "="*60)
        print("Exporting results...")
        print("="*60 + "\n")
        
        if 'csv' in output_formats:
            csv_exporter = CSVExporter(args.output)
            csv_exporter.export(metadata)
        
        if 'json' in output_formats:
            json_exporter = JSONExporter(args.output)
            json_exporter.export(metadata)
        
        if 'pdf' in output_formats:
            pdf_exporter = PDFExporter(args.output)
            pdf_exporter.export(metadata)
        
        print("\n" + "="*60)
        print("✓ Process completed successfully")
        print("="*60)
        print(f"\nGenerated files:")
        for fmt in output_formats:
            ext = fmt if fmt != 'json' else 'json'
            print(f"  - {args.output}.{ext}")
        print()
        
        print("="*60)
        print("🌐 Launching web viewer...")
        print("="*60)
        print("\nThe web viewer will open in your browser automatically.")
        print("You can filter, sort, and explore all extracted metadata.")
        print("Press Ctrl+C in the terminal to stop the web server.\n")
        
        try:
            viewer = WebViewer(metadata, args.output)
            viewer.start_server(open_browser=True)
        except Exception as e:
            print(f"⚠ Could not launch web viewer: {e}")
            print("You can still view the exported CSV, JSON, and PDF files.")
        
    except FileNotFoundError as e:
        print(f"\n✗ Error: {e}")
        print("\nPlease make sure you have the 'credentials.json' file")
        print("downloaded from Google Cloud Console.")
        sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\n⚠ Process interrupted by user")
        sys.exit(1)
    
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) == 1:
        print("="*60)
        print("🌐 Launching Web Application...")
        print("="*60)
        print("\nStarting web server. The browser will open automatically.")
        print("Use --help to see CLI options.\n")
        
        from web_app import app
        import webbrowser
        import threading
        import time
        
        def open_browser():
            time.sleep(1.5)
            webbrowser.open('http://localhost:5000')
        
        threading.Thread(target=open_browser, daemon=True).start()
        app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
    else:
        main()
