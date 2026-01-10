"""
Export modules for different forensic formats
"""
import json
import csv
import hashlib
from datetime import datetime
from typing import List, Dict
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


def calculate_file_hash(file_path: Path) -> str:
    """
    Calculate SHA-256 hash of a file for forensic integrity.
    
    Args:
        file_path: Path to the file
    
    Returns:
        SHA-256 hash as hexadecimal string
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def create_forensic_hash_data(metadata: List[Dict]) -> Dict:
    """
    Create a deterministic forensic data structure for hashing.
    
    The hash changes when:
    - Files are added or removed from Drive/folder
    - Files are modified (content changes → size_bytes, md5_checksum, modification_date_raw change)
    - Files are renamed (name changes)
    - File descriptions are modified (description changes)
    - Files are moved to trash or restored (trashed changes)
    - File type changes (mime_type changes)
    
    The hash does NOT change when:
    - Files are only viewed/accessed (last_viewed_date changes, but not included)
    - Files are moved to different folders (parents changes, but not included)
    - Share links change (not included)
    - Permissions change (not included)
    - Files are starred/unstarred (not included)
    - Version increments automatically (not included)
    - Last modifier changes due to access (not included)
    
    Only fields that indicate ACTUAL file content/name changes are included.
    
    Args:
        metadata: List of file metadata dictionaries (ALL files in Drive/folder)
    
    Returns:
        Dictionary with forensic fields for all files, sorted for determinism
    """
    
    forensic_fields = [
        'id',
        'name',
        'mime_type',
        'file_type',
        'creation_date_raw',
        'modification_date_raw',
        'size_bytes',
        'md5_checksum',
        'description',
        'trashed'
    ]
    
    sorted_metadata = sorted(metadata, key=lambda x: x.get('id', ''))
    
    forensic_files = []
    for file_data in sorted_metadata:
        forensic_file = {}
        for field in sorted(forensic_fields):
            value = file_data.get(field, '')
            
            if value is None:
                value = ''
            elif isinstance(value, bool):
                value = 'true' if value else 'false'
            elif isinstance(value, (int, float)):
                if isinstance(value, float) and value.is_integer():
                    value = str(int(value))
                else:
                    value = str(value)
            elif isinstance(value, list):
                value = ';'.join(sorted(str(v).strip() for v in value if v)) if value else ''
            elif isinstance(value, str):
                value = value.strip() if value else ''
                if not value:
                    value = ''
            
            forensic_file[field] = value
        
        forensic_file = {k: forensic_file[k] for k in sorted(forensic_file.keys())}
        forensic_files.append(forensic_file)
    
    return {'files': forensic_files}


class CSVExporter:
    """CSV format exporter"""
    
    def __init__(self, output_path: str):
        """
        Args:
            output_path: Base path for output file
        """
        output_dir = Path('output')
        output_dir.mkdir(exist_ok=True)
        
        self.output_path = output_dir / Path(output_path).with_suffix('.csv').name
    
    def export(self, metadata: List[Dict]):
        """
        Exports metadata to CSV file.
        
        Args:
            metadata: List of dictionaries with metadata
        """
        if not metadata:
            print("⚠ No metadata to export")
            return
        
        columns = sorted([
            'name', 'id', 'file_type', 'full_path',
            'creation_date', 'modification_date', 'last_viewed_date',
            'creation_date_raw', 'modification_date_raw',
            'size_bytes', 'size_formatted',
            'owner_email', 'owner_name',
            'last_modifier_email', 'last_modifier_name',
            'shared', 'trashed', 'share_link',
            'md5_checksum', 'version', 'permissions', 'permission_count',
            'mime_type', 'description', 'parents'
        ])
        
        sorted_metadata = sorted(metadata, key=lambda x: x.get('id', ''))
        
        with open(self.output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            
            for item in sorted_metadata:
                sorted_item = {k: item.get(k, '') for k in columns}
                writer.writerow(sorted_item)
        
        forensic_data_only = create_forensic_hash_data(metadata)
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as tmp_file:
            json.dump(forensic_data_only, tmp_file, indent=None, separators=(',', ':'), ensure_ascii=False, sort_keys=True)
            tmp_path = Path(tmp_file.name)
        
        file_hash = calculate_file_hash(tmp_path)
        tmp_path.unlink()
        
        print(f"✓ CSV exported: {self.output_path}")
        print(f"  Forensic Hash (SHA-256): {file_hash}")
        print(f"  Note: Hash calculated on immutable forensic data only (excludes last_viewed_date, etc.)")


class JSONExporter:
    """JSON format exporter"""
    
    def __init__(self, output_path: str):
        """
        Args:
            output_path: Base path for output file
        """
        output_dir = Path('output')
        output_dir.mkdir(exist_ok=True)
        
        self.output_path = output_dir / Path(output_path).with_suffix('.json').name
    
    def export(self, metadata: List[Dict]):
        """
        Exports metadata to JSON file with additional information.
        
        Args:
            metadata: List of dictionaries with metadata
        """

        forensic_data_only = create_forensic_hash_data(metadata)
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as tmp_file:
            json.dump(forensic_data_only, tmp_file, indent=None, separators=(',', ':'), ensure_ascii=False, sort_keys=True)
            tmp_path = Path(tmp_file.name)
        
        file_hash = calculate_file_hash(tmp_path)
        tmp_path.unlink()
        
        export_data = {
            'extraction_metadata': {
                'date': datetime.now().isoformat(),
                'total_files': len(metadata),
                'tool': 'Metadata Sniffer - Forensic Extractor',
                'version': '1.0.0',
                'file_hash_sha256': file_hash
            },
            'files': metadata
        }
        
        with open(self.output_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
        
        print(f"✓ JSON exported: {self.output_path}")
        print(f"  Forensic Hash (SHA-256): {file_hash}")
        print(f"  Note: Hash calculated on forensic data only (files), not extraction metadata")


class PDFExporter:
    """PDF format exporter for forensic reports"""
    
    def __init__(self, output_path: str):
        """
        Args:
            output_path: Base path for output file
        """
        output_dir = Path('output')
        output_dir.mkdir(exist_ok=True)
        
        self.output_path = output_dir / Path(output_path).with_suffix('.pdf').name
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Sets up custom styles for PDF"""
        def add_style_safe(name, **kwargs):
            if name not in self.styles.byName:
                try:
                    self.styles.add(ParagraphStyle(name=name, **kwargs))
                except Exception:
                    pass
            if name in self.styles.byName:
                style = self.styles.byName[name]
                for key, value in kwargs.items():
                    if hasattr(style, key):
                        setattr(style, key, value)
        
        add_style_safe('ForensicTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=12,
            alignment=1
        )
        
        add_style_safe('ForensicHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=8
        )
        
        add_style_safe('ForensicText',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6
        )
        
        add_style_safe('ForensicURL',
            parent=self.styles['Normal'],
            fontSize=7,
            spaceAfter=4,
            wordWrap='LTR',
            leading=8
        )
        
        add_style_safe('ForensicFooter',
            parent=self.styles['Normal'],
            fontSize=9,
            spaceAfter=0,
            alignment=1,
            textColor=colors.HexColor('#666666')
        )
    
    def export(self, metadata: List[Dict]):
        """
        Exports metadata to PDF file formatted for legal presentation.
        
        Args:
            metadata: List of dictionaries with metadata
        """
        forensic_data_only = create_forensic_hash_data(metadata)
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as tmp_file:
            json.dump(forensic_data_only, tmp_file, indent=None, separators=(',', ':'), ensure_ascii=False, sort_keys=True)
            tmp_path = Path(tmp_file.name)
        
        file_hash = calculate_file_hash(tmp_path)
        tmp_path.unlink()
        
        self.forensic_hash = file_hash
        
        doc = SimpleDocTemplate(
            str(self.output_path),
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=50
        )
        
        story = []
        
        story.append(Paragraph("FORENSIC METADATA REPORT", self.styles['ForensicTitle']))
        story.append(Paragraph("Google Drive - Document Extraction", self.styles['ForensicHeading']))
        story.append(Spacer(1, 0.2*inch))
        
        report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        info_data = [
            ['Extraction Date:', report_date],
            ['Total Files:', str(len(metadata))],
            ['Tool:', 'Metadata Sniffer v1.0.0'],
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.grey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph("STATISTICAL SUMMARY", self.styles['ForensicHeading']))
        
        total_size = sum(int(m.get('size_bytes', 0) or 0) for m in metadata)
        shared_files = sum(1 for m in metadata if m.get('shared', False))
        file_types = {}
        for m in metadata:
            file_type = m.get('file_type', 'Unknown')
            file_types[file_type] = file_types.get(file_type, 0) + 1
        
        stats_data = [
            ['Metric', 'Value'],
            ['Total Files', str(len(metadata))],
            ['Shared Files', str(shared_files)],
            ['Total Size', self._format_size(total_size)],
            ['Unique File Types', str(len(file_types))],
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 3*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 1), (0, -1), colors.lightgrey),
            ('BACKGROUND', (1, 1), (1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph("FILE DETAILS", self.styles['ForensicHeading']))
        story.append(Spacer(1, 0.1*inch))
        
        files_to_show = metadata
        
        for idx, file_data in enumerate(files_to_show, 1):
            if idx > 1:
                story.append(Spacer(1, 0.1*inch))
            
            story.append(Paragraph(
                f"File #{idx}: {file_data.get('name', 'N/A')}",
                self.styles['ForensicHeading']
            ))
            
            share_link = file_data.get('share_link', 'N/A')
            url_value = share_link if share_link != 'N/A' else 'N/A'
            
            file_id = file_data.get('id', 'N/A')
            file_table_data = [
                ['Field', 'Value'],
                ['ID', Paragraph(file_id, self.styles['ForensicURL'])],
                ['Type', file_data.get('file_type', 'N/A')],
                ['Path', file_data.get('full_path', 'N/A')],
                ['Creation Date', file_data.get('creation_date', 'N/A')],
                ['Modification Date', file_data.get('modification_date', 'N/A')],
                ['Last Viewed', file_data.get('last_viewed_date', 'N/A')],
                ['Size', file_data.get('size_formatted', 'N/A')],
                ['Owner', Paragraph(f"{file_data.get('owner_name', 'N/A')} ({file_data.get('owner_email', 'N/A')})", self.styles['ForensicURL'])],
                ['Last Modifier', Paragraph(f"{file_data.get('last_modifier_name', 'N/A')} ({file_data.get('last_modifier_email', 'N/A')})", self.styles['ForensicURL'])],
                ['Shared', 'Yes' if file_data.get('shared') else 'No'],
                ['MD5 Checksum', file_data.get('md5_checksum', 'N/A')],
            ]
            
            file_table_data.append(['URL', Paragraph(url_value, self.styles['ForensicURL'])])
            
            file_table = Table(file_table_data, colWidths=[2*inch, 4*inch])
            
            table_style = TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 1), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (1, -1), (1, -1), 7),
                ('VALIGN', (1, -1), (1, -1), 'TOP'),
                ('LEFTPADDING', (1, -1), (1, -1), 4),
                ('RIGHTPADDING', (1, -1), (1, -1), 4),
            ])
            
            file_table.setStyle(table_style)
            story.append(file_table)
            
            if idx < len(files_to_show):
                story.append(Spacer(1, 0.15*inch))
        
        story.append(PageBreak())
        story.append(Paragraph("LEGAL NOTICE", self.styles['ForensicHeading']))
        story.append(Paragraph(
            "This report has been generated through automatic metadata extraction "
            "from Google Drive. The dates and metadata shown are those recorded by "
            "the Google Drive system at the time of extraction.",
            self.styles['ForensicText']
        ))
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            f"Report generated on {report_date}",
            self.styles['ForensicText']
        ))
        
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph("FORENSIC INTEGRITY HASH", self.styles['ForensicHeading']))
        
        story.append(Spacer(1, 0.1*inch))
        hash_text = f"<b>SHA-256:</b> {file_hash}"
        story.append(Paragraph(hash_text, self.styles['ForensicText']))
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph(
            "This hash is calculated on immutable forensic data only (file IDs, names, "
            "modification dates, sizes, checksums). It changes only when files are added, "
            "removed, or modified. Viewing files does not affect this hash.",
            self.styles['ForensicText']
        ))
        
        self._max_page = 0
        self.total_pages = None
        
        doc.build(story, onFirstPage=self._add_footer, onLaterPages=self._add_footer)
        
        try:
            import PyPDF2
            with open(self.output_path, 'rb') as pdf_file:
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                total_pages = len(pdf_reader.pages)
            
            if total_pages != self._max_page and total_pages > 0:
                self.total_pages = total_pages
                import os
                if os.path.exists(self.output_path):
                    os.remove(self.output_path)
                self._max_page = 0
                doc.build(story, onFirstPage=self._add_footer, onLaterPages=self._add_footer)
            else:
                self.total_pages = self._max_page if self._max_page > 0 else 1
        except ImportError:
            self.total_pages = self._max_page if self._max_page > 0 else 1
        except Exception as e:
            self.total_pages = self._max_page if self._max_page > 0 else 1
        print(f"✓ PDF exported: {self.output_path}")
        print(f"  Forensic Hash (SHA-256): {file_hash}")
        print(f"  Note: PDF hash includes generation timestamp. For deterministic hash, use JSON/CSV files.")
    
    def _add_footer(self, canvas, doc):
        """
        Add footer with forensic hash and page numbers to all pages.
        
        Args:
            canvas: ReportLab canvas object
            doc: Document object
        """
        canvas.saveState()
        page_width = doc.pagesize[0]
        footer_y = 8 * mm
        gray_color = colors.HexColor('#666666')
        canvas.setFillColor(gray_color)
        canvas.setFont("Helvetica", 7)
        current_page = canvas.getPageNumber()

        self._max_page = max(self._max_page, current_page)
        
        total_pages = self.total_pages if self.total_pages is not None else self._max_page
        hash_text = f"SHA-256: {self.forensic_hash}"
        canvas.drawCentredString(page_width / 2.0, footer_y + 10, hash_text)
        
        if total_pages > 0:
            page_num_text = f"{current_page}/{total_pages}"
        else:
            page_num_text = f"{current_page}"
        
        canvas.drawCentredString(page_width / 2.0, footer_y, page_num_text)
        
        canvas.restoreState()
    
    def _format_size(self, size_bytes: int) -> str:
        """Formats size in bytes"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
