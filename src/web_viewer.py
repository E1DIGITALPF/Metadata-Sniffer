"""
Web viewer server for displaying extraction results
"""
import json
import hashlib
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template_string, jsonify
from typing import List, Dict
import webbrowser
import threading
import time


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Metadata Viewer - Metadata Sniffer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: white;
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border: 2px solid black;
            border-radius: 0;
            box-shadow: none;

            overflow: hidden;
        }
        
        .header {
            background: black;
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;

        }
        
        .stats-bar {
            background: white;
            padding: 20px 30px;
            display: flex;
            justify-content: space-around;
            border-bottom: 2px solid black;
            flex-wrap: wrap;
        }
        
        .stat-item {
            text-align: center;
            padding: 10px;

        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: black;
        }
        
        .stat-label {
            color: black;
            font-size: 0.9em;
            margin-top: 5px;
        }
        
        .controls {
            padding: 20px 30px;
            background: white;
            border-bottom: 2px solid black;
        }
        
        .search-box {
            width: 100%;
            padding: 12px;
            font-size: 1em;
            border: 2px solid black;
            border-radius: 0;
            margin-bottom: 15px;
            background: white;
            color: black;
        }
        
        .search-box:focus {
            outline: none;
            border-color: black;
        }
        
        .filters {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        .filter-group {
            flex: 1;
            min-width: 200px;
        }
        
        .filter-group label {
            display: block;
            margin-bottom: 5px;
            color: black;
            font-weight: 500;
        }
        .filter-group select,
        .filter-group input {
            width: 100%;
            padding: 8px;
            border: 2px solid black;
            border-radius: 0;
            font-size: 0.9em;
            background: white;
            color: black;
        }
        
        .table-container {
            overflow-x: auto;
            max-height: 70vh;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: black;
            color: white;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
            white-space: nowrap;
        }
        
        th:hover {
            background: #222;
        }
        
        th.sortable::after {
            content: ' ↕';
            opacity: 0.5;
        }
        
        th.sort-asc::after {
            content: ' ↑';

            opacity: 1;
        }
        
        th.sort-desc::after {
            content: ' ↓';
            opacity: 1;
        }
        
        tbody tr {
            border-bottom: 1px solid #dee2e6;
            transition: background 0.2s;
        }
        
        tbody tr:hover {
            background: #e0e0e0;
        }
        
        td {
            padding: 12px 15px;
            font-size: 0.9em;
        }
        
        .file-type {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
        }
        
        .type-folder { background: white; color: black; border: 1px solid black; }
        .type-doc { background: white; color: black; border: 1px solid black; }
        .type-sheet { background: white; color: black; border: 1px solid black; }
        .type-pdf { background: white; color: black; border: 1px solid black; }
        .type-image { background: white; color: black; border: 1px solid black; }
        .type-other { background: white; color: black; border: 1px solid black; }
        
        .date-cell {
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }
        
        .size-cell {
            font-weight: 500;
            color: black;
        }
        
        .link-cell a {
            color: black;
            text-decoration: underline;
        }
        
        .link-cell a:hover {
            color: black;
            font-weight: bold;
        }
        
        .forensic-hash {
            background: white;
            padding: 20px 30px;
            border-top: 2px solid black;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: black;
        }
        
        .forensic-hash strong {
            color: black;
        }
        
        .footer {
            background: white;
            padding: 20px 30px;
            border-top: 2px solid black;
            text-align: center;
            font-size: 0.9em;
            color: black;
        }
        
        .footer a {
            color: black;
            text-decoration: underline;
        }
        
        .footer a:hover {
            font-weight: bold;
        }
        
        .no-results {
            padding: 40px;
            text-align: center;
            color: black;
            font-size: 1.2em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Forensic Metadata Viewer</h1>
            <div class="subtitle">Google Drive Metadata Extraction Results</div>
        </div>
        
        <div class="stats-bar">
            <div class="stat-item">
                <div class="stat-value" id="total-files">{{ total_files }}</div>
                <div class="stat-label">Total Files</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="filtered-count">{{ total_files }}</div>
                <div class="stat-label">Displayed</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="extraction-date">{{ extraction_date }}</div>
                <div class="stat-label">Extraction Date</div>
            </div>
        </div>
        
        <div class="controls">
            <input type="text" id="search-box" class="search-box" placeholder="Search files by name, type, owner, path...">
            <div class="filters">
                <div class="filter-group">
                    <label>File Type</label>
                    <select id="filter-type">
                        <option value="">All Types</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Owner</label>
                    <select id="filter-owner">
                        <option value="">All Owners</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Date Range (From)</label>
                    <input type="date" id="filter-date-from">
                </div>
                <div class="filter-group">
                    <label>Date Range (To)</label>
                    <input type="date" id="filter-date-to">
                </div>
            </div>
        </div>
        
        <div class="table-container">
            <table id="data-table">
                <thead>
                    <tr>
                        <th class="sortable" data-column="name">Name</th>
                        <th class="sortable" data-column="file_type">Type</th>
                        <th class="sortable" data-column="creation_date">Created</th>
                        <th class="sortable" data-column="modification_date">Modified</th>
                        <th class="sortable" data-column="size_formatted">Size</th>
                        <th class="sortable" data-column="owner_name">Owner</th>
                        <th class="sortable" data-column="full_path">Path</th>
                        <th>Link</th>
                    </tr>
                </thead>
                <tbody id="table-body">
                    <!-- Data will be inserted here -->
                </tbody>
            </table>
        </div>
        
        <div class="forensic-hash">
            <strong>Forensic Integrity Hash (SHA-256):</strong><br>
            <span id="file-hash">{{ file_hash }}</span>
        </div>
        
        <div class="footer">
            Made with ❤️ by <a href="https://e1digital.vercel.app" target="_blank" rel="noopener noreferrer">E1DIGITAL</a>
        </div>
    </div>
    
    <!-- Store JSON data in a script tag to avoid HTML entity encoding issues -->
    <script id="metadata-data" type="application/json">{{ data|tojson|safe }}</script>
    
    <script>
        let allData = [];
        try {
            const dataScript = document.getElementById('metadata-data');
            if (dataScript) {
                const dataString = dataScript.textContent;
                console.log('Data string length:', dataString.length);
                allData = JSON.parse(dataString);
            } else {
                console.error('metadata-data script tag not found!');
            }
            
            if (!Array.isArray(allData)) {
                console.error('Data is not an array:', typeof allData, allData);
                if (allData && typeof allData === 'object') {
                    console.error('Data object keys:', Object.keys(allData));
                }
                allData = [];
            }
        } catch (e) {
            console.error('Error loading data:', e);
            console.error('Error stack:', e.stack);
            allData = [];
        }
        
        console.log('Loaded', allData.length, 'files');
        if (allData.length > 0) {
            console.log('First file keys:', Object.keys(allData[0]));
            console.log('First file name:', allData[0].name);
            console.log('First file sample:', JSON.stringify(allData[0]).substring(0, 300));
        } else {
            console.warn('No files loaded! Check console for errors above.');
            console.warn('Total files from server:', {{ total_files }});
        }
        
        let filteredData = [...allData];
        let sortColumn = 'creation_date';
        let sortDirection = 'desc';
        
        function initFilters() {
            const types = [...new Set(allData.map(f => f.file_type))].sort();
            const owners = [...new Set(allData.map(f => f.owner_email))].sort();
            
            const typeSelect = document.getElementById('filter-type');
            types.forEach(type => {
                const option = document.createElement('option');
                option.value = type;
                option.textContent = type;
                typeSelect.appendChild(option);
            });
            
            const ownerSelect = document.getElementById('filter-owner');
            owners.forEach(owner => {
                const option = document.createElement('option');
                option.value = owner;
                option.textContent = owner;
                ownerSelect.appendChild(option);
            });
        }
        
        function applyFilters() {
            const searchTerm = document.getElementById('search-box').value.toLowerCase();
            const typeFilter = document.getElementById('filter-type').value;
            const ownerFilter = document.getElementById('filter-owner').value;
            const dateFrom = document.getElementById('filter-date-from').value;
            const dateTo = document.getElementById('filter-date-to').value;
            
            filteredData = allData.filter(file => {
                const matchesSearch = !searchTerm || 
                    file.name.toLowerCase().includes(searchTerm) ||
                    file.file_type.toLowerCase().includes(searchTerm) ||
                    file.owner_email.toLowerCase().includes(searchTerm) ||
                    file.full_path.toLowerCase().includes(searchTerm);
                
                const matchesType = !typeFilter || file.file_type === typeFilter;
                const matchesOwner = !ownerFilter || file.owner_email === ownerFilter;
                
                let matchesDate = true;
                if (dateFrom || dateTo) {
                    const createdDate = file.creation_date_raw ? file.creation_date_raw.split('T')[0] : '';
                    if (dateFrom && createdDate < dateFrom) matchesDate = false;
                    if (dateTo && createdDate > dateTo) matchesDate = false;
                }
                
                return matchesSearch && matchesType && matchesOwner && matchesDate;
            });
            
            sortData();
            renderTable();
        }
        
        function sortData() {
            filteredData.sort((a, b) => {
                let aVal = a[sortColumn] || '';
                let bVal = b[sortColumn] || '';
                
                if (sortColumn.includes('date')) {
                    aVal = a.creation_date_raw || '';
                    bVal = b.creation_date_raw || '';
                }
                
                if (sortColumn === 'size_formatted') {
                    const aSize = parseInt(a.size_bytes) || 0;
                    const bSize = parseInt(b.size_bytes) || 0;
                    return sortDirection === 'asc' ? aSize - bSize : bSize - aSize;
                }
                
                if (typeof aVal === 'string') {
                    aVal = aVal.toLowerCase();
                    bVal = bVal.toLowerCase();
                }
                
                if (sortDirection === 'asc') {
                    return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
                } else {
                    return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
                }
            });
        }
        
        function renderTable() {
            const tbody = document.getElementById('table-body');
            const countEl = document.getElementById('filtered-count');
            
            console.log('renderTable called with', filteredData.length, 'files');
            
            if (!tbody) {
                console.error('table-body element not found!');
                return;
            }
            
            if (!countEl) {
                console.error('filtered-count element not found!');
                return;
            }
            
            countEl.textContent = filteredData.length;
            
            if (filteredData.length === 0) {
                console.warn('No files to display');
                tbody.innerHTML = '<tr><td colspan="8" class="no-results">No files match the current filters</td></tr>';
                return;
            }
            
            console.log('Rendering', filteredData.length, 'files to table');
            const tableHTML = filteredData.map(file => {
                const typeClass = getTypeClass(file.file_type);
                return `
                    <tr>
                        <td><strong>${escapeHtml(file.name || 'N/A')}</strong></td>
                        <td><span class="file-type ${typeClass}">${escapeHtml(file.file_type || 'N/A')}</span></td>
                        <td class="date-cell">${escapeHtml(file.creation_date || 'N/A')}</td>
                        <td class="date-cell">${escapeHtml(file.modification_date || 'N/A')}</td>
                        <td class="size-cell">${escapeHtml(file.size_formatted || 'N/A')}</td>
                        <td>${escapeHtml(file.owner_name || file.owner_email || 'N/A')}</td>
                        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(file.full_path || 'N/A')}">${escapeHtml(file.full_path || 'N/A')}</td>
                        <td class="link-cell">${file.share_link && file.share_link !== 'N/A' ? `<a href="${escapeHtml(file.share_link)}" target="_blank">Open</a>` : 'N/A'}</td>
                    </tr>
                `;
            }).join('');
            
            console.log('Generated table HTML length:', tableHTML.length);
            console.log('First 500 chars of table HTML:', tableHTML.substring(0, 500));
            
            tbody.innerHTML = tableHTML;
            
            console.log('Table rendered. tbody children:', tbody.children.length);
        }
        
        function getTypeClass(type) {
            if (!type) return 'type-other';
            const lower = type.toLowerCase();
            if (lower.includes('folder')) return 'type-folder';
            if (lower.includes('doc')) return 'type-doc';
            if (lower.includes('sheet')) return 'type-sheet';
            if (lower.includes('pdf')) return 'type-pdf';
            if (lower.includes('image') || lower.includes('jpeg') || lower.includes('png')) return 'type-image';
            return 'type-other';
        }
        
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        document.getElementById('search-box').addEventListener('input', applyFilters);
        document.getElementById('filter-type').addEventListener('change', applyFilters);
        document.getElementById('filter-owner').addEventListener('change', applyFilters);
        document.getElementById('filter-date-from').addEventListener('change', applyFilters);
        document.getElementById('filter-date-to').addEventListener('change', applyFilters);
        
        document.querySelectorAll('.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const column = th.dataset.column;
                
                if (sortColumn === column) {
                    sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
                } else {
                    sortColumn = column;
                    sortDirection = 'asc';
                }
                
                document.querySelectorAll('.sortable').forEach(t => {
                    t.classList.remove('sort-asc', 'sort-desc');
                });
                th.classList.add(sortDirection === 'asc' ? 'sort-asc' : 'sort-desc');
                
                sortData();
                renderTable();
            });
        });
        
        if (allData.length > 0) {
            initFilters();
            sortData();
            renderTable();
            
            const sortElement = document.querySelector('[data-column="creation_date"]');
            if (sortElement) {
                sortElement.classList.add('sort-desc');
            }
        } else {
            const tbody = document.getElementById('table-body');
            const countEl = document.getElementById('filtered-count');
            if (countEl) countEl.textContent = '0';
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="8" class="no-results">No files found. Please check the extraction results.</td></tr>';
            }
            console.error('No data available to display. Data type:', typeof allData, 'Length:', allData.length);
        }
    </script>
</body>
</html>
"""


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


class WebViewer:
    """Web viewer for displaying extraction results"""
    
    def __init__(self, metadata: List[Dict], output_path: str):
        """
        Args:
            metadata: List of metadata dictionaries
            output_path: Base path for output files
        """
        self.metadata = metadata
        self.output_path = Path(output_path)
        self.app = Flask(__name__)
        self.port = 5000
        self.setup_routes()
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            json_file = self.output_path.with_suffix('.json')
            file_hash = "N/A"
            extraction_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            if json_file.exists():
                file_hash = calculate_file_hash(json_file)
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        json_data = json.load(f)
                        if 'extraction_metadata' in json_data and 'date' in json_data['extraction_metadata']:
                            date_str = json_data['extraction_metadata']['date']
                            try:
                                dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                                extraction_date = dt.strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                extraction_date = date_str[:19] if len(date_str) > 19 else date_str
                except:
                    pass
            
            return render_template_string(
                HTML_TEMPLATE,
                data=json.dumps(self.metadata),
                total_files=len(self.metadata),
                extraction_date=extraction_date,
                file_hash=file_hash
            )
        
        @self.app.route('/api/data')
        def api_data():
            return jsonify(self.metadata)
    
    def start_server(self, open_browser: bool = True):
        """
        Start the web server and optionally open browser.
        
        Args:
            open_browser: Whether to automatically open browser
        """
        if open_browser:
            def open_browser_delayed():
                time.sleep(1.5)
                webbrowser.open(f'http://localhost:{self.port}')
            
            threading.Thread(target=open_browser_delayed, daemon=True).start()
        
        print(f"\n{'='*60}")
        print(f"🌐 Web viewer started at: http://localhost:{self.port}")
        print(f"{'='*60}\n")
        print("Press Ctrl+C to stop the server\n")
        
        try:
            self.app.run(host='127.0.0.1', port=self.port, debug=False, use_reloader=False)
        except KeyboardInterrupt:
            print("\n\nServer stopped.")