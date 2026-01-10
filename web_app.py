#!/usr/bin/env python3
"""
Web application for forensic metadata extraction from Google Drive
"""
import os
import sys
import json
import threading
import time
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, send_file
from flask_cors import CORS
from flask.json import jsonify as flask_jsonify
import webbrowser

sys.path.insert(0, str(Path(__file__).parent / 'src'))

def setup_jinja_filters(app):
    """Setup custom Jinja2 filters"""
    @app.template_filter('tojson')
    def tojson_filter(obj):
        """Convert Python object to JSON string"""
        return json.dumps(obj, ensure_ascii=False)
    
    if 'tojson' not in app.jinja_env.filters:
        app.jinja_env.filters['tojson'] = tojson_filter

from auth import authenticate, test_connection
from extractor import MetadataExtractor
from exporters import CSVExporter, JSONExporter, PDFExporter
from web_viewer import calculate_file_hash, HTML_TEMPLATE
from helpers import extract_folder_id_from_url

app = Flask(__name__)
CORS(app)

setup_jinja_filters(app)

extraction_state = {
    'status': 'idle',
    'progress': 0,
    'total': 0,
    'current_phase': '',
    'message': '',
    'metadata': None,
    'output_path': None,
    'error': None,
    'start_time': None,
    'elapsed_time': 0
}

extraction_lock = threading.Lock()
extraction_thread = None
pause_event = threading.Event()
stop_event = threading.Event()
extraction_thread = None
pause_event = threading.Event()
stop_event = threading.Event()

MAIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Metadata Sniffer - Forensic Extractor</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: white;
            min-height: 100vh;
            padding: 10px;
            margin: 0;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border: 2px solid black;
            border-radius: 0;
            box-shadow: none;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            height: calc(100vh - 20px);
        }
        
        .header {
            background: black;
            color: white;
            padding: 15px 20px;
            text-align: center;
            flex-shrink: 0;
        }
        
        .header h1 {
            font-size: 1.8em;
            margin-bottom: 5px;
        }
        
        .header .subtitle {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .content {
            padding: 15px 20px;
            flex: 1;
            overflow-y: auto;
            overflow-x: hidden;
        }
        
        .form-section {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        
        .form-section h2 {
            font-size: 1.2em;
            margin-bottom: 10px;
        }
        
        .form-group {
            margin-bottom: 12px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: black;
            font-weight: 500;
            font-size: 0.9em;
        }
        
        .form-group input,
        .form-group select {
            width: 100%;
            padding: 8px;
            border: 2px solid black;
            border-radius: 0;
            font-size: 0.9em;
            background: white;
            color: black;
        }
        
        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: black;
        }
        
        .form-group small {
            display: block;
            margin-top: 3px;
            color: black;
            font-size: 0.75em;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 0.95em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: black;
            color: white;
            border: 2px solid black;
        }
        
        .btn-primary:hover {
            background: white;
            color: black;
        }
        
        .btn-primary:disabled {
            background: #999;
            border-color: #999;
            cursor: not-allowed;
        }
        
        .btn-secondary {
            background: white;
            color: black;
            border: 2px solid black;
        }
        
        .btn-secondary:hover {
            background: black;
            color: white;
        }
        
        .progress-section {
            display: none;
            margin-top: 10px;
        }
        
        .progress-section.active {
            display: block;
        }
        
        .progress-section h2 {
            font-size: 1.1em;
            margin-bottom: 10px;
        }
        
        .status-message {
            padding: 15px;
            background: white;
            border: 2px solid black;
            border-radius: 0;
            margin-top: 10px;
            color: black;
            font-size: 0.9em;
            position: relative;
            overflow: hidden;
            min-height: 50px;
            transition: background-color 0.3s ease;
        }
        
        .status-message::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            height: 100%;
            width: 0%;
            background: black;
            transition: width 0.3s ease;
            z-index: 0;
        }
        
        .status-message .status-content {
            position: relative;
            z-index: 1;
            color: black;
            transition: color 0.3s ease;
        }
        
        .status-message.progress-fill::before {
            width: var(--progress-width, 0%);
        }
        
        .status-message.progress-fill .status-content {
            color: white;
        }
        
        .error-message {
            padding: 10px;
            background: black;
            border: 2px solid black;
            border-radius: 0;
            margin-top: 10px;
            color: white;
            font-size: 0.85em;
        }
        
        .results-section {
            display: none;
            margin-top: 10px;
        }
        
        .results-section.active {
            display: block;
        }
        
        .results-header {
            background: black;
            color: white;
            padding: 10px 15px;
            border-radius: 0;
            margin-bottom: 10px;
        }
        
        .results-header h2 {
            font-size: 1.1em;
            margin: 0;
        }
        
        .results-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 8px;
            margin-bottom: 10px;
        }
        
        .stat-card {
            background: #f8f9fa;
            padding: 8px 10px;
            border-radius: 4px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 1.2em;
            font-weight: bold;
            color: black;
            line-height: 1.2;
        }
        
        .stat-label {
            color: black;
            margin-top: 2px;
            font-size: 0.75em;
        }
        
        .action-buttons {
            display: flex;
            gap: 8px;
            margin-top: 10px;
            flex-wrap: wrap;
        }
        
        .action-buttons .btn {
            padding: 8px 12px;
            font-size: 0.85em;
            flex: 1;
            min-width: 120px;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9em;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
        }
        
        .footer {
            background: white;
            padding: 12px 20px;
            border-top: 2px solid black;
            text-align: center;
            font-size: 0.85em;
            color: black;
            flex-shrink: 0;
        }
        
        .footer a {
            color: black;
            text-decoration: underline;
        }
        
        .footer a:hover {
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Metadata Sniffer</h1>
            <div class="subtitle">Forensic Metadata Extractor for Google Drive</div>
        </div>
        
        <div class="content">
            <div class="form-section">
                <h2>Extraction Configuration</h2>
                
                <form id="extraction-form">
                    <div class="form-group">
                        <label for="folder-id">Folder ID or Shared Link (Optional)</label>
                        <input type="text" id="folder-id" name="folder_id" placeholder="Paste folder ID or shared link (leave empty to scan entire Drive)">
                        <small>You can paste either the folder ID or a Google Drive shared link. The tool will automatically extract the ID from the link.</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="output-name">Output File Name</label>
                        <input type="text" id="output-name" name="output_name" value="forensic_metadata" required>
                        <small>Base name for generated files (CSV, JSON, PDF)</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="workers">Parallel Workers</label>
                        <select id="workers" name="workers">
                            <option value="1">1 worker (Sequential - Recommended for Stability)</option>
                            <option value="auto">Auto (Max 4 workers)</option>
                            <option value="2">2 workers</option>
                            <option value="4">4 workers (Max - May cause issues)</option>
                        </select>
                        <small>⚠ Use 1 worker if experiencing crashes. Sequential processing is safest.</small>
                    </div>
                    
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="include-trashed" name="include_trashed">
                            <label for="include-trashed">Include trashed files</label>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <small style="color: #666;">Note: All files (CSV, JSON, PDF) will be generated automatically for forensic integrity.</small>
                    </div>
                    
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <button type="submit" class="btn btn-primary" id="start-btn">
                            ▶️ Start Extraction
                        </button>
                        <button type="button" class="btn btn-secondary" id="pause-btn" style="display: none;">
                            ⏸️ Pause
                        </button>
                        <button type="button" class="btn btn-secondary" id="stop-btn" style="display: none;">
                            ⏹️ Stop
                        </button>
                    </div>
                </form>
            </div>
            
            <div class="progress-section" id="progress-section">
                <h2>Extraction Progress</h2>
                
                <div class="progress-info">
                    <span id="phase-text">Initializing...</span>
                    <span id="time-text">00:00</span>
                </div>
                
                <div class="status-message" id="status-message">
                    <div class="status-content">
                        <strong id="progress-percent">0%</strong> - Preparing extraction...
                    </div>
                </div>
            </div>
            
            <div class="results-section" id="results-section">
                <div class="results-header">
                    <h2>✓ Extraction Completed Successfully!</h2>
                </div>
                
                <div class="results-stats" id="results-stats">
                    <!-- Stats will be inserted here -->
                </div>
                
                <div class="action-buttons">
                    <button class="btn btn-primary" onclick="viewResults()">📊 View Results</button>
                    <button class="btn btn-secondary" onclick="downloadFile('csv')">📥 Download CSV</button>
                    <button class="btn btn-secondary" onclick="downloadFile('json')">📥 Download JSON</button>
                    <button class="btn btn-secondary" onclick="downloadFile('pdf')">📥 Download PDF</button>
                    <button class="btn btn-secondary" onclick="resetForm()">🔄 New Extraction</button>
                </div>
            </div>
        </div>
        
        <div class="footer">
            Made with ❤️ by <a href="https://e1digital.vercel.app" target="_blank" rel="noopener noreferrer">E1DIGITAL</a>
        </div>
    </div>
    
    <script>
        let pollInterval = null;
        
        document.getElementById('extraction-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const startBtn = document.getElementById('start-btn');
            
            if (startBtn.textContent.includes('Pause')) {
                try {
                    const response = await fetch('/api/pause-extraction', { method: 'POST' });
                    if (response.ok) {
                        startBtn.textContent = '⏸️ Paused';
                        startBtn.disabled = true;
                        document.getElementById('pause-btn').textContent = '▶️ Resume';
                        document.getElementById('pause-btn').style.display = 'inline-block';
                    }
                } catch (error) {
                    console.error('Error pausing extraction:', error);
                }
                return;
            }
            
            const formData = new FormData(e.target);
            const data = {
                folder_id: formData.get('folder_id') || null,
                output_name: formData.get('output_name'),
                workers: formData.get('workers') === 'auto' ? null : parseInt(formData.get('workers')),
                include_trashed: formData.get('include_trashed') === 'on'
            };
            
            startBtn.disabled = true;
            document.getElementById('progress-section').classList.add('active');
            document.getElementById('results-section').classList.remove('active');
            
            try {
                const response = await fetch('/api/start-extraction', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                });
                
                if (!response.ok) {
                    throw new Error('Failed to start extraction');
                }
                
                startBtn.textContent = '⏸️ Pause';
                startBtn.disabled = false;
                document.getElementById('pause-btn').style.display = 'none';
                document.getElementById('stop-btn').style.display = 'inline-block';
                
                startPolling();
            } catch (error) {
                alert('Error starting extraction: ' + error.message);
                startBtn.disabled = false;
            }
        });
        
        document.getElementById('pause-btn').addEventListener('click', async () => {
            const btn = document.getElementById('pause-btn');
            const startBtn = document.getElementById('start-btn');
            
            if (btn.textContent.includes('Resume')) {
                try {
                    const response = await fetch('/api/resume-extraction', { method: 'POST' });
                    if (response.ok) {
                        btn.textContent = '⏸️ Pause';
                        btn.style.display = 'none';
                        startBtn.textContent = '⏸️ Pause';
                        startBtn.disabled = false;
                    }
                } catch (error) {
                    console.error('Error resuming extraction:', error);
                }
            } else {
                try {
                    const response = await fetch('/api/pause-extraction', { method: 'POST' });
                    if (response.ok) {
                        btn.textContent = '▶️ Resume';
                        startBtn.textContent = '⏸️ Paused';
                        startBtn.disabled = true;
                    }
                } catch (error) {
                    console.error('Error pausing extraction:', error);
                }
            }
        });
        
        document.getElementById('stop-btn').addEventListener('click', async () => {
            if (confirm('Are you sure you want to stop the extraction? Progress will be lost.')) {
                try {
                    const response = await fetch('/api/stop-extraction', { method: 'POST' });
                    if (response.ok) {
                        document.getElementById('start-btn').textContent = '🚀 Start Extraction';
                        document.getElementById('start-btn').disabled = false;
                        document.getElementById('pause-btn').style.display = 'none';
                        document.getElementById('stop-btn').style.display = 'none';
                        document.getElementById('progress-section').classList.remove('active');
                        
                        const statusMessage = document.getElementById('status-message');
                        statusMessage.style.setProperty('--progress-width', '0%');
                        statusMessage.classList.remove('progress-fill');
                        statusMessage.querySelector('.status-content').innerHTML = '<strong>0%</strong> - Ready';
                        document.getElementById('phase-text').textContent = 'Initializing...';
                        document.getElementById('time-text').textContent = '00:00';
                        
                        if (pollInterval) {
                            clearInterval(pollInterval);
                            pollInterval = null;
                        }
                    }
                } catch (error) {
                    console.error('Error stopping extraction:', error);
                }
            }
        });
        
        function startPolling() {
            pollInterval = setInterval(async () => {
                try {
                    const response = await fetch('/api/progress');
                    const data = await response.json();
                    
                    updateProgress(data);
                    
                    const startBtn = document.getElementById('start-btn');
                    const pauseBtn = document.getElementById('pause-btn');
                    const stopBtn = document.getElementById('stop-btn');
                    
                    if (data.status === 'running') {
                        startBtn.textContent = '⏸️ Pause';
                        startBtn.disabled = false;
                        pauseBtn.style.display = 'none';
                        stopBtn.style.display = 'inline-block';
                    } else if (data.status === 'paused') {
                        startBtn.textContent = '⏸️ Paused';
                        startBtn.disabled = true;
                        pauseBtn.textContent = '▶️ Resume';
                        pauseBtn.style.display = 'inline-block';
                        stopBtn.style.display = 'inline-block';
                    } else if (data.status === 'completed' || data.status === 'error' || data.status === 'stopped') {
                        clearInterval(pollInterval);
                        startBtn.textContent = '🚀 Start Extraction';
                        startBtn.disabled = false;
                        pauseBtn.style.display = 'none';
                        stopBtn.style.display = 'none';
                        
                        if (data.status === 'completed') {
                            document.getElementById('results-section').classList.add('active');
                            showResults(data);
                        } else if (data.status === 'stopped') {
                            document.getElementById('progress-section').classList.remove('active');
                        }
                    }
                } catch (error) {
                    console.error('Error polling progress:', error);
                }
            }, 500);
        }
        
        function updateProgress(data) {
            const progress = (data.total > 0 && data.progress >= 0) ? (data.progress / data.total) * 100 : 0;
            const progressPercent = Math.max(0, Math.min(100, Math.round(progress)));
            
            const statusMessage = document.getElementById('status-message');
            const statusContent = statusMessage.querySelector('.status-content');
            
            statusMessage.style.setProperty('--progress-width', progressPercent + '%');
            
            if (progressPercent > 0) {
                statusMessage.classList.add('progress-fill');
            } else {
                statusMessage.classList.remove('progress-fill');
            }
            
            const message = data.message || 'Processing...';
            statusContent.innerHTML = `<strong>${progressPercent}%</strong> - ${message}`;
            
            document.getElementById('phase-text').textContent = data.current_phase || 'Processing...';
            
            const elapsed = Math.floor(data.elapsed_time || 0);
            const minutes = Math.floor(elapsed / 60);
            const seconds = elapsed % 60;
            document.getElementById('time-text').textContent = 
                `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
            
            if (data.status === 'error' || data.error) {
                statusMessage.className = 'error-message';
                statusContent.innerHTML = '<strong>Error:</strong> ' + (data.error || 'Unknown error');
            } else {
                statusMessage.className = 'status-message';
            }
        }
        
        function showResults(data) {
            const stats = `
                <div class="stat-card">
                    <div class="stat-value">${data.total || 0}</div>
                    <div class="stat-label">Total Files</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${data.output_path || 'N/A'}</div>
                    <div class="stat-label">Output Path</div>
                </div>
            `;
            document.getElementById('results-stats').innerHTML = stats;
        }
        
        function viewResults() {
            window.open('/viewer', '_blank');
        }
        
        function downloadFile(format) {
            window.location.href = `/api/download/${format}`;
        }
        
        function resetForm() {
            document.getElementById('extraction-form').reset();
            document.getElementById('progress-section').classList.remove('active');
            document.getElementById('results-section').classList.remove('active');
            if (pollInterval) {
                clearInterval(pollInterval);
            }
        }
        
        fetch('/api/progress').then(r => r.json()).then(data => {
            if (data.status === 'running') {
                document.getElementById('progress-section').classList.add('active');
                document.getElementById('start-btn').disabled = true;
                startPolling();
            } else if (data.status === 'completed') {
                document.getElementById('results-section').classList.add('active');
                showResults(data);
            }
        });
    </script>
</body>
</html>
"""


def update_progress(status, progress, total, message):
    """Update extraction progress"""
    global extraction_state
    with extraction_lock:
        extraction_state['current_phase'] = status
        extraction_state['progress'] = progress
        extraction_state['total'] = total
        extraction_state['message'] = message
        if extraction_state['start_time']:
            extraction_state['elapsed_time'] = time.time() - extraction_state['start_time']


def run_extraction(folder_id, output_name, workers, include_trashed, export_formats):
    """Run extraction in background thread"""
    global extraction_state, pause_event, stop_event
    
    pause_event.clear()
    stop_event.clear()
    
    try:
        with extraction_lock:
            extraction_state['status'] = 'running'
            extraction_state['progress'] = 0
            extraction_state['total'] = 0
            extraction_state['error'] = None
            extraction_state['start_time'] = time.time()
            extraction_state['current_phase'] = 'authenticating'
            extraction_state['message'] = 'Connecting to Google Drive...'
            extraction_state['metadata'] = None
            extraction_state['output_path'] = None
        
        if stop_event.is_set():
            with extraction_lock:
                extraction_state['status'] = 'stopped'
                extraction_state['message'] = 'Extraction stopped by user'
            return
        
        update_progress('authenticating', 0, 0, 'Authenticating with Google Drive...')
        if stop_event.is_set():
            with extraction_lock:
                extraction_state['status'] = 'stopped'
                extraction_state['message'] = 'Extraction stopped by user'
            return
        
        service = authenticate()
        if not test_connection(service):
            raise Exception("Could not establish connection with Google Drive")
        
        update_progress('initializing', 0, 0, 'Initializing extractor...')
        if stop_event.is_set():
            with extraction_lock:
                extraction_state['status'] = 'stopped'
                extraction_state['message'] = 'Extraction stopped by user'
            return
        
        extractor = MetadataExtractor(service, max_workers=workers)
        
        def progress_callback(status, progress, total, message):
            if stop_event.is_set():
                return
            if pause_event.is_set():
                with extraction_lock:
                    extraction_state['status'] = 'paused'
                    extraction_state['message'] = 'Extraction paused. Click Resume to continue.'
                while pause_event.is_set() and not stop_event.is_set():
                    time.sleep(0.1)
                if stop_event.is_set():
                    return
                with extraction_lock:
                    if extraction_state['status'] == 'paused':
                        extraction_state['status'] = 'running'
                        extraction_state['message'] = 'Resuming extraction...'
            update_progress(status, progress, total, message)
        
        metadata = extractor.extract_folder(
            folder_id=folder_id,
            include_trashed=include_trashed,
            progress_callback=progress_callback
        )
        
        if stop_event.is_set():
            with extraction_lock:
                extraction_state['status'] = 'stopped'
                extraction_state['message'] = 'Extraction stopped by user'
            return
        
        if not metadata:
            raise Exception("No files found to extract")
        
        if stop_event.is_set():
            with extraction_lock:
                extraction_state['status'] = 'stopped'
                extraction_state['message'] = 'Extraction stopped by user'
            return
        
        with extraction_lock:
            extraction_state['total'] = len(metadata)
            extraction_state['progress'] = len(metadata)
            extraction_state['current_phase'] = 'Exporting results...'
            extraction_state['message'] = f'Exporting {len(metadata)} files...'
        
        output_dir = Path('output')
        output_dir.mkdir(exist_ok=True)
        output_path = output_dir / Path(output_name).name
        
        if stop_event.is_set():
            with extraction_lock:
                extraction_state['status'] = 'stopped'
                extraction_state['message'] = 'Extraction stopped by user'
            return
        
        if 'csv' in export_formats:
            csv_exporter = CSVExporter(str(output_path))
            csv_exporter.export(metadata)
        
        if stop_event.is_set():
            with extraction_lock:
                extraction_state['status'] = 'stopped'
                extraction_state['message'] = 'Extraction stopped by user'
            return
        
        if 'json' in export_formats:
            json_exporter = JSONExporter(str(output_path))
            json_exporter.export(metadata)
        
        if stop_event.is_set():
            with extraction_lock:
                extraction_state['status'] = 'stopped'
                extraction_state['message'] = 'Extraction stopped by user'
            return
        
        if 'pdf' in export_formats:
            pdf_exporter = PDFExporter(str(output_path))
            pdf_exporter.export(metadata)
        
        if stop_event.is_set():
            with extraction_lock:
                extraction_state['status'] = 'stopped'
                extraction_state['message'] = 'Extraction stopped by user'
            return
        
        with extraction_lock:
            extraction_state['status'] = 'completed'
            extraction_state['metadata'] = metadata
            extraction_state['output_path'] = f"output/{output_path.name}"
            extraction_state['message'] = f'Successfully extracted {len(metadata)} files!'
            extraction_state['elapsed_time'] = time.time() - extraction_state['start_time']
        
    except Exception as e:
        if not stop_event.is_set():
            with extraction_lock:
                extraction_state['status'] = 'error'
                extraction_state['error'] = str(e)
                extraction_state['message'] = f'Error: {str(e)}'


@app.route('/')
def index():
    """Main page"""
    return render_template_string(MAIN_TEMPLATE)


@app.route('/api/start-extraction', methods=['POST'])
def start_extraction():
    """Start extraction"""
    global extraction_state, stop_event, pause_event
    
    with extraction_lock:
        if extraction_state['status'] == 'running':
            return jsonify({'error': 'Extraction already running'}), 400
        
        data = request.json
        folder_id_input = data.get('folder_id')
        
        folder_id = None
        if folder_id_input and folder_id_input.strip():
            folder_id = extract_folder_id_from_url(folder_id_input.strip())
            if not folder_id:
                return jsonify({'error': 'Invalid folder ID or shared link format. Please provide a valid Google Drive folder ID or shared link.'}), 400
        
        output_name = data.get('output_name', 'forensic_metadata')
        workers = data.get('workers')
        include_trashed = data.get('include_trashed', False)
        
        export_formats = ['csv', 'json', 'pdf']
        
        stop_event.clear()
        pause_event.clear()
        
        extraction_state = {
            'status': 'idle',
            'progress': 0,
            'total': 0,
            'current_phase': '',
            'message': '',
            'metadata': None,
            'output_path': None,
            'error': None,
            'start_time': None,
            'elapsed_time': 0
        }
        
        thread = threading.Thread(
            target=run_extraction,
            args=(folder_id, output_name, workers, include_trashed, export_formats),
            daemon=True
        )
        thread.start()
        
        return jsonify({'status': 'started'})


@app.route('/api/progress')
def get_progress():
    """Get extraction progress"""
    global extraction_state
    
    with extraction_lock:
        if extraction_state['start_time']:
            extraction_state['elapsed_time'] = time.time() - extraction_state['start_time']
    
    return jsonify(extraction_state)


@app.route('/api/pause-extraction', methods=['POST'])
def pause_extraction():
    """Pause the extraction"""
    global extraction_state, pause_event
    
    with extraction_lock:
        if extraction_state['status'] == 'running':
            pause_event.set()
            extraction_state['status'] = 'paused'
            extraction_state['message'] = 'Extraction paused. Click Resume to continue.'
            return jsonify({'status': 'paused'})
        else:
            return jsonify({'error': 'Extraction is not running'}), 400


@app.route('/api/resume-extraction', methods=['POST'])
def resume_extraction():
    """Resume the extraction"""
    global extraction_state, pause_event
    
    with extraction_lock:
        if extraction_state['status'] == 'paused':
            pause_event.clear()
            extraction_state['status'] = 'running'
            extraction_state['message'] = 'Resuming extraction...'
            return jsonify({'status': 'resumed'})
        else:
            return jsonify({'error': 'Extraction is not paused'}), 400


@app.route('/api/stop-extraction', methods=['POST'])
def stop_extraction():
    """Stop the extraction"""
    global extraction_state, stop_event, pause_event
    
    with extraction_lock:
        if extraction_state['status'] in ['running', 'paused']:
            stop_event.set()
            pause_event.clear()
            
            extraction_state = {
                'status': 'idle',
                'progress': 0,
                'total': 0,
                'current_phase': '',
                'message': 'Extraction stopped by user',
                'metadata': None,
                'output_path': None,
                'error': None,
                'start_time': None,
                'elapsed_time': 0
            }
            
            return jsonify({'status': 'stopped'})
        else:
            return jsonify({'error': 'No extraction to stop'}), 400


@app.route('/api/download/<format>')
def download_file(format):
    """Download exported file"""
    global extraction_state
    
    with extraction_lock:
        if not extraction_state['output_path']:
            return jsonify({'error': 'No file available'}), 404
        
        output_dir = Path('output')
        output_path_str = extraction_state['output_path']
        
        if output_path_str.startswith('output/'):
            file_path = Path(output_path_str).with_suffix(f'.{format}')
        else:
            file_path = output_dir / Path(output_path_str).with_suffix(f'.{format}').name
        
        if not file_path.exists():
            return jsonify({'error': f'File not found: {file_path}'}), 404
        
        return send_file(str(file_path), as_attachment=True)


@app.route('/viewer')
def viewer():
    """Results viewer page - redirects to main viewer"""
    global extraction_state
    
    with extraction_lock:
        if not extraction_state['metadata']:
            return "No results available. Please run an extraction first.", 404
        
        
        output_dir = Path('output')
        output_path_str = extraction_state['output_path']
        
        if output_path_str.startswith('output/'):
            json_file = Path(output_path_str).with_suffix('.json')
        else:
            json_file = output_dir / Path(output_path_str).with_suffix('.json').name
        
        file_hash = "N/A"
        extraction_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        metadata_to_display = extraction_state.get('metadata', [])
        
        if json_file.exists():
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    json_data = json.load(f)
                    
                    if 'files' in json_data:
                        metadata_to_display = json_data['files']
                    
                    if 'extraction_metadata' in json_data:
                        if 'file_hash_sha256' in json_data['extraction_metadata']:
                            file_hash = json_data['extraction_metadata']['file_hash_sha256']
                        elif 'forensic_integrity_hash_sha256' in json_data['extraction_metadata']:
                            file_hash = json_data['extraction_metadata']['forensic_integrity_hash_sha256']
                        
                        if 'date' in json_data['extraction_metadata']:
                            date_str = json_data['extraction_metadata']['date']
                            try:
                                dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                                extraction_date = dt.strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                extraction_date = date_str[:19] if len(date_str) > 19 else date_str
            except Exception as e:
                print(f"Warning: Could not read JSON file: {e}")
                if json_file.exists():
                    file_hash = calculate_file_hash(json_file)
        
        if not metadata_to_display:
            metadata_to_display = []
        
        return render_template_string(
            HTML_TEMPLATE,
            data=metadata_to_display,
            total_files=len(metadata_to_display),
            extraction_date=extraction_date,
            file_hash=file_hash
        )


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("="*60)
    print("🌐 Metadata Sniffer Web Application")
    print("="*60)
    print(f"\nServer starting on http://localhost:{port}")
    print("Opening browser automatically...\n")
    
    def open_browser():
        time.sleep(1.5)
        webbrowser.open(f'http://localhost:{port}')
    
    threading.Thread(target=open_browser, daemon=True).start()
    
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)
