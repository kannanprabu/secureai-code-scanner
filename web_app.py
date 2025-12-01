"""
Simple Web Interface for SecureCodeAI
Run this instead of using command line
"""

from flask import Flask, render_template_string, request, jsonify, send_file
import os
import sys
import threading
import json
import logging
from pathlib import Path
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set UTF-8 for Windows
os.environ['PYTHONUTF8'] = '1'
os.environ['PYTHONIOENCODING'] = 'utf-8'

# Import the scanner
from code_review_agent_final import EnhancedCodeReviewAgent

app = Flask(__name__)

# Store scan status
scan_status = {
    'running': False,
    'progress': '',
    'results': None,
    'error': None
}

# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SecureCodeAI - Web Scanner</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
        }
        
        h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 32px;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
        }
        
        input[type="text"], select {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        input[type="text"]:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 30px;
        }
        
        button {
            flex: 1;
            padding: 15px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        
        .btn-primary:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-secondary {
            background: white;
            color: #667eea;
            border: 2px solid #667eea;
        }
        
        .btn-secondary:hover {
            background: #f0f0ff;
        }
        
        .status {
            margin-top: 30px;
            padding: 20px;
            border-radius: 8px;
            display: none;
        }
        
        .status.show {
            display: block;
        }
        
        .status.running {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
        }
        
        .status.success {
            background: #d4edda;
            border-left: 4px solid #28a745;
        }
        
        .status.error {
            background: #f8d7da;
            border-left: 4px solid #dc3545;
        }
        
        .results {
            margin-top: 30px;
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .stat-card {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-card.critical {
            background: #fee;
            border: 2px solid #f00;
        }
        
        .stat-card.high {
            background: #fff3e0;
            border: 2px solid #ff9800;
        }
        
        .stat-card.medium {
            background: #fff9e0;
            border: 2px solid #ffc107;
        }
        
        .stat-card.low {
            background: #e8f5e9;
            border: 2px solid #4caf50;
        }
        
        .stat-number {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 12px;
            text-transform: uppercase;
            color: #666;
        }
        
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 10px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .example-links {
            margin-top: 10px;
            font-size: 12px;
            color: #666;
        }
        
        .example-links a {
            color: #667eea;
            text-decoration: none;
            margin-right: 10px;
        }
        
        .example-links a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SecureCodeAI</h1>
        <p class="subtitle">LLM-Enhanced Security Code Review</p>
        
        <form id="scanForm">
            <div class="form-group">
                <label for="scanType">Scan Type</label>
                <select id="scanType" onchange="updateForm()">
                    <option value="repo">Git Repository (Azure DevOps / GitHub)</option>
                    <option value="local">Local Directory</option>
                </select>
            </div>
            
            <div class="form-group" id="repoGroup">
                <label for="repoUrl">Repository URL</label>
                <input type="text" id="repoUrl" placeholder="https://dev.azure.com/org/project/_git/repo">
                <div class="example-links">
                    Examples:
                    <a href="#" onclick="fillExample('ado'); return false;">Azure DevOps</a>
                    <a href="#" onclick="fillExample('github'); return false;">GitHub</a>
                </div>
            </div>
            
            <div class="form-group" id="localGroup" style="display:none;">
                <label for="localPath">Local Path</label>
                <input type="text" id="localPath" placeholder="C:\\path\\to\\code">
            </div>
            
            <div class="button-group">
                <button type="submit" class="btn-primary" id="scanBtn">
                    🔍 Start Security Scan
                </button>
                <button type="button" class="btn-secondary" onclick="viewResults()">
                    📊 View Results
                </button>
            </div>
        </form>
        
        <div id="status" class="status">
            <div id="statusMessage"></div>
        </div>
        
        <div id="results" class="results" style="display:none;">
            <h2>Scan Results</h2>
            <div class="stat-grid" id="statsGrid"></div>
            <div style="margin-top: 20px; text-align: center;">
                <button onclick="downloadReport()" class="btn-primary" style="display:inline-block; width:auto; padding:12px 30px;">
                    📥 Download Report
                </button>
            </div>
        </div>
    </div>
    
    <script>
        let currentScanId = null;
        
        function updateForm() {
            const scanType = document.getElementById('scanType').value;
            document.getElementById('repoGroup').style.display = scanType === 'repo' ? 'block' : 'none';
            document.getElementById('localGroup').style.display = scanType === 'local' ? 'block' : 'none';
        }
        
        function fillExample(type) {
            if (type === 'ado') {
                document.getElementById('repoUrl').value = 'https://dev.azure.com/yourorg/yourproject/_git/yourrepo';
            } else if (type === 'github') {
                document.getElementById('repoUrl').value = 'https://github.com/yourusername/yourrepo.git';
            }
        }
        
        document.getElementById('scanForm').onsubmit = async function(e) {
            e.preventDefault();
            
            const scanType = document.getElementById('scanType').value;
            const data = {
                scan_type: scanType,
                url: scanType === 'repo' ? document.getElementById('repoUrl').value : document.getElementById('localPath').value
            };
            
            // Disable button
            const btn = document.getElementById('scanBtn');
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Scanning...';
            
            // Show status
            showStatus('running', 'Starting security scan... This may take 5-10 minutes.');
            document.getElementById('results').style.display = 'none';
            
            // Start scan
            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    currentScanId = result.scan_id;
                    checkStatus();
                } else {
                    showStatus('error', result.error || 'Scan failed');
                    btn.disabled = false;
                    btn.innerHTML = '🔍 Start Security Scan';
                }
            } catch (error) {
                showStatus('error', 'Error: ' + error.message);
                btn.disabled = false;
                btn.innerHTML = '🔍 Start Security Scan';
            }
        };
        
        function checkStatus() {
            fetch('/status')
                .then(res => res.json())
                .then(data => {
                    if (data.running) {
                        showStatus('running', data.progress || 'Scanning...');
                        setTimeout(checkStatus, 2000);
                    } else if (data.results) {
                        showResults(data.results);
                        document.getElementById('scanBtn').disabled = false;
                        document.getElementById('scanBtn').innerHTML = '🔍 Start Security Scan';
                    } else if (data.error) {
                        showStatus('error', data.error);
                        document.getElementById('scanBtn').disabled = false;
                        document.getElementById('scanBtn').innerHTML = '🔍 Start Security Scan';
                    }
                });
        }
        
        function showStatus(type, message) {
            const status = document.getElementById('status');
            const statusMessage = document.getElementById('statusMessage');
            status.className = 'status show ' + type;
            statusMessage.innerHTML = type === 'running' ? '<span class="spinner"></span>' + message : message;
        }
        
        function showResults(results) {
            showStatus('success', '✅ Scan completed successfully!');
            
            const resultsDiv = document.getElementById('results');
            const statsGrid = document.getElementById('statsGrid');
            
            statsGrid.innerHTML = `
                <div class="stat-card critical">
                    <div class="stat-number">${results.critical || 0}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">${results.high || 0}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number">${results.medium || 0}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number">${results.low || 0}</div>
                    <div class="stat-label">Low</div>
                </div>
            `;
            
            resultsDiv.style.display = 'block';
        }
        
        function viewResults() {
            window.open('/results', '_blank');
        }
        
        function downloadReport() {
            if (currentScanId) {
                window.open('/download/' + currentScanId);
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    """Home page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def scan():
    """Start a scan"""
    global scan_status
    
    if scan_status['running']:
        return jsonify({'success': False, 'error': 'Scan already running'})
    
    data = request.json
    scan_type = data.get('scan_type')
    url = data.get('url')
    
    if not url:
        return jsonify({'success': False, 'error': 'URL/path required'})
    
    # Reset status
    scan_status = {
        'running': True,
        'progress': 'Starting scan...',
        'results': None,
        'error': None
    }
    
    # Start scan in background
    thread = threading.Thread(target=run_scan, args=(scan_type, url))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'scan_id': datetime.now().strftime('%Y%m%d_%H%M%S')})

def run_scan(scan_type, url):
    """Run the actual scan"""
    global scan_status
    
    try:
        scan_status['progress'] = 'Initializing scanner...'
        agent = EnhancedCodeReviewAgent()
        
        scan_status['progress'] = 'Running security scan...'
        
        if scan_type == 'repo':
            scan_result = agent.scan_github_repo(url)
        else:
            scan_result = agent.scan_local_path(Path(url))
        
        if scan_result and 'analysis' in scan_result:
            analysis = scan_result['analysis']
            scan_status['progress'] = 'Scan completed!'
            scan_status['results'] = {
                'total': analysis.get('total_findings', 0),
                'critical': analysis.get('by_severity', {}).get('CRITICAL', 0),
                'high': analysis.get('by_severity', {}).get('HIGH', 0),
                'medium': analysis.get('by_severity', {}).get('MEDIUM', 0),
                'low': analysis.get('by_severity', {}).get('LOW', 0),
                'report_path': None  # Can add path tracking if needed
            }
        else:
            scan_status['error'] = 'Scan failed - check console for details'
    
    except Exception as e:
        scan_status['error'] = f'Error: {str(e)}'
        import traceback
        logger.error(f"Scan error: {traceback.format_exc()}")
    
    finally:
        scan_status['running'] = False

@app.route('/status')
def status():
    """Get scan status"""
    return jsonify(scan_status)

@app.route('/results')
def results_page():
    """View detailed results"""
    results_dir = Path('scan_results')
    if not results_dir.exists():
        return "No scan results found"
    
    # Get latest report
    reports = sorted(results_dir.glob('*_report.txt'), key=lambda x: x.stat().st_mtime, reverse=True)
    
    if not reports:
        return "No reports found"
    
    with open(reports[0], 'r', encoding='utf-8') as f:
        content = f.read()
    
    return f"<pre style='font-family: monospace; white-space: pre-wrap; padding: 20px;'>{content}</pre>"

@app.route('/download/<scan_id>')
def download(scan_id):
    """Download report"""
    results_dir = Path('scan_results')
    reports = sorted(results_dir.glob('*_report.txt'), key=lambda x: x.stat().st_mtime, reverse=True)
    
    if reports:
        return send_file(reports[0], as_attachment=True)
    
    return "Report not found", 404

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔒 SecureCodeAI Web Interface")
    print("="*60)
    print("\n📱 Open your browser and go to:")
    print("\n   http://localhost:5000")
    print("\n⚠️  Press Ctrl+C to stop the server")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)