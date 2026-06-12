"""
app.py
======
Main Flask application for CyberShield Security Suite.

This file orchestrates all functionality:
- Route definitions
- File upload handling
- Security tool integration
- Response formatting
"""

import os
import json
from datetime import datetime
from pathlib import Path
from flask import (
    Flask, render_template, request, jsonify, 
    send_file, flash, redirect, url_for
)
from werkzeug.utils import secure_filename

from config import Config
from utils import FileIntegrityChecker, PhishingDetector, PasswordAnalyzer


# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Ensure required directories exist
Config.init_directories()

# Initialize security modules
file_checker = FileIntegrityChecker(Config.HASHES_FOLDER)
phishing_detector = PhishingDetector()
password_analyzer = PasswordAnalyzer()

# Application statistics (in-memory for demo; use database in production)
app_stats = {
    'files_scanned': 0,
    'threats_detected': 0,
    'passwords_analyzed': 0,
    'security_score': 95
}


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


# ==================== ROUTES ====================

@app.route('/')
def index():
    """
    Home dashboard displaying overview and statistics.
    """
    return render_template('index.html', 
                         stats=app_stats,
                         app_name=Config.APP_NAME)


@app.route('/file-integrity')
def file_integrity():
    """
    File Integrity Checker page.
    """
    saved_hashes = file_checker.get_saved_hashes()
    return render_template('file_integrity.html',
                         saved_hashes=saved_hashes,
                         app_name=Config.APP_NAME)


@app.route('/api/file/upload', methods=['POST'])
def upload_file():
    """
    Handle file upload and generate hash.
    
    Security measures:
    - Filename sanitization
    - Extension whitelist
    - Size limit (configured in MAX_CONTENT_LENGTH)
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    try:
        # Sanitize filename to prevent directory traversal attacks
        filename = secure_filename(file.filename)
        filepath = Config.UPLOAD_FOLDER / filename
        
        # Save file temporarily
        file.save(filepath)
        
        # Calculate hash
        hash_data = file_checker.calculate_hash(filepath)
        
        # Update statistics
        app_stats['files_scanned'] += 1
        
        # Clean up uploaded file (optional: keep for verification)
        # os.remove(filepath)
        
        return jsonify({
            'success': True,
            'data': hash_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/file/save-hash', methods=['POST'])
def save_hash():
    """Save hash record for future verification."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        record_path = file_checker.save_hash(data)
        return jsonify({
            'success': True,
            'message': 'Hash saved successfully',
            'record_path': record_path
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/file/verify', methods=['POST'])
def verify_file():
    """
    Verify uploaded file against stored hash.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    original_hash = request.form.get('original_hash', '')
    
    if not original_hash:
        return jsonify({'error': 'No original hash provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        filename = secure_filename(file.filename)
        filepath = Config.UPLOAD_FOLDER / filename
        file.save(filepath)
        
        result = file_checker.verify_integrity(filepath, original_hash)
        
        # Update statistics
        if not result['is_intact']:
            app_stats['threats_detected'] += 1
        
        # Clean up
        os.remove(filepath)
        
        return jsonify({
            'success': True,
            'data': result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/file/report', methods=['POST'])
def generate_report():
    """Generate downloadable integrity report."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        report_path = file_checker.generate_report(data, Config.REPORTS_FOLDER)
        
        return jsonify({
            'success': True,
            'report_path': report_path
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/file/download-report/<filename>')
def download_report(filename):
    """Download generated report."""
    filename = secure_filename(filename)
    report_path = Config.REPORTS_FOLDER / filename
    
    if report_path.exists():
        return send_file(report_path, as_attachment=True)
    
    return jsonify({'error': 'Report not found'}), 404


@app.route('/phishing')
def phishing():
    """Phishing Detector page."""
    return render_template('phishing.html', app_name=Config.APP_NAME)


@app.route('/api/phishing/analyze-url', methods=['POST'])
def analyze_url():
    """
    Analyze URL for phishing indicators.
    """
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        result = phishing_detector.analyze_url(url)
        
        # Update statistics
        if result['threat_level'] in ['high', 'critical']:
            app_stats['threats_detected'] += 1
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/phishing/analyze-email', methods=['POST'])
def analyze_email():
    """
    Analyze email content for phishing indicators.
    """
    data = request.get_json()
    content = data.get('content', '').strip()
    
    if not content:
        return jsonify({'error': 'No email content provided'}), 400
    
    try:
        result = phishing_detector.analyze_email(content)
        
        # Update statistics
        if result['threat_level'] in ['high', 'critical']:
            app_stats['threats_detected'] += 1
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/password')
def password():
    """Password Strength Analyzer page."""
    return render_template('password.html', app_name=Config.APP_NAME)


@app.route('/api/password/analyze', methods=['POST'])
def analyze_password():
    """
    Analyze password strength.
    """
    data = request.get_json()
    pwd = data.get('password', '')
    
    try:
        result = password_analyzer.analyze(pwd)
        
        # Update statistics
        app_stats['passwords_analyzed'] += 1
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/password/generate', methods=['GET'])
def generate_password():
    """Generate a strong random password."""
    length = request.args.get('length', 16, type=int)
    
    # Enforce reasonable limits
    length = max(8, min(length, 64))
    
    try:
        password = password_analyzer.generate_strong_password(length)
        return jsonify({
            'success': True,
            'password': password
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/about')
def about():
    """About Cybersecurity page."""
    return render_template('about.html', app_name=Config.APP_NAME)


@app.route('/contact')
def contact():
    """Contact page."""
    return render_template('contact.html', app_name=Config.APP_NAME)


@app.route('/api/contact', methods=['POST'])
def submit_contact():
    """Handle contact form submission."""
    data = request.get_json()
    
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    message = data.get('message', '').strip()
    
    # Validate inputs
    if not all([name, email, message]):
        return jsonify({'error': 'All fields are required'}), 400
    
    # Simple email validation
    import re
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # In production, you would:
    # - Save to database
    # - Send notification email
    # - Rate limit submissions
    
    return jsonify({
        'success': True,
        'message': 'Thank you for your message! We will respond shortly.'
    })


@app.route('/api/stats')
def get_stats():
    """Return current application statistics."""
    return jsonify(app_stats)


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return render_template('base.html', 
                         error='Page not found',
                         app_name=Config.APP_NAME), 404


@app.errorhandler(413)
def file_too_large(e):
    """Handle file size exceeded errors."""
    return jsonify({'error': 'File too large. Maximum size is 16MB'}), 413


@app.errorhandler(500)
def server_error(e):
    """Handle internal server errors."""
    return jsonify({'error': 'Internal server error'}), 500


# ==================== MAIN ====================

if __name__ == '__main__':
    # Development server
    # In production, use: gunicorn app:app
    app.run(debug=True, host='0.0.0.0', port=5000)
