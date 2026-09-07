#!/usr/bin/env python3
"""
Simplified Flask Web Application for AI-Powered Phishing Detection System
"""

from flask import Flask, render_template, request, jsonify
import json
import os
from datetime import datetime
import logging

# Import simplified detector
from simple_demo import SimplePhishingDetector

app = Flask(__name__)
app.secret_key = 'phishing_detection_secret_key_2024'

# Disable template caching for development
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Make datetime available in templates
@app.template_global()
def datetime_now():
    return datetime

app.jinja_env.globals['datetime'] = datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize detection system
detection_system = SimplePhishingDetector()
use_full_system = False
logger.info("Simple detection system loaded")

# Global variables for system state
analysis_history = []
system_stats = {
    'total_analyzed': 0,
    'phishing_detected': 0,
    'last_analysis': None
}

@app.route('/')
def index():
    """Main dashboard page."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('index.html', 
                         stats=system_stats, 
                         recent_analyses=analysis_history[-5:],
                         use_full_system=use_full_system,
                         current_time=current_time)

@app.route('/analyze')
def analyze_page():
    """Message analysis page."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('analyze.html', current_time=current_time)

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for analyzing messages."""
    try:
        data = request.get_json()
        
        content = data.get('content', '').strip()
        sender = data.get('sender', '').strip()
        subject = data.get('subject', '').strip()
        channel = data.get('channel', 'email')
        urls = data.get('urls', [])
        
        if not content:
            return jsonify({'error': 'Message content is required'}), 400
        
        # Analyze the message using simple detector
        result = detection_system.analyze_message(content, sender, subject, urls)
        
        # Update statistics
        system_stats['total_analyzed'] += 1
        if result.get('is_phishing', False):
            system_stats['phishing_detected'] += 1
        system_stats['last_analysis'] = datetime.now().isoformat()
        
        # Add to history
        analysis_entry = {
            'id': len(analysis_history) + 1,
            'timestamp': datetime.now().isoformat(),
            'content_preview': content[:100] + ('...' if len(content) > 100 else ''),
            'sender': sender,
            'channel': channel,
            'is_phishing': result.get('is_phishing', False),
            'risk_level': result.get('risk_level', 'UNKNOWN'),
            'confidence': result.get('confidence', 0),
            'result': result
        }
        analysis_history.append(analysis_entry)
        
        # Keep only last 100 analyses
        if len(analysis_history) > 100:
            analysis_history.pop(0)
        
        return jsonify({
            'success': True,
            'result': result,
            'analysis_id': analysis_entry['id']
        })
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/batch-analyze', methods=['POST'])
def api_batch_analyze():
    """API endpoint for batch analyzing multiple messages."""
    try:
        data = request.get_json()
        messages = data.get('messages', [])
        
        if not messages:
            return jsonify({'error': 'No messages provided'}), 400
        
        results = []
        for msg in messages:
            content = msg.get('content', '').strip()
            sender = msg.get('sender', '').strip()
            subject = msg.get('subject', '').strip()
            
            if content:
                result = detection_system.analyze_message(content, sender, subject)
                results.append(result)
                
                # Update statistics
                system_stats['total_analyzed'] += 1
                if result.get('is_phishing', False):
                    system_stats['phishing_detected'] += 1
        
        system_stats['last_analysis'] = datetime.now().isoformat()
        
        return jsonify({
            'success': True,
            'results': results,
            'summary': {
                'total_messages': len(results),
                'phishing_detected': sum(1 for r in results if r.get('is_phishing', False)),
                'average_risk_score': sum(r.get('risk_score', 0) for r in results) / len(results) if results else 0
            }
        })
        
    except Exception as e:
        logger.error(f"Batch analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/history')
def history_page():
    """Analysis history page."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('history.html', analyses=reversed(analysis_history), current_time=current_time)

@app.route('/api/history')
def api_history():
    """API endpoint for getting analysis history."""
    return jsonify({
        'success': True,
        'analyses': list(reversed(analysis_history)),
        'total': len(analysis_history)
    })

@app.route('/api/analysis/<int:analysis_id>')
def api_get_analysis(analysis_id):
    """API endpoint for getting specific analysis details."""
    try:
        analysis = next((a for a in analysis_history if a['id'] == analysis_id), None)
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        
        return jsonify({
            'success': True,
            'analysis': analysis
        })
        
    except Exception as e:
        logger.error(f"Get analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/settings')
def settings_page():
    """System settings page."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    config = {
        'detection_threshold': 0.5,
        'notification_methods': ['email'],
        'alert_recipients': ['admin@company.com']
    }
    return render_template('settings.html', config=config, use_full_system=use_full_system, current_time=current_time)

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    """API endpoint for managing settings."""
    if request.method == 'GET':
        config = {
            'detection_threshold': 0.5,
            'notification_methods': ['email'],
            'alert_recipients': ['admin@company.com']
        }
        return jsonify({
            'success': True,
            'config': config
        })
    
    elif request.method == 'POST':
        try:
            new_config = request.get_json()
            # In a real implementation, save to file
            return jsonify({
                'success': True,
                'message': 'Settings saved successfully'
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def api_stats():
    """API endpoint for getting system statistics."""
    # Calculate additional stats
    if analysis_history:
        risk_levels = [a.get('risk_level', 'UNKNOWN') for a in analysis_history]
        risk_level_counts = {level: risk_levels.count(level) for level in set(risk_levels)}
        
        channels = [a.get('channel', 'unknown') for a in analysis_history]
        channel_counts = {channel: channels.count(channel) for channel in set(channels)}
        
        recent_24h = [a for a in analysis_history 
                     if (datetime.now() - datetime.fromisoformat(a['timestamp'])).days == 0]
        
        extended_stats = {
            **system_stats,
            'detection_rate': (system_stats['phishing_detected'] / system_stats['total_analyzed'] * 100) 
                            if system_stats['total_analyzed'] > 0 else 0,
            'risk_level_distribution': risk_level_counts,
            'channel_distribution': channel_counts,
            'analyses_today': len(recent_24h),
            'phishing_today': sum(1 for a in recent_24h if a.get('is_phishing', False))
        }
    else:
        extended_stats = {
            **system_stats,
            'detection_rate': 0,
            'risk_level_distribution': {},
            'channel_distribution': {},
            'analyses_today': 0,
            'phishing_today': 0
        }
    
    return jsonify({
        'success': True,
        'stats': extended_stats
    })

@app.route('/api/monitor')
def api_monitor():
    """API endpoint for real-time monitoring."""
    return jsonify({
        'success': True,
        'status': 'simple_mode',
        'message': 'Running in simple detection mode',
        'last_check': datetime.now().isoformat()
    })

@app.route('/monitor')
def monitor_page():
    """Real-time monitoring page."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('monitor.html', use_full_system=use_full_system, current_time=current_time)

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', 
                         error_code=500, 
                         error_message="Internal server error"), 500

if __name__ == '__main__':
    # Create templates and static directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    print("🚀 Starting AI-Powered Phishing Detection Web Interface...")
    print("🌐 Access the application at: http://localhost:5000")
    print("📊 Features available: Message Analysis, History, Monitoring, Settings")
    
    # Run the Flask application
    app.run(debug=True, host='0.0.0.0', port=5000)