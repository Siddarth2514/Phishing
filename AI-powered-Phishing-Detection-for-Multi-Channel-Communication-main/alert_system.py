import smtplib
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from twilio.rest import Client
import os

class AlertSystem:
    """System for sending real-time phishing alerts."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        self.alert_history = []
        
        # Initialize notification services
        self._init_email_service()
        self._init_sms_service()
        self._init_webhook_service()
        
    def _init_email_service(self):
        """Initialize email notification service."""
        self.email_config = self.config.get('email', {})
        self.smtp_server = self.email_config.get('smtp_server', 'localhost')
        self.smtp_port = self.email_config.get('smtp_port', 587)
        self.email_username = self.email_config.get('username', '')
        self.email_password = self.email_config.get('password', '')
        self.from_email = self.email_config.get('from_email', 'security@company.com')
        
    def _init_sms_service(self):
        """Initialize SMS notification service using Twilio."""
        sms_config = self.config.get('sms', {})
        self.twilio_account_sid = sms_config.get('account_sid', '')
        self.twilio_auth_token = sms_config.get('auth_token', '')
        self.twilio_phone = sms_config.get('phone_number', '')
        
        if self.twilio_account_sid and self.twilio_auth_token:
            self.twilio_client = Client(self.twilio_account_sid, self.twilio_auth_token)
        else:
            self.twilio_client = None
            
    def _init_webhook_service(self):
        """Initialize webhook notification service."""
        self.webhook_config = self.config.get('webhook', {})
        self.webhook_url = self.webhook_config.get('url', '')
        self.webhook_secret = self.webhook_config.get('secret', '')
        
    def create_alert(self, message: Dict[str, Any], prediction: int, 
                    confidence: float, features: Dict[str, float]) -> Dict[str, Any]:
        """Create a phishing alert."""
        alert = {
            'alert_id': f"PHISH_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'severity': self._calculate_severity(confidence),
            'confidence': confidence,
            'prediction': prediction,
            'channel': message.get('channel', 'unknown'),
            'message_preview': message.get('content', '')[:200],
            'sender_info': self._extract_sender_info(message),
            'detected_threats': self._identify_threats(features),
            'recommended_actions': self._get_recommended_actions(confidence, features),
            'urls_detected': message.get('urls', []),
            'metadata': message.get('metadata', {})
        }
        
        # Store alert in history
        self.alert_history.append(alert)
        
        return alert
    
    def _calculate_severity(self, confidence: float) -> str:
        """Calculate alert severity based on confidence."""
        if confidence >= 0.9:
            return 'CRITICAL'
        elif confidence >= 0.7:
            return 'HIGH'
        elif confidence >= 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'
            
    def _extract_sender_info(self, message: Dict[str, Any]) -> Dict[str, str]:
        """Extract sender information from message."""
        metadata = message.get('metadata', {})
        channel = message.get('channel', '')
        
        if channel == 'email':
            return {
                'sender': metadata.get('sender', 'Unknown'),
                'type': 'email'
            }
        elif channel == 'sms':
            return {
                'sender': metadata.get('sender_number', 'Unknown'),
                'type': 'phone'
            }
        elif channel == 'chat':
            return {
                'sender': metadata.get('sender_id', 'Unknown'),
                'platform': metadata.get('platform', 'Unknown'),
                'type': 'chat'
            }
        else:
            return {'sender': 'Unknown', 'type': 'unknown'}
            
    def _identify_threats(self, features: Dict[str, float]) -> List[str]:
        """Identify specific threats based on features."""
        threats = []
        
        # Check for URL-based threats
        if features.get('suspicious_domain_count', 0) > 0:
            threats.append('Suspicious domains detected')
        if features.get('ip_address_count', 0) > 0:
            threats.append('IP addresses in URLs')
        if features.get('shortened_url_count', 0) > 0:
            threats.append('URL shorteners detected')
            
        # Check for content-based threats
        if features.get('urgency_keywords', 0) > 2:
            threats.append('High urgency language')
        if features.get('financial_keywords', 0) > 1:
            threats.append('Financial information request')
        if features.get('action_keywords', 0) > 2:
            threats.append('Suspicious action requests')
            
        # Check for metadata threats
        if features.get('sender_suspicious_chars', 0) > 3:
            threats.append('Suspicious sender information')
        if features.get('has_attachments', 0) > 0:
            threats.append('Contains attachments')
            
        return threats
    
    def _get_recommended_actions(self, confidence: float, features: Dict[str, float]) -> List[str]:
        """Get recommended actions based on threat level."""
        actions = []
        
        if confidence >= 0.8:
            actions.extend([
                'DO NOT click any links',
                'DO NOT download attachments',
                'Report to security team immediately',
                'Block sender if possible'
            ])
        elif confidence >= 0.6:
            actions.extend([
                'Exercise extreme caution',
                'Verify sender through alternative means',
                'Do not provide personal information',
                'Report suspicious activity'
            ])
        else:
            actions.extend([
                'Review message carefully',
                'Verify legitimacy if unsure',
                'Monitor for similar messages'
            ])
            
        # Add specific actions based on features
        if features.get('url_count', 0) > 0:
            actions.append('Verify URLs before clicking')
        if features.get('has_attachments', 0) > 0:
            actions.append('Scan attachments before opening')
            
        return actions
    
    def send_alert(self, alert: Dict[str, Any], recipients: List[str], 
                  notification_methods: List[str] = None) -> Dict[str, bool]:
        """Send alert through specified notification methods."""
        if notification_methods is None:
            notification_methods = ['email']
            
        results = {}
        
        for method in notification_methods:
            if method == 'email':
                results['email'] = self._send_email_alert(alert, recipients)
            elif method == 'sms':
                results['sms'] = self._send_sms_alert(alert, recipients)
            elif method == 'webhook':
                results['webhook'] = self._send_webhook_alert(alert)
            else:
                self.logger.warning(f"Unknown notification method: {method}")
                results[method] = False
                
        return results
    
    def _send_email_alert(self, alert: Dict[str, Any], recipients: List[str]) -> bool:
        """Send email alert."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"🚨 PHISHING ALERT - {alert['severity']} - {alert['alert_id']}"
            
            # Create email body
            body = self._create_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.email_username and self.email_password:
                    server.starttls()
                    server.login(self.email_username, self.email_password)
                server.send_message(msg)
                
            self.logger.info(f"Email alert sent successfully: {alert['alert_id']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _send_sms_alert(self, alert: Dict[str, Any], recipients: List[str]) -> bool:
        """Send SMS alert."""
        if not self.twilio_client:
            self.logger.warning("Twilio client not configured")
            return False
            
        try:
            message_body = self._create_sms_body(alert)
            
            for recipient in recipients:
                self.twilio_client.messages.create(
                    body=message_body,
                    from_=self.twilio_phone,
                    to=recipient
                )
                
            self.logger.info(f"SMS alert sent successfully: {alert['alert_id']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send SMS alert: {e}")
            return False
    
    def _send_webhook_alert(self, alert: Dict[str, Any]) -> bool:
        """Send webhook alert."""
        if not self.webhook_url:
            self.logger.warning("Webhook URL not configured")
            return False
            
        try:
            headers = {'Content-Type': 'application/json'}
            if self.webhook_secret:
                headers['X-Secret'] = self.webhook_secret
                
            response = requests.post(
                self.webhook_url,
                json=alert,
                headers=headers,
                timeout=10
            )
            
            response.raise_for_status()
            self.logger.info(f"Webhook alert sent successfully: {alert['alert_id']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {e}")
            return False
    
    def _create_email_body(self, alert: Dict[str, Any]) -> str:
        """Create HTML email body for alert."""
        return f"""
        <html>
        <body>
            <h2 style="color: red;">🚨 PHISHING DETECTION ALERT</h2>
            
            <div style="border: 2px solid red; padding: 15px; margin: 10px 0;">
                <h3>Alert Details</h3>
                <p><strong>Alert ID:</strong> {alert['alert_id']}</p>
                <p><strong>Severity:</strong> <span style="color: red; font-weight: bold;">{alert['severity']}</span></p>
                <p><strong>Confidence:</strong> {alert['confidence']:.2%}</p>
                <p><strong>Channel:</strong> {alert['channel'].upper()}</p>
                <p><strong>Timestamp:</strong> {alert['timestamp']}</p>
            </div>
            
            <div style="border: 1px solid #ccc; padding: 10px; margin: 10px 0;">
                <h3>Message Preview</h3>
                <p><strong>Sender:</strong> {alert['sender_info'].get('sender', 'Unknown')}</p>
                <p><strong>Content:</strong></p>
                <div style="background-color: #f5f5f5; padding: 10px; border-left: 3px solid #007cba;">
                    {alert['message_preview']}
                </div>
            </div>
            
            <div style="border: 1px solid #ccc; padding: 10px; margin: 10px 0;">
                <h3>Detected Threats</h3>
                <ul>
                    {''.join(f'<li style="color: red;">{threat}</li>' for threat in alert['detected_threats'])}
                </ul>
            </div>
            
            <div style="border: 1px solid #ccc; padding: 10px; margin: 10px 0;">
                <h3>Recommended Actions</h3>
                <ul>
                    {''.join(f'<li>{action}</li>' for action in alert['recommended_actions'])}
                </ul>
            </div>
            
            {f'''
            <div style="border: 1px solid #ccc; padding: 10px; margin: 10px 0;">
                <h3>Suspicious URLs</h3>
                <ul>
                    {''.join(f'<li style="color: red; word-break: break-all;">{url}</li>' for url in alert['urls_detected'])}
                </ul>
            </div>
            ''' if alert['urls_detected'] else ''}
            
            <p style="margin-top: 20px; font-size: 12px; color: #666;">
                This alert was generated by the AI-Powered Phishing Detection System.
            </p>
        </body>
        </html>
        """
    
    def _create_sms_body(self, alert: Dict[str, Any]) -> str:
        """Create SMS body for alert."""
        return f"""
🚨 PHISHING ALERT - {alert['severity']}

Alert ID: {alert['alert_id']}
Confidence: {alert['confidence']:.0%}
Channel: {alert['channel'].upper()}
Sender: {alert['sender_info'].get('sender', 'Unknown')}

Threats: {', '.join(alert['detected_threats'][:2])}

DO NOT interact with this message. Report to security team immediately.
        """.strip()
    
    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent alert history."""
        return self.alert_history[-limit:]
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        if not self.alert_history:
            return {'total_alerts': 0}
            
        total = len(self.alert_history)
        by_severity = {}
        by_channel = {}
        
        for alert in self.alert_history:
            severity = alert['severity']
            channel = alert['channel']
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_channel[channel] = by_channel.get(channel, 0) + 1
            
        return {
            'total_alerts': total,
            'by_severity': by_severity,
            'by_channel': by_channel,
            'avg_confidence': sum(alert['confidence'] for alert in self.alert_history) / total
        }