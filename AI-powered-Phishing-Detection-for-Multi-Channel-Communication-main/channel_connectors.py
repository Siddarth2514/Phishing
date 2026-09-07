import imaplib
import email
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from email.header import decode_header
import re

class EmailConnector:
    """Connector for email platforms (Gmail, Outlook, etc.)."""
    
    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.connection = None
        
    def connect(self) -> bool:
        """Connect to email server."""
        try:
            server = self.config.get('server', 'imap.gmail.com')
            port = self.config.get('port', 993)
            username = self.config['username']
            password = self.config['password']
            
            self.connection = imaplib.IMAP4_SSL(server, port)
            self.connection.login(username, password)
            
            self.logger.info("Email connection established")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to email: {e}")
            return False
    
    def fetch_messages(self, folder: str = 'INBOX', limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch recent messages from email."""
        if not self.connection:
            raise ConnectionError("Not connected to email server")
            
        messages = []
        
        try:
            self.connection.select(folder)
            
            # Search for recent messages
            status, message_ids = self.connection.search(None, 'ALL')
            
            if status == 'OK':
                id_list = message_ids[0].split()
                # Get most recent messages
                recent_ids = id_list[-limit:] if len(id_list) >= limit else id_list
                
                for msg_id in recent_ids:
                    status, msg_data = self.connection.fetch(msg_id, '(RFC822)')
                    
                    if status == 'OK':
                        raw_email = msg_data[0][1]
                        email_message = email.message_from_bytes(raw_email)
                        
                        parsed_message = self._parse_email(email_message)
                        if parsed_message:
                            messages.append(parsed_message)
                            
        except Exception as e:
            self.logger.error(f"Failed to fetch emails: {e}")
            
        return messages
    
    def _parse_email(self, email_message) -> Dict[str, Any]:
        """Parse email message into standardized format."""
        try:
            # Extract subject
            subject = decode_header(email_message.get('Subject', ''))[0][0]
            if isinstance(subject, bytes):
                subject = subject.decode('utf-8', errors='ignore')
                
            # Extract sender
            sender = email_message.get('From', '')
            
            # Extract content
            content = ""
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            content += payload.decode('utf-8', errors='ignore')
            else:
                payload = email_message.get_payload(decode=True)
                if payload:
                    content = payload.decode('utf-8', errors='ignore')
            
            return {
                'sender': sender,
                'subject': subject,
                'content': content,
                'timestamp': email_message.get('Date', ''),
                'message_id': email_message.get('Message-ID', ''),
                'reply_to': email_message.get('Reply-To', ''),
                'return_path': email_message.get('Return-Path', ''),
                'content_type': email_message.get_content_type(),
                'has_attachments': len([part for part in email_message.walk() if part.get_filename()]) > 0,
                'received_headers': email_message.get_all('Received', [])
            }
            
        except Exception as e:
            self.logger.error(f"Failed to parse email: {e}")
            return None
    
    def disconnect(self):
        """Disconnect from email server."""
        if self.connection:
            try:
                self.connection.close()
                self.connection.logout()
                self.logger.info("Email connection closed")
            except:
                pass


class SMSConnector:
    """Connector for SMS platforms using Twilio."""
    
    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.client = None
        
        try:
            from twilio.rest import Client
            account_sid = config['account_sid']
            auth_token = config['auth_token']
            self.client = Client(account_sid, auth_token)
            self.phone_number = config['phone_number']
        except Exception as e:
            self.logger.error(f"Failed to initialize SMS connector: {e}")
    
    def fetch_messages(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch recent SMS messages."""
        if not self.client:
            return []
            
        messages = []
        
        try:
            # Fetch incoming messages
            twilio_messages = self.client.messages.list(
                to=self.phone_number,
                limit=limit
            )
            
            for msg in twilio_messages:
                parsed_message = {
                    'sender_number': msg.from_,
                    'content': msg.body,
                    'timestamp': msg.date_created.isoformat() if msg.date_created else '',
                    'message_id': msg.sid,
                    'status': msg.status
                }
                messages.append(parsed_message)
                
        except Exception as e:
            self.logger.error(f"Failed to fetch SMS messages: {e}")
            
        return messages


class TelegramConnector:
    """Connector for Telegram using Bot API."""
    
    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.bot_token = config.get('bot_token', '')
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
        
    def fetch_messages(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch recent Telegram messages."""
        if not self.bot_token:
            return []
            
        messages = []
        
        try:
            import requests
            
            # Get updates from Telegram
            response = requests.get(
                f"{self.base_url}/getUpdates",
                params={'limit': limit},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('ok'):
                    for update in data.get('result', []):
                        message = update.get('message', {})
                        
                        if message:
                            parsed_message = {
                                'sender_id': message.get('from', {}).get('username', 'Unknown'),
                                'content': message.get('text', ''),
                                'timestamp': datetime.fromtimestamp(message.get('date', 0)).isoformat(),
                                'chat_id': str(message.get('chat', {}).get('id', '')),
                                'message_id': message.get('message_id'),
                                'platform': 'telegram',
                                'message_type': 'text',
                                'has_media': any(key in message for key in ['photo', 'document', 'video', 'audio'])
                            }
                            messages.append(parsed_message)
                            
        except Exception as e:
            self.logger.error(f"Failed to fetch Telegram messages: {e}")
            
        return messages


class MultiChannelConnector:
    """Main connector that manages all communication channels."""
    
    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.connectors = {}
        
        # Initialize connectors based on configuration
        self._init_connectors()
    
    def _init_connectors(self):
        """Initialize all configured connectors."""
        # Email connector
        if 'email' in self.config:
            try:
                self.connectors['email'] = EmailConnector(self.config['email'])
                if self.connectors['email'].connect():
                    self.logger.info("Email connector initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize email connector: {e}")
        
        # SMS connector
        if 'sms' in self.config:
            try:
                self.connectors['sms'] = SMSConnector(self.config['sms'])
                self.logger.info("SMS connector initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize SMS connector: {e}")
        
        # Telegram connector
        if 'telegram' in self.config:
            try:
                self.connectors['telegram'] = TelegramConnector(self.config['telegram'])
                self.logger.info("Telegram connector initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Telegram connector: {e}")
    
    def fetch_all_messages(self, limit_per_channel: int = 10) -> Dict[str, List[Dict[str, Any]]]:
        """Fetch messages from all configured channels."""
        all_messages = {}
        
        for channel, connector in self.connectors.items():
            try:
                messages = connector.fetch_messages(limit=limit_per_channel)
                all_messages[channel] = messages
                self.logger.info(f"Fetched {len(messages)} messages from {channel}")
            except Exception as e:
                self.logger.error(f"Failed to fetch messages from {channel}: {e}")
                all_messages[channel] = []
        
        return all_messages
    
    def fetch_channel_messages(self, channel: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch messages from a specific channel."""
        if channel not in self.connectors:
            self.logger.warning(f"Channel {channel} not configured")
            return []
        
        try:
            return self.connectors[channel].fetch_messages(limit=limit)
        except Exception as e:
            self.logger.error(f"Failed to fetch messages from {channel}: {e}")
            return []
    
    def get_available_channels(self) -> List[str]:
        """Get list of available channels."""
        return list(self.connectors.keys())
    
    def disconnect_all(self):
        """Disconnect from all channels."""
        for channel, connector in self.connectors.items():
            try:
                if hasattr(connector, 'disconnect'):
                    connector.disconnect()
                self.logger.info(f"Disconnected from {channel}")
            except Exception as e:
                self.logger.error(f"Failed to disconnect from {channel}: {e}")