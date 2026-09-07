import os
import re
import string
import logging
from typing import Dict, List, Any
from urllib.parse import urlparse
import validators
import requests
from email.mime.text import MIMEText
from email.header import decode_header

class MessagePreprocessor:
    """Preprocesses messages from different channels for analysis."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def extract_text_content(self, message: Dict[str, Any]) -> str:
        """Extract clean text content from message."""
        content = message.get('content', '')
        
        # Remove HTML tags if present
        content = re.sub(r'<[^>]+>', '', content)
        
        # Remove excessive whitespace
        content = ' '.join(content.split())
        
        return content
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        
        # Also check for domain patterns without protocol
        domain_pattern = r'(?:www\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\.[a-zA-Z]{2,}'
        potential_domains = re.findall(domain_pattern, text)
        
        for domain in potential_domains:
            if validators.domain(domain):
                urls.append(f"http://{domain}")
                
        return list(set(urls))
    
    def extract_email_metadata(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from email messages."""
        metadata = {
            'sender': message.get('sender', ''),
            'subject': message.get('subject', ''),
            'timestamp': message.get('timestamp', ''),
            'reply_to': message.get('reply_to', ''),
            'return_path': message.get('return_path', ''),
            'received_headers': message.get('received_headers', []),
            'message_id': message.get('message_id', ''),
            'has_attachments': message.get('has_attachments', False),
            'content_type': message.get('content_type', 'text/plain')
        }
        return metadata
    
    def extract_sms_metadata(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from SMS messages."""
        metadata = {
            'sender_number': message.get('sender_number', ''),
            'timestamp': message.get('timestamp', ''),
            'message_length': len(message.get('content', '')),
            'contains_links': len(self.extract_urls(message.get('content', ''))) > 0
        }
        return metadata
    
    def extract_chat_metadata(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from chat platform messages."""
        metadata = {
            'sender_id': message.get('sender_id', ''),
            'platform': message.get('platform', ''),
            'timestamp': message.get('timestamp', ''),
            'chat_id': message.get('chat_id', ''),
            'message_type': message.get('message_type', 'text'),
            'has_media': message.get('has_media', False)
        }
        return metadata
    
    def standardize_message(self, message: Dict[str, Any], channel: str) -> Dict[str, Any]:
        """Standardize message format across channels."""
        standardized = {
            'channel': channel,
            'content': self.extract_text_content(message),
            'urls': self.extract_urls(message.get('content', '')),
            'timestamp': message.get('timestamp', ''),
            'raw_message': message
        }
        
        if channel == 'email':
            standardized['metadata'] = self.extract_email_metadata(message)
        elif channel == 'sms':
            standardized['metadata'] = self.extract_sms_metadata(message)
        elif channel == 'chat':
            standardized['metadata'] = self.extract_chat_metadata(message)
            
        return standardized
    
    def clean_text(self, text: str) -> str:
        """Clean and normalize text for analysis."""
        # Convert to lowercase
        text = text.lower()
        
        # Remove punctuation
        text = text.translate(str.maketrans('', '', string.punctuation))
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text