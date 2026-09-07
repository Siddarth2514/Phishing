import re
import string
import logging
from typing import Dict, List, Any, Tuple
from collections import Counter
import numpy as np
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
from nltk.sentiment import SentimentIntensityAnalyzer
from textblob import TextBlob
import requests
from urllib.parse import urlparse
import validators

try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

try:
    nltk.data.find('vader_lexicon')
except LookupError:
    nltk.download('vader_lexicon')

class FeatureExtractor:
    """Extract features from preprocessed messages for ML model."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.sia = SentimentIntensityAnalyzer()
        self.stop_words = set(stopwords.words('english'))
        self.phishing_keywords = {
            'urgency': ['urgent', 'immediate', 'asap', 'expire', 'deadline', 'limited time'],
            'action': ['click', 'download', 'verify', 'confirm', 'update', 'login', 'submit'],
            'financial': ['bank', 'paypal', 'credit card', 'account', 'payment', 'refund', 'money'],
            'threats': ['suspend', 'block', 'freeze', 'close', 'penalty', 'legal action'],
            'legitimacy': ['official', 'secure', 'verified', 'authentic', 'legitimate']
        }
        
    def extract_text_features(self, text: str) -> Dict[str, float]:
        """Extract text-based features."""
        features = {}
        
        # Basic text statistics
        features['text_length'] = len(text)
        features['word_count'] = len(text.split())
        features['sentence_count'] = len(sent_tokenize(text))
        features['avg_word_length'] = np.mean([len(word) for word in text.split()]) if text.split() else 0
        
        # Character analysis
        features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        features['digit_ratio'] = sum(1 for c in text if c.isdigit()) / len(text) if text else 0
        features['special_char_ratio'] = sum(1 for c in text if c in string.punctuation) / len(text) if text else 0
        
        # Exclamation and question marks
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        
        # Spelling and grammar
        blob = TextBlob(text)
        features['polarity'] = blob.sentiment.polarity
        features['subjectivity'] = blob.sentiment.subjectivity
        
        return features
    
    def extract_keyword_features(self, text: str) -> Dict[str, float]:
        """Extract phishing keyword features."""
        features = {}
        text_lower = text.lower()
        
        for category, keywords in self.phishing_keywords.items():
            count = sum(1 for keyword in keywords if keyword in text_lower)
            features[f'{category}_keywords'] = count
            features[f'{category}_keyword_ratio'] = count / len(text.split()) if text.split() else 0
            
        return features
    
    def extract_url_features(self, urls: List[str]) -> Dict[str, float]:
        """Extract URL-based features."""
        features = {
            'url_count': len(urls),
            'has_urls': 1 if urls else 0,
            'suspicious_tld_count': 0,
            'ip_address_count': 0,
            'shortened_url_count': 0,
            'suspicious_domain_count': 0,
            'avg_url_length': 0
        }
        
        if not urls:
            return features
            
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        
        url_lengths = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Check for IP addresses
                if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                    features['ip_address_count'] += 1
                
                # Check for suspicious TLDs
                for tld in suspicious_tlds:
                    if domain.endswith(tld):
                        features['suspicious_tld_count'] += 1
                        break
                
                # Check for URL shorteners
                for shortener in shorteners:
                    if shortener in domain:
                        features['shortened_url_count'] += 1
                        break
                
                # Check for suspicious patterns
                if re.search(r'[0-9]{4,}', domain) or len(domain.split('.')) > 4:
                    features['suspicious_domain_count'] += 1
                    
                url_lengths.append(len(url))
                
            except Exception as e:
                self.logger.warning(f"Error parsing URL {url}: {e}")
                
        features['avg_url_length'] = np.mean(url_lengths) if url_lengths else 0
        
        return features
    
    def extract_metadata_features(self, metadata: Dict[str, Any], channel: str) -> Dict[str, float]:
        """Extract channel-specific metadata features."""
        features = {}
        
        if channel == 'email':
            features.update(self._extract_email_metadata_features(metadata))
        elif channel == 'sms':
            features.update(self._extract_sms_metadata_features(metadata))
        elif channel == 'chat':
            features.update(self._extract_chat_metadata_features(metadata))
            
        return features
    
    def _extract_email_metadata_features(self, metadata: Dict[str, Any]) -> Dict[str, float]:
        """Extract email-specific features."""
        features = {}
        
        sender = metadata.get('sender', '')
        subject = metadata.get('subject', '')
        
        # Sender analysis
        features['sender_has_display_name'] = 1 if '<' in sender and '>' in sender else 0
        features['sender_suspicious_chars'] = sum(1 for c in sender if c in '!@#$%^&*()+=[]{}|;:,.<>?')
        
        # Subject analysis
        features['subject_length'] = len(subject)
        features['subject_uppercase_ratio'] = sum(1 for c in subject if c.isupper()) / len(subject) if subject else 0
        features['subject_has_re_fwd'] = 1 if re.search(r'^(re:|fwd:|fw:)', subject.lower()) else 0
        
        # Other metadata
        features['has_reply_to'] = 1 if metadata.get('reply_to') else 0
        features['has_attachments'] = 1 if metadata.get('has_attachments') else 0
        features['is_html'] = 1 if 'html' in metadata.get('content_type', '') else 0
        
        return features
    
    def _extract_sms_metadata_features(self, metadata: Dict[str, Any]) -> Dict[str, float]:
        """Extract SMS-specific features."""
        features = {}
        
        sender_number = metadata.get('sender_number', '')
        
        # Sender number analysis
        features['sender_is_shortcode'] = 1 if len(sender_number) <= 6 and sender_number.isdigit() else 0
        features['sender_has_country_code'] = 1 if sender_number.startswith('+') else 0
        features['message_length'] = metadata.get('message_length', 0)
        features['contains_links'] = 1 if metadata.get('contains_links') else 0
        
        return features
    
    def _extract_chat_metadata_features(self, metadata: Dict[str, Any]) -> Dict[str, float]:
        """Extract chat platform-specific features."""
        features = {}
        
        # Platform analysis
        platform = metadata.get('platform', '')
        features['is_telegram'] = 1 if platform == 'telegram' else 0
        features['is_whatsapp'] = 1 if platform == 'whatsapp' else 0
        features['is_discord'] = 1 if platform == 'discord' else 0
        
        # Message type
        features['has_media'] = 1 if metadata.get('has_media') else 0
        features['is_private_chat'] = 1 if 'private' in metadata.get('chat_id', '') else 0
        
        return features
    
    def extract_all_features(self, standardized_message: Dict[str, Any]) -> Dict[str, float]:
        """Extract all features from standardized message."""
        content = standardized_message.get('content', '')
        urls = standardized_message.get('urls', [])
        metadata = standardized_message.get('metadata', {})
        channel = standardized_message.get('channel', '')
        
        features = {}
        
        # Text features
        features.update(self.extract_text_features(content))
        
        # Keyword features
        features.update(self.extract_keyword_features(content))
        
        # URL features
        features.update(self.extract_url_features(urls))
        
        # Metadata features
        features.update(self.extract_metadata_features(metadata, channel))
        
        # Channel indicator
        features['is_email'] = 1 if channel == 'email' else 0
        features['is_sms'] = 1 if channel == 'sms' else 0
        features['is_chat'] = 1 if channel == 'chat' else 0
        
        return features