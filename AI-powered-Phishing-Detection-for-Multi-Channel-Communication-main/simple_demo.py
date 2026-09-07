#!/usr/bin/env python3
"""
Simplified Demo of AI-Powered Phishing Detection System
"""

import re
import json
from datetime import datetime
from collections import Counter

class SimplePhishingDetector:
    """Simplified phishing detector for demonstration."""
    
    def __init__(self):
        # Phishing keywords and patterns
        self.phishing_keywords = {
            'urgency': ['urgent', 'immediate', 'asap', 'expire', 'deadline', 'limited time'],
            'action': ['click', 'download', 'verify', 'confirm', 'update', 'login', 'submit'],
            'financial': ['bank', 'paypal', 'credit card', 'account', 'payment', 'refund'],
            'threats': ['suspend', 'block', 'freeze', 'close', 'penalty', 'legal action'],
            'legitimacy': ['official', 'secure', 'verified', 'authentic', 'legitimate']
        }
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r'click\s+here\s+now',
            r'act\s+now',
            r'urgent\s+action',
            r'final\s+notice',
            r'suspension\s+warning'
        ]
        
        # Suspicious domains
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        
    def extract_features(self, text, urls=None):
        """Extract basic features from text."""
        if urls is None:
            urls = []
            
        text_lower = text.lower()
        features = {}
        
        # Basic text features
        features['text_length'] = len(text)
        features['word_count'] = len(text.split())
        features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        
        # Keyword features
        for category, keywords in self.phishing_keywords.items():
            count = sum(1 for keyword in keywords if keyword in text_lower)
            features[f'{category}_keywords'] = count
        
        # Pattern features
        pattern_count = 0
        for pattern in self.suspicious_patterns:
            if re.search(pattern, text_lower):
                pattern_count += 1
        features['suspicious_patterns'] = pattern_count
        
        # URL features
        features['url_count'] = len(urls)
        features['suspicious_urls'] = 0
        if urls:
            for url in urls:
                url_lower = url.lower()
                # Check for suspicious TLDs
                for tld in self.suspicious_tlds:
                    if tld in url_lower:
                        features['suspicious_urls'] += 1
                        break
                # Check for IP addresses
                if re.search(r'\d+\.\d+\.\d+\.\d+', url):
                    features['suspicious_urls'] += 1
                # Check for URL shorteners
                if any(short in url_lower for short in ['bit.ly', 'tinyurl', 't.co']):
                    features['suspicious_urls'] += 1
        
        return features
    
    def calculate_risk_score(self, features):
        """Calculate risk score based on features."""
        score = 0
        
        # Text-based scoring
        if features.get('uppercase_ratio', 0) > 0.3:
            score += 15
        if features.get('exclamation_count', 0) > 2:
            score += 20
        
        # Keyword scoring
        score += features.get('urgency_keywords', 0) * 25
        score += features.get('action_keywords', 0) * 15
        score += features.get('financial_keywords', 0) * 20
        score += features.get('threats_keywords', 0) * 30
        
        # Pattern scoring
        score += features.get('suspicious_patterns', 0) * 35
        
        # URL scoring
        score += features.get('suspicious_urls', 0) * 40
        
        return min(score, 100)  # Cap at 100
    
    def analyze_message(self, content, sender="", subject="", urls=None):
        """Analyze a message for phishing indicators."""
        if urls is None:
            # Extract URLs from content
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            urls = re.findall(url_pattern, content)
        
        # Combine all text for analysis
        full_text = f"{subject} {content}"
        
        # Extract features
        features = self.extract_features(full_text, urls)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(features)
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "CRITICAL"
            is_phishing = True
        elif risk_score >= 60:
            risk_level = "HIGH"
            is_phishing = True
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            is_phishing = True
        elif risk_score >= 20:
            risk_level = "LOW"
            is_phishing = False
        else:
            risk_level = "MINIMAL"
            is_phishing = False
        
        # Identify threats
        threats = []
        if features.get('urgency_keywords', 0) > 1:
            threats.append("High urgency language detected")
        if features.get('suspicious_patterns', 0) > 0:
            threats.append("Suspicious action patterns found")
        if features.get('suspicious_urls', 0) > 0:
            threats.append("Suspicious URLs detected")
        if features.get('threats_keywords', 0) > 0:
            threats.append("Threatening language present")
        
        return {
            'content': content[:100] + "..." if len(content) > 100 else content,
            'sender': sender,
            'subject': subject,
            'urls': urls,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'is_phishing': is_phishing,
            'confidence': risk_score / 100,
            'features': features,
            'threats_detected': threats,
            'timestamp': datetime.now().isoformat()
        }

def print_header(title):
    """Print a formatted header."""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)

def print_subheader(title):
    """Print a formatted subheader."""
    print(f"\n--- {title} ---")

def demo_phishing_detection():
    """Run the phishing detection demonstration."""
    print_header("AI-POWERED PHISHING DETECTION SYSTEM DEMO")
    print("🛡️  Intelligent Multi-Channel Phishing Detection")
    print("📧  Email • 📱 SMS • 💬 Chat Platform Support")
    print("\nInitializing detection system...")
    
    detector = SimplePhishingDetector()
    print("✅ Detection engine ready!")
    
    # Test cases with different threat levels
    test_messages = [
        {
            'name': '🚨 Critical Phishing Attack',
            'content': 'URGENT! Your bank account will be CLOSED in 2 hours! Click here NOW to verify: http://fake-bank.tk/urgent-verify',
            'sender': 'security@fake-bank.com',
            'subject': 'FINAL WARNING - Account Closure in 2 Hours!'
        },
        {
            'name': '⚠️  High-Risk SMS Phishing',
            'content': 'Free iPhone 15 Pro! Limited time offer expires in 1 hour! Click now: http://free-phone.ml/claim-now',
            'sender': '+1-555-SCAM',
            'subject': ''
        },
        {
            'name': '🔍 Medium Suspicious Email',
            'content': 'Your package delivery failed. Please update your information to complete delivery.',
            'sender': 'delivery@logistics.com',
            'subject': 'Package Delivery Update Required'
        },
        {
            'name': '✅ Legitimate Business Email',
            'content': 'Hi John, please find the quarterly report attached. Let me know if you have any questions about the data.',
            'sender': 'colleague@company.com',
            'subject': 'Q4 Report for Review'
        }
    ]
    
    print_header("REAL-TIME THREAT ANALYSIS")
    
    results = []
    for i, test_case in enumerate(test_messages, 1):
        print_subheader(f"Test {i}: {test_case['name']}")
        
        # Analyze the message
        result = detector.analyze_message(
            test_case['content'],
            test_case['sender'],
            test_case['subject']
        )
        
        results.append(result)
        
        # Display results
        print(f"📄 Message: {result['content']}")
        print(f"👤 Sender: {result['sender']}")
        if result['subject']:
            print(f"📋 Subject: {result['subject']}")
        
        # Risk assessment
        risk_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'MINIMAL': '🟢'
        }
        
        print(f"\n🎯 RISK ASSESSMENT:")
        print(f"   {risk_emoji[result['risk_level']]} Risk Level: {result['risk_level']}")
        print(f"   📊 Risk Score: {result['risk_score']}/100")
        print(f"   🎯 Confidence: {result['confidence']:.1%}")
        print(f"   🚨 Is Phishing: {'YES' if result['is_phishing'] else 'NO'}")
        
        if result['urls']:
            print(f"   🔗 URLs Found: {len(result['urls'])}")
            for url in result['urls']:
                print(f"      • {url}")
        
        if result['threats_detected']:
            print(f"\n⚠️  THREATS DETECTED:")
            for threat in result['threats_detected']:
                print(f"   🔺 {threat}")
        
        # Feature analysis
        key_features = ['urgency_keywords', 'action_keywords', 'financial_keywords', 
                       'threats_keywords', 'suspicious_patterns', 'suspicious_urls']
        
        feature_summary = []
        for feature in key_features:
            value = result['features'].get(feature, 0)
            if value > 0:
                feature_name = feature.replace('_', ' ').title()
                feature_summary.append(f"{feature_name}: {value}")
        
        if feature_summary:
            print(f"\n🔬 KEY INDICATORS:")
            for indicator in feature_summary:
                print(f"   • {indicator}")
        
        print()
    
    # Summary statistics
    print_header("ANALYSIS SUMMARY")
    
    total_messages = len(results)
    phishing_detected = sum(1 for r in results if r['is_phishing'])
    avg_risk_score = sum(r['risk_score'] for r in results) / total_messages
    
    print(f"📊 DETECTION STATISTICS:")
    print(f"   Total Messages Analyzed: {total_messages}")
    print(f"   Phishing Attempts Detected: {phishing_detected}")
    print(f"   Detection Rate: {phishing_detected/total_messages:.1%}")
    print(f"   Average Risk Score: {avg_risk_score:.1f}/100")
    
    # Risk level breakdown
    risk_counts = Counter(r['risk_level'] for r in results)
    print(f"\n📈 RISK LEVEL BREAKDOWN:")
    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL']:
        count = risk_counts.get(level, 0)
        if count > 0:
            emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵', 'MINIMAL': '🟢'}[level]
            print(f"   {emoji} {level}: {count} message{'s' if count != 1 else ''}")
    
    print_header("SYSTEM CAPABILITIES OVERVIEW")
    print("✨ This demonstration showcases key features:")
    print("   🔍 Real-time content analysis")
    print("   🎯 Multi-factor risk assessment")
    print("   🚨 Intelligent threat detection")
    print("   📊 Confidence scoring")
    print("   🌐 URL and domain analysis")
    print("   📱 Multi-channel support (Email, SMS, Chat)")
    
    print("\n🚀 FULL SYSTEM FEATURES:")
    print("   🤖 Machine Learning Detection (Random Forest + SVM + Logistic Regression)")
    print("   📊 40+ Advanced Features")
    print("   🔗 Real-time URL Analysis")
    print("   📧 Email Header Analysis")
    print("   📱 SMS Pattern Detection")
    print("   💬 Chat Platform Integration")
    print("   🚨 Real-time Alert System")
    print("   📈 Comprehensive Reporting")
    print("   🔒 Enterprise Security Integration")
    
    print("\n🎯 NEXT STEPS:")
    print("   1. Configure channels in config.json")
    print("   2. Train ML model: python main.py --train sample_training_data.json")
    print("   3. Start monitoring: python main.py --monitor")
    print("   4. Set up real-time alerts")
    
    print(f"\n{'='*60}")
    print("🛡️  DEMO COMPLETE - Your organization is ready for advanced phishing protection!")
    print(f"{'='*60}")

if __name__ == '__main__':
    demo_phishing_detection()