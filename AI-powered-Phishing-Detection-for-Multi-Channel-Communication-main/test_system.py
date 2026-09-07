#!/usr/bin/env python3
"""
Test script for the Phishing Detection System
"""

import json
import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from message_preprocessor import MessagePreprocessor
from feature_extractor import FeatureExtractor
from phishing_model import PhishingDetectionModel
from alert_system import AlertSystem
from phishing_detection_system import PhishingDetectionSystem

class TestMessagePreprocessor(unittest.TestCase):
    def setUp(self):
        self.preprocessor = MessagePreprocessor()
    
    def test_extract_urls(self):
        text = "Visit http://example.com and https://test.org for more info"
        urls = self.preprocessor.extract_urls(text)
        self.assertIn("http://example.com", urls)
        self.assertIn("https://test.org", urls)
    
    def test_clean_text(self):
        text = "Hello, World! This is a TEST."
        cleaned = self.preprocessor.clean_text(text)
        self.assertEqual(cleaned, "hello world this is a test")
    
    def test_standardize_email_message(self):
        message = {
            'content': 'Test email content',
            'sender': 'test@example.com',
            'subject': 'Test Subject'
        }
        result = self.preprocessor.standardize_message(message, 'email')
        self.assertEqual(result['channel'], 'email')
        self.assertEqual(result['content'], 'Test email content')

class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor()
    
    def test_text_features(self):
        text = "URGENT! Click here NOW!!!"
        features = self.extractor.extract_text_features(text)
        self.assertGreater(features['exclamation_count'], 0)
        self.assertGreater(features['uppercase_ratio'], 0)
    
    def test_keyword_features(self):
        text = "Urgent action required! Click to verify your account immediately!"
        features = self.extractor.extract_keyword_features(text)
        self.assertGreater(features['urgency_keywords'], 0)
        self.assertGreater(features['action_keywords'], 0)
    
    def test_url_features(self):
        urls = ['http://suspicious.tk', 'https://192.168.1.1/fake']
        features = self.extractor.extract_url_features(urls)
        self.assertEqual(features['url_count'], 2)
        self.assertGreater(features['suspicious_tld_count'], 0)
        self.assertGreater(features['ip_address_count'], 0)

class TestPhishingModel(unittest.TestCase):
    def setUp(self):
        self.model = PhishingDetectionModel()
    
    def test_model_creation(self):
        self.assertIsNotNone(self.model.model)
        self.assertFalse(self.model.is_trained)
    
    def test_prepare_features(self):
        features_list = [
            {'feature1': 1.0, 'feature2': 2.0},
            {'feature1': 0.5, 'feature2': 1.5}
        ]
        X = self.model.prepare_features(features_list)
        self.assertEqual(X.shape[0], 2)
        self.assertEqual(X.shape[1], 2)

class TestAlertSystem(unittest.TestCase):
    def setUp(self):
        self.alert_system = AlertSystem()
    
    def test_create_alert(self):
        message = {
            'channel': 'email',
            'content': 'Suspicious message content',
            'urls': ['http://suspicious.com'],
            'metadata': {'sender': 'fake@scam.com'}
        }
        alert = self.alert_system.create_alert(message, 1, 0.85, {})
        self.assertEqual(alert['prediction'], 1)
        self.assertEqual(alert['confidence'], 0.85)
        self.assertIn('alert_id', alert)
    
    def test_calculate_severity(self):
        self.assertEqual(self.alert_system._calculate_severity(0.95), 'CRITICAL')
        self.assertEqual(self.alert_system._calculate_severity(0.75), 'HIGH')
        self.assertEqual(self.alert_system._calculate_severity(0.55), 'MEDIUM')
        self.assertEqual(self.alert_system._calculate_severity(0.35), 'LOW')

class TestPhishingDetectionSystem(unittest.TestCase):
    def setUp(self):
        # Create a minimal config for testing
        config = {
            'detection_threshold': 0.5,
            'alert_recipients': ['test@example.com'],
            'notification_methods': ['email'],
            'channels': {},
            'alerts': {}
        }
        
        # Mock the config loading
        with patch('phishing_detection_system.PhishingDetectionSystem._load_config', return_value=config):
            with patch('phishing_detection_system.MultiChannelConnector'):
                self.system = PhishingDetectionSystem()
    
    def test_system_initialization(self):
        self.assertIsNotNone(self.system.preprocessor)
        self.assertIsNotNone(self.system.feature_extractor)
        self.assertIsNotNone(self.system.model)
        self.assertIsNotNone(self.system.alert_system)
    
    def test_get_risk_level(self):
        self.assertEqual(self.system._get_risk_level(0.95), 'CRITICAL')
        self.assertEqual(self.system._get_risk_level(0.75), 'HIGH')
        self.assertEqual(self.system._get_risk_level(0.55), 'MEDIUM')
        self.assertEqual(self.system._get_risk_level(0.35), 'LOW')
        self.assertEqual(self.system._get_risk_level(0.15), 'MINIMAL')

def run_integration_test():
    """Run a simple integration test with sample data."""
    print("Running integration test...")
    
    # Load sample training data
    try:
        with open('sample_training_data.json', 'r') as f:
            training_data = json.load(f)
        
        messages = training_data['messages']
        labels = training_data['labels']
        
        print(f"Loaded {len(messages)} training samples")
        
        # Initialize system
        system = PhishingDetectionSystem()
        
        # Train model
        print("Training model...")
        results = system.train_model(messages, labels)
        print(f"Training completed - Test accuracy: {results['test_accuracy']:.3f}")
        
        # Test with a sample phishing message
        test_message = {
            'content': 'URGENT! Your account will be suspended. Click here immediately: http://fake-bank.tk/verify',
            'sender': 'security@fake.com',
            'subject': 'URGENT: Account Suspension'
        }
        
        print("\nTesting with sample message...")
        result = system.analyze_message(test_message, 'email')
        
        print(f"Prediction: {'PHISHING' if result['is_phishing'] else 'LEGITIMATE'}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Risk Level: {result['risk_level']}")
        
        # Test feature importance
        if system.model.is_trained:
            print("\nTop 10 Feature Importances:")
            importance = system.model.get_feature_importance()
            for feature, score in list(importance.items())[:10]:
                print(f"  {feature}: {score:.4f}")
        
        print("\nIntegration test completed successfully!")
        return True
        
    except Exception as e:
        print(f"Integration test failed: {e}")
        return False

def main():
    print("=" * 50)
    print("AI-Powered Phishing Detection System - Test Suite")
    print("=" * 50)
    
    # Run unit tests
    print("\n1. Running unit tests...")
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run integration test
    print("\n2. Running integration test...")
    run_integration_test()
    
    print("\n" + "=" * 50)
    print("All tests completed!")

if __name__ == '__main__':
    main()