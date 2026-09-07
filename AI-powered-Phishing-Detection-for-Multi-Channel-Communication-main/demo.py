#!/usr/bin/env python3
"""
Demo script for AI-Powered Phishing Detection System
Demonstrates key capabilities and features
"""

import json
import time
from datetime import datetime
from phishing_detection_system import PhishingDetectionSystem

def print_header(title):
    """Print a formatted header."""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)

def print_subheader(title):
    """Print a formatted subheader."""
    print(f"\n--- {title} ---")

def demo_system_initialization():
    """Demonstrate system initialization."""
    print_header("AI-POWERED PHISHING DETECTION SYSTEM DEMO")
    print("Initializing system components...")
    
    # Initialize the system
    system = PhishingDetectionSystem()
    
    print("✓ Message Preprocessor initialized")
    print("✓ Feature Extractor initialized") 
    print("✓ Machine Learning Model initialized")
    print("✓ Alert System initialized")
    print("✓ Multi-Channel Connector initialized")
    
    return system

def demo_model_training(system):
    """Demonstrate model training with sample data."""
    print_header("MODEL TRAINING DEMONSTRATION")
    
    # Load sample training data
    print("Loading sample training data...")
    with open('sample_training_data.json', 'r') as f:
        training_data = json.load(f)
    
    messages = training_data['messages']
    labels = training_data['labels']
    
    print(f"✓ Loaded {len(messages)} training samples")
    print(f"  - Phishing messages: {sum(labels)}")
    print(f"  - Legitimate messages: {len(labels) - sum(labels)}")
    
    # Train the model
    print("\nTraining ensemble model (Random Forest + Logistic Regression + SVM)...")
    start_time = time.time()
    
    results = system.train_model(messages, labels)
    
    training_time = time.time() - start_time
    
    print(f"✓ Training completed in {training_time:.2f} seconds")
    print(f"\nModel Performance:")
    print(f"  - Training Accuracy: {results['train_accuracy']:.1%}")
    print(f"  - Test Accuracy: {results['test_accuracy']:.1%}")
    print(f"  - Cross-validation Score: {results['cv_mean_accuracy']:.1%} (±{results['cv_std_accuracy']:.1%})")
    print(f"  - ROC AUC Score: {results['roc_auc']:.3f}")
    
    return results

def demo_feature_extraction(system):
    """Demonstrate feature extraction capabilities."""
    print_header("FEATURE EXTRACTION DEMONSTRATION")
    
    # Sample phishing message
    phishing_message = {
        'content': 'URGENT! Your PayPal account will be suspended in 24 hours! Click here immediately to verify: http://paypal-security.tk/login?user=urgent',
        'sender': 'security@paypal-fake.com',
        'subject': 'URGENT: Account Suspension Warning - ACT NOW!',
        'timestamp': datetime.now().isoformat()
    }
    
    print("Analyzing sample phishing message:")
    print(f"From: {phishing_message['sender']}")
    print(f"Subject: {phishing_message['subject']}")
    print(f"Content: {phishing_message['content'][:80]}...")
    
    # Preprocess and extract features
    standardized = system.preprocessor.standardize_message(phishing_message, 'email')
    features = system.feature_extractor.extract_all_features(standardized)
    
    print_subheader("Extracted Features")
    
    # Show key features
    key_features = [
        ('text_length', 'Text Length'),
        ('word_count', 'Word Count'),
        ('uppercase_ratio', 'Uppercase Ratio'),
        ('exclamation_count', 'Exclamation Count'),
        ('urgency_keywords', 'Urgency Keywords'),
        ('action_keywords', 'Action Keywords'),
        ('financial_keywords', 'Financial Keywords'),
        ('url_count', 'URL Count'),
        ('suspicious_tld_count', 'Suspicious TLD Count')
    ]
    
    for feature_key, feature_name in key_features:
        value = features.get(feature_key, 0)
        if isinstance(value, float):
            print(f"  {feature_name}: {value:.3f}")
        else:
            print(f"  {feature_name}: {value}")
    
    print(f"\nTotal features extracted: {len(features)}")
    
    return features

def demo_threat_detection(system):
    """Demonstrate real-time threat detection."""
    print_header("REAL-TIME THREAT DETECTION DEMONSTRATION")
    
    # Test messages with different threat levels
    test_messages = [
        {
            'name': 'Critical Phishing',
            'message': {
                'content': 'FINAL WARNING! Your bank account will be CLOSED in 2 hours! Click NOW: http://urgent-bank.tk/save-account',
                'sender': 'security@fake-bank.com',
                'subject': 'FINAL WARNING - Account Closure'
            },
            'channel': 'email'
        },
        {
            'name': 'SMS Phishing',
            'message': {
                'content': 'Free iPhone 15! Limited time! Click: http://free-phone.ml/get',
                'sender_number': '+12345678901'
            },
            'channel': 'sms'
        },
        {
            'name': 'Legitimate Email',
            'message': {
                'content': 'Hi John, please review the quarterly report attached to this email. Let me know if you have any questions.',
                'sender': 'colleague@company.com',
                'subject': 'Q4 Report Review'
            },
            'channel': 'email'
        },
        {
            'name': 'Borderline Suspicious',
            'message': {
                'content': 'Your package delivery failed. Please update your address to complete delivery.',
                'sender': 'delivery@logistics.com',
                'subject': 'Delivery Update Required'
            },
            'channel': 'email'
        }
    ]
    
    for test_case in test_messages:
        print_subheader(f"Analyzing: {test_case['name']}")
        
        # Analyze the message
        result = system.analyze_message(test_case['message'], test_case['channel'])
        
        # Display results
        print(f"Channel: {test_case['channel'].upper()}")
        print(f"Prediction: {'🚨 PHISHING' if result['is_phishing'] else '✅ LEGITIMATE'}")
        print(f"Confidence: {result['confidence']:.1%}")
        print(f"Risk Level: {result['risk_level']}")
        
        if result.get('alert'):
            print(f"Alert Generated: {result['alert']['alert_id']}")
            print(f"Alert Severity: {result['alert']['severity']}")
            
            if result['alert']['detected_threats']:
                print("Detected Threats:")
                for threat in result['alert']['detected_threats']:
                    print(f"  - {threat}")
        
        time.sleep(1)  # Pause for demo effect

def demo_feature_importance(system):
    """Demonstrate model interpretability."""
    print_header("MODEL INTERPRETABILITY - FEATURE IMPORTANCE")
    
    if system.model.is_trained:
        importance = system.model.get_feature_importance()
        
        print("Top 15 Most Important Features for Phishing Detection:")
        print()
        
        for i, (feature, score) in enumerate(list(importance.items())[:15], 1):
            # Format feature name for better readability
            formatted_name = feature.replace('_', ' ').title()
            bar_length = int(score * 50)  # Scale for visualization
            bar = '█' * bar_length + '░' * (20 - bar_length)
            print(f"{i:2d}. {formatted_name:<25} {bar} {score:.4f}")
        
        print("\nThese features help the model identify phishing patterns:")
        print("- Higher scores indicate more important features")
        print("- The model uses all features together for final prediction")
    else:
        print("Model must be trained first to show feature importance")

def demo_alert_system(system):
    """Demonstrate alert system capabilities."""
    print_header("ALERT SYSTEM DEMONSTRATION")
    
    # Create a sample alert
    critical_message = {
        'channel': 'email',
        'content': 'URGENT SECURITY ALERT! Your account has been compromised. Click here immediately: http://emergency-security.tk/fix',
        'urls': ['http://emergency-security.tk/fix'],
        'metadata': {
            'sender': 'security@fake-alert.com',
            'subject': 'CRITICAL SECURITY BREACH'
        }
    }
    
    # Create alert
    alert = system.alert_system.create_alert(
        critical_message, 
        prediction=1, 
        confidence=0.95, 
        features={'urgency_keywords': 3, 'suspicious_domain_count': 1}
    )
    
    print("Sample Critical Alert Generated:")
    print(f"  Alert ID: {alert['alert_id']}")
    print(f"  Severity: {alert['severity']}")
    print(f"  Confidence: {alert['confidence']:.1%}")
    print(f"  Channel: {alert['channel'].upper()}")
    print(f"  Timestamp: {alert['timestamp']}")
    
    print("\nDetected Threats:")
    for threat in alert['detected_threats']:
        print(f"  🔺 {threat}")
    
    print("\nRecommended Actions:")
    for action in alert['recommended_actions']:
        print(f"  ✋ {action}")
    
    # Show alert statistics
    stats = system.alert_system.get_alert_stats()
    print(f"\nAlert System Statistics:")
    print(f"  Total Alerts Generated: {stats['total_alerts']}")
    if stats['total_alerts'] > 0:
        print(f"  Average Confidence: {stats['avg_confidence']:.1%}")

def demo_system_stats(system):
    """Show comprehensive system statistics."""
    print_header("SYSTEM STATUS AND STATISTICS")
    
    stats = system.get_system_stats()
    
    print("System Status:")
    print(f"  Model Trained: {'✓ YES' if stats['model_trained'] else '✗ NO'}")
    print(f"  Available Channels: {', '.join(stats['available_channels']) if stats['available_channels'] else 'None configured'}")
    print(f"  Detection Threshold: {stats['detection_threshold']:.1%}")
    
    alert_stats = stats['alert_stats']
    print(f"\nAlert Statistics:")
    print(f"  Total Alerts: {alert_stats['total_alerts']}")
    
    if alert_stats['total_alerts'] > 0:
        print(f"  Average Confidence: {alert_stats['avg_confidence']:.1%}")
        
        if alert_stats.get('by_severity'):
            print("  By Severity:")
            for severity, count in alert_stats['by_severity'].items():
                print(f"    {severity}: {count}")

def main():
    """Run the complete demonstration."""
    # Initialize system
    system = demo_system_initialization()
    
    # Train model
    training_results = demo_model_training(system)
    
    # Demonstrate feature extraction
    demo_feature_extraction(system)
    
    # Show feature importance
    demo_feature_importance(system)
    
    # Demonstrate threat detection
    demo_threat_detection(system)
    
    # Show alert system
    demo_alert_system(system)
    
    # Display system stats
    demo_system_stats(system)
    
    # Final summary
    print_header("DEMONSTRATION COMPLETE")
    print("✓ System successfully demonstrated all key capabilities:")
    print("  - Multi-channel message processing")
    print("  - Advanced feature extraction (40+ features)")
    print("  - Ensemble machine learning detection")
    print("  - Real-time threat analysis")
    print("  - Intelligent alert generation")
    print("  - Comprehensive reporting")
    
    print(f"\nModel achieved {training_results['test_accuracy']:.1%} accuracy on test data")
    print("System is ready for production deployment!")
    
    print("\nNext steps:")
    print("1. Configure your communication channels in config.json")
    print("2. Set up alert recipients and notification methods")
    print("3. Run: python main.py --monitor")
    print("4. Monitor logs and alerts for ongoing protection")

if __name__ == '__main__':
    main()