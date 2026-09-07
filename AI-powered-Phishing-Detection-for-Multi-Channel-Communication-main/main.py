#!/usr/bin/env python3
"""
AI-Powered Phishing Detection System
Main entry point for the application
"""

import argparse
import json
import sys
import os
from typing import Dict, Any

from phishing_detection_system import PhishingDetectionSystem

def load_training_data(file_path: str) -> tuple:
    """Load training data from JSON file."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        messages = data.get('messages', [])
        labels = data.get('labels', [])
        
        if len(messages) != len(labels):
            raise ValueError("Number of messages and labels must match")
        
        return messages, labels
        
    except Exception as e:
        print(f"Error loading training data: {e}")
        sys.exit(1)

def train_model(system: PhishingDetectionSystem, training_file: str):
    """Train the phishing detection model."""
    print("Loading training data...")
    messages, labels = load_training_data(training_file)
    
    print(f"Training model with {len(messages)} samples...")
    results = system.train_model(messages, labels)
    
    print("Training completed!")
    print(f"Training accuracy: {results['train_accuracy']:.4f}")
    print(f"Test accuracy: {results['test_accuracy']:.4f}")
    print(f"Cross-validation accuracy: {results['cv_mean_accuracy']:.4f} (+/- {results['cv_std_accuracy']:.4f})")
    print(f"ROC AUC: {results['roc_auc']:.4f}")
    
    return results

def monitor_channels(system: PhishingDetectionSystem, limit: int, output_file: str = None):
    """Monitor all configured channels."""
    print("Monitoring channels for phishing...")
    
    results = system.monitor_channels(limit_per_channel=limit)
    
    # Generate report
    report = system.generate_report(results)
    
    print("\n=== MONITORING REPORT ===")
    print(f"Total messages analyzed: {report['summary']['total_messages_analyzed']}")
    print(f"Phishing detected: {report['summary']['total_phishing_detected']}")
    print(f"Overall phishing rate: {report['summary']['overall_phishing_rate']:.2%}")
    
    print("\nBy Channel:")
    for channel, stats in report['summary']['by_channel'].items():
        print(f"  {channel.upper()}: {stats['phishing_detected']}/{stats['total_messages']} "
              f"({stats['phishing_rate']:.2%})")
    
    if report['recommendations']:
        print("\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  - {rec}")
    
    # Export results if requested
    if output_file:
        system.export_results(results, output_file)
        print(f"\nResults exported to {output_file}")
    
    return results, report

def analyze_single_message(system: PhishingDetectionSystem, message_data: Dict[str, Any], channel: str):
    """Analyze a single message."""
    print(f"Analyzing message from {channel}...")
    
    result = system.analyze_message(message_data, channel)
    
    print("\n=== ANALYSIS RESULT ===")
    print(f"Channel: {channel.upper()}")
    print(f"Is Phishing: {'YES' if result['is_phishing'] else 'NO'}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Risk Level: {result['risk_level']}")
    
    if result.get('alert'):
        print(f"Alert Generated: {result['alert']['alert_id']}")
        print(f"Alert Severity: {result['alert']['severity']}")
    
    return result

def display_system_stats(system: PhishingDetectionSystem):
    """Display system statistics."""
    stats = system.get_system_stats()
    
    print("\n=== SYSTEM STATISTICS ===")
    print(f"Model Trained: {'YES' if stats['model_trained'] else 'NO'}")
    print(f"Available Channels: {', '.join(stats['available_channels'])}")
    print(f"Detection Threshold: {stats['detection_threshold']}")
    
    if stats['alert_stats']['total_alerts'] > 0:
        print(f"\nAlert Statistics:")
        print(f"  Total Alerts: {stats['alert_stats']['total_alerts']}")
        print(f"  Average Confidence: {stats['alert_stats']['avg_confidence']:.2%}")
        
        print(f"  By Severity:")
        for severity, count in stats['alert_stats']['by_severity'].items():
            print(f"    {severity}: {count}")

def main():
    parser = argparse.ArgumentParser(description='AI-Powered Phishing Detection System')
    parser.add_argument('--config', default='config.json', help='Configuration file path')
    parser.add_argument('--train', metavar='TRAINING_FILE', help='Train model with training data file')
    parser.add_argument('--monitor', action='store_true', help='Monitor all configured channels')
    parser.add_argument('--limit', type=int, default=10, help='Limit messages per channel (default: 10)')
    parser.add_argument('--output', help='Output file for results export')
    parser.add_argument('--message', help='JSON string containing message data for single analysis')
    parser.add_argument('--channel', default='email', help='Channel type for single message analysis')
    parser.add_argument('--stats', action='store_true', help='Display system statistics')
    parser.add_argument('--load-model', metavar='MODEL_PATH', help='Load pre-trained model')
    
    args = parser.parse_args()
    
    try:
        # Initialize system
        print("Initializing Phishing Detection System...")
        system = PhishingDetectionSystem(args.config)
        
        # Load pre-trained model if specified
        if args.load_model:
            system.load_trained_model(args.load_model)
        
        # Handle different operations
        if args.train:
            if not os.path.exists(args.train):
                print(f"Error: Training file '{args.train}' not found")
                sys.exit(1)
            train_model(system, args.train)
            
        elif args.monitor:
            if not system.model.is_trained:
                print("Error: Model must be trained before monitoring. Use --train first.")
                sys.exit(1)
            monitor_channels(system, args.limit, args.output)
            
        elif args.message:
            if not system.model.is_trained:
                print("Error: Model must be trained before analysis. Use --train first.")
                sys.exit(1)
            try:
                message_data = json.loads(args.message)
                analyze_single_message(system, message_data, args.channel)
            except json.JSONDecodeError:
                print("Error: Invalid JSON in --message argument")
                sys.exit(1)
                
        elif args.stats:
            display_system_stats(system)
            
        else:
            print("No operation specified. Use --help for available options.")
            print("\nQuick start:")
            print("1. Train model: python main.py --train training_data.json")
            print("2. Monitor channels: python main.py --monitor")
            print("3. Analyze message: python main.py --message '{\"content\":\"Click here now!\", \"sender\":\"unknown@domain.com\"}'")
    
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        # Cleanup
        try:
            system.shutdown()
        except:
            pass

if __name__ == '__main__':
    main()