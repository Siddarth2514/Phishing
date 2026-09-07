import logging
import json
import os
from typing import Dict, List, Any, Tuple
from datetime import datetime
import pandas as pd

from message_preprocessor import MessagePreprocessor
from feature_extractor import FeatureExtractor
from phishing_model import PhishingDetectionModel
from alert_system import AlertSystem
from channel_connectors import MultiChannelConnector

class PhishingDetectionSystem:
    """Main phishing detection system that orchestrates all components."""
    
    def __init__(self, config_file: str = 'config.json'):
        self.logger = self._setup_logging()
        self.config = self._load_config(config_file)
        
        # Initialize components
        self.preprocessor = MessagePreprocessor()
        self.feature_extractor = FeatureExtractor()
        self.model = PhishingDetectionModel()
        self.alert_system = AlertSystem(self.config.get('alerts', {}))
        self.connector = MultiChannelConnector(self.config.get('channels', {}))
        
        # Detection settings
        self.detection_threshold = self.config.get('detection_threshold', 0.5)
        self.alert_recipients = self.config.get('alert_recipients', [])
        self.notification_methods = self.config.get('notification_methods', ['email'])
        
        self.logger.info("Phishing Detection System initialized")
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('phishing_detection.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from file."""
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load config file {config_file}: {e}")
        
        # Return default configuration
        return {
            'detection_threshold': 0.5,
            'alert_recipients': [],
            'notification_methods': ['email'],
            'channels': {},
            'alerts': {}
        }
    
    def train_model(self, training_data: List[Dict[str, Any]], labels: List[int]) -> Dict[str, Any]:
        """Train the phishing detection model."""
        self.logger.info("Starting model training...")
        
        # Preprocess training data
        processed_messages = []
        for message in training_data:
            channel = message.get('channel', 'email')
            standardized = self.preprocessor.standardize_message(message, channel)
            processed_messages.append(standardized)
        
        # Extract features
        features_list = []
        for message in processed_messages:
            features = self.feature_extractor.extract_all_features(message)
            features_list.append(features)
        
        # Train model
        results = self.model.train(features_list, labels)
        
        # Save trained model
        self.model.save_model()
        
        self.logger.info("Model training completed")
        return results
    
    def load_trained_model(self, model_path: str = None):
        """Load a pre-trained model."""
        try:
            self.model.load_model(model_path)
            self.logger.info("Trained model loaded successfully")
        except Exception as e:
            self.logger.error(f"Failed to load trained model: {e}")
            raise
    
    def analyze_message(self, message: Dict[str, Any], channel: str) -> Dict[str, Any]:
        """Analyze a single message for phishing."""
        # Preprocess message
        standardized_message = self.preprocessor.standardize_message(message, channel)
        
        # Extract features
        features = self.feature_extractor.extract_all_features(standardized_message)
        
        # Make prediction
        prediction, confidence = self.model.predict(features)
        
        # Create result
        result = {
            'message': standardized_message,
            'features': features,
            'prediction': prediction,
            'confidence': confidence,
            'is_phishing': prediction == 1,
            'risk_level': self._get_risk_level(confidence),
            'timestamp': datetime.now().isoformat()
        }
        
        # Generate alert if phishing detected
        if prediction == 1 and confidence >= self.detection_threshold:
            alert = self.alert_system.create_alert(
                standardized_message, prediction, confidence, features
            )
            result['alert'] = alert
            
            # Send notifications
            if self.alert_recipients:
                notification_results = self.alert_system.send_alert(
                    alert, self.alert_recipients, self.notification_methods
                )
                result['notification_results'] = notification_results
        
        return result
    
    def analyze_batch(self, messages: List[Dict[str, Any]], channel: str) -> List[Dict[str, Any]]:
        """Analyze multiple messages for phishing."""
        results = []
        
        for message in messages:
            try:
                result = self.analyze_message(message, channel)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Failed to analyze message: {e}")
                results.append({
                    'message': message,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        return results
    
    def monitor_channels(self, limit_per_channel: int = 10) -> Dict[str, List[Dict[str, Any]]]:
        """Monitor all configured channels for new messages."""
        self.logger.info("Starting channel monitoring...")
        
        # Fetch messages from all channels
        all_messages = self.connector.fetch_all_messages(limit_per_channel)
        
        results = {}
        
        for channel, messages in all_messages.items():
            if messages:
                self.logger.info(f"Analyzing {len(messages)} messages from {channel}")
                channel_results = self.analyze_batch(messages, channel)
                results[channel] = channel_results
                
                # Log phishing detections
                phishing_count = sum(1 for r in channel_results if r.get('is_phishing', False))
                if phishing_count > 0:
                    self.logger.warning(f"Detected {phishing_count} phishing messages in {channel}")
            else:
                results[channel] = []
        
        return results
    
    def monitor_single_channel(self, channel: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Monitor a single channel for new messages."""
        messages = self.connector.fetch_channel_messages(channel, limit)
        
        if messages:
            self.logger.info(f"Analyzing {len(messages)} messages from {channel}")
            return self.analyze_batch(messages, channel)
        
        return []
    
    def _get_risk_level(self, confidence: float) -> str:
        """Get risk level based on confidence score."""
        if confidence >= 0.9:
            return 'CRITICAL'
        elif confidence >= 0.7:
            return 'HIGH'
        elif confidence >= 0.5:
            return 'MEDIUM'
        elif confidence >= 0.3:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics."""
        alert_stats = self.alert_system.get_alert_stats()
        
        return {
            'model_trained': self.model.is_trained,
            'available_channels': self.connector.get_available_channels(),
            'detection_threshold': self.detection_threshold,
            'alert_stats': alert_stats,
            'system_uptime': datetime.now().isoformat()
        }
    
    def generate_report(self, results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Generate a comprehensive analysis report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {},
            'details': {},
            'recommendations': []
        }
        
        total_messages = 0
        total_phishing = 0
        by_channel = {}
        
        for channel, channel_results in results.items():
            channel_total = len(channel_results)
            channel_phishing = sum(1 for r in channel_results if r.get('is_phishing', False))
            
            total_messages += channel_total
            total_phishing += channel_phishing
            
            by_channel[channel] = {
                'total_messages': channel_total,
                'phishing_detected': channel_phishing,
                'phishing_rate': channel_phishing / channel_total if channel_total > 0 else 0
            }
        
        report['summary'] = {
            'total_messages_analyzed': total_messages,
            'total_phishing_detected': total_phishing,
            'overall_phishing_rate': total_phishing / total_messages if total_messages > 0 else 0,
            'by_channel': by_channel
        }
        
        # Generate recommendations
        if total_phishing > 0:
            report['recommendations'].extend([
                'Review and validate detected phishing messages',
                'Update security policies if necessary',
                'Consider additional user training',
                'Monitor for similar attack patterns'
            ])
        
        # Add high-risk channels to recommendations
        for channel, stats in by_channel.items():
            if stats['phishing_rate'] > 0.1:  # More than 10% phishing rate
                report['recommendations'].append(
                    f'Pay special attention to {channel} channel - high phishing rate detected'
                )
        
        return report
    
    def export_results(self, results: Dict[str, List[Dict[str, Any]]], output_file: str):
        """Export analysis results to file."""
        try:
            # Flatten results for export
            export_data = []
            
            for channel, channel_results in results.items():
                for result in channel_results:
                    if 'error' not in result:
                        export_row = {
                            'channel': channel,
                            'timestamp': result.get('timestamp', ''),
                            'is_phishing': result.get('is_phishing', False),
                            'confidence': result.get('confidence', 0),
                            'risk_level': result.get('risk_level', ''),
                            'sender': result.get('message', {}).get('metadata', {}).get('sender', ''),
                            'content_preview': result.get('message', {}).get('content', '')[:100],
                            'urls_detected': len(result.get('message', {}).get('urls', [])),
                            'alert_generated': 'alert' in result
                        }
                        export_data.append(export_row)
            
            # Save to CSV
            if export_data:
                df = pd.DataFrame(export_data)
                df.to_csv(output_file, index=False)
                self.logger.info(f"Results exported to {output_file}")
            else:
                self.logger.warning("No data to export")
                
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
    
    def shutdown(self):
        """Shutdown the system and cleanup resources."""
        self.logger.info("Shutting down Phishing Detection System")
        self.connector.disconnect_all()